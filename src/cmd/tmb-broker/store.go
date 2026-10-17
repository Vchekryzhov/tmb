// PROTOTYPE CODE - throwaway PoC, not production.
package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"time"
)

// ClaimStore implements exactly-once consumption of tokens and nonces via
// O_CREAT|O_EXCL claim files under StateDir/claims, fsynced (file and parent
// dir). The files live on the container filesystem, so consumption survives
// broker restarts: a token/nonce claimed before a restart can never be
// redeemed again while its approval could still be live.
//
// Every file carries expires_at (unix seconds) = creation + retention, where
// retention is the token TTL plus ClaimGrace. GC removes files past it: by
// then the approval behind the token expired long ago, so a replay meets
// no_pending_approval instead of token_consumed_replay.
type ClaimStore struct {
	dir       string
	retention atomic.Int64 // time.Duration; only grows (ExtendRetention)
	now       func() time.Time
}

// ClaimGrace is how long a claim file outlives the token TTL.
const ClaimGrace = 24 * time.Hour

func NewClaimStore(stateDir string, ttl time.Duration) (*ClaimStore, error) {
	dir := filepath.Join(stateDir, "claims")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	s := &ClaimStore{dir: dir, now: time.Now}
	s.retention.Store(int64(ttl + ClaimGrace))
	return s, nil
}

// ExtendRetention raises the retention to ttl + ClaimGrace when a reload
// grows the token TTL. It never shrinks it: a file written under a longer
// TTL keeps protecting a token whose approval may still be live.
func (s *ClaimStore) ExtendRetention(ttl time.Duration) {
	want := int64(ttl + ClaimGrace)
	for {
		cur := s.retention.Load()
		if want <= cur || s.retention.CompareAndSwap(cur, want) {
			return
		}
	}
}

func (s *ClaimStore) tokenPath(fullHash string) string {
	return filepath.Join(s.dir, fullHash+".claim")
}

func (s *ClaimStore) noncePath(nonce string) string {
	sum := sha256.Sum256([]byte("nonce:" + nonce))
	return filepath.Join(s.dir, hex.EncodeToString(sum[:])+".nonce")
}

// Claim creates the claim file exclusively. Returns (true, nil) when the
// claim was freshly created, (false, nil) when it already existed (replay),
// and an error on real I/O trouble. Both file and parent dir are fsynced
// before returning success.
func (s *ClaimStore) Claim(path string, meta map[string]any) (bool, error) {
	meta["expires_at"] = s.now().Add(time.Duration(s.retention.Load())).Unix()
	f, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		if os.IsExist(err) {
			return false, nil
		}
		return false, err
	}
	b, _ := json.MarshalIndent(meta, "", "  ")
	f.Write(append(b, '\n'))
	if err := f.Sync(); err != nil {
		f.Close()
		return false, err
	}
	if err := f.Close(); err != nil {
		return false, err
	}
	// fsync the parent directory so the directory entry itself survives a crash
	d, err := os.Open(s.dir)
	if err != nil {
		return false, err
	}
	defer d.Close()
	if err := d.Sync(); err != nil {
		return false, fmt.Errorf("dir fsync: %w", err)
	}
	return true, nil
}

// ClaimToken consumes a token; false means "already used" (replay).
func (s *ClaimStore) ClaimToken(fullHash, tokenID, requesterKey string) (bool, error) {
	return s.Claim(s.tokenPath(fullHash), map[string]any{
		"kind":      "token",
		"token_id":  tokenID,
		"hash":      fullHash,
		"requester": requesterKey,
	})
}

// ClaimNonce consumes a nonce; false means "already used" (replay).
func (s *ClaimStore) ClaimNonce(nonce, requesterKey string) (bool, error) {
	return s.Claim(s.noncePath(nonce), map[string]any{
		"kind":      "nonce",
		"nonce":     nonce,
		"requester": requesterKey,
	})
}

// GCSkip is a claim file GC left in place because it could not judge it.
type GCSkip struct {
	File, Error string
}

// GC removes token and nonce claim files whose expires_at is in the past.
// A file without expires_at (written before the field existed) expires by
// mtime + retention. A file that cannot be read or parsed is never removed:
// it is reported as skipped, so a damaged store cannot shrink replay
// protection silently.
func (s *ClaimStore) GC() (removed int, skipped []GCSkip, err error) {
	entries, err := os.ReadDir(s.dir)
	if err != nil {
		return 0, nil, err
	}
	now := s.now()
	for _, e := range entries {
		name := e.Name()
		if !e.Type().IsRegular() || !(strings.HasSuffix(name, ".claim") || strings.HasSuffix(name, ".nonce")) {
			continue
		}
		path := filepath.Join(s.dir, name)
		info, jerr := e.Info()
		var expires time.Time
		if jerr == nil {
			expires, jerr = s.expiry(path, info.ModTime())
		}
		if jerr != nil {
			skipped = append(skipped, GCSkip{File: name, Error: jerr.Error()})
			continue
		}
		if !expires.Before(now) {
			continue
		}
		if rerr := os.Remove(path); rerr != nil && !os.IsNotExist(rerr) {
			skipped = append(skipped, GCSkip{File: name, Error: rerr.Error()})
			continue
		}
		removed++
	}
	return removed, skipped, nil
}

// expiry reads a claim file's expires_at, falling back to mtime + retention
// for the old format.
func (s *ClaimStore) expiry(path string, mtime time.Time) (time.Time, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return time.Time{}, err
	}
	var meta struct {
		ExpiresAt *int64 `json:"expires_at"`
	}
	if err := json.Unmarshal(b, &meta); err != nil {
		return time.Time{}, fmt.Errorf("parse: %w", err)
	}
	if meta.ExpiresAt != nil {
		return time.Unix(*meta.ExpiresAt, 0), nil
	}
	return mtime.Add(time.Duration(s.retention.Load())), nil
}
