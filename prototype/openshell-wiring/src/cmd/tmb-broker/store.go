// PROTOTYPE CODE - throwaway PoC, not production.
package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
)

// ClaimStore implements exactly-once consumption of tokens and nonces via
// O_CREAT|O_EXCL claim files under StateDir/claims, fsynced (file and parent
// dir). The files live on the container filesystem, so consumption survives
// broker restarts: a token/nonce claimed before a restart can never be
// redeemed again.
type ClaimStore struct {
	dir string
}

func NewClaimStore(stateDir string) (*ClaimStore, error) {
	dir := filepath.Join(stateDir, "claims")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	return &ClaimStore{dir: dir}, nil
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
func (s *ClaimStore) Claim(path string, meta map[string]string) (bool, error) {
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
func (s *ClaimStore) ClaimToken(fullHash, tokenID, requester string) (bool, error) {
	return s.Claim(s.tokenPath(fullHash), map[string]string{
		"kind":          "token",
		"token_id":      tokenID,
		"hash":          fullHash,
		"requester_uid": requester,
	})
}

// ClaimNonce consumes a nonce; false means "already used" (replay).
func (s *ClaimStore) ClaimNonce(nonce, requester string) (bool, error) {
	return s.Claim(s.noncePath(nonce), map[string]string{
		"kind":          "nonce",
		"nonce":         nonce,
		"requester_uid": requester,
	})
}
