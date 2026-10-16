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
	dir  string
	open func(path string) (claimFile, error) // openClaimFile; replaced by fault-injection tests
}

// claimFile is the part of *os.File a claim needs.
type claimFile interface {
	Write(p []byte) (int, error)
	Sync() error
	Close() error
}

// openClaimFile creates a claim file exclusively: O_EXCL is the one-shot
// primitive, an existing file means the token or nonce was already used.
func openClaimFile(path string) (claimFile, error) {
	return os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
}

func NewClaimStore(stateDir string) (*ClaimStore, error) {
	dir := filepath.Join(stateDir, "claims")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	return &ClaimStore{dir: dir, open: openClaimFile}, nil
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
	f, err := s.open(path)
	if err != nil {
		if os.IsExist(err) {
			return false, nil
		}
		return false, err
	}
	b, _ := json.MarshalIndent(meta, "", "  ")
	if _, err := f.Write(append(b, '\n')); err != nil {
		f.Close()
		return false, err
	}
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
	return s.Claim(s.tokenPath(fullHash), map[string]string{
		"kind":      "token",
		"token_id":  tokenID,
		"hash":      fullHash,
		"requester": requesterKey,
	})
}

// ClaimNonce consumes a nonce; false means "already used" (replay).
func (s *ClaimStore) ClaimNonce(nonce, requesterKey string) (bool, error) {
	return s.Claim(s.noncePath(nonce), map[string]string{
		"kind":      "nonce",
		"nonce":     nonce,
		"requester": requesterKey,
	})
}
