package main

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// M6 / SEC-05: a claim file is created exclusively, so a token or nonce is
// redeemed once, including by a broker restarted over the same state dir.
func TestClaimStoreIsOneShotAcrossRestart(t *testing.T) {
	state := t.TempDir()
	s, err := NewClaimStore(state, time.Minute)
	if err != nil {
		t.Fatalf("store: %v", err)
	}
	if ok, err := s.ClaimToken("hash1", "tok1", "uid:1"); !ok || err != nil {
		t.Fatalf("first token claim = %v, %v; want true", ok, err)
	}
	if ok, err := s.ClaimToken("hash1", "tok1", "uid:1"); ok || err != nil {
		t.Fatalf("second token claim = %v, %v; want false (replay)", ok, err)
	}
	if ok, err := s.ClaimNonce("n1", "uid:1"); !ok || err != nil {
		t.Fatalf("first nonce claim = %v, %v; want true", ok, err)
	}

	restarted, err := NewClaimStore(state, time.Minute)
	if err != nil {
		t.Fatalf("store after restart: %v", err)
	}
	if ok, err := restarted.ClaimToken("hash1", "tok1", "uid:2"); ok || err != nil {
		t.Fatalf("token claim after restart = %v, %v; want false (replay)", ok, err)
	}
	if ok, err := restarted.ClaimNonce("n1", "uid:2"); ok || err != nil {
		t.Fatalf("nonce claim after restart = %v, %v; want false (replay)", ok, err)
	}
	if ok, err := restarted.ClaimToken("hash2", "tok2", "uid:1"); !ok || err != nil {
		t.Fatalf("fresh token after restart = %v, %v; want true", ok, err)
	}
}

func TestNewClaimStoreFailsOnUnusableStateDir(t *testing.T) {
	file := filepath.Join(t.TempDir(), "not-a-dir")
	if err := os.WriteFile(file, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := NewClaimStore(file, time.Minute); err == nil {
		t.Fatal("NewClaimStore accepted a regular file as the state dir")
	}
}

var errDisk = errors.New("injected disk failure")

// faultyFile wraps a real claim file and fails one operation.
type faultyFile struct {
	claimFile
	failWrite, failSync, failClose bool
}

func (f faultyFile) Write(p []byte) (int, error) {
	if f.failWrite {
		return 0, errDisk
	}
	return f.claimFile.Write(p)
}

func (f faultyFile) Sync() error {
	if f.failSync {
		return errDisk
	}
	return f.claimFile.Sync()
}

func (f faultyFile) Close() error {
	err := f.claimFile.Close()
	if f.failClose {
		return errDisk
	}
	return err
}

// SEC-09: a create, write, fsync or close failure of the claim store
// denies the claim with claim_store_error and runs nothing, and the
// half-written claim still blocks a retry.
func TestClaimStoreFailureFailsClosed(t *testing.T) {
	wrap := func(ff faultyFile) func(string) (claimFile, error) {
		return func(p string) (claimFile, error) {
			f, err := openClaimFile(p)
			ff.claimFile = f
			return ff, err
		}
	}
	// retryRuns: a failed create leaves nothing behind, so the retry may run
	// the approved command once; any later failure leaves the claim file and
	// the approval stays burned.
	cases := map[string]struct {
		open      func(string) (claimFile, error)
		retryRuns bool
	}{
		"create": {func(string) (claimFile, error) { return nil, errDisk }, true},
		"write":  {wrap(faultyFile{failWrite: true}), false},
		"fsync":  {wrap(faultyFile{failSync: true}), false},
		"close":  {wrap(faultyFile{failClose: true}), false},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			b := newTestBroker(t)
			req := testReq(t, "store-fault-"+name)
			id := UIDRequester(4242, 1)
			f := approveDo(t, b, req, id)
			if f.Type != "approved" {
				t.Fatalf("approve: %+v", f)
			}
			req.ClaimToken = f.Token

			b.claims.open = c.open
			if got := claimDo(t, b, req, id); got.Type != "denied" || got.Reason != "claim_store_error" {
				t.Fatalf("claim with %s failure = %+v, want denied claim_store_error", name, got)
			}
			b.claims.open = openClaimFile
			got := claimDo(t, b, req, id)
			if ran := got.Type == "exit"; ran != c.retryRuns {
				t.Fatalf("retry after a %s failure = %+v, want executed=%v", name, got, c.retryRuns)
			}
		})
	}
}
