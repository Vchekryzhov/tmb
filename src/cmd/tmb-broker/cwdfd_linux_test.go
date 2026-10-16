//go:build linux

package main

// The held cwd fd: the child chdirs through /proc/self/fd/N, so a directory
// swap after the last identity check cannot move the command, and every
// outcome closes the fd.

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"tmb-poc/internal/proto"
)

func cwdReq(exe, cwd, nonce string, argv ...string) *proto.Request {
	return &proto.Request{Executable: exe, Argv: append([]string{exe}, argv...), Cwd: cwd, UID: 0, Nonce: nonce}
}

func claimOf(req *proto.Request, token string) *proto.Request {
	c := *req
	c.Type = "claim"
	c.ClaimToken = token
	return &c
}

// TestExecChdirsThroughHeldCwdDespiteSwapAfterCheck swaps the cwd in the
// window between cwdStillPinned and the fork: the child must still start in
// the approved directory, so the marker lands in the held inode.
func TestExecChdirsThroughHeldCwdDespiteSwapAfterCheck(t *testing.T) {
	dir := t.TempDir()
	b, logPath := newPinBroker(t, dir, 30*time.Second)
	exe := busyboxApplet(t, dir, "touch")
	cwd := filepath.Join(dir, "wd")
	if err := os.Mkdir(cwd, 0o750); err != nil {
		t.Fatalf("mkdir cwd: %v", err)
	}
	id := UIDRequester(4242, 20)
	req := cwdReq(exe, cwd, "cwd-fd-race", "marker")
	f := approveDo(t, b, req, id)
	if f.Type != "approved" {
		t.Fatalf("approve: %+v", f)
	}
	if got := dirPinFds(cwd); got != 1 {
		t.Errorf("after approve: fds held on %s = %d, want 1", cwd, got)
	}

	swapped := false
	afterCwdCheck = func() {
		swapped = os.Rename(cwd, cwd+".old") == nil && os.Mkdir(cwd, 0o750) == nil
	}
	t.Cleanup(func() { afterCwdCheck = func() {} })

	term, _ := claimCollect(t, b, claimOf(req, f.Token), id)
	if !swapped {
		t.Fatal("cwd swap after the check did not happen")
	}
	if term.Type != "exit" || term.Code == nil || *term.Code != 0 {
		t.Fatalf("claim: got %+v, want exit 0", term)
	}
	if _, err := os.Stat(filepath.Join(cwd+".old", "marker")); err != nil {
		t.Errorf("marker missing in the approved (held) directory: %v", err)
	}
	if _, err := os.Stat(filepath.Join(cwd, "marker")); err == nil {
		t.Errorf("marker created in the swapped-in directory: the child chdir'ed by path")
	}
	logBytes, _ := os.ReadFile(logPath)
	if !lineHasBoth(string(logBytes), `"event":"exec_start"`, `"cwd_via_fd":true`) {
		t.Errorf("exec_start missing cwd_via_fd=true:\n%s", logBytes)
	}
	if !waitDirPinsClosed(cwd+".old", 2*time.Second) {
		t.Errorf("after exec: cwd fd leaked")
	}
}

// TestCwdPinClosedOnEveryOutcome: deny (cwd_changed), approval expiry and a
// failed exec all close the held directory fd.
func TestCwdPinClosedOnEveryOutcome(t *testing.T) {
	t.Run("cwd_changed", func(t *testing.T) {
		dir := t.TempDir()
		b, _ := newPinBroker(t, dir, 30*time.Second)
		exe := busyboxApplet(t, dir, "echo")
		cwd := filepath.Join(dir, "wd")
		if err := os.Mkdir(cwd, 0o750); err != nil {
			t.Fatalf("mkdir: %v", err)
		}
		id := UIDRequester(4242, 21)
		req := cwdReq(exe, cwd, "cwd-fd-deny", "x")
		f := approveDo(t, b, req, id)
		if err := os.Rename(cwd, cwd+".old"); err != nil {
			t.Fatalf("rename: %v", err)
		}
		if err := os.Mkdir(cwd, 0o750); err != nil {
			t.Fatalf("mkdir: %v", err)
		}
		if term, _ := claimCollect(t, b, claimOf(req, f.Token), id); term.Reason != "cwd_changed" {
			t.Fatalf("claim: got %+v, want cwd_changed", term)
		}
		if !waitDirPinsClosed(cwd+".old", 2*time.Second) {
			t.Errorf("cwd fd leaked after cwd_changed")
		}
	})
	t.Run("expiry", func(t *testing.T) {
		dir := t.TempDir()
		b, _ := newPinBroker(t, dir, 100*time.Millisecond)
		exe := busyboxApplet(t, dir, "echo")
		cwd := filepath.Join(dir, "wd")
		if err := os.Mkdir(cwd, 0o750); err != nil {
			t.Fatalf("mkdir: %v", err)
		}
		req := cwdReq(exe, cwd, "cwd-fd-ttl", "x")
		approveDo(t, b, req, UIDRequester(4242, 22))
		time.Sleep(250 * time.Millisecond)
		if _, has := b.takePending(req.Hash()); has {
			t.Fatal("pending should be expired")
		}
		if got := dirPinFds(cwd); got != 0 {
			t.Errorf("after expiry: fds held on cwd = %d, want 0", got)
		}
	})
	t.Run("exec_error", func(t *testing.T) {
		dir := t.TempDir()
		b, _ := newPinBroker(t, dir, 30*time.Second)
		exe := busyboxApplet(t, dir, "echo")
		cwd := filepath.Join(dir, "wd")
		if err := os.Mkdir(cwd, 0o750); err != nil {
			t.Fatalf("mkdir: %v", err)
		}
		id := UIDRequester(4242, 23)
		req := cwdReq(exe, cwd, "cwd-fd-execerr", "x")
		f := approveDo(t, b, req, id)
		// the approved inode loses its exec bit: execve of the pinned fd fails
		if err := os.Chmod(exe, 0o600); err != nil {
			t.Fatalf("chmod: %v", err)
		}
		term, _ := claimCollect(t, b, claimOf(req, f.Token), id)
		if term.Type != "denied" || term.Reason != "exec_start_failed" {
			t.Fatalf("claim: got %+v, want denied exec_start_failed", term)
		}
		if !waitDirPinsClosed(cwd, 2*time.Second) {
			t.Errorf("cwd fd leaked after exec error")
		}
	})
}

// dirPinFds counts open fds in this process pointing at the directory path.
func dirPinFds(path string) int { return exePinFds(path) }

func waitDirPinsClosed(path string, d time.Duration) bool { return waitPinsClosed(path, d) }
