//go:build linux

package main

// Red-green hardening tests for the two exec-time races:
//   slice 1: the exe path is replaced between claim validation and execve ->
//            the APPROVED inode must run (fd pinning), never the replacement
//   slice 2: the cwd directory is replaced between approval and claim ->
//            deny cwd_changed instead of silently running in the new dir
//
// Fixtures avoid building helpers: approved exe = a fresh copy of busybox
// named after the applet it should run (busybox dispatches on argv[0]
// basename, and argv comes verbatim from the request), the swap-in
// replacement = a copy of the go toolchain binary (different program, same
// argv -> usage error). The broker under test runs in-process, so pinned
// fds are observable by readlinking /proc/self/fd in the test process.

import (
	"encoding/base64"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"tmb-poc/internal/proto"
)

// busyboxApplet copies busybox to <dir>/<applet> (fresh inode); a request
// with argv[0] = that path runs the named applet.
func busyboxApplet(t *testing.T, dir, applet string) string {
	t.Helper()
	bb, err := exec.LookPath("busybox")
	if err != nil {
		t.Skipf("no busybox on host: %v", err)
	}
	data, err := os.ReadFile(bb)
	if err != nil {
		t.Fatalf("read busybox: %v", err)
	}
	path := filepath.Join(dir, applet)
	if err := os.WriteFile(path, data, 0o755); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
	return path
}

// foreignBinary copies an unrelated real binary (the go toolchain) to
// <dir>/<name>: a different program that misbehaves under the approved argv.
func foreignBinary(t *testing.T, dir, name string) string {
	t.Helper()
	goBin, err := exec.LookPath("go")
	if err != nil {
		t.Skipf("no go toolchain on host: %v", err)
	}
	data, err := os.ReadFile(goBin)
	if err != nil {
		t.Fatalf("read go binary: %v", err)
	}
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, data, 0o755); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
	return path
}

// newPinBroker mirrors newTestBroker but takes the shared temp dir (so tests
// can watch the claim store) and returns the broker.log path.
func newPinBroker(t *testing.T, dir string, ttl time.Duration) (*Broker, string) {
	t.Helper()
	log, err := NewLogger(filepath.Join(dir, "broker.log"))
	if err != nil {
		t.Fatalf("logger: %v", err)
	}
	claims, err := NewClaimStore(dir)
	if err != nil {
		t.Fatalf("claim store: %v", err)
	}
	cfg := &Config{
		AllowedRequesterUIDs: []uint32{4242},
		AllowedEnvKeys:       []string{"LANG"},
		FixedEnv:             map[string]string{"PATH": "/usr/bin:/bin"},
		AllowedCwdRoots:      []string{"/"},
	}
	return NewBroker(cfg, log, claims, ModeMockApprove, ttl), filepath.Join(dir, "broker.log")
}

// claimCollect runs claimStage over an in-memory pipe and returns the
// terminal frame plus the accumulated child stdout.
func claimCollect(t *testing.T, b *Broker, req *proto.Request, id RequesterID) (*proto.Frame, string) {
	t.Helper()
	server, client := net.Pipe()
	go func() { defer server.Close(); b.claimStage(req, id, server) }()
	defer client.Close()
	var stdout strings.Builder
	for {
		f, err := proto.ReadFrame(client)
		if err != nil {
			t.Fatalf("claim: read frame: %v", err)
		}
		if f.Type == "stdout" {
			if data, err := base64.StdEncoding.DecodeString(f.Data); err == nil {
				stdout.Write(data)
			}
			continue
		}
		if f.Type == "denied" || f.Type == "exit" {
			return f, stdout.String()
		}
	}
}

// exePinFds counts open fds in this process pointing at exePath.
func exePinFds(exePath string) int {
	n := 0
	entries, err := os.ReadDir("/proc/self/fd")
	if err != nil {
		return 0
	}
	for _, e := range entries {
		if target, err := os.Readlink(filepath.Join("/proc/self/fd", e.Name())); err == nil && target == exePath {
			n++
		}
	}
	return n
}

// waitPinsClosed polls until no fd points at exePath or the deadline hits.
func waitPinsClosed(exePath string, d time.Duration) bool {
	deadline := time.Now().Add(d)
	for time.Now().Before(deadline) {
		if exePinFds(exePath) == 0 {
			return true
		}
		time.Sleep(5 * time.Millisecond)
	}
	return exePinFds(exePath) == 0
}

// --- slice 1: approved inode runs despite an in-window exe swap -----------

// TestExecRunsApprovedInodeDespiteMidClaimSwap proves the stat->execve TOCTOU
// is closed: the exe is swapped in the exact window between the claim's
// validation stat and the execve. The swap is armed on the claim store: the
// token claim file is created after validation but long before execve, so a
// spinning watcher that renames the replacement over the approved path the
// instant that file appears lands deterministically inside the window.
func TestExecRunsApprovedInodeDespiteMidClaimSwap(t *testing.T) {
	dir := t.TempDir()
	b, logPath := newPinBroker(t, dir, 30*time.Second)

	exe := busyboxApplet(t, dir, "echo") // runs `echo A` -> "A"
	swap := foreignBinary(t, dir, "prog.b")
	id := UIDRequester(4242, 10)

	req := &proto.Request{
		Executable: exe,
		Argv:       []string{exe, "A"},
		Cwd:        "/tmp",
		UID:        0,
		Env:        map[string]string{"LANG": "C.UTF-8"},
		Nonce:      "pin-exe-1",
	}
	f := approveDo(t, b, req, id)
	if f.Type != "approved" || f.Token == "" {
		t.Fatalf("approve: got frame %+v, want approved with token", f)
	}

	// the approval must pin the exe with an open read-only fd
	if got := exePinFds(exe); got != 1 {
		t.Errorf("after approve: fds pinned to %s = %d, want 1 (exe not fd-pinned at approval)", exe, got)
	}

	// arm the in-window swapper: fire the rename when the token claim file
	// appears (broker is then between validateRequest and execute)
	claimFile := filepath.Join(dir, "claims", req.Hash()+".claim")
	var swapped atomic.Bool
	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			if _, err := os.Stat(claimFile); err == nil {
				swapped.Store(os.Rename(swap, exe) == nil)
				return
			}
		}
	}()

	claim := &proto.Request{
		Executable: exe,
		Argv:       []string{exe, "A"},
		Cwd:        "/tmp",
		UID:        0,
		Env:        map[string]string{"LANG": "C.UTF-8"},
		Nonce:      "pin-exe-1",
		Type:       "claim",
		ClaimToken: f.Token,
	}
	term, stdout := claimCollect(t, b, claim, id)
	<-done

	if !swapped.Load() {
		t.Fatal("replacement never landed inside the claim window")
	}
	if term.Type != "exit" || term.Code == nil || *term.Code != 0 {
		t.Fatalf("claim after in-window swap: got frame %+v (stdout %q), want exit 0 with \"A\": the APPROVED inode must run, not the swapped-in replacement", term, stdout)
	}
	if strings.TrimSpace(stdout) != "A" {
		t.Fatalf("executed output = %q, want \"A\": the APPROVED inode must run, not the swapped-in replacement", stdout)
	}
	// JSONL: exec_start records that the exec went via the pinned fd
	logBytes, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatalf("read broker.log: %v", err)
	}
	if !lineHasBoth(string(logBytes), `"event":"exec_start"`, `"exe_via_fd":true`) {
		t.Errorf("exec_start missing exe_via_fd=true in log:\n%s", logBytes)
	}
	// fd lifecycle: the claim consumed the pending -> pin closed
	if !waitPinsClosed(exe, 2*time.Second) {
		t.Errorf("after claim: fds pinned to %s = %d, want 0 (pin fd leaked)", exe, exePinFds(exe))
	}
}

// TestExecChildFdHygieneViaPinnedExec: when the exec goes through the pinned
// fd (/proc/self/fd/N), the child must still see ONLY fds 0,1,2 plus fds it
// opens itself (the pin fd is O_CLOEXEC and must not survive execve).
func TestExecChildFdHygieneViaPinnedExec(t *testing.T) {
	dir := t.TempDir()
	b, _ := newPinBroker(t, dir, 30*time.Second)
	id := UIDRequester(4242, 11)
	req := &proto.Request{
		Executable: "/bin/ls",
		Argv:       []string{"/bin/ls", "/proc/self/fd"},
		Cwd:        "/tmp",
		UID:        0,
		Env:        map[string]string{"LANG": "C.UTF-8"},
		Nonce:      "pin-fdlist-1",
	}
	f := approveDo(t, b, req, id)
	if f.Type != "approved" || f.Token == "" {
		t.Fatalf("approve: got frame %+v", f)
	}
	claim := &proto.Request{
		Executable: "/bin/ls",
		Argv:       []string{"/bin/ls", "/proc/self/fd"},
		Cwd:        "/tmp",
		UID:        0,
		Env:        map[string]string{"LANG": "C.UTF-8"},
		Nonce:      "pin-fdlist-1",
		Type:       "claim",
		ClaimToken: f.Token,
	}
	term, stdout := claimCollect(t, b, claim, id)
	if term.Type != "exit" || term.Code == nil || *term.Code != 0 {
		t.Fatalf("fd listing exec: got frame %+v, want exit 0", term)
	}
	// 0,1,2 from the broker + fd 3 is ls's own directory handle; any pinned
	// exe fd leaking past execve would appear here as an extra entry
	if got := strings.Fields(stdout); len(got) != 4 || got[0] != "0" || got[1] != "1" || got[2] != "2" || got[3] != "3" {
		t.Errorf("child fd list = %q, want exactly [0 1 2 3] (pin fd leaked into child?)", stdout)
	}
}

// TestExecChildDoesNotInheritStrayFds: a descriptor the broker process
// inherited from whatever started it (opened without O_CLOEXEC, as CI
// runners and init scripts do) must not reach the privileged child.
func TestExecChildDoesNotInheritStrayFds(t *testing.T) {
	stray, err := syscall.Open("/dev/null", syscall.O_RDONLY, 0) // no O_CLOEXEC
	if err != nil {
		t.Fatal(err)
	}
	defer syscall.Close(stray)

	dir := t.TempDir()
	b, _ := newPinBroker(t, dir, 30*time.Second)
	id := UIDRequester(4242, 11)
	req := &proto.Request{
		Executable: "/bin/ls",
		Argv:       []string{"/bin/ls", "/proc/self/fd"},
		Cwd:        "/tmp",
		UID:        0,
		Env:        map[string]string{"LANG": "C.UTF-8"},
		Nonce:      "stray-fd-1",
	}
	f := approveDo(t, b, req, id)
	if f.Type != "approved" || f.Token == "" {
		t.Fatalf("approve: got frame %+v", f)
	}
	claim := *req
	claim.Type = "claim"
	claim.ClaimToken = f.Token
	term, stdout := claimCollect(t, b, &claim, id)
	if term.Type != "exit" || term.Code == nil || *term.Code != 0 {
		t.Fatalf("fd listing exec: got frame %+v, want exit 0", term)
	}
	if got := strings.Fields(stdout); len(got) != 4 || got[0] != "0" || got[1] != "1" || got[2] != "2" || got[3] != "3" {
		t.Errorf("child fd list = %q, want exactly [0 1 2 3] (inherited fd %d leaked into child)", stdout, stray)
	}
}

// --- slice 1: fd lifecycle on pending drop paths ---------------------------

// TestPendingExpiryClosesPinnedFd: an approval that dies of TTL (either via
// peekPending or takePending) must close its pinned exe fd.
func TestPendingExpiryClosesPinnedFd(t *testing.T) {
	dir := t.TempDir()
	b, _ := newPinBroker(t, dir, 150*time.Millisecond)

	exeA := busyboxApplet(t, dir, "echo-a")
	exeB := busyboxApplet(t, dir, "echo-b")
	id := UIDRequester(4242, 12)

	reqA := &proto.Request{Executable: exeA, Argv: []string{exeA}, Cwd: "/tmp", UID: 0, Env: map[string]string{"LANG": "C.UTF-8"}, Nonce: "pin-ttl-a"}
	if f := approveDo(t, b, reqA, id); f.Type != "approved" {
		t.Fatalf("approve A: %+v", f)
	}
	reqB := &proto.Request{Executable: exeB, Argv: []string{exeB}, Cwd: "/tmp", UID: 0, Env: map[string]string{"LANG": "C.UTF-8"}, Nonce: "pin-ttl-b"}
	if f := approveDo(t, b, reqB, id); f.Type != "approved" {
		t.Fatalf("approve B: %+v", f)
	}
	if got := exePinFds(exeA); got != 1 {
		t.Fatalf("after approve A: pinned fds = %d, want 1", got)
	}

	time.Sleep(300 * time.Millisecond) // let both approvals expire

	if _, has := b.peekPending(reqA.Hash()); has {
		t.Fatal("pending A should be expired")
	}
	if got := exePinFds(exeA); got != 0 {
		t.Errorf("after peekPending expiry drop: fds pinned to A = %d, want 0 (leak)", got)
	}
	if _, has := b.takePending(reqB.Hash()); has {
		t.Fatal("pending B should be expired")
	}
	if got := exePinFds(exeB); got != 0 {
		t.Errorf("after takePending expiry drop: fds pinned to B = %d, want 0 (leak)", got)
	}
}

// TestReapproveClosesOldPin: re-approving the same request hash replaces the
// pending approval; the old pin must be closed, not leaked.
func TestReapproveClosesOldPin(t *testing.T) {
	dir := t.TempDir()
	b, _ := newPinBroker(t, dir, 30*time.Second)

	exe := busyboxApplet(t, dir, "echo")
	id := UIDRequester(4242, 13)
	req := &proto.Request{Executable: exe, Argv: []string{exe, "x"}, Cwd: "/tmp", UID: 0, Env: map[string]string{"LANG": "C.UTF-8"}, Nonce: "pin-reapprove-1"}

	if f := approveDo(t, b, req, id); f.Type != "approved" {
		t.Fatalf("first approve: %+v", f)
	}
	if f := approveDo(t, b, req, id); f.Type != "approved" {
		t.Fatalf("second approve: %+v", f)
	}
	if got := exePinFds(exe); got != 1 {
		t.Errorf("after re-approve: fds pinned to %s = %d, want 1 (old pin leaked)", exe, got)
	}
}

// --- slice 2: replaced cwd denies instead of running elsewhere -------------

// TestClaimDeniedWhenCwdReplaced: the approved cwd directory is moved aside
// and a NEW directory is created at the same path before the claim. The
// claim must be denied with cwd_changed and nothing may execute.
func TestClaimDeniedWhenCwdReplaced(t *testing.T) {
	dir := t.TempDir()
	b, logPath := newPinBroker(t, dir, 30*time.Second)

	exe := busyboxApplet(t, dir, "echo")
	cwd := filepath.Join(dir, "wd")
	if err := os.Mkdir(cwd, 0o755); err != nil {
		t.Fatalf("mkdir cwd: %v", err)
	}
	id := UIDRequester(4242, 14)

	req := &proto.Request{Executable: exe, Argv: []string{exe, "B"}, Cwd: cwd, UID: 0, Env: map[string]string{"LANG": "C.UTF-8"}, Nonce: "pin-cwd-1"}
	f := approveDo(t, b, req, id)
	if f.Type != "approved" || f.Token == "" {
		t.Fatalf("approve: got frame %+v, want approved with token", f)
	}

	// replace the directory at the same path (new inode)
	if err := os.Rename(cwd, cwd+".old"); err != nil {
		t.Fatalf("move cwd aside: %v", err)
	}
	if err := os.Mkdir(cwd, 0o755); err != nil {
		t.Fatalf("mkdir replacement cwd: %v", err)
	}

	claim := &proto.Request{Executable: exe, Argv: []string{exe, "B"}, Cwd: cwd, UID: 0, Env: map[string]string{"LANG": "C.UTF-8"}, Nonce: "pin-cwd-1", Type: "claim", ClaimToken: f.Token}
	term, stdout := claimCollect(t, b, claim, id)

	if term.Type != "denied" || term.Reason != "cwd_changed" {
		t.Fatalf("claim after cwd swap: got frame %+v, want denied cwd_changed", term)
	}
	if stdout != "" {
		t.Errorf("nothing may execute on cwd_changed; got stdout %q", stdout)
	}
	logBytes, _ := os.ReadFile(logPath)
	if !lineHasBoth(string(logBytes), `"event":"deny"`, `"reason":"cwd_changed"`) {
		t.Errorf("deny event with reason cwd_changed missing from log:\n%s", logBytes)
	}
	if !waitPinsClosed(exe, 2*time.Second) {
		t.Errorf("after denied claim: fds pinned to %s = %d, want 0 (leak)", exe, exePinFds(exe))
	}
}

// TestClaimUnmodifiedCwdStillExecutes: positive control - same flow, cwd
// untouched -> exit 0 (the re-verification must not break the happy path).
func TestClaimUnmodifiedCwdStillExecutes(t *testing.T) {
	dir := t.TempDir()
	b, _ := newPinBroker(t, dir, 30*time.Second)

	exe := busyboxApplet(t, dir, "echo")
	cwd := filepath.Join(dir, "wd")
	if err := os.Mkdir(cwd, 0o755); err != nil {
		t.Fatalf("mkdir cwd: %v", err)
	}
	id := UIDRequester(4242, 15)

	req := &proto.Request{Executable: exe, Argv: []string{exe, "B"}, Cwd: cwd, UID: 0, Env: map[string]string{"LANG": "C.UTF-8"}, Nonce: "pin-cwd-2"}
	f := approveDo(t, b, req, id)
	if f.Type != "approved" || f.Token == "" {
		t.Fatalf("approve: got frame %+v, want approved with token", f)
	}

	claim := &proto.Request{Executable: exe, Argv: []string{exe, "B"}, Cwd: cwd, UID: 0, Env: map[string]string{"LANG": "C.UTF-8"}, Nonce: "pin-cwd-2", Type: "claim", ClaimToken: f.Token}
	term, stdout := claimCollect(t, b, claim, id)
	if term.Type != "exit" || term.Code == nil || *term.Code != 0 {
		t.Fatalf("claim with intact cwd: got frame %+v, want exit 0", term)
	}
	if strings.TrimSpace(stdout) != "B" {
		t.Errorf("stdout = %q, want \"B\"", stdout)
	}
}
