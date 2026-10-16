package main

import (
	"encoding/base64"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"

	"tmb-poc/internal/proto"
)

// approved approves req for id and returns it with the claim token set.
func approved(t *testing.T, b *Broker, req *proto.Request, id RequesterID) *proto.Request {
	t.Helper()
	f := approveDo(t, b, req, id)
	if f.Type != "approved" {
		t.Fatalf("approve: got %+v, want approved", f)
	}
	req.ClaimToken = f.Token
	return req
}

func cloneReq(r *proto.Request) *proto.Request {
	c := *r
	c.Argv = append([]string(nil), r.Argv...)
	c.Env = map[string]string{}
	for k, v := range r.Env {
		c.Env[k] = v
	}
	return &c
}

// M5 / SEC-02: a claim whose request differs from the approved one in any
// field of the tuple is denied, consumes nothing, and leaves the approved
// request redeemable.
func TestClaimDeniedWhenRequestMutatedAfterApproval(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(*proto.Request)
		reason string
	}{
		{"argv", func(r *proto.Request) { r.Argv = append(r.Argv, "--extra") }, "token_binding_mismatch"},
		{"env value", func(r *proto.Request) { r.Env["LANG"] = "POSIX" }, "token_binding_mismatch"},
		{"env key added", func(r *proto.Request) { r.Env = map[string]string{} }, "token_binding_mismatch"},
		{"nonce", func(r *proto.Request) { r.Nonce += "-other" }, "token_binding_mismatch"},
		{"cwd", func(r *proto.Request) { r.Cwd = "/" }, "token_binding_mismatch"},
		// the broker accepts only uid 0, so a changed uid is refused before
		// the token binding is even checked
		{"uid", func(r *proto.Request) { r.UID = 1000 }, "uid_not_supported"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			b := newTestBroker(t)
			id := UIDRequester(4242, 1)
			orig := approved(t, b, testReq(t, "mutate-"+strings.ReplaceAll(c.name, " ", "-")), id)

			mutated := cloneReq(orig)
			c.mutate(mutated)
			got := claimDo(t, b, mutated, id)
			if got.Type != "denied" || got.Reason != c.reason {
				t.Fatalf("mutated claim = %+v, want denied %s", got, c.reason)
			}
			if got := claimDo(t, b, orig, id); got.Type != "exit" || *got.Code != 0 {
				t.Fatalf("original claim after a mutated one = %+v, want exit 0", got)
			}
		})
	}
}

func TestClaimWithoutApprovalIsDenied(t *testing.T) {
	b := newTestBroker(t)
	req := testReq(t, "never-approved")
	req.ClaimToken = proto.TokenID(req.Hash())
	if got := claimDo(t, b, req, UIDRequester(4242, 1)); got.Type != "denied" || got.Reason != "no_pending_approval" {
		t.Fatalf("claim without approval = %+v, want denied no_pending_approval", got)
	}
}

// SEC-04: many concurrent claims of one approval execute at most once. The
// CI test job runs this under the race detector.
func TestConcurrentClaimsRunAtMostOnce(t *testing.T) {
	const n = 48
	b := newTestBroker(t)
	id := UIDRequester(4242, 1)
	req := approved(t, b, testReq(t, "concurrent"), id)

	var wg sync.WaitGroup
	frames := make(chan *proto.Frame, n)
	start := make(chan struct{})
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			frames <- claimDo(t, b, cloneReq(req), id)
		}()
	}
	close(start)
	wg.Wait()
	close(frames)

	exits := 0
	for f := range frames {
		switch {
		case f.Type == "exit":
			exits++
		case f.Type == "denied" && (f.Reason == "token_consumed_replay" || f.Reason == "no_pending_approval"):
		default:
			t.Errorf("unexpected frame %+v", f)
		}
	}
	if exits != 1 {
		t.Fatalf("%d concurrent claims executed %d times, want exactly 1", n, exits)
	}
}

// execResult is everything a client sees for one claim.
type execResult struct {
	stdout, stderr strings.Builder
	exit           *proto.Frame
}

func claimStream(t *testing.T, b *Broker, req *proto.Request, id RequesterID) *execResult {
	t.Helper()
	server, client := net.Pipe()
	go func() { defer server.Close(); b.claimStage(req, id, server) }()
	defer client.Close()
	res := &execResult{}
	for {
		f, err := proto.ReadFrame(client)
		if err != nil {
			t.Fatalf("read frame: %v", err)
		}
		switch f.Type {
		case "stdout", "stderr":
			data, err := base64.StdEncoding.DecodeString(f.Data)
			if err != nil {
				t.Fatalf("chunk: %v", err)
			}
			if f.Type == "stdout" {
				res.stdout.Write(data)
			} else {
				res.stderr.Write(data)
			}
		case "exit", "denied":
			res.exit = f
			return res
		}
	}
}

func shExe(t *testing.T) string {
	t.Helper()
	sh, err := exec.LookPath("sh")
	if err != nil {
		t.Skipf("no sh on host: %v", err)
	}
	abs, err := filepath.Abs(sh)
	if err != nil {
		t.Fatal(err)
	}
	return abs
}

// SEC-11: stdout and stderr arrive separately and in full, including output
// far larger than one frame, and nonzero and signal exits are reported.
func TestExecReturnsOutputAndExitStatus(t *testing.T) {
	sh := shExe(t)
	const big = 3 << 20 // three MiB: many frames, more than MaxFrame
	cases := []struct {
		name           string
		script         string
		code           int
		stdout, stderr string
		stdoutLen      int
	}{
		{"streams", "printf out; printf err >&2", 0, "out", "err", -1},
		{"nonzero exit", "exit 7", 7, "", "", -1},
		{"signal exit", "kill -TERM $$", 128 + 15, "", "", -1},
		{"large output", "head -c " + strconv.Itoa(big) + " /dev/zero", 0, "", "", big},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			b := newTestBroker(t)
			id := UIDRequester(4242, 1)
			req := testReq(t, "sec11-"+strings.ReplaceAll(c.name, " ", "-"))
			req.Executable, req.Argv = sh, []string{sh, "-c", c.script}
			res := claimStream(t, b, approved(t, b, req, id), id)
			if res.exit.Type != "exit" || *res.exit.Code != c.code {
				t.Fatalf("terminal frame = %s %v, want exit %d", res.exit.Type, exitCodeOrReason(res.exit), c.code)
			}
			if c.stdoutLen >= 0 {
				if res.stdout.Len() != c.stdoutLen {
					t.Fatalf("stdout = %d bytes, want %d", res.stdout.Len(), c.stdoutLen)
				}
				return
			}
			if res.stdout.String() != c.stdout || res.stderr.String() != c.stderr {
				t.Fatalf("stdout=%q stderr=%q, want %q and %q", res.stdout.String(), res.stderr.String(), c.stdout, c.stderr)
			}
		})
	}
}

// exitCodeOrReason renders a terminal frame for a failure message.
func exitCodeOrReason(f *proto.Frame) any {
	if f.Code == nil {
		return f.Reason
	}
	return *f.Code
}

// SEC-05: a nonce is spent once even under a different, separately
// approved request.
func TestNonceReuseAcrossRequestsIsDenied(t *testing.T) {
	b := newTestBroker(t)
	id := UIDRequester(4242, 1)
	first := approved(t, b, testReq(t, "shared-nonce"), id)
	if f := claimDo(t, b, first, id); f.Type != "exit" {
		t.Fatalf("first claim = %+v", f)
	}
	second := testReq(t, "shared-nonce")
	second.Argv = append(second.Argv, "again")
	second = approved(t, b, second, id)
	if f := claimDo(t, b, second, id); f.Type != "denied" || f.Reason != "nonce_consumed_replay" {
		t.Fatalf("second claim = %+v, want denied nonce_consumed_replay", f)
	}
}

// SEC-10: an executable replaced at its path between approval and claim
// is denied.
func TestClaimDeniedWhenExecutableReplaced(t *testing.T) {
	exe := filepath.Join(t.TempDir(), "tool")
	if err := os.Symlink(trueExe(t), exe); err != nil {
		t.Fatal(err)
	}
	b := newTestBroker(t)
	id := UIDRequester(4242, 1)
	req := testReq(t, "exe-replaced")
	req.Executable, req.Argv = exe, []string{exe}
	req = approved(t, b, req, id)

	// same request path, now a different file
	if err := os.Remove(exe); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(shExe(t), exe); err != nil {
		t.Fatal(err)
	}
	if f := claimDo(t, b, req, id); f.Type != "denied" || f.Reason != "executable_changed" {
		t.Fatalf("claim = %+v, want denied executable_changed", f)
	}
}
