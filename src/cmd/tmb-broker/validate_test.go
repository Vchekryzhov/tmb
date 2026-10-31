package main

import (
	"encoding/binary"
	"fmt"
	"math"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"tmb-poc/internal/proto"
)

// Every request-shape and policy check denies with its stable code before
// any approval is shown.
func TestApproveDeniesInvalidRequests(t *testing.T) {
	dir := t.TempDir()
	file := filepath.Join(dir, "file")
	if err := os.WriteFile(file, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	script := filepath.Join(dir, "script")
	if err := os.WriteFile(script, []byte("#!/bin/sh\nid\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "shell-link")
	sh := shExe(t)
	if err := os.Symlink(sh, link); err != nil {
		t.Fatal(err)
	}
	manyEnv := map[string]string{}
	for i := 0; i < 33; i++ {
		manyEnv[fmt.Sprintf("K%d", i)] = "v"
	}
	cases := []struct {
		name   string
		edit   func(*proto.Request)
		reason string
	}{
		{"relative executable", func(r *proto.Request) { r.Executable = "true" }, "executable_not_absolute"},
		{"empty argv", func(r *proto.Request) { r.Argv = nil }, "argv_empty"},
		{"too many argv", func(r *proto.Request) { r.Argv = make([]string, 129) }, "argv_too_long"},
		{"argv element too long", func(r *proto.Request) { r.Argv = []string{strings.Repeat("a", 8193)} }, "argv_too_long"},
		{"non-root uid", func(r *proto.Request) { r.UID = 1000 }, "uid_not_supported"},
		{"env key not allowed", func(r *proto.Request) { r.Env = map[string]string{"LD_PRELOAD": "/x.so"} }, "env_key_not_allowed"},
		{"too many env keys", func(r *proto.Request) { r.Env = manyEnv }, "env_too_many"},
		{"empty nonce", func(r *proto.Request) { r.Nonce = "" }, "nonce_invalid"},
		{"long nonce", func(r *proto.Request) { r.Nonce = strings.Repeat("n", 129) }, "nonce_invalid"},
		{"relative cwd", func(r *proto.Request) { r.Cwd = "tmp" }, "cwd_not_absolute"},
		{"missing executable", func(r *proto.Request) { r.Executable = filepath.Join(dir, "none") }, "executable_not_found"},
		{"directory executable", func(r *proto.Request) { r.Executable = dir }, "executable_not_regular"},
		{"shell by symlink", func(r *proto.Request) { r.Executable = link }, "shell_policy"},
		{"script with shebang", func(r *proto.Request) { r.Executable = script }, "executable_script"},
		{"missing cwd", func(r *proto.Request) { r.Cwd = filepath.Join(dir, "none") }, "cwd_invalid"},
		{"file cwd", func(r *proto.Request) { r.Cwd = file }, "cwd_invalid"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			b := newTestBroker(t)
			b.conf().ShellDenyList = []string{sh}
			for k := range manyEnv {
				b.conf().AllowedEnvKeys = append(b.conf().AllowedEnvKeys, k)
			}
			req := testReq(t, "validate")
			c.edit(req)
			if f := approveDo(t, b, req, UIDRequester(4242, 1)); f.Type != "denied" || f.Reason != c.reason {
				t.Fatalf("frame = %+v, want denied %s", f, c.reason)
			}
		})
	}
}

func TestEmptyCwdDefaultsToTmp(t *testing.T) {
	b := newTestBroker(t)
	id := UIDRequester(4242, 1)
	req := testReq(t, "default-cwd")
	req.Cwd = ""
	req = approved(t, b, req, id)
	if req.Cwd != "/tmp" {
		t.Fatalf("cwd = %q after approval, want /tmp", req.Cwd)
	}
	if f := claimDo(t, b, req, id); f.Type != "exit" {
		t.Fatalf("claim = %+v, want exit", f)
	}
}

// serveRaw sends one raw frame body to serveRequest and returns the reply.
func serveRaw(t *testing.T, b *Broker, body []byte) (*proto.Frame, error) {
	t.Helper()
	server, client := net.Pipe()
	go func() { defer server.Close(); b.serveRequest(server, UIDRequester(4242, 1), "unix") }()
	defer client.Close()
	n := len(body)
	if n < 0 || n > math.MaxUint32 {
		panic("test body does not fit a frame")
	}
	var hdr [4]byte
	binary.BigEndian.PutUint32(hdr[:], uint32(n))
	go client.Write(append(hdr[:], body...))
	return proto.ReadFrame(client)
}

// SEC-07 at the broker: a malformed or unknown request is a controlled
// denial and runs nothing.
func TestServeRequestDeniesMalformedRequests(t *testing.T) {
	b := newTestBroker(t)
	cases := map[string]string{
		`{"type":`:                  "bad_request",
		`[]`:                        "bad_request",
		`{"type":"exec","uid":"0"}`: "bad_request",
		`{"type":"shutdown"}`:       "unknown_request_type",
		`{}`:                        "unknown_request_type",
	}
	for body, reason := range cases {
		f, err := serveRaw(t, b, []byte(body))
		if err != nil || f.Type != "denied" || f.Reason != reason {
			t.Errorf("%s: frame %+v, %v; want denied %s", body, f, err, reason)
		}
	}
}

// A connection that closes before a whole frame arrives gets no answer and
// leaves a bad_frame event.
func TestServeRequestTruncatedFrame(t *testing.T) {
	b := newTestBroker(t)
	server, client := net.Pipe()
	done := make(chan struct{})
	go func() { defer close(done); defer server.Close(); b.serveRequest(server, UIDRequester(4242, 1), "unix") }()
	client.Write([]byte{0, 0, 0, 10, '{'})
	client.Close()
	<-done
	log, _ := os.ReadFile(b.log.f.Name())
	if !strings.Contains(string(log), `"event":"bad_frame"`) || strings.Contains(string(log), `"event":"request"`) {
		t.Fatalf("truncated frame: want only a bad_frame event, log:\n%s", log)
	}
}

func TestServeRequestExecAndApproveTypes(t *testing.T) {
	b := newTestBroker(t)
	req := testReq(t, "serve-exec")
	req.Type = "approve"
	body, _ := jsonBody(req)
	if f, err := serveRaw(t, b, body); err != nil || f.Type != "approved" {
		t.Fatalf("approve: %+v, %v", f, err)
	}
	req.Type, req.ClaimToken = "claim", proto.TokenID(req.Hash())
	body, _ = jsonBody(req)
	if f, err := serveRaw(t, b, body); err != nil || f.Type != "exit" {
		t.Fatalf("claim: %+v, %v", f, err)
	}
}

func jsonBody(r *proto.Request) ([]byte, error) {
	var buf strings.Builder
	if err := proto.WriteFrame(&buf, r); err != nil {
		return nil, err
	}
	return []byte(buf.String()[4:]), nil
}

// scriptDeny reads the first bytes of the pinned file (linux) or of the
// path (elsewhere): a script is refused, a file that cannot be read is
// refused with its own code, anything else passes.
func TestScriptDeny(t *testing.T) {
	dir := t.TempDir()
	cases := []struct {
		name string
		body []byte
		code string
	}{
		{"script", []byte("#!/bin/sh\n"), "executable_script"},
		{"elf", []byte("\x7fELF"), ""},
		{"empty", nil, ""},
		{"one byte", []byte("#"), ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			path := filepath.Join(dir, strings.ReplaceAll(c.name, " ", "-"))
			if err := os.WriteFile(path, c.body, 0o600); err != nil {
				t.Fatal(err)
			}
			p := pinnedFor(t, path)
			if code, _ := p.scriptDeny(); code != c.code {
				t.Fatalf("scriptDeny = %q, want %q", code, c.code)
			}
		})
	}
	t.Run("not pinned or missing", func(t *testing.T) {
		p := &pendingApproval{ExePath: filepath.Join(dir, "none")}
		if code, _ := p.scriptDeny(); code != "executable_unreadable" {
			t.Fatalf("scriptDeny = %q, want executable_unreadable", code)
		}
	})
	t.Run("read fails", func(t *testing.T) {
		f, err := os.Open(".") // a directory: ReadAt fails with EISDIR
		if err != nil {
			t.Fatal(err)
		}
		defer f.Close()
		p := &pendingApproval{ExePath: ".", ExeFile: f}
		if code, _ := p.scriptDeny(); code != "executable_unreadable" {
			t.Fatalf("scriptDeny = %q, want executable_unreadable", code)
		}
	})
}

// pinnedFor returns a pending approval for path pinned the way approveStage
// pins it (an open fd on linux, nothing elsewhere).
func pinnedFor(t *testing.T, path string) *pendingApproval {
	t.Helper()
	req := testReq(t, "pin")
	req.Executable = path
	exeReal, cwdReal, dev, ino, deny, detail := newTestBroker(t).validateRequest(req)
	if deny != "" {
		t.Fatalf("validate: %s %s", deny, detail)
	}
	p := &pendingApproval{ExePath: exeReal}
	if code, detail := pinApproval(p, exeReal, cwdReal, dev, ino); code != "" {
		t.Fatalf("pin: %s %s", code, detail)
	}
	t.Cleanup(p.closePins)
	return p
}

// #68: the approved inode rewritten in place into a script is refused at
// claim before the token is consumed.
func TestClaimDeniesExecutableRewrittenToScript(t *testing.T) {
	exe := filepath.Join(t.TempDir(), "tool")
	if err := os.WriteFile(exe, []byte("\x7fELF not a script"), 0o600); err != nil {
		t.Fatal(err)
	}
	b := newTestBroker(t)
	id := UIDRequester(4242, 1)
	req := testReq(t, "rewritten-to-script")
	req.Executable, req.Argv = exe, []string{exe}
	req = approved(t, b, req, id)

	before, _ := os.Stat(exe)
	if err := os.WriteFile(exe, []byte("#!/bin/sh\nid\n"), 0o600); err != nil { // O_TRUNC: same inode
		t.Fatal(err)
	}
	if after, _ := os.Stat(exe); !os.SameFile(before, after) {
		t.Fatal("rewrite changed the inode; the test needs the same one")
	}
	if got := claimDo(t, b, req, id); got.Type != "denied" || got.Reason != "executable_script" {
		t.Fatalf("claim = %+v, want denied executable_script", got)
	}
	hash := req.Hash()
	if ok, err := b.claims.ClaimToken(hash, proto.TokenID(hash), id.Key()); err != nil || !ok {
		t.Fatalf("token after the denied claim: ok=%v err=%v, want still unconsumed", ok, err)
	}
}
