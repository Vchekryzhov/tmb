package main

import (
	"bytes"
	"encoding/json"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"tmb-poc/internal/proto"
)

// fakeBroker accepts one connection on a fresh unix socket, hands the
// decoded request to reply, and records it. reply writes the frames.
type fakeBroker struct {
	sock string
	got  chan *proto.Request
}

func newFakeBroker(t *testing.T, reply func(conn net.Conn, req *proto.Request)) *fakeBroker {
	t.Helper()
	dir, err := os.MkdirTemp("", "tmbc")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	fb := &fakeBroker{sock: filepath.Join(dir, "b.sock"), got: make(chan *proto.Request, 1)}
	ln, err := net.Listen("unix", fb.sock)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		raw, err := proto.ReadRawFrame(conn)
		if err != nil {
			return
		}
		req, err := proto.DecodeRequest(raw)
		if err != nil {
			return
		}
		fb.got <- req
		reply(conn, req)
	}()
	return fb
}

func frames(fs ...*proto.Frame) func(net.Conn, *proto.Request) {
	return func(conn net.Conn, _ *proto.Request) {
		for _, f := range fs {
			proto.WriteFrame(conn, f)
		}
	}
}

func exitFrame(code int) *proto.Frame { return &proto.Frame{Type: "exit", Code: &code} }

type result struct {
	code           int
	stdout, stderr string
}

func runCLI(t *testing.T, stdin string, args ...string) result {
	t.Helper()
	t.Setenv("TMB_ADDR", "")
	t.Setenv("TMB_SOCK", "")
	var out, errb bytes.Buffer
	code := run(args, strings.NewReader(stdin), &out, &errb)
	return result{code, out.String(), errb.String()}
}

func writeJSON(t *testing.T, v any) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "req.json")
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, b, 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

// exec sends a structured request with the resolved absolute executable,
// streams stdout and stderr, and exits with the remote exit code.
func TestRunExecStreamsAndReturnsRemoteExitCode(t *testing.T) {
	fb := newFakeBroker(t, frames(
		&proto.Frame{Type: "approved", Token: "tok123", Detail: "one-shot"},
		proto.Chunk("stdout", []byte("remote out\n")),
		proto.Chunk("stderr", []byte("remote err\n")),
		&proto.Frame{Type: "progress"},
		exitFrame(5),
	))
	dir := t.TempDir()
	tool := filepath.Join(dir, "tool")
	if err := os.Symlink("/bin/sh", tool); err != nil { // any executable on the host
		t.Fatal(err)
	}
	t.Setenv("PATH", "relative/dir:"+dir)

	r := runCLI(t, "", "exec", "--socket", fb.sock, "--root", "--cwd", "/var", "--env", "TZ=UTC", "--", "tool", "-x")
	if r.code != 5 {
		t.Fatalf("exit code %d, want the remote 5; stderr:\n%s", r.code, r.stderr)
	}
	if r.stdout != "remote out\n" {
		t.Errorf("stdout = %q", r.stdout)
	}
	for _, want := range []string{"REQ: {", "TOK: tok123 (one-shot)", "remote err\n", `FRAME: {"type":"progress"}`, "EXIT: 5"} {
		if !strings.Contains(r.stderr, want) {
			t.Errorf("stderr lacks %q:\n%s", want, r.stderr)
		}
	}
	req := <-fb.got
	if req.Type != "exec" || req.Executable != tool || strings.Join(req.Argv, " ") != tool+" -x" ||
		req.Cwd != "/var" || req.UID != 0 || len(req.Env) != 1 || req.Env["TZ"] != "UTC" || len(req.Nonce) != 32 {
		t.Errorf("request sent = %+v", req)
	}
}

func TestRunExitCodes(t *testing.T) {
	dead := filepath.Join(t.TempDir(), "no.sock")
	cases := []struct {
		name  string
		reply func(net.Conn, *proto.Request)
		args  []string
		code  int
		inErr string
	}{
		{"denied", frames(&proto.Frame{Type: "denied", Reason: "shell_policy", Detail: "/bin/sh"}),
			[]string{"exec", "--root", "--", "/bin/true"}, 125, "tmb: DENIED: shell_policy (/bin/sh)"},
		{"denied without detail", frames(&proto.Frame{Type: "denied", Reason: "nope"}),
			[]string{"exec", "--root", "--", "/bin/true"}, 125, "tmb: DENIED: nope"},
		{"connection lost", frames(&proto.Frame{Type: "approved"}),
			[]string{"exec", "--root", "--", "/bin/true"}, 3, "connection to broker lost"},
		{"broker error frame", frames(&proto.Frame{Type: "error", Reason: "internal", Detail: "x"}),
			[]string{"exec", "--root", "--", "/bin/true"}, 2, "broker error: internal x"},
		{"bad chunk", frames(&proto.Frame{Type: "stdout", Data: "!!"}),
			[]string{"exec", "--root", "--", "/bin/true"}, 2, "bad chunk frame"},
		{"broker down", nil, []string{"exec", "--socket", dead, "--root", "--", "/bin/true"}, 3, "FAIL CLOSED"},
		{"no --root", nil, []string{"exec", "--", "/bin/true"}, 2, "only --root"},
		{"no command", nil, []string{"exec", "--root"}, 2, "expected '--'"},
		{"bad --env", nil, []string{"exec", "--root", "--env", "NOEQ", "--", "/bin/true"}, 2, "--env expects K=V"},
		{"relative path", nil, []string{"exec", "--root", "--", "./x"}, 2, "not absolute"},
		{"not on PATH", nil, []string{"exec", "--root", "--", "no-such-tool-xyz"}, 2, "not found on PATH"},
		{"unknown flag", nil, []string{"exec", "--bogus"}, 2, "flag provided but not defined"},
		{"help", nil, []string{"exec", "-h"}, 0, "Usage of exec"},
		{"no subcommand", nil, nil, 2, "usage:"},
		{"unknown subcommand", nil, []string{"frobnicate"}, 2, "usage:"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			args := c.args
			if c.reply != nil {
				fb := newFakeBroker(t, c.reply)
				args = append([]string{args[0], "--socket", fb.sock}, args[1:]...)
			}
			r := runCLI(t, "", args...)
			if r.code != c.code || !strings.Contains(r.stderr, c.inErr) {
				t.Fatalf("code %d, want %d; stderr lacks %q:\n%s", r.code, c.code, c.inErr, r.stderr)
			}
		})
	}
}

// A socket file without a listener is retried, then reported as the
// broker being down (exit 3).
func TestRunRetriesRefusedSocketThenFailsClosed(t *testing.T) {
	dir, err := os.MkdirTemp("", "tmbr")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(dir)
	sock := filepath.Join(dir, "stale.sock")
	ln, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	ln.(*net.UnixListener).SetUnlinkOnClose(false)
	ln.Close()
	r := runCLI(t, "", "exec", "--socket", sock, "--root", "--", "/bin/true")
	if r.code != 3 || !strings.Contains(r.stderr, "is tmb-broker running?") {
		t.Fatalf("code %d, stderr:\n%s", r.code, r.stderr)
	}
}

func TestRunDebugSubcommands(t *testing.T) {
	base := map[string]any{"type": "exec", "executable": "/bin/true", "argv": []string{"/bin/true"}, "cwd": "/tmp", "nonce": "n1"}
	file := writeJSON(t, base)

	t.Run("approve from file", func(t *testing.T) {
		fb := newFakeBroker(t, frames(&proto.Frame{Type: "approved", Token: "t1"}))
		r := runCLI(t, "", "debug", "approve", "--socket", fb.sock, "--json", file)
		if r.code != 0 || !strings.Contains(r.stderr, `FRAME: {"type":"approved","token":"t1"}`) {
			t.Fatalf("code %d, stderr:\n%s", r.code, r.stderr)
		}
		if req := <-fb.got; req.Type != "approve" || req.Nonce != "n1" {
			t.Errorf("request = %+v", req)
		}
	})
	t.Run("approve from stdin, broker hangs up first", func(t *testing.T) {
		fb := newFakeBroker(t, frames())
		raw, _ := json.Marshal(base)
		r := runCLI(t, string(raw), "debug", "approve", "--socket", fb.sock, "--json", "-")
		if r.code != 3 {
			t.Fatalf("code %d, want 3; stderr:\n%s", r.code, r.stderr)
		}
	})
	t.Run("claim", func(t *testing.T) {
		fb := newFakeBroker(t, frames(proto.Chunk("stdout", []byte("o")), proto.Chunk("stderr", []byte("e")), exitFrame(4)))
		r := runCLI(t, "", "debug", "claim", "--socket", fb.sock, "--token", "tok9", "--json", file)
		if r.code != 4 || r.stdout != "o" || !strings.Contains(r.stderr, "EXIT: 4") {
			t.Fatalf("code %d stdout %q stderr:\n%s", r.code, r.stdout, r.stderr)
		}
		if req := <-fb.got; req.Type != "claim" || req.ClaimToken != "tok9" {
			t.Errorf("request = %+v", req)
		}
	})
	t.Run("claim without token", func(t *testing.T) {
		if r := runCLI(t, "", "debug", "claim", "--json", file); r.code != 2 || !strings.Contains(r.stderr, "--token is required") {
			t.Fatalf("code %d, stderr:\n%s", r.code, r.stderr)
		}
	})
	t.Run("raw keeps the type and reports denial", func(t *testing.T) {
		fb := newFakeBroker(t, frames(&proto.Frame{Type: "progress"}, &proto.Frame{Type: "denied", Reason: "unknown_request_type"}))
		r := runCLI(t, "", "debug", "raw", "--socket", fb.sock, "--json", writeJSON(t, map[string]any{"type": "shutdown"}))
		if r.code != 125 || !strings.Contains(r.stderr, "REQ-RAW:") || !strings.Contains(r.stderr, `"reason":"unknown_request_type"`) {
			t.Fatalf("code %d, stderr:\n%s", r.code, r.stderr)
		}
		if req := <-fb.got; req.Type != "shutdown" {
			t.Errorf("raw request type = %q", req.Type)
		}
	})
	for _, sub := range []string{"approve", "claim", "raw"} {
		t.Run(sub+" bad input", func(t *testing.T) {
			args := []string{"debug", sub, "--token", "t"}
			if sub != "claim" {
				args = []string{"debug", sub}
			}
			if r := runCLI(t, "", append(args, "--json", filepath.Join(t.TempDir(), "none"))...); r.code != 2 {
				t.Errorf("missing file: code %d", r.code)
			}
			if r := runCLI(t, "{", append(args, "--json", "-")...); r.code != 2 || !strings.Contains(r.stderr, "bad request JSON") {
				t.Errorf("bad JSON: code %d, stderr:\n%s", r.code, r.stderr)
			}
			if r := runCLI(t, "", "debug", sub, "--bogus"); r.code != 2 {
				t.Errorf("bad flag: code %d", r.code)
			}
		})
	}
}

func TestMultiFlagCollectsValues(t *testing.T) {
	var m multiFlag
	m.Set("A=1")
	m.Set("B=2")
	if m.String() != "A=1,B=2" {
		t.Fatalf("multiFlag = %q", m.String())
	}
}
