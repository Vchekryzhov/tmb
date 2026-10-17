package main

import (
	"bytes"
	"encoding/json"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"tmb-poc/internal/proto"
)

// fakeApprover is a stand-in approver socket: it keeps a queue and answers
// list/decide like the broker, recording the decisions it accepted.
type fakeApprover struct {
	mu        sync.Mutex
	items     []proto.QueueItem
	decided   map[string]string
	denyAll   string // when set, every message gets this denial
	mode      string // "weird": wrong answer types; "hangup": no answer; "acceptAny": decide always succeeds; "denyDecide": decide denied
	path      string
	listener  net.Listener
	decisions []proto.Request
}

func startFakeApprover(t *testing.T, items ...proto.QueueItem) *fakeApprover {
	t.Helper()
	dir, err := os.MkdirTemp("", "tmba")
	if err != nil {
		t.Fatalf("mkdtemp: %v", err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	f := &fakeApprover{items: items, decided: map[string]string{}, path: filepath.Join(dir, "a.sock")}
	ln, err := net.Listen("unix", f.path)
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	f.listener = ln
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go f.serve(c)
		}
	}()
	return f
}

func (f *fakeApprover) setMode(m string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.mode = m
}

func (f *fakeApprover) serve(c net.Conn) {
	defer c.Close()
	raw, err := proto.ReadRawFrame(c)
	if err != nil {
		return
	}
	var req proto.Request
	_ = json.Unmarshal(raw, &req)
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.denyAll != "" {
		proto.WriteFrame(c, &proto.Frame{Type: "denied", Reason: f.denyAll, Detail: "from the fake"})
		return
	}
	switch {
	case f.mode == "hangup":
		return
	case f.mode == "weird" && req.Type == "list":
		proto.WriteFrame(c, &proto.Frame{Type: "decided"})
		return
	case f.mode == "weird":
		proto.WriteFrame(c, &proto.Frame{Type: "queue"})
		return
	case f.mode == "acceptAny" && req.Type == "decide":
		proto.WriteFrame(c, &proto.Frame{Type: "decided"})
		return
	case f.mode == "denyDecide" && req.Type == "decide":
		proto.WriteFrame(c, &proto.Frame{Type: "denied", Reason: "decision_mismatch"})
		return
	}
	switch req.Type {
	case "list":
		proto.WriteFrame(c, &proto.Frame{Type: "queue", Items: f.items})
	case "decide":
		for i, it := range f.items {
			if it.ID == req.ItemID {
				if it.Hash != req.ItemHash {
					proto.WriteFrame(c, &proto.Frame{Type: "denied", Reason: "decision_mismatch"})
					return
				}
				f.items = append(f.items[:i], f.items[i+1:]...)
				f.decided[req.ItemID] = req.Decision
				f.decisions = append(f.decisions, req)
				proto.WriteFrame(c, &proto.Frame{Type: "decided", Detail: req.Decision})
				return
			}
		}
		if _, was := f.decided[req.ItemID]; was {
			proto.WriteFrame(c, &proto.Frame{Type: "denied", Reason: "already_decided"})
			return
		}
		proto.WriteFrame(c, &proto.Frame{Type: "denied", Reason: "no_such_item"})
	default:
		proto.WriteFrame(c, &proto.Frame{Type: "denied", Reason: "unknown_request_type"})
	}
}

func runApprove(t *testing.T, stdin string, args ...string) (int, string, string) {
	t.Helper()
	var out, errb bytes.Buffer
	code := cmdApprover(args, strings.NewReader(stdin), &out, &errb)
	return code, out.String(), errb.String()
}

func sampleItem(id string) proto.QueueItem {
	return proto.QueueItem{ID: id, Hash: id + strings.Repeat("0", 48), Requester: "uid=4242 pid=7 (kernel SO_PEERCRED)",
		Executable: "/usr/bin/id", Argv: []string{"/usr/bin/id", "-u"}, Cwd: "/tmp",
		Env: []string{"LANG=C.UTF-8", "PATH=/usr/bin:/bin"}, Nonce: "n-" + id, QueuedAt: "2026-10-17T00:00:00Z"}
}

func TestApproveListShowsTheWholeRequest(t *testing.T) {
	f := startFakeApprover(t, sampleItem("aaaaaaaaaaaaaaaa"))
	code, out, _ := runApprove(t, "", "--list", "--socket", f.path)
	if code != 0 {
		t.Fatalf("--list exit %d", code)
	}
	for _, want := range []string{"=== aaaaaaaaaaaaaaaa ===", "requester : uid=4242 ", "executable: /usr/bin/id", `argv      : ["/usr/bin/id","-u"]`, "cwd       : /tmp", `env       : ["LANG=C.UTF-8","PATH=/usr/bin:/bin"]`, "nonce     : n-aaaaaaaaaaaaaaaa"} {
		if !strings.Contains(out, want) {
			t.Errorf("--list lacks %q:\n%s", want, out)
		}
	}
	empty := startFakeApprover(t)
	if code, out, _ := runApprove(t, "", "--list", "--socket", empty.path); code != 0 || !strings.Contains(out, "queue is empty") {
		t.Errorf("empty --list: %d %q", code, out)
	}
}

func TestApproveYesNoAndAlreadyDecided(t *testing.T) {
	f := startFakeApprover(t, sampleItem("aaaaaaaaaaaaaaaa"), sampleItem("bbbbbbbbbbbbbbbb"))
	t.Setenv("TMB_APPROVE_SOCK", f.path)
	if code, _, errs := runApprove(t, "", "--yes", "aaaaaaaaaaaaaaaa"); code != 0 {
		t.Fatalf("--yes: exit %d %s", code, errs)
	}
	if code, _, errs := runApprove(t, "", "--no", "bbbbbbbbbbbbbbbb"); code != 0 {
		t.Fatalf("--no: exit %d %s", code, errs)
	}
	if f.decided["aaaaaaaaaaaaaaaa"] != "approve" || f.decided["bbbbbbbbbbbbbbbb"] != "deny" {
		t.Fatalf("decisions %v", f.decided)
	}
	if f.decisions[0].ItemHash != sampleItem("aaaaaaaaaaaaaaaa").Hash {
		t.Errorf("decision did not carry the listed hash")
	}
	code, _, errs := runApprove(t, "", "--no", "aaaaaaaaaaaaaaaa")
	if code != 1 || !strings.Contains(errs, "already decided") {
		t.Fatalf("second decision: exit %d stderr %q, want 1 and 'already decided'", code, errs)
	}
	if code, _, _ := runApprove(t, "", "--yes", "cccccccccccccccc"); code != 1 {
		t.Errorf("unknown id: exit %d, want 1", code)
	}
}

func TestApproveInteractive(t *testing.T) {
	f := startFakeApprover(t, sampleItem("aaaaaaaaaaaaaaaa"), sampleItem("bbbbbbbbbbbbbbbb"))
	code, out, errs := runApprove(t, "y\nn\n", "--socket", f.path)
	if code != 0 {
		t.Fatalf("interactive: exit %d %s", code, errs)
	}
	if f.decided["aaaaaaaaaaaaaaaa"] != "approve" || f.decided["bbbbbbbbbbbbbbbb"] != "deny" {
		t.Fatalf("decisions %v", f.decided)
	}
	if strings.Count(out, "Approve exactly this command? [y/N]: ") != 2 {
		t.Errorf("prompts:\n%s", out)
	}
	empty := startFakeApprover(t)
	if code, out, _ := runApprove(t, "", "--socket", empty.path); code != 0 || !strings.Contains(out, "queue is empty") {
		t.Errorf("empty interactive: %d %q", code, out)
	}
}

func TestApproveExitCodes(t *testing.T) {
	f := startFakeApprover(t, sampleItem("aaaaaaaaaaaaaaaa"))
	f.denyAll = "approver_not_allowed"
	if code, _, errs := runApprove(t, "", "--list", "--socket", f.path); code != 125 || !strings.Contains(errs, "approver_not_allowed") {
		t.Errorf("not an approver: exit %d %q, want 125", code, errs)
	}
	if code, _, _ := runApprove(t, "", "--list", "--socket", filepath.Join(t.TempDir(), "none.sock")); code != 3 {
		t.Errorf("no socket: exit %d, want 3", code)
	}
	for _, args := range [][]string{{"--list", "--yes", "x"}, {"--bogus"}, {"extra"}} {
		if code, _, _ := runApprove(t, "", args...); code != 2 {
			t.Errorf("%q: exit %d, want 2", args, code)
		}
	}
}

func TestApproveBrokerMisbehaves(t *testing.T) {
	f := startFakeApprover(t, sampleItem("aaaaaaaaaaaaaaaa"))
	f.setMode("hangup")
	if code, _, errs := runApprove(t, "", "--list", "--socket", f.path); code != 3 || !strings.Contains(errs, "connection to broker lost") {
		t.Errorf("no answer: exit %d %q, want 3", code, errs)
	}
	f.setMode("weird")
	if code, _, errs := runApprove(t, "", "--list", "--socket", f.path); code != 1 || !strings.Contains(errs, "unexpected answer") {
		t.Errorf("wrong answer to list: exit %d %q, want 1", code, errs)
	}
	for _, args := range [][]string{{"--yes", "aaaaaaaaaaaaaaaa"}, {}} {
		if code, _, _ := runApprove(t, "y\n", append(args, "--socket", f.path)...); code != 1 {
			t.Errorf("%q with a broken list: exit %d, want 1", args, code)
		}
	}
	// a broker answering decide with something else
	g := startFakeApprover(t, sampleItem("aaaaaaaaaaaaaaaa"))
	g.setMode("weird")
	c := approverClient{path: g.path}
	if err := c.decide(sampleItem("aaaaaaaaaaaaaaaa"), "approve"); err == nil || !strings.Contains(err.Error(), "unexpected answer") {
		t.Errorf("wrong answer to decide: %v", err)
	}
	h := startFakeApprover(t, sampleItem("aaaaaaaaaaaaaaaa"))
	h.setMode("denyDecide")
	if code, _, errs := runApprove(t, "y\n", "--socket", h.path); code != 125 || !strings.Contains(errs, "decision_mismatch") {
		t.Errorf("denied decision in interactive mode: exit %d %q, want 125", code, errs)
	}
	if code, _, _ := runApprove(t, "", "--no", "aaaaaaaaaaaaaaaa", "--socket", h.path); code != 125 {
		t.Errorf("denied --no: exit %d, want 125", code)
	}
	k := startFakeApprover(t)
	k.setMode("acceptAny")
	if code, _, errs := runApprove(t, "", "--yes", "dddddddddddddddd", "--socket", k.path); code != 1 || !strings.Contains(errs, "without a hash") {
		t.Errorf("broker accepting an unlisted id: exit %d %q, want 1", code, errs)
	}
	if got := (&approverDenied{reason: "x"}).Error(); got != "DENIED: x" {
		t.Errorf("Error() = %q", got)
	}
}

// The requester picks the nonce, argv, env and paths: a control sequence in
// any of them reaches the approver's screen only as an escape.
func TestApproveListEscapesControlSequences(t *testing.T) {
	it := sampleItem("aaaaaaaaaaaaaaaa")
	it.Nonce = "n\x1b[2A\x1b[2K  argv      : [\"/usr/bin/true\"]"
	it.Cwd = "/tmp/\u202ecod"
	it.Argv = []string{"/usr/bin/id", "\u009b2A", "x\x7f"}
	it.Env = []string{"A=\U000e0041"}
	f := startFakeApprover(t, it)
	code, out, _ := runApprove(t, "", "--list", "--socket", f.path)
	if code != 0 {
		t.Fatalf("--list exit %d", code)
	}
	if strings.ContainsAny(out, "\x1b\u202e\u009b\x7f\U000e0041") {
		t.Fatalf("--list passes raw control characters through:\n%q", out)
	}
	for _, want := range []string{
		`nonce     : "n\x1b[2A\x1b[2K  argv      : [\"/usr/bin/true\"]"`,
		`cwd       : "/tmp/\u202ecod"`,
		`argv      : ["/usr/bin/id","\u009b2A","x\u007f"]`,
		`env       : ["A=\udb40\udc41"]`,
	} {
		if !strings.Contains(out, want) {
			t.Errorf("--list lacks %s:\n%s", want, out)
		}
	}
}

// End of input is no answer: the item it stops at stays queued for another
// approver instead of being denied.
func TestApproveInteractiveEndOfInputLeavesItemsQueued(t *testing.T) {
	f := startFakeApprover(t, sampleItem("aaaaaaaaaaaaaaaa"), sampleItem("bbbbbbbbbbbbbbbb"))
	code, out, errs := runApprove(t, "y\n", "--socket", f.path)
	if code != 0 {
		t.Fatalf("interactive: exit %d %s", code, errs)
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.decided["aaaaaaaaaaaaaaaa"] != "approve" {
		t.Fatalf("first item not approved: %v", f.decided)
	}
	if d, ok := f.decided["bbbbbbbbbbbbbbbb"]; ok {
		t.Fatalf("end of input decided the second item: %s", d)
	}
	if !strings.Contains(out, "no answer, bbbbbbbbbbbbbbbb and later items left in the queue") {
		t.Errorf("no end-of-input notice:\n%s", out)
	}
}

// tmb exec reports the broker's waiting frame once on stderr and keeps
// reading until the exit frame.
func TestExecPrintsWaitingOnce(t *testing.T) {
	server, client := net.Pipe()
	go func() {
		defer server.Close()
		code := 0
		proto.WriteFrame(server, &proto.Frame{Type: "waiting", Token: "aaaaaaaaaaaaaaaa", Detail: "at most 5m0s"})
		proto.WriteFrame(server, &proto.Frame{Type: "approved", Token: "aaaaaaaaaaaaaaaa"})
		proto.WriteFrame(server, &proto.Frame{Type: "exit", Code: &code})
	}()
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("pipe: %v", err)
	}
	orig := os.Stderr
	os.Stderr = w
	got, serr := streamFrames(client, true)
	os.Stderr = orig
	w.Close()
	var buf bytes.Buffer
	buf.ReadFrom(r)
	if serr != nil || got != 0 {
		t.Fatalf("streamFrames = %d %v", got, serr)
	}
	if n := strings.Count(buf.String(), "waiting for approval"); n != 1 {
		t.Fatalf("stderr says waiting %d times:\n%s", n, buf.String())
	}
}
