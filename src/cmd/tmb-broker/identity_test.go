package main

import (
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"tmb-poc/internal/proto"
)

// newTestBroker builds a Broker against temp dirs with both uid and cert
// fingerprint identities allowlisted, mock-approve mode.
func newTestBroker(t *testing.T) *Broker {
	t.Helper()
	log, err := NewLogger(filepath.Join(t.TempDir(), "broker.log"))
	if err != nil {
		t.Fatalf("logger: %v", err)
	}
	claims, err := NewClaimStore(t.TempDir(), time.Minute)
	if err != nil {
		t.Fatalf("claim store: %v", err)
	}
	cfg := &Config{
		AllowedRequesterUIDs: []uint32{4242, 4343},
		AllowedRequesterKeys: []string{strings.Repeat("aa", 32), strings.Repeat("bb", 32)},
		AllowedEnvKeys:       []string{"LANG"},
		FixedEnv:             map[string]string{"PATH": "/usr/bin:/bin"},
		AllowedCwdRoots:      []string{"/"},
	}
	b := NewBroker(cfg, log, claims, ModeMockApprove, 30*time.Second)
	b.hostKey = testHostKey
	return b
}

func trueExe(t *testing.T) string {
	t.Helper()
	exe, err := exec.LookPath("true")
	if err != nil {
		t.Skipf("no true binary on host: %v", err)
	}
	abs, err := filepath.Abs(exe)
	if err != nil {
		t.Fatalf("abs: %v", err)
	}
	return abs
}

func testReq(t *testing.T, nonce string) *proto.Request {
	t.Helper()
	exe := trueExe(t)
	return &proto.Request{
		Executable: exe,
		Argv:       []string{exe},
		Cwd:        "/tmp",
		UID:        0,
		Env:        map[string]string{"LANG": "C.UTF-8"},
		Nonce:      nonce,
	}
}

// approveDo runs doApprove over an in-memory pipe and returns the first frame.
func approveDo(t *testing.T, b *Broker, req *proto.Request, id RequesterID) *proto.Frame {
	t.Helper()
	server, client := net.Pipe()
	go func() { defer server.Close(); b.doApprove(req, id, server) }()
	defer client.Close()
	f, err := proto.ReadFrame(client)
	if err != nil {
		t.Fatalf("approve: read frame: %v", err)
	}
	return f
}

// claimDo runs claimStage over an in-memory pipe and returns the first
// terminal frame (denied or exit).
func claimDo(t *testing.T, b *Broker, req *proto.Request, id RequesterID) *proto.Frame {
	t.Helper()
	return claimStream(t, b, req, id).exit
}

// --- identity rendering ------------------------------------------------------

func TestRequesterIDRendering(t *testing.T) {
	id := UIDRequester(4242, 99)
	if got, want := id.ConsoleLine(), "uid=4242 pid=99 (kernel SO_PEERCRED)"; got != want {
		t.Errorf("uid console line = %q, want %q", got, want)
	}
	lf := id.LogFields()
	if lf["requester_uid"] != uint32(4242) || lf["requester_pid"] != uint32(99) {
		t.Errorf("uid log fields = %v, want requester_uid=4242 requester_pid=99", lf)
	}
	if _, has := lf["requester_fp"]; has {
		t.Errorf("uid log fields must not carry requester_fp: %v", lf)
	}
	if id.Key() != "uid:4242" {
		t.Errorf("uid key = %q, want %q", id.Key(), "uid:4242")
	}

	// 64 hex chars; console shows the first 16. Low entropy on purpose:
	// gitleaks reads "key fp=<random hex>" as a credential.
	fp := strings.Repeat("a", 8) + strings.Repeat("b", 8) + strings.Repeat("c", 48)
	cert := KeyRequester(fp)
	if got, want := cert.ConsoleLine(), "key fp=aaaaaaaabbbbbbbb"; got != want {
		t.Errorf("key console line = %q, want %q (first 16 hex)", got, want)
	}
	clf := cert.LogFields()
	if clf["requester_fp"] != fp {
		t.Errorf("key log fields = %v, want requester_fp=%s", clf, fp)
	}
	if _, has := clf["requester_uid"]; has {
		t.Errorf("key log fields must not carry requester_uid: %v", clf)
	}
	if cert.Key() != "keyfp:"+fp {
		t.Errorf("key identity key = %q, want %q", cert.Key(), "keyfp:"+fp)
	}
}

func TestRequesterIDEquality(t *testing.T) {
	alice := UIDRequester(4242, 11)
	aliceNewProc := UIDRequester(4242, 22) // approve and claim are separate processes
	if !alice.Equal(aliceNewProc) {
		t.Error("same uid with different pid must be the SAME requester (pid is display-only)")
	}
	if alice.Equal(UIDRequester(4343, 11)) {
		t.Error("different uid must be a different requester")
	}
	if alice.Equal(KeyRequester(strings.Repeat("aa", 32))) {
		t.Error("uid and key identities must never be equal")
	}
	if !KeyRequester("aa").Equal(KeyRequester("aa")) {
		t.Error("same fingerprint must be the same requester")
	}
	if KeyRequester("aa").Equal(KeyRequester("bb")) {
		t.Error("different fingerprint must be a different requester")
	}
}

func TestAllowedRequesterPerKind(t *testing.T) {
	b := newTestBroker(t)
	if !b.allowedRequester(UIDRequester(4242, 1)) {
		t.Error("allowlisted uid must pass")
	}
	if b.allowedRequester(UIDRequester(1000, 1)) {
		t.Error("non-allowlisted uid must fail")
	}
	if !b.allowedRequester(KeyRequester(strings.Repeat("aa", 32))) {
		t.Error("allowlisted fingerprint must pass")
	}
	if b.allowedRequester(KeyRequester(strings.Repeat("cc", 32))) {
		t.Error("non-allowlisted fingerprint must fail")
	}
}

// The shared deny path (both listeners) must send, per identity kind, the
// exact denied frame and a requester_denied JSONL event carrying the identity
// fields + reason - and no transport field (stable event shape).
func TestDenyRequesterNotAllowed(t *testing.T) {
	dir := t.TempDir()
	log, err := NewLogger(filepath.Join(dir, "broker.log"))
	if err != nil {
		t.Fatalf("logger: %v", err)
	}
	claims, err := NewClaimStore(dir, time.Minute)
	if err != nil {
		t.Fatalf("claim store: %v", err)
	}
	b := NewBroker(&Config{}, log, claims, ModeMockApprove, 30*time.Second)

	fp := strings.Repeat("cc", 32)
	for _, tc := range []struct {
		id     RequesterID
		detail string
		idJSON string
	}{
		{UIDRequester(1000, 7), "uid 1000 is not in the broker allowlist",
			`"requester_pid":7,"requester_uid":1000`},
		{KeyRequester(fp), "key fp " + fp + " is not in the broker allowlist",
			`"requester_fp":"` + fp + `"`},
	} {
		server, client := net.Pipe()
		go func() { defer server.Close(); b.denyRequesterNotAllowed(server, tc.id) }()
		f, err := proto.ReadFrame(client)
		client.Close()
		if err != nil {
			t.Fatalf("%s: read frame: %v", tc.id.Key(), err)
		}
		if f.Type != "denied" || f.Reason != "requester_not_allowed" || f.Detail != tc.detail {
			t.Errorf("%s: frame = %+v, want denied requester_not_allowed (%s)", tc.id.Key(), f, tc.detail)
		}
	}

	logBytes, err := os.ReadFile(filepath.Join(dir, "broker.log"))
	if err != nil {
		t.Fatalf("read broker.log: %v", err)
	}
	got := string(logBytes)
	for _, idJSON := range []string{`"requester_pid":7,"requester_uid":1000`, `"requester_fp":"` + fp + `"`} {
		if !lineHasBoth(got, `"event":"requester_denied"`, idJSON) {
			t.Errorf("requester_denied event missing %s in log:\n%s", idJSON, got)
		}
	}
	if !lineHasBoth(got, `"event":"requester_denied"`, `"reason":"requester_not_allowed"`) {
		t.Errorf("requester_denied event missing reason in log:\n%s", got)
	}
	if lineHasBoth(got, `"event":"requester_denied"`, `"transport":`) {
		t.Errorf("requester_denied event must not carry a transport field:\n%s", got)
	}
}

// A real client writes its request before reading the answer. The deny path
// must consume that request before replying and closing; otherwise a fast
// client's write races the close (EPIPE on unix sockets) and a clean denial
// surfaces as a transport error (harness N7 on GitHub-hosted Linux).
func TestDenyRequesterNotAllowedAfterClientWrites(t *testing.T) {
	b := newTestBroker(t)
	server, client := net.Pipe() // synchronous: an unread write blocks
	go func() { defer server.Close(); b.denyRequesterNotAllowed(server, UIDRequester(1000, 7)) }()
	defer client.Close()
	_ = client.SetDeadline(time.Now().Add(2 * time.Second))
	req := &proto.Request{Type: "exec", Executable: "/usr/bin/id", Argv: []string{"/usr/bin/id"}, Cwd: "/tmp", Nonce: "n7"}
	if err := proto.WriteFrame(client, req); err != nil {
		t.Fatalf("client write before reading the answer: %v", err)
	}
	f, err := proto.ReadFrame(client)
	if err != nil {
		t.Fatalf("read frame: %v", err)
	}
	if f.Type != "denied" || f.Reason != "requester_not_allowed" {
		t.Fatalf("frame = %+v, want denied requester_not_allowed", f)
	}
}

// --- approval bound to requester identity ------------------------------------

// A claim presented by a DIFFERENT allowlisted identity must be denied with
// requester_mismatch BEFORE the token is consumed; the original identity can
// still claim it afterwards. Proven for BOTH identity kinds: uid (SO_PEERCRED)
// and cert fingerprint (future mTLS listener) - the mechanic must not be
// uid-special-cased.

func TestClaimRequesterMismatchUID(t *testing.T) {
	b := newTestBroker(t)
	alice, bob := UIDRequester(4242, 100), UIDRequester(4343, 200)

	req := testReq(t, "unit-mismatch-uid-1")
	f := approveDo(t, b, req, alice)
	if f.Type != "approved" || f.Token == "" {
		t.Fatalf("approve under alice: got frame %+v, want approved with token", f)
	}
	claim := testReq(t, "unit-mismatch-uid-1")
	claim.Type = "claim"
	claim.ClaimToken = f.Token

	f = claimDo(t, b, claim, bob)
	if f.Type != "denied" || f.Reason != "requester_mismatch" {
		t.Fatalf("claim under bob: got frame %+v, want denied requester_mismatch", f)
	}

	// token NOT consumed by the mismatched claim: alice still redeems it
	f = claimDo(t, b, claim, alice)
	if f.Type != "exit" || f.Code == nil || *f.Code != 0 {
		t.Fatalf("claim under alice after mismatch: got frame %+v, want exit 0", f)
	}
}

func TestClaimRequesterMismatchCert(t *testing.T) {
	b := newTestBroker(t)
	fpA, fpB := strings.Repeat("aa", 32), strings.Repeat("bb", 32)
	alice, bob := KeyRequester(fpA), KeyRequester(fpB)

	req := testReq(t, "unit-mismatch-cert-1")
	f := approveDo(t, b, req, alice)
	if f.Type != "approved" || f.Token == "" {
		t.Fatalf("approve under cert A: got frame %+v, want approved with token", f)
	}
	claim := testReq(t, "unit-mismatch-cert-1")
	claim.Type = "claim"
	claim.ClaimToken = f.Token

	f = claimDo(t, b, claim, bob)
	if f.Type != "denied" || f.Reason != "requester_mismatch" {
		t.Fatalf("claim under cert B: got frame %+v, want denied requester_mismatch", f)
	}

	f = claimDo(t, b, claim, alice)
	if f.Type != "exit" || f.Code == nil || *f.Code != 0 {
		t.Fatalf("claim under cert A after mismatch: got frame %+v, want exit 0", f)
	}
}

// An identity of unknown kind never matches and renders as unknown.
func TestUnknownRequesterKind(t *testing.T) {
	var zero RequesterID
	if zero.Equal(zero) {
		t.Error("an identity of unknown kind must not equal anything")
	}
	if zero.Key() != "unknown:" || zero.ConsoleLine() != "unknown" || len(zero.LogFields()) != 0 ||
		zero.NotAllowedDetail() != "requester not in the broker allowlist" {
		t.Errorf("unknown kind renders as key %q, console %q, fields %v, detail %q",
			zero.Key(), zero.ConsoleLine(), zero.LogFields(), zero.NotAllowedDetail())
	}
	if newTestBroker(t).allowedRequester(zero) {
		t.Error("an identity of unknown kind passed the allowlist")
	}
}
