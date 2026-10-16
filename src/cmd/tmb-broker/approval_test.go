package main

import (
	"bufio"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"tmb-poc/internal/proto"
)

// manualBroker is a manual-mode broker whose console reads answer and
// writes into the returned builder.
func manualBroker(t *testing.T, answer string) (*Broker, *strings.Builder) {
	t.Helper()
	b := newTestBroker(t)
	b.mode = ModeManual
	b.stdin = bufio.NewReader(strings.NewReader(answer))
	out := &strings.Builder{}
	b.console = out
	return b, out
}

// The human sees the exact request and requester, and only "y"/"yes"
// approves; anything else, or closed input, denies and runs nothing.
func TestManualApproval(t *testing.T) {
	cases := []struct {
		answer, frame, reason, console string
	}{
		{"y\n", "approved", "", "-> APPROVED"},
		{"YES\n", "approved", "", "-> APPROVED"},
		{"n\n", "denied", "approval_denied_by_human", "-> DENIED"},
		{"\n", "denied", "approval_denied_by_human", "-> DENIED"},
		{"", "denied", "approval_input_closed", "CLOSED (no human input) -> DENIED"},
	}
	for _, c := range cases {
		t.Run(strings.TrimSpace(c.answer), func(t *testing.T) {
			b, out := manualBroker(t, c.answer)
			req := testReq(t, "manual-nonce-1")
			f := approveDo(t, b, req, UIDRequester(4242, 77))
			if f.Type != c.frame || f.Reason != c.reason {
				t.Fatalf("frame = %+v, want %s %s", f, c.frame, c.reason)
			}
			console := out.String()
			for _, want := range []string{
				"=== TMB APPROVAL REQUIRED ===",
				"requester : uid=4242 pid=77 (kernel SO_PEERCRED)",
				"executable: " + req.Executable,
				`argv      : ["` + req.Executable + `"]`,
				"cwd       : /tmp",
				"run as uid: 0",
				`env       : ["LANG=C.UTF-8","PATH=/usr/bin:/bin"]`,
				"nonce     : manual-nonce-1",
				c.console,
			} {
				if !strings.Contains(console, want) {
					t.Errorf("console lacks %q:\n%s", want, console)
				}
			}
		})
	}
}

func TestMockApprovalModes(t *testing.T) {
	cases := map[string]string{
		ModeMockDeny:    "approval_denied_by_mode",
		ModeMockTimeout: "approval_timeout",
		"no-such-mode":  "approval_mode_unknown",
	}
	for mode, reason := range cases {
		t.Run(mode, func(t *testing.T) {
			b := newTestBroker(t)
			b.mode, b.ttl = mode, 10*time.Millisecond
			req := testReq(t, "mode-"+mode)
			if f := approveDo(t, b, req, UIDRequester(4242, 1)); f.Type != "denied" || f.Reason != reason {
				t.Fatalf("frame = %+v, want denied %s", f, reason)
			}
			req.ClaimToken = proto.TokenID(req.Hash())
			if f := claimDo(t, b, req, UIDRequester(4242, 1)); f.Type == "exit" {
				t.Fatal("a denied approval was redeemed")
			}
		})
	}
}

// An approval expires after its TTL: a later claim runs nothing.
func TestClaimAfterTTLIsDenied(t *testing.T) {
	b := newTestBroker(t)
	b.ttl = 20 * time.Millisecond
	id := UIDRequester(4242, 1)
	req := approved(t, b, testReq(t, "ttl"), id)
	time.Sleep(60 * time.Millisecond)
	if f := claimDo(t, b, req, id); f.Type != "denied" || f.Reason != "no_pending_approval" {
		t.Fatalf("claim after TTL = %+v, want denied no_pending_approval", f)
	}
}

// approvalEvents returns every "approval" JSONL event the broker logged.
func approvalEvents(t *testing.T, b *Broker) []map[string]any {
	t.Helper()
	raw, err := os.ReadFile(b.log.f.Name())
	if err != nil {
		t.Fatalf("read log: %v", err)
	}
	var out []map[string]any
	for _, line := range strings.Split(strings.TrimSpace(string(raw)), "\n") {
		var ev map[string]any
		if err := json.Unmarshal([]byte(line), &ev); err != nil {
			t.Fatalf("bad JSONL line %q: %v", line, err)
		}
		if ev["event"] == "approval" {
			out = append(out, ev)
		}
	}
	return out
}

func TestApprovalEventCarriesApproverAndDecision(t *testing.T) {
	for _, tc := range []struct {
		mode, decision string
	}{
		{ModeMockApprove, "approve"},
		{ModeMockDeny, "deny"},
	} {
		t.Run(tc.mode, func(t *testing.T) {
			b := newTestBroker(t)
			b.mode = tc.mode
			approveDo(t, b, testReq(t, "approval-event-"+tc.mode), UIDRequester(4242, 1))
			evs := approvalEvents(t, b)
			if len(evs) != 1 {
				t.Fatalf("want 1 approval event, got %d", len(evs))
			}
			if got := evs[0]["approver"]; got != "mode:"+tc.mode {
				t.Errorf("approver = %v, want mode:%s", got, tc.mode)
			}
			if got := evs[0]["decision"]; got != tc.decision {
				t.Errorf("decision = %v, want %s", got, tc.decision)
			}
		})
	}
}

// The manual console shows the environment the process will start with
// (fixed_env plus allowlisted request keys), not the request's env.
func TestManualConsoleShowsFinalEnv(t *testing.T) {
	b, out := manualBroker(t, "n\n")
	req := testReq(t, "manual-env")
	req.Env = map[string]string{"LANG": "ru_RU.UTF-8"}
	exeReal, err := filepath.EvalSymlinks(req.Executable)
	if err != nil {
		t.Fatalf("realpath: %v", err)
	}
	if granted, _, _ := b.runApprovalInteraction(req, UIDRequester(4242, 1), exeReal, "/tmp", 0, 0); granted {
		t.Fatalf("answer n must deny")
	}
	want := `  env       : ["LANG=ru_RU.UTF-8","PATH=/usr/bin:/bin"]`
	if !strings.Contains(out.String(), want+"\n") {
		t.Fatalf("console lacks final env line %q:\n%s", want, out.String())
	}
}
