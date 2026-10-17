package main

import (
	"bufio"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

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

// captureStdout runs fn with os.Stdout redirected and returns what it printed.
func captureStdout(t *testing.T, fn func()) string {
	t.Helper()
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("pipe: %v", err)
	}
	orig := os.Stdout
	os.Stdout = w
	done := make(chan string)
	go func() {
		b, _ := io.ReadAll(r)
		done <- string(b)
	}()
	fn()
	os.Stdout = orig
	w.Close()
	return <-done
}

// The manual console shows the environment the process will start with
// (fixed_env plus allowlisted request keys), not the request's env.
func TestManualConsoleShowsFinalEnv(t *testing.T) {
	b := newTestBroker(t)
	b.mode = ModeManual
	b.stdin = bufio.NewReader(strings.NewReader("n\n"))
	req := testReq(t, "manual-env")
	req.Env = map[string]string{"LANG": "ru_RU.UTF-8"}
	exeReal, err := filepath.EvalSymlinks(req.Executable)
	if err != nil {
		t.Fatalf("realpath: %v", err)
	}
	var granted bool
	out := captureStdout(t, func() {
		granted, _, _ = b.runApprovalInteraction(req, UIDRequester(4242, 1), exeReal, "/tmp", 0, 0, nil)
	})
	if granted {
		t.Fatalf("answer n must deny")
	}
	want := `  env       : ["LANG=ru_RU.UTF-8","PATH=/usr/bin:/bin"]`
	if !strings.Contains(out, want+"\n") {
		t.Fatalf("console lacks final env line %q:\n%s", want, out)
	}
}

// pendingCount reads the size of the pending table under the broker lock.
func pendingCount(b *Broker) int {
	b.mu.Lock()
	defer b.mu.Unlock()
	return len(b.pending)
}

// TestUnclaimedApprovalDroppedAtExpiry: an approval nobody claims leaves the
// pending table (and closes its pins) when its ttl runs out, without another
// request for the same hash; a re-approve's replaced entry does not evict
// the new one.
func TestUnclaimedApprovalDroppedAtExpiry(t *testing.T) {
	b := newTestBroker(t)
	b.mode = ModeMockApprove
	b.ttl = 50 * time.Millisecond
	req := testReq(t, "pending-expiry")
	id := UIDRequester(4242, 1)
	approveDo(t, b, req, id)
	if got := pendingCount(b); got != 1 {
		t.Fatalf("after approve: pending = %d, want 1", got)
	}
	deadline := time.Now().Add(2 * time.Second)
	for pendingCount(b) != 0 && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	if got := pendingCount(b); got != 0 {
		t.Fatalf("after expiry: pending = %d, want 0", got)
	}

	b.ttl = time.Minute
	approveDo(t, b, req, id)
	old := b.pending[req.Hash()]
	approveDo(t, b, req, id)
	b.dropIfExpired(req.Hash(), old)
	if got := pendingCount(b); got != 1 {
		t.Errorf("stale timer evicted the re-approved pending: pending = %d, want 1", got)
	}
}

// TestExpiredPendingDroppedOnLookup: a lookup that beats the expiry timer
// still treats an expired entry as gone and drops it.
func TestExpiredPendingDroppedOnLookup(t *testing.T) {
	for name, lookup := range map[string]func(*Broker, string) (*pendingApproval, bool){
		"peek": (*Broker).peekPending,
		"take": (*Broker).takePending,
	} {
		t.Run(name, func(t *testing.T) {
			b := newTestBroker(t)
			b.pending["h"] = &pendingApproval{Hash: "h", Expiry: time.Now().Add(-time.Second)}
			if _, has := lookup(b, "h"); has {
				t.Errorf("%s returned an expired pending", name)
			}
			if got := pendingCount(b); got != 0 {
				t.Errorf("%s left the expired pending: pending = %d, want 0", name, got)
			}
		})
	}
}
