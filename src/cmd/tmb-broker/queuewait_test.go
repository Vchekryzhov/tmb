package main

import (
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"tmb-poc/internal/proto"
)

// approveFrames runs doApprove and collects every frame until the terminal
// one; close(hangup) closes the client side early.
func approveFrames(b *Broker, req *proto.Request, id RequesterID, hangup <-chan struct{}) <-chan []*proto.Frame {
	server, client := net.Pipe()
	go func() { defer server.Close(); b.doApprove(req, id, server) }()
	out := make(chan []*proto.Frame, 1)
	go func() {
		var frames []*proto.Frame
		defer func() { out <- frames }()
		defer client.Close()
		got := make(chan *proto.Frame)
		go func() {
			defer close(got)
			for {
				f, err := proto.ReadFrame(client)
				if err != nil {
					return
				}
				got <- f
			}
		}()
		for {
			select {
			case f, ok := <-got:
				if !ok {
					return
				}
				frames = append(frames, f)
				if f.Type != "waiting" {
					return
				}
			case <-hangup:
				return
			}
		}
	}()
	return out
}

func TestQueueWaitTimesOut(t *testing.T) {
	b := newQueueBroker(t)
	b.pol.Store(&policy{cfg: b.conf(), ttl: b.tokenTTL(), wait: 150 * time.Millisecond})
	start := time.Now()
	frames := <-approveFrames(b, testReq(t, "queue-timeout"), UIDRequester(4242, 1), nil)
	if took := time.Since(start); took < b.approvalWait() {
		t.Errorf("denied after %v, before the %v wait", took, b.approvalWait())
	}
	if len(frames) != 2 || frames[0].Type != "waiting" || frames[1].Reason != "approval_timeout" {
		t.Fatalf("frames %+v, want waiting then denied approval_timeout", frames)
	}
	if !strings.Contains(frames[0].Detail, "at most") {
		t.Errorf("waiting frame detail %q", frames[0].Detail)
	}
	if len(b.queue.list()) != 0 {
		t.Errorf("timed-out item still queued")
	}
	if !strings.Contains(logText(t, b), `"event":"approval_timeout"`) {
		t.Errorf("approval_timeout event missing")
	}
}

func TestQueueRequesterHangupWithdraws(t *testing.T) {
	b := newQueueBroker(t)
	hangup := make(chan struct{})
	done := approveFrames(b, testReq(t, "queue-abandon"), UIDRequester(4242, 1), hangup)
	deadline := time.Now().Add(2 * time.Second)
	for len(b.queue.list()) == 0 && time.Now().Before(deadline) {
		time.Sleep(2 * time.Millisecond)
	}
	if len(b.queue.list()) != 1 {
		t.Fatal("request never queued")
	}
	close(hangup)
	<-done
	for len(b.queue.list()) != 0 && time.Now().Before(deadline) {
		time.Sleep(2 * time.Millisecond)
	}
	if len(b.queue.list()) != 0 {
		t.Fatal("abandoned request still queued")
	}
	for !strings.Contains(logText(t, b), `"event":"request_abandoned"`) && time.Now().Before(deadline) {
		time.Sleep(2 * time.Millisecond)
	}
	if !strings.Contains(logText(t, b), `"event":"request_abandoned"`) {
		t.Errorf("request_abandoned event missing")
	}
}

// One waiting request does not hold up another: the second is approved and
// answered while the first still waits.
func TestQueueIsNotAMutex(t *testing.T) {
	b := newQueueBroker(t)
	first, firstDone := queueRequest(t, b, testReq(t, "queue-first"), UIDRequester(4242, 1))
	second, secondDone := queueRequest(t, b, testReq(t, "queue-second"), UIDRequester(4242, 2))
	human := UIDRequester(humanUID, 9)
	approverDo(t, b, human, &proto.Request{Type: "decide", ItemID: second.ID, ItemHash: second.Hash, Decision: "approve"})
	select {
	case f := <-secondDone:
		if f.Type != "approved" {
			t.Fatalf("second: %+v", f)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("second request blocked behind the first")
	}
	if items := b.queue.list(); len(items) != 1 || items[0].ID != first.ID {
		t.Fatalf("queue %+v, want only the first", items)
	}
	approverDo(t, b, human, &proto.Request{Type: "decide", ItemID: first.ID, ItemHash: first.Hash, Decision: "approve"})
	if f := <-firstDone; f.Type != "approved" {
		t.Fatalf("first: %+v", f)
	}
}

// A decision that lands before a timeout or hangup is honoured.
func TestQueueWithdrawLosesToDecision(t *testing.T) {
	q := newApprovalQueue()
	e, _ := q.add(proto.QueueItem{ID: "x", Hash: "h"})
	if deny, _ := q.decide("x", "h", queueDecision{granted: true}); deny != "" {
		t.Fatalf("decide: %s", deny)
	}
	if q.withdraw("x") {
		t.Fatal("withdraw removed a decided item")
	}
	if d := <-e.result; !d.granted {
		t.Fatal("decision lost")
	}
}

func TestLoadConfigApprovalWaitIsSeparate(t *testing.T) {
	p := filepath.Join(t.TempDir(), "c.json")
	if err := os.WriteFile(p, []byte(`{"socket_path": "/a", "state_dir": "/s", "log_path": "/l", "token_ttl_seconds": 7}`), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	c, err := loadConfig(p)
	if err != nil {
		t.Fatalf("loadConfig: %v", err)
	}
	if c.ApprovalWaitSeconds != 300 || c.TokenTTLSeconds != 7 {
		t.Errorf("wait %d ttl %d, want 300 and 7", c.ApprovalWaitSeconds, c.TokenTTLSeconds)
	}
	c.ApprovalWaitSeconds = 2
	b := NewBroker(c, nil, nil, ModeQueue, time.Minute)
	if b.approvalWait() != 2*time.Second || b.tokenTTL() != time.Minute {
		t.Errorf("broker wait %v ttl %v", b.approvalWait(), b.tokenTTL())
	}
}
