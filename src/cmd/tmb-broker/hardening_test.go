package main

import (
	"errors"
	"net"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"tmb-poc/internal/proto"
)

// ADR 0004: the requester never approves its own request, even when its
// uid is also in approver_uids; another approver still can.
func TestRequesterCannotApproveOwnRequest(t *testing.T) {
	b := newQueueBroker(t)
	b.conf().ApproverUIDs = []uint32{4242, humanUID}
	item, done := queueRequest(t, b, testReq(t, "self-approve"), UIDRequester(4242, 7))

	f := approverDo(t, b, UIDRequester(4242, 8), &proto.Request{Type: "decide", ItemID: item.ID, ItemHash: item.Hash, Decision: "approve"})
	if f.Type != "denied" || f.Reason != "approver_is_requester" {
		t.Fatalf("self decision = %+v, want denied approver_is_requester", f)
	}
	if len(b.queue.list()) != 1 {
		t.Fatal("a refused self decision removed the item from the queue")
	}
	if !lineHasBoth(logText(t, b), `"event":"decision_rejected"`, `"approver_uid":4242`) {
		t.Error("decision_rejected for the self decision is not in the journal")
	}
	if f := approverDo(t, b, UIDRequester(humanUID, 9), &proto.Request{Type: "decide", ItemID: item.ID, ItemHash: item.Hash, Decision: "approve"}); f.Type != "decided" {
		t.Fatalf("other approver: %+v", f)
	}
	if f := <-done; f.Type != "approved" {
		t.Fatalf("requester got %+v, want approved", f)
	}
}

// A requester that hangs up while an approval is being delivered gets
// nothing run: the hangup wins over a decision that raced it.
func TestHangupWinsOverRacingDecision(t *testing.T) {
	b := newQueueBroker(t)
	req := testReq(t, "hangup-race")
	id := UIDRequester(4242, 7)
	server, client := net.Pipe()
	result := make(chan bool, 1)
	go func() {
		defer server.Close()
		result <- b.approveStage(req, id, server)
	}()
	if f, err := proto.ReadFrame(client); err != nil || f.Type != "waiting" {
		t.Fatalf("first frame %+v, %v; want waiting", f, err)
	}
	itemID := proto.TokenID(req.Hash())

	// Hold the queue lock: the hangup branch then blocks in withdraw while
	// the decision is delivered, which is the race withdraw loses.
	b.queue.mu.Lock()
	e := b.queue.items[itemID]
	client.Close()
	time.Sleep(100 * time.Millisecond)
	b.queue.remove(itemID)
	b.queue.decided[itemID] = time.Now()
	e.result <- queueDecision{granted: true, approver: UIDRequester(humanUID, 1)}
	b.queue.mu.Unlock()

	if <-result {
		t.Fatal("approveStage granted a request whose requester had hung up")
	}
	if _, has := b.peekPending(req.Hash()); has {
		t.Fatal("an abandoned request left a pending approval")
	}
	if !lineHasBoth(logText(t, b), `"event":"approval"`, `"reason":"request_abandoned"`) {
		t.Error("approval event does not record request_abandoned")
	}
}

// The queue refuses an item that would push the approver's list past one
// frame, so list always answers.
func TestQueueFullKeepsListInOneFrame(t *testing.T) {
	q := newApprovalQueue()
	big := strings.Repeat("a", 8000)
	argv := make([]string, 64)
	for i := range argv {
		argv[i] = big
	}
	var refused string
	for i := 0; i < 10 && refused == ""; i++ {
		_, refused = q.add(proto.QueueItem{ID: string(rune('a' + i)), Hash: "h", Argv: argv}, RequesterID{})
	}
	if refused != "queue_full" {
		t.Fatalf("refused = %q, want queue_full", refused)
	}
	server, client := net.Pipe()
	defer client.Close()
	errc := make(chan error, 1)
	go func() {
		defer server.Close()
		errc <- proto.WriteFrame(server, &proto.Frame{Type: "queue", Items: q.list()})
	}()
	if _, err := proto.ReadFrame(client); err != nil {
		t.Fatalf("list frame: %v", err)
	}
	if err := <-errc; err != nil {
		t.Fatalf("write list: %v", err)
	}
	for _, it := range q.list() {
		q.withdraw(it.ID)
	}
	if q.size != 0 {
		t.Errorf("queue size %d after withdrawing every item, want 0", q.size)
	}
}

// failingListener fails Accept n times with a non-closed error, then
// reports itself closed.
type failingListener struct {
	n     int32
	calls atomic.Int32
}

func (l *failingListener) Accept() (net.Conn, error) {
	if l.calls.Add(1) <= l.n {
		return nil, errors.New("accept: too many open files")
	}
	return nil, net.ErrClosed
}
func (l *failingListener) Close() error   { return nil }
func (l *failingListener) Addr() net.Addr { return &net.UnixAddr{Name: "x", Net: "unix"} }

// A failed Accept (EMFILE and the like) does not end the accept loop; only
// a closed listener does.
func TestServeConnsRetriesAcceptErrors(t *testing.T) {
	ln := &failingListener{n: 3}
	err := serveConns(ln, func(net.Conn) {})
	if !errors.Is(err, net.ErrClosed) {
		t.Fatalf("serveConns = %v, want net.ErrClosed", err)
	}
	if got := ln.calls.Load(); got != 4 {
		t.Errorf("Accept called %d times, want 4 (three failures, then closed)", got)
	}
}

// A client that stops reading does not block the command: its output is
// dropped after the write deadline, the command runs to its end and the
// journal records exec_exit with client_gone.
func TestExecDoesNotBlockOnSilentClient(t *testing.T) {
	old := clientWriteTimeout
	clientWriteTimeout = 200 * time.Millisecond
	t.Cleanup(func() { clientWriteTimeout = old })

	b := newTestBroker(t)
	sh := shExe(t)
	req := &proto.Request{
		Executable: sh,
		Argv:       []string{sh, "-c", "i=0; while [ $i -lt 64 ]; do head -c 65536 /dev/zero; i=$((i+1)); done"},
		Cwd:        "/tmp",
		Nonce:      "silent-client",
	}
	id := UIDRequester(4242, 7)
	req = approved(t, b, req, id)
	server, client := net.Pipe()
	defer client.Close()
	done := make(chan struct{})
	go func() { defer close(done); defer server.Close(); b.doClaim(req, id, server) }()
	select {
	case <-done:
	case <-time.After(20 * time.Second):
		t.Fatal("exec is still blocked on a client that does not read")
	}
	if !lineHasBoth(logText(t, b), `"event":"exec_exit"`, `"client_gone":true`) {
		t.Error("exec_exit does not record client_gone")
	}
}

// A descendant that keeps stdout open after the command exits does not hold
// the claim: exec_exit is written once execWaitDelay passes.
func TestExecBoundsDescendantHoldingOutput(t *testing.T) {
	old := execWaitDelay
	execWaitDelay = 300 * time.Millisecond
	t.Cleanup(func() { execWaitDelay = old })

	b := newTestBroker(t)
	sh := shExe(t)
	req := &proto.Request{
		Executable: sh,
		Argv:       []string{sh, "-c", "sleep 30 & echo started"},
		Cwd:        "/tmp",
		Nonce:      "descendant-holds-stdout",
	}
	id := UIDRequester(4242, 7)
	req = approved(t, b, req, id)
	start := time.Now()
	f := claimDo(t, b, req, id)
	if f.Type != "exit" || f.Code == nil || *f.Code != 0 {
		t.Fatalf("claim = %+v, want exit 0", f)
	}
	if time.Since(start) > 10*time.Second {
		t.Fatalf("claim took %v: the descendant held it", time.Since(start))
	}
}
