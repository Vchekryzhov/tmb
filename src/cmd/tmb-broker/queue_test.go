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

const humanUID = 1500

func newQueueBroker(t *testing.T) *Broker {
	t.Helper()
	b := newTestBroker(t)
	b.mode = ModeQueue
	b.cfg.ApproverUIDs = []uint32{humanUID}
	return b
}

// approverDo runs one approver message over an in-memory pipe.
func approverDo(t *testing.T, b *Broker, id RequesterID, req *proto.Request) *proto.Frame {
	t.Helper()
	server, client := net.Pipe()
	go func() { defer server.Close(); b.serveApprover(server, id) }()
	defer client.Close()
	if err := proto.WriteFrame(client, req); err != nil {
		t.Fatalf("approver write: %v", err)
	}
	f, err := proto.ReadFrame(client)
	if err != nil {
		t.Fatalf("approver read: %v", err)
	}
	return f
}

// queueRequest starts doApprove in the background and waits until the
// request shows up in the queue.
func queueRequest(t *testing.T, b *Broker, req *proto.Request, id RequesterID) (proto.QueueItem, <-chan *proto.Frame) {
	t.Helper()
	server, client := net.Pipe()
	go func() { defer server.Close(); b.doApprove(req, id, server) }()
	out := make(chan *proto.Frame, 1)
	go func() {
		defer client.Close()
		for {
			f, err := proto.ReadFrame(client)
			if err != nil {
				f = &proto.Frame{Type: "error", Detail: err.Error()}
			}
			if f.Type == "waiting" {
				continue
			}
			out <- f
			return
		}
	}()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		for _, it := range b.queue.list() {
			if it.Nonce == req.Nonce {
				return it, out
			}
		}
		time.Sleep(2 * time.Millisecond)
	}
	t.Fatalf("request %s never reached the queue", req.Nonce)
	return proto.QueueItem{}, nil
}

func logText(t *testing.T, b *Broker) string {
	t.Helper()
	raw, err := os.ReadFile(b.log.f.Name())
	if err != nil {
		t.Fatalf("read log: %v", err)
	}
	return string(raw)
}

func TestQueueApprovalByApprover(t *testing.T) {
	b := newQueueBroker(t)
	req := testReq(t, "queue-approve")
	item, done := queueRequest(t, b, req, UIDRequester(4242, 7))

	exeReal, _ := filepath.EvalSymlinks(req.Executable)
	cwdReal, _ := filepath.EvalSymlinks("/tmp")
	if item.ID != proto.TokenID(req.Hash()) || item.Hash != req.Hash() || item.Executable != exeReal || item.Cwd != cwdReal {
		t.Errorf("item %+v does not describe the request", item)
	}
	if strings.Join(item.Env, ",") != "LANG=C.UTF-8,PATH=/usr/bin:/bin" || !strings.HasPrefix(item.Requester, "uid=4242 ") {
		t.Errorf("item env %q requester %q, want the final env and the requester", item.Env, item.Requester)
	}
	select {
	case f := <-done:
		t.Fatalf("request answered before any decision: %+v", f)
	case <-time.After(50 * time.Millisecond):
	}

	approver := UIDRequester(humanUID, 99)
	if f := approverDo(t, b, approver, &proto.Request{Type: "list"}); f.Type != "queue" || len(f.Items) != 1 || f.Items[0].ID != item.ID {
		t.Fatalf("list: %+v", f)
	}
	if f := approverDo(t, b, approver, &proto.Request{Type: "decide", ItemID: item.ID, ItemHash: item.Hash, Decision: "approve"}); f.Type != "decided" {
		t.Fatalf("decide: %+v", f)
	}
	if f := <-done; f.Type != "approved" || f.Token != item.ID {
		t.Fatalf("requester got %+v, want approved with token %s", f, item.ID)
	}
	if f := approverDo(t, b, approver, &proto.Request{Type: "decide", ItemID: item.ID, ItemHash: item.Hash, Decision: "deny"}); f.Reason != "already_decided" {
		t.Fatalf("second decision: %+v, want already_decided", f)
	}
	if len(b.queue.list()) != 0 {
		t.Errorf("decided item still queued")
	}
	log := logText(t, b)
	if !lineHasBoth(log, `"event":"queued"`, `"item":"`+item.ID+`"`) {
		t.Errorf("queued event missing:\n%s", log)
	}
	if !lineHasBoth(log, `"event":"approval"`, `"approver":"uid:1500"`) || !lineHasBoth(log, `"event":"approval"`, `"decision":"approve"`) {
		t.Errorf("approval event lacks approver uid:1500 / decision approve:\n%s", log)
	}
}

func TestQueueDenyByApprover(t *testing.T) {
	b := newQueueBroker(t)
	item, done := queueRequest(t, b, testReq(t, "queue-deny"), UIDRequester(4242, 7))
	if f := approverDo(t, b, UIDRequester(humanUID, 1), &proto.Request{Type: "decide", ItemID: item.ID, ItemHash: item.Hash, Decision: "deny"}); f.Type != "decided" {
		t.Fatalf("decide: %+v", f)
	}
	if f := <-done; f.Type != "denied" || f.Reason != "approval_denied_by_human" {
		t.Fatalf("requester got %+v, want approval_denied_by_human", f)
	}
}

func TestApproverMessagesRejected(t *testing.T) {
	b := newQueueBroker(t)
	item, done := queueRequest(t, b, testReq(t, "queue-reject"), UIDRequester(4242, 7))
	human := UIDRequester(humanUID, 1)
	for _, tc := range []struct {
		name   string
		id     RequesterID
		req    *proto.Request
		reason string
	}{
		{"requester uid on the approver socket", UIDRequester(4242, 3), &proto.Request{Type: "list"}, "approver_not_allowed"},
		{"cert identity", KeyRequester(strings.Repeat("aa", 32)), &proto.Request{Type: "list"}, "approver_not_allowed"},
		{"hash mismatch", human, &proto.Request{Type: "decide", ItemID: item.ID, ItemHash: strings.Repeat("0", 64), Decision: "approve"}, "decision_mismatch"},
		{"unknown item", human, &proto.Request{Type: "decide", ItemID: "0123456789abcdef", ItemHash: "x", Decision: "approve"}, "no_such_item"},
		{"bad decision", human, &proto.Request{Type: "decide", ItemID: item.ID, ItemHash: item.Hash, Decision: "maybe"}, "bad_request"},
		{"requester message type", human, &proto.Request{Type: "exec"}, "unknown_request_type"},
	} {
		if f := approverDo(t, b, tc.id, tc.req); f.Type != "denied" || f.Reason != tc.reason {
			t.Errorf("%s: got %+v, want denied %s", tc.name, f, tc.reason)
		}
	}
	if len(b.queue.list()) != 1 {
		t.Fatalf("rejected messages changed the queue")
	}
	if !lineHasBoth(logText(t, b), `"event":"approver_denied"`, `"requester_uid":4242`) {
		t.Errorf("approver_denied event for uid 4242 missing")
	}
	// clean up the waiting request
	approverDo(t, b, human, &proto.Request{Type: "decide", ItemID: item.ID, ItemHash: item.Hash, Decision: "deny"})
	<-done
}

func TestApproverBadFrame(t *testing.T) {
	b := newQueueBroker(t)
	server, client := net.Pipe()
	go func() { defer server.Close(); b.serveApprover(server, UIDRequester(humanUID, 1)) }()
	defer client.Close()
	if _, err := client.Write([]byte{0, 0, 0, 3, 'n', 'o', 't'}); err != nil {
		t.Fatalf("write: %v", err)
	}
	if f, err := proto.ReadFrame(client); err != nil || f.Reason != "bad_request" {
		t.Fatalf("bad JSON: %+v %v, want bad_request", f, err)
	}
	server2, client2 := net.Pipe()
	go func() { defer server2.Close(); b.serveApprover(server2, UIDRequester(humanUID, 1)) }()
	client2.Close()
	time.Sleep(20 * time.Millisecond)
	if !strings.Contains(logText(t, b), `"event":"bad_frame"`) {
		t.Errorf("bad_frame event missing for a closed approver connection")
	}
}

// The same request cannot wait twice at once.
func TestQueueRejectsDuplicateRequest(t *testing.T) {
	b := newQueueBroker(t)
	req := testReq(t, "queue-dup")
	item, done := queueRequest(t, b, req, UIDRequester(4242, 7))
	if f := approveDo(t, b, testReq(t, "queue-dup"), UIDRequester(4242, 8)); f.Type != "denied" || f.Reason != "request_already_queued" {
		t.Fatalf("duplicate: %+v, want request_already_queued", f)
	}
	approverDo(t, b, UIDRequester(humanUID, 1), &proto.Request{Type: "decide", ItemID: item.ID, ItemHash: item.Hash, Decision: "deny"})
	<-done
}

// Approver message types do not exist on the requester sockets.
func TestRequesterSocketRefusesApproverTypes(t *testing.T) {
	b := newQueueBroker(t)
	for _, typ := range []string{"list", "decide"} {
		server, client := net.Pipe()
		go func() { defer server.Close(); b.serveRequest(server, UIDRequester(4242, 1), "unix") }()
		if err := proto.WriteFrame(client, &proto.Request{Type: typ}); err != nil {
			t.Fatalf("write: %v", err)
		}
		f, err := proto.ReadFrame(client)
		client.Close()
		if err != nil || f.Reason != "unknown_request_type" {
			t.Errorf("%s on the requester socket: %+v %v, want unknown_request_type", typ, f, err)
		}
	}
}

func TestStartApproverServesSocket(t *testing.T) {
	dir, err := os.MkdirTemp("", "tmbq")
	if err != nil {
		t.Fatalf("mkdtemp: %v", err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	path := filepath.Join(dir, "sub", "a.sock")
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(path, nil, 0o600); err != nil { // stale leftover
		t.Fatalf("write: %v", err)
	}
	b := newQueueBroker(t)
	if err := b.startApprover(path); err != nil {
		t.Fatalf("startApprover: %v", err)
	}
	st, err := os.Stat(path)
	if err != nil || st.Mode()&os.ModeSocket == 0 || st.Mode().Perm() != 0o666 {
		t.Fatalf("approver socket %v %v, want a 0666 socket", st, err)
	}
	conn, err := net.Dial("unix", path)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()
	if err := proto.WriteFrame(conn, &proto.Request{Type: "list"}); err != nil {
		t.Fatalf("write: %v", err)
	}
	// this test's uid is no approver (and off Linux SO_PEERCRED is missing):
	// either way the queue stays hidden
	f, err := proto.ReadFrame(conn)
	if err != nil || f.Type != "denied" || (f.Reason != "approver_not_allowed" && f.Reason != "peercred_failed") {
		t.Fatalf("list from a non-approver: %+v %v, want denied", f, err)
	}
	if err := b.startApprover(filepath.Join(path, "x")); err == nil {
		t.Errorf("approver socket under a socket path succeeded")
	}
	file := filepath.Join(dir, "file")
	if err := os.WriteFile(file, nil, 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	if err := b.startApprover(filepath.Join(file, "sub", "a.sock")); err == nil {
		t.Errorf("approver socket under a regular file succeeded")
	}
}

// Items list oldest first (id breaks ties) and decided ids are forgotten
// after decidedMemory.
func TestQueueOrderAndDecidedMemory(t *testing.T) {
	q := newApprovalQueue()
	for _, it := range []proto.QueueItem{{ID: "b", QueuedAt: "2"}, {ID: "c", QueuedAt: "1"}, {ID: "a", QueuedAt: "2"}} {
		if _, ok := q.add(it); !ok {
			t.Fatalf("add %s refused", it.ID)
		}
	}
	var got []string
	for _, it := range q.list() {
		got = append(got, it.ID)
	}
	if strings.Join(got, ",") != "c,a,b" {
		t.Errorf("order %v, want c,a,b", got)
	}
	q.decided["old"] = time.Now().Add(-2 * decidedMemory)
	if deny, _ := q.decide("old", "", queueDecision{}); deny != "no_such_item" {
		t.Errorf("expired decided id: %q, want no_such_item", deny)
	}
}

func TestLoadConfigApproverDefaults(t *testing.T) {
	dir := t.TempDir()
	write := func(body string) string {
		p := filepath.Join(dir, "c.json")
		if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
			t.Fatalf("write: %v", err)
		}
		return p
	}
	c, err := loadConfig(write(`{"socket_path": "/run/tmb/tmb.sock", "state_dir": "/s", "log_path": "/l"}`))
	if err != nil {
		t.Fatalf("loadConfig: %v", err)
	}
	if c.ApprovalDefault != ModeQueue || c.ApproverSocketPath != "/run/tmb/approve.sock" {
		t.Errorf("defaults: mode %q socket %q, want queue and /run/tmb/approve.sock", c.ApprovalDefault, c.ApproverSocketPath)
	}
	if _, err := loadConfig(write(`{"socket_path": "/run/x.sock", "state_dir": "/s", "log_path": "/l", "approver_socket_path": "/run/x.sock"}`)); err == nil {
		t.Errorf("approver socket equal to the requester socket accepted")
	}
}
