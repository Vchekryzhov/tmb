// PROTOTYPE CODE - throwaway PoC, not production.
package main

// The approval queue (ADR 0004): a request that passed validation and policy
// waits here until an approver decides it over the approver socket. Waiting
// holds only the queue's own lock briefly, never across the wait, so one
// pending request does not delay any other connection.

import (
	"encoding/json"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"time"

	"tmb-poc/internal/proto"
)

// ModeQueue is the broker's default approval mode: approval comes from an
// approver over the approver socket, not from the broker's own console.
const ModeQueue = "queue"

// decision is one approver verdict delivered to the waiting request.
type queueDecision struct {
	granted  bool
	approver RequesterID
}

type queueEntry struct {
	item   proto.QueueItem
	result chan queueDecision // buffered 1: the first decision wins
}

// approvalQueue holds the waiting requests by item id. Decided ids are
// remembered so a late second decision is told already_decided instead of
// "no such item".
type approvalQueue struct {
	mu      sync.Mutex
	items   map[string]*queueEntry
	decided map[string]time.Time
}

func newApprovalQueue() *approvalQueue {
	return &approvalQueue{items: map[string]*queueEntry{}, decided: map[string]time.Time{}}
}

// decidedMemory bounds how long a decided id is remembered.
const decidedMemory = time.Hour

// add enqueues an item; false when a request with the same hash is already
// waiting (the same request cannot be approved twice at once).
func (q *approvalQueue) add(item proto.QueueItem) (*queueEntry, bool) {
	q.mu.Lock()
	defer q.mu.Unlock()
	if _, dup := q.items[item.ID]; dup {
		return nil, false
	}
	e := &queueEntry{item: item, result: make(chan queueDecision, 1)}
	q.items[item.ID] = e
	return e, true
}

// list returns the waiting items, oldest first.
func (q *approvalQueue) list() []proto.QueueItem {
	q.mu.Lock()
	defer q.mu.Unlock()
	out := make([]proto.QueueItem, 0, len(q.items))
	for _, e := range q.items {
		out = append(out, e.item)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].QueuedAt != out[j].QueuedAt {
			return out[i].QueuedAt < out[j].QueuedAt
		}
		return out[i].ID < out[j].ID
	})
	return out
}

// decide delivers a verdict once. The item leaves the queue on the first
// decision; the hash must match what the approver was shown.
func (q *approvalQueue) decide(id, hash string, d queueDecision) (deny, detail string) {
	q.mu.Lock()
	defer q.mu.Unlock()
	now := time.Now()
	for k, t := range q.decided {
		if now.Sub(t) > decidedMemory {
			delete(q.decided, k)
		}
	}
	e, ok := q.items[id]
	if !ok {
		if _, was := q.decided[id]; was {
			return "already_decided", id
		}
		return "no_such_item", id
	}
	if e.item.Hash != hash {
		return "decision_mismatch", fmt.Sprintf("item %s has hash %s, decision carries %s", id, e.item.Hash, hash)
	}
	delete(q.items, id)
	q.decided[id] = now
	e.result <- d
	return "", ""
}

// queueApproval puts the request in the queue and blocks until an approver
// decides. It returns the verdict, the deny reason and the approver.
func (b *Broker) queueApproval(req *proto.Request, id RequesterID, exeReal, cwdReal string) (bool, string, string) {
	hash := req.Hash()
	item := proto.QueueItem{
		ID:         proto.TokenID(hash),
		Hash:       hash,
		Requester:  id.ConsoleLine(),
		Executable: exeReal,
		Argv:       req.Argv,
		Cwd:        cwdReal,
		UID:        req.UID,
		Env:        b.buildEnv(req),
		Nonce:      req.Nonce,
		QueuedAt:   time.Now().UTC().Format(time.RFC3339Nano),
	}
	e, ok := b.queue.add(item)
	if !ok {
		return false, "request_already_queued", "mode:" + ModeQueue
	}
	ev := id.LogFields()
	ev["item"] = item.ID
	ev["hash"] = hash
	ev["executable"] = exeReal
	ev["argv"] = req.Argv
	ev["cwd"] = cwdReal
	ev["nonce"] = short(req.Nonce, 12)
	b.log.Event("queued", ev)

	d := <-e.result
	if !d.granted {
		return false, "approval_denied_by_human", d.approver.Key()
	}
	return true, "", d.approver.Key()
}

// --- approver socket ----------------------------------------------------------

// allowedApprover checks a unix peer against approver_uids. The roles are
// told apart by socket and message type, so a uid in both lists gains
// nothing from it.
func (b *Broker) allowedApprover(id RequesterID) bool {
	if id.Kind != KindUID {
		return false
	}
	for _, u := range b.cfg.ApproverUIDs {
		if u == id.UID {
			return true
		}
	}
	return false
}

// startApprover opens the approver socket (replacing a stale one) and
// serves it in the background. Any local user may connect (0666, directory
// 0755): SO_PEERCRED and approver_uids decide who sees the queue.
func (b *Broker) startApprover(path string) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
		return err
	}
	ln, err := net.Listen("unix", path)
	if err != nil {
		return err
	}
	if err := os.Chmod(path, 0o666); err != nil {
		ln.Close()
		return err
	}
	go func() { _ = b.ServeApprover(ln) }()
	return nil
}

// ServeApprover runs the accept loop of the approver socket.
func (b *Broker) ServeApprover(ln net.Listener) error {
	for {
		conn, err := ln.Accept()
		if err != nil {
			return err
		}
		go b.handleApproverConn(conn.(*net.UnixConn))
	}
}

func (b *Broker) handleApproverConn(conn *net.UnixConn) {
	defer conn.Close()
	id, err := peerCred(conn)
	if err != nil {
		b.log.Event("peercred_error", map[string]any{"error": err.Error(), "socket": "approver"})
		proto.WriteFrame(conn, &proto.Frame{Type: "denied", Reason: "peercred_failed", Detail: err.Error()})
		return
	}
	b.serveApprover(conn, id)
}

// serveApprover answers one approver message. A peer outside approver_uids
// is refused before it sees anything of the queue.
func (b *Broker) serveApprover(conn net.Conn, id RequesterID) {
	if !b.allowedApprover(id) {
		ev := id.LogFields()
		ev["reason"] = "approver_not_allowed"
		b.log.Event("approver_denied", ev)
		_ = conn.SetReadDeadline(time.Now().Add(denyDrainTimeout))
		_, _ = proto.ReadRawFrame(conn)
		_ = conn.SetReadDeadline(time.Time{})
		proto.WriteFrame(conn, &proto.Frame{Type: "denied", Reason: "approver_not_allowed",
			Detail: fmt.Sprintf("%s is not in approver_uids", id.Key())})
		return
	}
	raw, err := proto.ReadRawFrame(conn)
	if err != nil {
		ev := id.LogFields()
		ev["error"] = err.Error()
		b.log.Event("bad_frame", ev)
		return
	}
	var req proto.Request
	if err := json.Unmarshal(raw, &req); err != nil {
		proto.WriteFrame(conn, &proto.Frame{Type: "denied", Reason: "bad_request", Detail: err.Error()})
		return
	}
	switch req.Type {
	case "list":
		proto.WriteFrame(conn, &proto.Frame{Type: "queue", Items: b.queue.list()})
	case "decide":
		var granted bool
		switch req.Decision {
		case "approve":
			granted = true
		case "deny":
		default:
			proto.WriteFrame(conn, &proto.Frame{Type: "denied", Reason: "bad_request", Detail: fmt.Sprintf("decision %q, want approve or deny", req.Decision)})
			return
		}
		if deny, detail := b.queue.decide(req.ItemID, req.ItemHash, queueDecision{granted: granted, approver: id}); deny != "" {
			ev := id.LogFields()
			ev["item"] = req.ItemID
			ev["reason"] = deny
			b.log.Event("decision_rejected", ev)
			proto.WriteFrame(conn, &proto.Frame{Type: "denied", Reason: deny, Detail: detail})
			return
		}
		proto.WriteFrame(conn, &proto.Frame{Type: "decided", Detail: req.Decision})
	default:
		proto.WriteFrame(conn, &proto.Frame{Type: "denied", Reason: "unknown_request_type", Detail: req.Type})
	}
}
