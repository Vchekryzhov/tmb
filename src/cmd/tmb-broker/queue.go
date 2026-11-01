// PROTOTYPE CODE - throwaway PoC, not production.
package main

// The approval queue (ADR 0004): a request that passed validation and policy
// waits here until an approver decides it over the approver socket. Waiting
// holds only the queue's own lock briefly, never across the wait, so one
// pending request does not delay any other connection.

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"os/user"
	"path/filepath"
	"sort"
	"strconv"
	"sync"
	"time"

	"tmb-poc/internal/proto"
)

// ModeQueue is the broker's default approval mode: approval comes from an
// approver over the approver socket, not from the broker's own console.
const ModeQueue = "queue"

// queueDecision is one approver verdict delivered to the waiting request.
type queueDecision struct {
	granted  bool
	approver RequesterID
	// vote is the signature a signed decide carries, not yet verified:
	// approvalQueue.decide checks it against the item's payload. nil for an
	// unsigned decide.
	vote *approverSignature
	// proof is set by approvalQueue.decide: the item's payload terms and the
	// verified signatures. nil only for items queued without a payload.
	proof *decisionProof
}

// approverSignature is a signature over an item's payload by one key of
// approver_keys.
type approverSignature struct {
	key approverKey
	der []byte // the decoded signature
	b64 string // as the approver sent it, for the journal
}

// decisionProof is what proves a queue decision beyond the approver
// socket's peer credentials (ADR 0006): the exact payload the item was
// queued with, its short code, the token TTL signed in it and the verified
// signatures (none for an unsigned decision). approveStage writes it to the
// approval event and caps the token's life with tokenTTL.
type decisionProof struct {
	payload    []byte
	shortCode  string
	tokenTTL   time.Duration
	signatures []approverSignature
}

// approvalOutcome is the result of one approval interaction: the verdict,
// the deny reason, the approver (its key in queue mode, mode:<mode> for the
// bench modes), the decision proof (nil when there is none) and the
// environment the approver was shown, which exec uses as is.
type approvalOutcome struct {
	granted  bool
	reason   string
	approver string
	proof    *decisionProof
	env      []string
}

type queueEntry struct {
	item      proto.QueueItem
	requester RequesterID        // who asked: never the one who decides (ADR 0004)
	result    chan queueDecision // buffered 1: the first decision wins
	// per-item terms, fixed when the item is queued: a reload does not move
	// them. Zero values mean none (entries built by add).
	queuedAt time.Time
	deadline time.Time // no decision is accepted after it (decision_expired)
	// payload is the exact approval payload (ADR 0006) a signature must
	// cover; tokenTTL is the token TTL written in it. nil and zero for
	// entries built by add.
	payload  []byte
	tokenTTL time.Duration
	// sigs are the verified approve signatures recorded short of the
	// threshold, one per key, in arrival order
	sigs []approverSignature
}

// signatureRule is the threshold and the approver keys a decision is
// counted against (ADR 0007, R2): the policy at the time of the decide or
// list, so a reload applies to items already waiting. A recorded signature
// counts only while its key is still in keys: a key removed by a reload no
// longer helps any item reach the threshold.
type signatureRule struct {
	required int
	keys     map[string]approverKey
}

// counted is the recorded signatures that count under the rule.
func (r signatureRule) counted(sigs []approverSignature) []approverSignature {
	var out []approverSignature
	for _, s := range sigs {
		if _, ok := r.keys[s.key.fp]; ok {
			out = append(out, s)
		}
	}
	return out
}

// proof is the decision proof of this entry with the given verified
// signatures; nil when the entry has no payload.
func (e *queueEntry) proof(sigs ...approverSignature) *decisionProof {
	if e.payload == nil {
		return nil
	}
	return &decisionProof{payload: e.payload, shortCode: proto.ShortCode(e.payload), tokenTTL: e.tokenTTL, signatures: sigs}
}

// approvalQueue holds the waiting requests by item id. Decided ids are
// remembered so a late second decision is told already_decided instead of
// "no such item".
type approvalQueue struct {
	mu      sync.Mutex
	items   map[string]*queueEntry
	decided map[string]time.Time
	size    int              // encoded bytes of the waiting items
	now     func() time.Time // the broker clock (tests move it); read under mu
}

// maxQueueBytes bounds the encoded size of all waiting items, so the list
// an approver asks for always fits in one frame; the rest of MaxFrame is
// room for the frame envelope and the separators.
const maxQueueBytes = proto.MaxFrame - 64*1024

// itemSize is the encoded size of one item in a queue frame.
func itemSize(item proto.QueueItem) int {
	b, err := json.Marshal(item)
	if err != nil {
		return maxQueueBytes + 1
	}
	return len(b) + 1 // the separating comma
}

func newApprovalQueue() *approvalQueue {
	return &approvalQueue{items: map[string]*queueEntry{}, decided: map[string]time.Time{}, now: time.Now}
}

// decidedMemory bounds how long a decided id is remembered.
const decidedMemory = time.Hour

// add enqueues an item. It refuses with request_already_queued when a
// request with the same hash is already waiting (the same request cannot be
// approved twice at once) and with queue_full when the item would not fit
// in the approver's list frame.
func (q *approvalQueue) add(item proto.QueueItem, requester RequesterID) (*queueEntry, string) {
	return q.addEntry(&queueEntry{item: item, requester: requester})
}

// addEntry enqueues a prepared entry (item, requester and the per-item
// terms) under the same rules as add; it owns the entry's result channel.
func (q *approvalQueue) addEntry(e *queueEntry) (*queueEntry, string) {
	q.mu.Lock()
	defer q.mu.Unlock()
	if _, dup := q.items[e.item.ID]; dup {
		return nil, "request_already_queued"
	}
	n := itemSize(e.item)
	if q.size+n > maxQueueBytes {
		return nil, "queue_full"
	}
	e.result = make(chan queueDecision, 1)
	q.items[e.item.ID] = e
	q.size += n
	return e, ""
}

// remove drops a waiting item and its size; the caller holds q.mu.
func (q *approvalQueue) remove(id string) {
	if e, ok := q.items[id]; ok {
		q.size -= itemSize(e.item)
		delete(q.items, id)
	}
}

// list returns the waiting items, oldest first. An item with a payload
// shows the threshold of the rule and the signatures that count under it.
func (q *approvalQueue) list(rule signatureRule) []proto.QueueItem {
	q.mu.Lock()
	defer q.mu.Unlock()
	out := make([]proto.QueueItem, 0, len(q.items))
	for _, e := range q.items {
		it := e.item
		if e.payload != nil {
			it.SignaturesRequired = rule.required
			it.Signatures = len(rule.counted(e.sigs))
		}
		out = append(out, it)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].QueuedAt != out[j].QueuedAt {
			return out[i].QueuedAt < out[j].QueuedAt
		}
		return out[i].ID < out[j].ID
	})
	return out
}

// withdraw removes a still undecided item (timeout or abandonment). False
// means a decision got there first and is waiting in the entry's channel.
func (q *approvalQueue) withdraw(id string) bool {
	q.mu.Lock()
	defer q.mu.Unlock()
	if _, ok := q.items[id]; !ok {
		return false
	}
	q.remove(id)
	return true
}

// clock reads the queue clock.
func (q *approvalQueue) clock() time.Time {
	q.mu.Lock()
	defer q.mu.Unlock()
	return q.now()
}

// decide is vote with a threshold of one signature.
func (q *approvalQueue) decide(id, hash string, d queueDecision) (deny, detail string) {
	r := q.vote(id, hash, d, signatureRule{required: 1}, voteHooks{})
	return r.deny, r.detail
}

// voteResult is what one vote did: refused it (deny), recorded a signature
// short of the threshold (recorded > 0: the signatures that count now),
// found the policy changed since the decide was read (stale: nothing done,
// read the policy again), or decided the item (all zero).
type voteResult struct {
	deny, detail string
	recorded     int
	shortCode    string // of the item's payload, when recorded
	stale        bool
}

// voteHooks tie a vote to the broker around it; both run under the queue
// lock and may be nil.
type voteHooks struct {
	// current reports whether the policy the decide was checked against is
	// still the broker's: Reload swaps the policy under the queue lock, so
	// a vote never counts against a policy that was already replaced.
	current func() bool
	// record journals a signature recorded short of the threshold, with
	// the count it brings; an error leaves the item as it was (no
	// signature without its record) and the vote is refused with
	// audit_unavailable.
	record func(recorded int, shortCode string) error
}

// vote applies one decision to a waiting item. The hash must match what the
// approver was shown, and the requester never decides its own request: a
// uid in both allowlists is refused with approver_is_requester and the item
// stays for another approver. No decision is taken after the item's
// deadline (decision_expired), and a signed decision (d.vote) must verify
// over the payload the item was queued with (signature_invalid), whether it
// approves or denies. A deny decides the item at once. A signed approve is
// recorded until rule.required signatures by different keys count; a
// second signature by a key already recorded is refused
// (signature_duplicate) and does not move the count. An unsigned approve
// decides only under a threshold of one (signature_required otherwise). A
// refused or recorded decision leaves the item waiting; the delivered
// decision carries the item's proof.
func (q *approvalQueue) vote(id, hash string, d queueDecision, rule signatureRule, h voteHooks) voteResult {
	refuse := func(deny, detail string) voteResult { return voteResult{deny: deny, detail: detail} }
	q.mu.Lock()
	defer q.mu.Unlock()
	if h.current != nil && !h.current() {
		return voteResult{stale: true}
	}
	now := q.now()
	for k, t := range q.decided {
		if now.Sub(t) > decidedMemory {
			delete(q.decided, k)
		}
	}
	e, ok := q.items[id]
	if !ok {
		if _, was := q.decided[id]; was {
			return refuse("already_decided", id)
		}
		return refuse("no_such_item", id)
	}
	if e.item.Hash != hash {
		return refuse("decision_mismatch", fmt.Sprintf("item %s has hash %s, decision carries %s", id, e.item.Hash, hash))
	}
	if e.requester.Equal(d.approver) {
		return refuse("approver_is_requester", fmt.Sprintf("item %s was requested by %s, another approver must decide it", id, d.approver.Key()))
	}
	if !e.deadline.IsZero() && now.After(e.deadline) {
		return refuse("decision_expired", fmt.Sprintf("item %s: its deadline %s has passed", id, e.deadline.UTC().Format(time.RFC3339Nano)))
	}
	v := d.vote
	if v != nil && (e.payload == nil || !proto.VerifyPayloadSignature(v.key.pub, e.payload, v.der)) {
		return refuse("signature_invalid", fmt.Sprintf("the signature does not verify over the payload of item %s with key %s (%s)", id, v.key.name, v.key.fp))
	}
	var sigs []approverSignature
	switch {
	case !d.granted:
		if v != nil {
			sigs = []approverSignature{*v}
		}
	case v == nil:
		if rule.required > 1 {
			return refuse("signature_required", fmt.Sprintf("item %s needs %d signatures: an unsigned approve does not count", id, rule.required))
		}
	default:
		for _, s := range e.sigs {
			if s.key.fp == v.key.fp {
				return refuse("signature_duplicate", fmt.Sprintf("item %s already has a signature by key %s (%s): the next one must come from another key", id, s.key.name, s.key.fp))
			}
		}
		sigs = rule.counted(append(e.sigs[:len(e.sigs):len(e.sigs)], *v))
		if len(sigs) < rule.required {
			code := proto.ShortCode(e.payload)
			if h.record != nil && h.record(len(sigs), code) != nil {
				return refuse("audit_unavailable", auditUnavailableDetail+": the signature was not recorded")
			}
			e.sigs = append(e.sigs, *v)
			return voteResult{recorded: len(sigs), shortCode: code}
		}
		e.sigs = append(e.sigs, *v)
	}
	d.proof = e.proof(sigs...)
	q.remove(id)
	q.decided[id] = now
	e.result <- d
	return voteResult{}
}

// newChallenge is the broker's random challenge for one queue item.
// crypto/rand.Read never fails (Go 1.24+).
func newChallenge() string {
	b := make([]byte, 32)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

// userName is the name of a target uid for the payload, "" if it has none.
func userName(uid int) string {
	u, err := user.LookupId(strconv.Itoa(uid))
	if err != nil {
		return ""
	}
	return u.Username
}

// ttlSeconds is a token TTL in whole seconds, rounded up, at least 1.
func ttlSeconds(d time.Duration) int {
	n := int((d + time.Second - 1) / time.Second)
	if n < 1 {
		n = 1
	}
	return n
}

// queueApproval puts the request in the queue and blocks until an approver
// decides, approval_wait_seconds pass (approval_timeout) or the requester
// hangs up (request_abandoned). It tells the requester once that it waits,
// and returns the outcome with the item's decision proof.
//
// The approval payload is built here, once per item, from what the broker
// resolved: realpaths, the pinned executable inode, the final environment,
// a fresh challenge, the host identity and the broker's own deadline and
// token TTL (ADR 0006, ADR 0007). A request whose payload cannot be encoded
// (a path that is not UTF-8) is refused before it is queued.
func (b *Broker) queueApproval(req *proto.Request, id RequesterID, exeReal, cwdReal string, dev, ino uint64, conn net.Conn) approvalOutcome {
	refuse := func(reason, approver string) approvalOutcome {
		return approvalOutcome{reason: reason, approver: approver}
	}
	pol := b.pol.Load()
	hash := req.Hash()
	now := b.queue.clock()
	wait := pol.wait // fixed for this item: a reload does not move it
	env := b.buildEnv(req)
	p := &proto.ApprovalPayload{
		HostID:      pol.cfg.HostID, // empty only in code: the payload is then refused
		HostKey:     b.hostKey,
		ItemID:      proto.TokenID(hash),
		RequestHash: hash,
		Challenge:   newChallenge(),
		Requester:   id.Key(),
		UID:         req.UID,
		User:        userName(req.UID),
		Executable:  exeReal,
		ExeDev:      dev,
		ExeIno:      ino,
		Argv:        req.Argv,
		Cwd:         cwdReal,
		Env:         env,
		Nonce:       req.Nonce,
		QueuedAt:    now.UnixMilli(),
		Deadline:    now.Add(wait).UnixMilli(),
		TokenTTL:    ttlSeconds(pol.ttl),
	}
	payload, err := p.Encode()
	if err != nil {
		return refuse("approval_payload_invalid", "mode:"+ModeQueue)
	}
	code := proto.ShortCode(payload)
	deadline := time.UnixMilli(p.Deadline)
	item := proto.QueueItem{
		ID:              p.ItemID,
		Hash:            hash,
		Requester:       id.ConsoleLine(),
		Executable:      exeReal,
		Argv:            req.Argv,
		Cwd:             cwdReal,
		UID:             req.UID,
		Env:             env,
		Nonce:           req.Nonce,
		QueuedAt:        now.UTC().Format(time.RFC3339Nano),
		Payload:         base64.StdEncoding.EncodeToString(payload),
		ShortCode:       code,
		HostID:          p.HostID,
		HostKey:         p.HostKey,
		Challenge:       p.Challenge,
		Deadline:        deadline.UTC().Format(time.RFC3339Nano),
		TokenTTLSeconds: p.TokenTTL,
	}
	e, refused := b.queue.addEntry(&queueEntry{item: item, requester: id, queuedAt: now, deadline: deadline,
		payload: payload, tokenTTL: time.Duration(p.TokenTTL) * time.Second})
	if refused != "" {
		return refuse(refused, "mode:"+ModeQueue)
	}
	ev := id.LogFields()
	ev["item"] = item.ID
	ev["hash"] = hash
	ev["executable"] = exeReal
	ev["argv"] = req.Argv
	ev["cwd"] = cwdReal
	ev["nonce"] = logNonce(req.Nonce)
	ev["short_code"] = code
	b.log.Event("queued", ev)
	proto.WriteFrame(conn, &proto.Frame{Type: "waiting", Token: item.ID,
		Detail: fmt.Sprintf("at most %s", wait)})

	hangup := watchHangup(conn)
	timer := time.NewTimer(wait)
	defer timer.Stop()
	var d queueDecision
	select {
	case d = <-e.result:
	case <-timer.C:
		if b.queue.withdraw(item.ID) {
			stopWatch(conn, hangup)
			b.log.Event("approval_timeout", queueEvent(id, item.ID, wait))
			out := refuse("approval_timeout", "mode:"+ModeQueue)
			out.proof = e.proof()
			return out
		}
		d = <-e.result // decided at the last moment
	case <-hangup.done:
		// the requester is gone: nothing runs, even when a decision raced
		// the hangup and is already waiting in the channel
		out := refuse("request_abandoned", "mode:"+ModeQueue)
		out.proof = e.proof()
		if !b.queue.withdraw(item.ID) {
			d = <-e.result
			out.approver, out.proof = d.approver.Key(), d.proof
		}
		b.log.Event("request_abandoned", queueEvent(id, item.ID, wait))
		return out
	}
	out := approvalOutcome{approver: d.approver.Key(), proof: d.proof, env: env}
	switch {
	case stopWatch(conn, hangup):
		b.log.Event("request_abandoned", queueEvent(id, item.ID, wait))
		out.reason = "request_abandoned"
	case !d.granted:
		out.reason = "approval_denied_by_human"
	default:
		out.granted = true
	}
	return out
}

func queueEvent(id RequesterID, item string, wait time.Duration) map[string]any {
	ev := id.LogFields()
	ev["item"] = item
	ev["wait_seconds"] = int(wait.Seconds())
	return ev
}

// hangupWatch keeps the read result even when a ready decision wins the
// select. Receiving done synchronizes access to err.
type hangupWatch struct {
	done chan struct{}
	err  error
}

// watchHangup reads the requester connection while its request waits: the
// client sends nothing more, so a read that returns means it hung up, unless
// stopWatch interrupted the read with a deadline.
func watchHangup(conn net.Conn) *hangupWatch {
	w := &hangupWatch{done: make(chan struct{})}
	go func() {
		defer close(w.done)
		var buf [1]byte
		_, w.err = conn.Read(buf[:])
	}()
	return w
}

// stopWatch unblocks the hangup reader with a past read deadline and waits
// for it, so nothing else reads the connection concurrently; the deadline
// is then cleared. True means the peer disconnected (or sent unexpected
// data), rather than the read ending because we stopped the watch.
func stopWatch(conn net.Conn, w *hangupWatch) bool {
	_ = conn.SetReadDeadline(time.Unix(1, 0))
	<-w.done
	_ = conn.SetReadDeadline(time.Time{})
	if !errors.Is(w.err, os.ErrDeadlineExceeded) {
		return true
	}
	// A past deadline can win over an EOF already waiting in a real
	// socket. Inspect it without consuming bytes, after joining the reader.
	return socketReadReady(conn)
}

// beforeVote is a test seam: it runs in serveDecide between reading the
// policy and the vote.
var beforeVote = func() {}

// --- approver socket ----------------------------------------------------------

// allowedApprover checks a unix peer against approver_uids. The roles are
// told apart by socket and message type; a uid in both lists still cannot
// decide its own request (approvalQueue.decide).
func (b *Broker) allowedApprover(id RequesterID) bool {
	if id.Kind != KindUID {
		return false
	}
	for _, u := range b.conf().ApproverUIDs {
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
	return serveConns(ln, func(c net.Conn) { b.handleApproverConn(c.(*net.UnixConn)) })
}

func (b *Broker) handleApproverConn(conn *net.UnixConn) {
	defer conn.Close()
	if b.refuseIfAuditDown(conn) {
		return
	}
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
		ev := approverLogFields(id)
		ev["reason"] = "approver_not_allowed"
		b.log.Event("approver_denied", ev)
		_ = conn.SetReadDeadline(time.Now().Add(denyDrainTimeout))
		_, _ = proto.ReadRawFrame(conn)
		_ = conn.SetReadDeadline(time.Time{})
		proto.WriteFrame(conn, &proto.Frame{Type: "denied", Reason: "approver_not_allowed",
			Detail: fmt.Sprintf("%s is not in approver_uids", id.Key())})
		return
	}
	_ = conn.SetReadDeadline(time.Now().Add(requestReadTimeout))
	raw, err := proto.ReadRawFrame(conn)
	_ = conn.SetReadDeadline(time.Time{})
	if err != nil {
		ev := approverLogFields(id)
		ev["error"] = err.Error()
		b.log.Event("bad_frame", ev)
		return
	}
	req, err := proto.DecodeRequest(raw)
	if err != nil {
		proto.WriteFrame(conn, &proto.Frame{Type: "denied", Reason: "bad_request", Detail: err.Error()})
		return
	}
	switch req.Type {
	case "list":
		if err := proto.WriteFrame(conn, &proto.Frame{Type: "queue", Items: b.queue.list(b.pol.Load().signatureRule())}); err != nil {
			ev := approverLogFields(id)
			ev["error"] = err.Error()
			b.log.Event("queue_list_failed", ev)
		}
	case "decide":
		b.serveDecide(conn, id, req)
	default:
		proto.WriteFrame(conn, &proto.Frame{Type: "denied", Reason: "unknown_request_type", Detail: req.Type})
	}
}

// serveDecide applies one decide from an allowed approver (ADR 0004, ADR
// 0006). For a signed decide it finds the key named by approver_key in
// approver_keys (approver_key_unknown) and decodes the signature
// (signature_invalid); the queue then verifies it over the item's payload.
// A signed decide is checked whatever require_signed_decision says. With
// require_signed_decision an unsigned approve is refused
// (signature_required); an unsigned deny is always accepted, a deny grants
// nothing. The queue counts the signature against the current
// required_signatures and approver_keys: the checks and the vote run
// against one policy, and a reload in between makes the decide be checked
// again under the new one. It answers decided; recorded with "N of M
// signatures" and signature_recorded in the journal when a valid signature
// is short of the threshold (audit_unavailable, nothing recorded, if that
// event cannot be written); or denied with decision_rejected in the
// journal.
func (b *Broker) serveDecide(conn net.Conn, id RequesterID, req *proto.Request) {
	var granted bool
	switch req.Decision {
	case "approve":
		granted = true
	case "deny":
	default:
		proto.WriteFrame(conn, &proto.Frame{Type: "denied", Reason: "bad_request", Detail: fmt.Sprintf("decision %q, want approve or deny", req.Decision)})
		return
	}
	var r voteResult
	var rule signatureRule
	for {
		pol := b.pol.Load()
		d, deny, detail := checkDecide(pol, req, granted, id)
		if deny != "" {
			r = voteResult{deny: deny, detail: detail}
			break
		}
		beforeVote()
		rule = pol.signatureRule()
		r = b.queue.vote(req.ItemID, req.ItemHash, d, rule, voteHooks{
			current: func() bool { return b.pol.Load() == pol },
			record: func(n int, code string) error {
				ev := approverLogFields(id)
				ev["item"] = req.ItemID
				ev["short_code"] = code
				ev["approver_key"] = d.vote.key.fp
				ev["approver_key_class"] = d.vote.key.class
				ev["approver_key_name"] = d.vote.key.name
				ev["signature"] = d.vote.b64
				ev["signatures"] = n
				ev["signatures_required"] = rule.required
				return b.log.Event("signature_recorded", ev)
			},
		})
		if !r.stale {
			break
		}
		// a reload swapped the policy: check the decide again under it
	}
	if r.recorded > 0 {
		proto.WriteFrame(conn, &proto.Frame{Type: "recorded", Detail: fmt.Sprintf("%d of %d signatures", r.recorded, rule.required)})
		return
	}
	if r.deny != "" {
		ev := approverLogFields(id)
		ev["item"] = req.ItemID
		ev["reason"] = r.deny
		ev["approver_key"] = req.ApproverKey
		b.log.Event("decision_rejected", ev)
		proto.WriteFrame(conn, &proto.Frame{Type: "denied", Reason: r.deny, Detail: r.detail})
		return
	}
	proto.WriteFrame(conn, &proto.Frame{Type: "decided", Detail: req.Decision})
}

// checkDecide checks a decide against one policy before the vote: the key
// a signed decide names, the shape of its signature, and
// require_signed_decision for an unsigned approve.
func checkDecide(pol *policy, req *proto.Request, granted bool, id RequesterID) (d queueDecision, deny, detail string) {
	d = queueDecision{granted: granted, approver: id}
	switch {
	case req.Signature != "" || req.ApproverKey != "":
		k, known := pol.keys[req.ApproverKey]
		sig, err := proto.DecodeSignature(req.Signature)
		switch {
		case !known:
			return d, "approver_key_unknown", fmt.Sprintf("approver_key %q is not in approver_keys", req.ApproverKey)
		case err != nil:
			return d, "signature_invalid", err.Error()
		}
		d.vote = &approverSignature{key: k, der: sig, b64: req.Signature}
	case granted && pol.cfg.RequireSignedDecision:
		return d, "signature_required", "require_signed_decision is on: an approve must be signed by a key in approver_keys"
	}
	return d, "", ""
}
