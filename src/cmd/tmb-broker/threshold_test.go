package main

import (
	"path/filepath"
	"strings"
	"testing"
	"time"

	"tmb-poc/internal/proto"
)

// newThresholdBroker is a queue broker with require_signed_decision, the
// signers in approver_keys and required_signatures set to required.
func newThresholdBroker(t *testing.T, required int, signers ...*fakeSigner) *Broker {
	t.Helper()
	b := newSignedBroker(t, true, signers...)
	cfg := b.conf()
	cfg.RequiredSignatures = required
	b.pol.Store(newPolicy(cfg, b.tokenTTL()))
	return b
}

// listed is the item as the approver's list shows it now.
func listed(t *testing.T, b *Broker, id string) proto.QueueItem {
	t.Helper()
	for _, it := range approverDo(t, b, human(), &proto.Request{Type: "list"}).Items {
		if it.ID == id {
			return it
		}
	}
	t.Fatalf("item %s is not in the list", id)
	return proto.QueueItem{}
}

// With required_signatures 2 the first valid signature is recorded: the
// item stays queued, the approver is told how many signatures it has, the
// list counts them and the journal gets signature_recorded. The second
// signature, by another key, decides the item, and the approval event
// carries both.
func TestThresholdReachedByDistinctKeys(t *testing.T) {
	a, c := newFakeSigner(t, "mac-a"), newFakeSigner(t, "mac-b")
	b := newThresholdBroker(t, 2, a, c)
	item, done := queueRequest(t, b, testReq(t, "threshold-two"), UIDRequester(4242, 7))
	if it := listed(t, b, item.ID); it.SignaturesRequired != 2 || it.Signatures != 0 {
		t.Errorf("fresh item counts %d of %d, want 0 of 2", it.Signatures, it.SignaturesRequired)
	}

	first := a.decide(t, item, "approve")
	if f := approverDo(t, b, human(), first); f.Type != "recorded" || f.Detail != "1 of 2 signatures" {
		t.Fatalf("first signature: %+v, want recorded 1 of 2", f)
	}
	select {
	case f := <-done:
		t.Fatalf("requester answered below the threshold: %+v", f)
	default:
	}
	if it := listed(t, b, item.ID); it.SignaturesRequired != 2 || it.Signatures != 1 {
		t.Errorf("after one signature the list counts %d of %d, want 1 of 2", it.Signatures, it.SignaturesRequired)
	}
	rec := lastEvent(t, b, "signature_recorded")
	if rec["item"] != item.ID || rec["short_code"] != item.ShortCode || rec["approver_key"] != a.fp ||
		rec["approver_key_class"] != "mac-se" || rec["approver_key_name"] != "mac-a" || rec["signature"] != first.Signature ||
		rec["signatures"] != float64(1) || rec["signatures_required"] != float64(2) || rec["approver_uid"] != float64(approverHuman) {
		t.Errorf("signature_recorded event %v", rec)
	}

	second := c.decide(t, item, "approve")
	if f := approverDo(t, b, human(), second); f.Type != "decided" || f.Detail != "approve" {
		t.Fatalf("second signature: %+v, want decided", f)
	}
	if f := <-done; f.Type != "approved" {
		t.Fatalf("requester got %+v, want approved", f)
	}
	ev := lastEvent(t, b, "approval")
	if k := strList(ev["approver_keys"]); len(k) != 2 || k[0] != a.fp || k[1] != c.fp {
		t.Errorf("approver_keys %v, want [%s %s]", k, a.fp, c.fp)
	}
	if s := strList(ev["signatures"]); len(s) != 2 || s[0] != first.Signature || s[1] != second.Signature {
		t.Errorf("signatures %v", s)
	}
	if n := strList(ev["approver_key_names"]); len(n) != 2 || n[0] != "mac-a" || n[1] != "mac-b" {
		t.Errorf("names %v", n)
	}
}

// Two signatures by one key do not make a threshold of 2: the second is
// refused with signature_duplicate and the count stays at one. A deny
// still takes the item out of the queue at once, whatever was recorded.
func TestThresholdSameKeyTwiceAndDeny(t *testing.T) {
	a, c := newFakeSigner(t, "mac-a"), newFakeSigner(t, "mac-b")
	b := newThresholdBroker(t, 2, a, c)
	item, done := queueRequest(t, b, testReq(t, "threshold-dup"), UIDRequester(4242, 7))
	if f := approverDo(t, b, human(), a.decide(t, item, "approve")); f.Type != "recorded" {
		t.Fatalf("first signature: %+v", f)
	}
	again := a.decide(t, item, "approve") // a fresh signature by the same key
	if f := approverDo(t, b, human(), again); f.Type != "denied" || f.Reason != "signature_duplicate" {
		t.Fatalf("same key again: %+v, want denied signature_duplicate", f)
	}
	if ev := lastEvent(t, b, "decision_rejected"); ev["reason"] != "signature_duplicate" || ev["approver_key"] != a.fp {
		t.Errorf("rejection event %v", ev)
	}
	if it := listed(t, b, item.ID); it.Signatures != 1 {
		t.Errorf("count after a repeated key %d, want 1", it.Signatures)
	}
	if n := len(logEvents(t, b, "signature_recorded")); n != 1 {
		t.Errorf("%d signature_recorded events, want 1", n)
	}
	// an unsigned approve never counts towards a threshold above one
	if r := b.queue.vote(item.ID, item.Hash, queueDecision{granted: true, approver: human()}, b.pol.Load().signatureRule(), voteHooks{}); r.deny != "signature_required" {
		t.Errorf("unsigned vote under threshold 2: %+v, want signature_required", r)
	}

	if f := approverDo(t, b, human(), c.decide(t, item, "deny")); f.Type != "decided" || f.Detail != "deny" {
		t.Fatalf("signed deny: %+v", f)
	}
	if f := <-done; f.Reason != "approval_denied_by_human" {
		t.Fatalf("requester got %+v", f)
	}
	ev := lastEvent(t, b, "approval")
	if k := strList(ev["approver_keys"]); ev["decision"] != "deny" || len(k) != 1 || k[0] != c.fp {
		t.Errorf("deny event %v, want only the deny signature", ev)
	}
}

// A key removed by a reload is no longer accepted, and a signature it
// recorded before stops counting; the item keeps its deadline and the
// token TTL it was queued with. A reload that raises the threshold applies
// to the waiting item too.
func TestThresholdReloadRevokesKey(t *testing.T) {
	a, c, d := newFakeSigner(t, "mac-a"), newFakeSigner(t, "mac-b"), newFakeSigner(t, "mac-c")
	dir := t.TempDir()
	path := filepath.Join(dir, "config.json")
	conf := func(required int, signers ...*fakeSigner) map[string]any {
		keys := []ApproverKey{}
		for _, s := range signers {
			keys = append(keys, s.entry())
		}
		return reloadConfig(dir, map[string]any{"approver_keys": keys, "require_signed_decision": true, "required_signatures": required})
	}
	writeJSONConfig(t, path, conf(2, a, c, d))
	b := reloadBroker(t, path, ModeQueue)
	item, done := queueRequest(t, b, testReq(t, "threshold-reload"), UIDRequester(4242, 7))
	if f := approverDo(t, b, human(), a.decide(t, item, "approve")); f.Type != "recorded" {
		t.Fatalf("first signature: %+v", f)
	}

	writeJSONConfig(t, path, conf(2, c, d))
	b.Reload(path)
	if ev := lastEvent(t, b, "reload"); strings.Join(strList(ev["changed"]), ",") != "approver_keys" {
		t.Errorf("reload event %v", ev)
	}
	if f := approverDo(t, b, human(), a.decide(t, item, "approve")); f.Reason != "approver_key_unknown" {
		t.Errorf("removed key: %+v, want approver_key_unknown", f)
	}
	it := listed(t, b, item.ID)
	if it.Signatures != 0 || it.Deadline != item.Deadline || it.TokenTTLSeconds != item.TokenTTLSeconds || it.Payload != item.Payload {
		t.Errorf("after the reload the item is %+v, want no counted signature and its own terms", it)
	}
	if f := approverDo(t, b, human(), c.decide(t, item, "approve")); f.Type != "recorded" || f.Detail != "1 of 2 signatures" {
		t.Fatalf("a kept key after the revocation: %+v, want recorded 1 of 2", f)
	}

	writeJSONConfig(t, path, conf(3, a, c, d))
	b.Reload(path)
	if it := listed(t, b, item.ID); it.SignaturesRequired != 3 || it.Signatures != 2 {
		t.Errorf("after re-adding the key and raising the threshold: %d of %d, want 2 of 3", it.Signatures, it.SignaturesRequired)
	}
	if f := approverDo(t, b, human(), d.decide(t, item, "approve")); f.Type != "decided" {
		t.Fatalf("third key: %+v", f)
	}
	if f := <-done; f.Type != "approved" {
		t.Fatalf("requester got %+v", f)
	}
	if k := strList(lastEvent(t, b, "approval")["approver_keys"]); len(k) != 3 || k[0] != a.fp || k[1] != c.fp || k[2] != d.fp {
		t.Errorf("approval keys %v", k)
	}
}

// required_signatures defaults to 1; a negative threshold, a threshold
// above 1 without require_signed_decision and one above the number of
// keys are config errors: the broker does not start with them and a
// reload does not apply them (reload_failed).
func TestThresholdConfigErrors(t *testing.T) {
	a, c := newFakeSigner(t, "mac-a"), newFakeSigner(t, "mac-b")
	dir := t.TempDir()
	path := filepath.Join(dir, "config.json")
	two := []ApproverKey{a.entry(), c.entry()}
	writeJSONConfig(t, path, reloadConfig(dir, map[string]any{"approver_keys": two, "require_signed_decision": true, "required_signatures": 2}))
	if cfg, err := loadConfig(path); err != nil || cfg.RequiredSignatures != 2 {
		t.Fatalf("threshold 2 of 2 keys: %+v, %v", cfg, err)
	}
	writeJSONConfig(t, path, reloadConfig(dir, nil))
	if cfg, err := loadConfig(path); err != nil || cfg.RequiredSignatures != 1 || newPolicy(cfg, time.Minute).required != 1 {
		t.Fatalf("default threshold: %+v, %v, want 1", cfg, err)
	}
	if p := newPolicy(&Config{}, time.Minute); p.required != 1 {
		t.Errorf("in-code policy threshold %d, want 1", p.required)
	}
	b := reloadBroker(t, path, ModeQueue)
	for name, c := range map[string]struct {
		over map[string]any
		want string
	}{
		"negative":         {map[string]any{"required_signatures": -1}, "negative"},
		"unsigned above 1": {map[string]any{"approver_keys": two, "required_signatures": 2}, "needs require_signed_decision"},
		"above the keys":   {map[string]any{"approver_keys": two, "require_signed_decision": true, "required_signatures": 3}, "at least 3 approver_keys"},
		"reserved class":   {map[string]any{"approver_keys": []ApproverKey{{Name: "p", Class: KeyClassIOSSE, PublicKey: a.spki}}}, "reserved"},
		"repeated name":    {map[string]any{"approver_keys": []ApproverKey{a.entry(), {Name: "mac-a", Class: KeyClassMacSE, PublicKey: c.spki}}}, "empty or repeated"},
	} {
		writeJSONConfig(t, path, reloadConfig(dir, c.over))
		if _, err := loadConfig(path); err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: %v, want an error with %q", name, err, c.want)
		}
		b.Reload(path)
		if ev := lastEvent(t, b, "reload_failed"); !strings.Contains(ev["error"].(string), c.want) {
			t.Errorf("%s: reload_failed %v", name, ev)
		}
		if b.pol.Load().required != 1 || len(b.pol.Load().keys) != 0 {
			t.Errorf("%s: a failed reload changed the policy", name)
		}
	}
}
