package main

import (
	"testing"

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
