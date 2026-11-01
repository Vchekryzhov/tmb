package main

import (
	"errors"
	"os"
	"strings"
	"sync/atomic"
	"testing"
)

// A signature short of the threshold counts only with its
// signature_recorded event on disk: when that write fails the approver is
// told audit_unavailable, the item keeps its count, and the same key may
// sign again once the journal is back.
func TestSignatureRecordedNeedsTheJournal(t *testing.T) {
	a, c := newFakeSigner(t, "mac-a"), newFakeSigner(t, "mac-b")
	b := newThresholdBroker(t, 2, a, c)
	b.log.stderr = &lockedBuffer{}
	var broken atomic.Bool
	broken.Store(true)
	b.log.write = func(f *os.File, p []byte) (int, error) {
		if broken.Load() && strings.Contains(string(p), `"event":"signature_recorded"`) {
			return 0, errors.New("injected EIO")
		}
		return f.Write(p)
	}
	item, done := queueRequest(t, b, testReq(t, "recorded-journal"), UIDRequester(4242, 7))
	if f := approverDo(t, b, human(), a.decide(t, item, "approve")); f.Type != "denied" || f.Reason != "audit_unavailable" {
		t.Fatalf("signature with a failing journal: %+v, want denied audit_unavailable", f)
	}
	if n := listed(t, b, item.ID).Signatures; n != 0 {
		t.Fatalf("%d signatures kept without their record", n)
	}

	broken.Store(false)
	if err := b.log.Reopen(); err != nil {
		t.Fatalf("reopen: %v", err)
	}
	if f := approverDo(t, b, human(), a.decide(t, item, "approve")); f.Type != "recorded" || f.Detail != "1 of 2 signatures" {
		t.Fatalf("same key after the journal is back: %+v, want recorded 1 of 2", f)
	}
	if f := approverDo(t, b, human(), c.decide(t, item, "approve")); f.Type != "decided" {
		t.Fatalf("second key: %+v", f)
	}
	if f := <-done; f.Type != "approved" {
		t.Fatalf("requester got %+v", f)
	}
}
