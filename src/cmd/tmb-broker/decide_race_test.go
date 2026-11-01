package main

import (
	"path/filepath"
	"sync"
	"testing"

	"tmb-poc/internal/proto"
)

// A reload that lands between the approver's decide being read and the
// vote does not let the decide through under the old policy: a key the
// reload removed decides nothing.
func TestDecideUsesPolicyAfterConcurrentReload(t *testing.T) {
	a, c := newFakeSigner(t, "mac-a"), newFakeSigner(t, "mac-b")
	dir := t.TempDir()
	path := filepath.Join(dir, "config.json")
	conf := func(signers ...*fakeSigner) map[string]any {
		keys := []ApproverKey{}
		for _, s := range signers {
			keys = append(keys, s.entry())
		}
		return reloadConfig(dir, map[string]any{"approver_keys": keys, "require_signed_decision": true})
	}
	writeJSONConfig(t, path, conf(a, c))
	b := reloadBroker(t, path, ModeQueue)
	item, done := queueRequest(t, b, testReq(t, "decide-race"), UIDRequester(4242, 7))

	var once sync.Once
	beforeVote = func() {
		once.Do(func() {
			writeJSONConfig(t, path, conf(c))
			b.Reload(path)
		})
	}
	t.Cleanup(func() { beforeVote = func() {} })
	if f := approverDo(t, b, human(), a.decide(t, item, "approve")); f.Type != "denied" || f.Reason != "approver_key_unknown" {
		t.Fatalf("decide by a key removed mid-decide: %+v, want denied approver_key_unknown", f)
	}
	select {
	case f := <-done:
		t.Fatalf("requester answered: %+v", f)
	default:
	}
	if f := approverDo(t, b, human(), c.decide(t, item, "approve")); f.Type != "decided" {
		t.Fatalf("kept key: %+v", f)
	}
	if f := <-done; f.Type != "approved" {
		t.Fatalf("requester got %+v", f)
	}
}

// Votes on one item from several approvers at once, and votes racing a
// reload, keep the queue consistent: under threshold 1 exactly one
// decision wins, under threshold 2 the item is decided once both keys
// signed. Run under -race.
func TestConcurrentVotes(t *testing.T) {
	for _, required := range []int{1, 2} {
		a, c := newFakeSigner(t, "mac-a"), newFakeSigner(t, "mac-b")
		dir := t.TempDir()
		path := filepath.Join(dir, "config.json")
		writeJSONConfig(t, path, reloadConfig(dir, map[string]any{
			"approver_keys": []ApproverKey{a.entry(), c.entry()}, "require_signed_decision": true, "required_signatures": required,
		}))
		b := reloadBroker(t, path, ModeQueue)
		item, done := queueRequest(t, b, testReq(t, "concurrent-votes"), UIDRequester(4242, 7))
		reqs := []*proto.Request{a.decide(t, item, "approve"), c.decide(t, item, "approve")}
		frames := make([]*proto.Frame, len(reqs))
		var wg sync.WaitGroup
		for i, r := range reqs {
			wg.Add(1)
			go func(i int, r *proto.Request) {
				defer wg.Done()
				frames[i] = approverDo(t, b, human(), r)
			}(i, r)
		}
		wg.Add(1)
		go func() { defer wg.Done(); b.Reload(path) }()
		wg.Wait()
		decided, other := 0, 0
		for _, f := range frames {
			switch {
			case f.Type == "decided":
				decided++
			case required == 1 && f.Reason == "already_decided", required == 2 && f.Type == "recorded":
				other++
			default:
				t.Errorf("threshold %d: unexpected answer %+v", required, f)
			}
		}
		if decided != 1 || other != 1 {
			t.Errorf("threshold %d: %d decided, %d other, want one each", required, decided, other)
		}
		if f := <-done; f.Type != "approved" {
			t.Fatalf("threshold %d: requester got %+v", required, f)
		}
	}
}
