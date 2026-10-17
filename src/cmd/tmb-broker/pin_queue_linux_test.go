//go:build linux

package main

import (
	"os"
	"testing"

	"tmb-poc/internal/proto"
)

// The exe is pinned when the request enters the queue, not after the
// decision: a file renamed over the path while the approver looks at the
// request is refused at claim, never run.
func TestExeSwappedWhileQueuedIsNotRun(t *testing.T) {
	b := newQueueBroker(t)
	dir := t.TempDir()
	tool := foreignBinary(t, dir, "tool")
	req := &proto.Request{Executable: tool, Argv: []string{tool}, Cwd: "/tmp", Nonce: "swap-while-queued"}
	id := UIDRequester(4242, 7)
	item, done := queueRequest(t, b, req, id)

	other := foreignBinary(t, dir, "other")
	if err := os.Rename(other, tool); err != nil {
		t.Fatal(err)
	}
	if f := approverDo(t, b, UIDRequester(humanUID, 1), &proto.Request{Type: "decide", ItemID: item.ID, ItemHash: item.Hash, Decision: "approve"}); f.Type != "decided" {
		t.Fatalf("decide: %+v", f)
	}
	f := <-done
	if f.Type != "approved" {
		t.Fatalf("requester got %+v, want approved", f)
	}
	req.ClaimToken = f.Token
	if f := claimDo(t, b, req, id); f.Type != "denied" || f.Reason != "executable_changed" {
		t.Fatalf("claim = %+v, want denied executable_changed", f)
	}
}
