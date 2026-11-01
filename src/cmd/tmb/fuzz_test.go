package main

import (
	"bytes"
	"encoding/json"
	"reflect"
	"strings"
	"testing"

	"tmb-poc/internal/proto"
)

// FuzzReadDecision: the --decide stdin parser never panics or hangs, and
// whatever it accepts is a well-formed decide: a known decision, an item id
// bound to a 64-hex hash, and a signature in canonical base64 always paired
// with a 64-hex approver key. An accepted object re-encoded is accepted
// again as the same decide.
func FuzzReadDecision(f *testing.F) {
	hash := strings.Repeat("ab", 32)
	id := hash[:16]
	key := strings.Repeat("cd", 32)
	for _, s := range []string{
		``,
		`{}`,
		`[]`,
		`{"item_id":"` + id + `","item_hash":"` + hash + `","decision":"deny"}`,
		`{"item_id":"` + id + `","item_hash":"` + hash + `","decision":"approve","signature":"MEUCIQDx","approver_key":"` + key + `"}`,
		`{"item_id":"` + id + `","item_hash":"` + hash + `","decision":"approve","signature":"MEUC\r\nIQDx","approver_key":"` + key + `"}`,
		`{"item_id":"` + id + `","item_hash":"` + hash + `","decision":"deny","decision":"approve"}`,
		`{"item_id":"` + id + `","item_hash":"` + hash + `","decision":"deny"} x`,
		`{"Decision":"deny"}`,
		`{"item_id":1}`,
		`{"item_id":"` + id,
	} {
		f.Add([]byte(s))
	}
	f.Fuzz(func(t *testing.T, in []byte) {
		req, err := readDecision(bytes.NewReader(in))
		if err != nil {
			if req != nil {
				t.Fatalf("error %v returned with a request", err)
			}
			return
		}
		if req.Type != "decide" || (req.Decision != "approve" && req.Decision != "deny") ||
			!isLowerHex(req.ItemHash, 64) || req.ItemID != proto.TokenID(req.ItemHash) {
			t.Fatalf("accepted a malformed decide %+v", req)
		}
		if (req.Signature == "") != (req.ApproverKey == "") {
			t.Fatalf("signature and approver_key not paired: %+v", req)
		}
		if req.Signature != "" {
			if _, err := proto.DecodeSignature(req.Signature); err != nil || !isLowerHex(req.ApproverKey, 64) {
				t.Fatalf("accepted signature %q key %q", req.Signature, req.ApproverKey)
			}
		}
		obj := map[string]string{"item_id": req.ItemID, "item_hash": req.ItemHash, "decision": req.Decision}
		if req.Signature != "" {
			obj["signature"], obj["approver_key"] = req.Signature, req.ApproverKey
		}
		again, _ := json.Marshal(obj)
		back, err := readDecision(bytes.NewReader(again))
		if err != nil || !reflect.DeepEqual(back, req) {
			t.Fatalf("re-encoded decide %s: %+v, %v; want %+v", again, back, err, req)
		}
	})
}
