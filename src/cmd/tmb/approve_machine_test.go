package main

import (
	"encoding/json"
	"strings"
	"testing"

	"tmb-poc/internal/proto"
)

func signerItem(id string) proto.QueueItem {
	it := sampleItem(id)
	it.Payload = "dG1iLWFwcHJvdmFsLXYxAHt9"
	it.ShortCode = "ABCD-EFGH"
	it.HostID = "test-host"
	it.HostKey = strings.Repeat("ab", 32)
	it.Challenge = strings.Repeat("cd", 32)
	it.Deadline = "2026-10-17T00:05:00Z"
	it.TokenTTLSeconds = 300
	it.SignaturesRequired = 2
	it.Signatures = 1
	return it
}

// The signer reads the queue over SSH: one JSON object with every field the
// broker sent, the payload and the short code included.
func TestApproveListJSONHasEveryField(t *testing.T) {
	f := startFakeApprover(t, signerItem("aaaaaaaaaaaaaaaa"))
	code, out, errs := runApprove(t, "", "--list", "--json", "--socket", f.path)
	if code != 0 {
		t.Fatalf("--list --json exit %d %s", code, errs)
	}
	if strings.Count(out, "\n") != 1 || !strings.HasSuffix(out, "\n") {
		t.Errorf("want one line of JSON, got %q", out)
	}
	var got struct {
		Type  string           `json:"type"`
		Items []map[string]any `json:"items"`
	}
	if err := json.Unmarshal([]byte(out), &got); err != nil {
		t.Fatalf("not JSON: %v\n%s", err, out)
	}
	if got.Type != "queue" || len(got.Items) != 1 {
		t.Fatalf("got %+v", got)
	}
	it := got.Items[0]
	for k, want := range map[string]any{
		"id": "aaaaaaaaaaaaaaaa", "payload": "dG1iLWFwcHJvdmFsLXYxAHt9", "short_code": "ABCD-EFGH",
		"host_id": "test-host", "host_key": strings.Repeat("ab", 32), "challenge": strings.Repeat("cd", 32),
		"deadline": "2026-10-17T00:05:00Z", "token_ttl_seconds": float64(300),
		"signatures_required": float64(2), "signatures": float64(1), "executable": "/usr/bin/id",
	} {
		if it[k] != want {
			t.Errorf("item[%s] = %v, want %v", k, it[k], want)
		}
	}
	empty := startFakeApprover(t)
	if code, out, _ := runApprove(t, "", "--list", "--json", "--socket", empty.path); code != 0 || out != "{\"type\":\"queue\",\"items\":[]}\n" {
		t.Errorf("empty --list --json: %d %q", code, out)
	}
}

// A field the broker adds later reaches the signer without a client change.
func TestApproveListJSONPassesUnknownFields(t *testing.T) {
	f := startFakeApprover(t)
	f.rawQueue = json.RawMessage(`{"type":"queue","items":[{"id":"aaaaaaaaaaaaaaaa","future_field":{"x":[1,2]},"note":"a\u001b[2Ab"}]}`)
	code, out, errs := runApprove(t, "", "--list", "--json", "--socket", f.path)
	if code != 0 {
		t.Fatalf("exit %d %s", code, errs)
	}
	want := `{"type":"queue","items":[{"id":"aaaaaaaaaaaaaaaa","future_field":{"x":[1,2]},"note":"a\u001b[2Ab"}]}` + "\n"
	if out != want {
		t.Errorf("got  %s\nwant %s", out, want)
	}
	// a raw bidi or DEL in a string is escaped, and the line stays JSON
	f.rawQueue = json.RawMessage("{\"type\":\"queue\",\"items\":[{\"cwd\":\"/tmp/\u202ecod\x7f\"}]}")
	_, out, _ = runApprove(t, "", "--list", "--json", "--socket", f.path)
	if strings.ContainsAny(out, "\u202e\x7f") || !strings.Contains(out, `"/tmp/\`+`u202ecod\`+`u007f"`) {
		t.Errorf("raw control characters in machine output: %q", out)
	}
	var v any
	if err := json.Unmarshal([]byte(out), &v); err != nil {
		t.Errorf("escaped output is not JSON: %v", err)
	}
}

func TestApproveListJSONErrors(t *testing.T) {
	f := startFakeApprover(t, signerItem("aaaaaaaaaaaaaaaa"))
	f.denyAll = "approver_not_allowed"
	code, out, errs := runApprove(t, "", "--list", "--json", "--socket", f.path)
	if code != 125 || !strings.Contains(errs, "approver_not_allowed") || out != `{"type":"denied","reason":"approver_not_allowed","detail":"from the fake"}`+"\n" {
		t.Errorf("denied list: exit %d out %q err %q", code, out, errs)
	}
	g := startFakeApprover(t)
	g.setMode("weird")
	if code, out, _ := runApprove(t, "", "--list", "--json", "--socket", g.path); code != 1 || out != "" {
		t.Errorf("wrong answer to list: exit %d out %q, want 1 and nothing", code, out)
	}
	g.rawQueue = json.RawMessage(`{"type":"queue","items":{"not":"a list"}}`)
	// an answer that is not a frame is a broken connection, as in human mode
	if code, out, errs := runApprove(t, "", "--list", "--json", "--socket", g.path); code != 3 || out != "" || !strings.Contains(errs, "connection to broker lost") {
		t.Errorf("malformed queue: exit %d out %q err %q, want 3", code, out, errs)
	}
	if code, _, _ := runApprove(t, "", "--list", "--json", "--socket", t.TempDir()+"/none.sock"); code != 3 {
		t.Errorf("no socket: exit %d, want 3", code)
	}
	for _, args := range [][]string{{"--json"}, {"--json", "--yes", "x"}, {"--decide", "--list"}, {"--decide", "--no", "x"}} {
		if code, _, _ := runApprove(t, "", append(args, "--socket", f.path)...); code != 2 {
			t.Errorf("%q: exit %d, want 2", args, code)
		}
	}
}

const testSig = "MEUCIQDx" // base64 of a few bytes: the client does not verify it

var testKey = strings.Repeat("e", 64)

func decisionJSON(it proto.QueueItem, decision string, signed bool) string {
	m := map[string]string{"item_id": it.ID, "item_hash": it.Hash, "decision": decision}
	if signed {
		m["signature"] = testSig
		m["approver_key"] = testKey
	}
	b, _ := json.Marshal(m)
	return string(b)
}

// The signer sends its DecideMessage as is; the client passes the signature
// and key to the broker and prints the broker's answer.
func TestApproveDecideFromStdin(t *testing.T) {
	a, b := signerItem("aaaaaaaaaaaaaaaa"), signerItem("bbbbbbbbbbbbbbbb")
	f := startFakeApprover(t, a, b)
	code, out, errs := runApprove(t, decisionJSON(a, "approve", true)+"\n", "--decide", "--socket", f.path)
	if code != 0 || out != `{"type":"decided","detail":"approve"}`+"\n" {
		t.Fatalf("signed approve: exit %d out %q err %q", code, out, errs)
	}
	got := f.decisions[0]
	if got.Type != "decide" || got.ItemID != a.ID || got.ItemHash != a.Hash || got.Decision != "approve" || got.Signature != testSig || got.ApproverKey != testKey {
		t.Errorf("broker got %+v", got)
	}
	// an unsigned deny, as the signer sends it after a cancel
	code, out, _ = runApprove(t, decisionJSON(b, "deny", false), "--decide", "--socket", f.path)
	if code != 0 || out != `{"type":"decided","detail":"deny"}`+"\n" || f.decided[b.ID] != "deny" {
		t.Fatalf("deny: exit %d out %q decided %v", code, out, f.decided)
	}
	if f.decisions[1].Signature != "" || f.decisions[1].ApproverKey != "" {
		t.Errorf("unsigned deny carried signature fields: %+v", f.decisions[1])
	}
	// already decided and unknown items keep exit 1
	code, out, errs = runApprove(t, decisionJSON(a, "deny", false), "--decide", "--socket", f.path)
	if code != 1 || !strings.Contains(errs, "already_decided") || out != `{"type":"denied","reason":"already_decided"}`+"\n" {
		t.Errorf("second decision: exit %d out %q err %q", code, out, errs)
	}
	if code, _, _ := runApprove(t, decisionJSON(sampleItem("cccccccccccccccc"), "deny", false), "--decide", "--socket", f.path); code != 1 {
		t.Errorf("unknown item: exit %d, want 1", code)
	}
}

func TestApproveDecideBrokerAnswers(t *testing.T) {
	it := signerItem("aaaaaaaaaaaaaaaa")
	in := decisionJSON(it, "approve", true)
	f := startFakeApprover(t, it)
	f.answer = &proto.Frame{Type: "denied", Reason: "signature_invalid"}
	code, out, errs := runApprove(t, in, "--decide", "--socket", f.path)
	if code != 125 || !strings.Contains(errs, "signature_invalid") || out != `{"type":"denied","reason":"signature_invalid"}`+"\n" {
		t.Errorf("refused signature: exit %d out %q err %q", code, out, errs)
	}
	// a valid signature below the threshold is recorded: a success
	f.answer = &proto.Frame{Type: "recorded", Detail: "1 of 2"}
	if code, out, _ := runApprove(t, in, "--decide", "--socket", f.path); code != 0 || out != `{"type":"recorded","detail":"1 of 2"}`+"\n" {
		t.Errorf("recorded: exit %d out %q", code, out)
	}
	f.answer = &proto.Frame{Type: "queue"}
	if code, out, errs := runApprove(t, in, "--decide", "--socket", f.path); code != 1 || out != "" || !strings.Contains(errs, "unexpected answer") {
		t.Errorf("wrong answer: exit %d out %q err %q", code, out, errs)
	}
	f.answer = nil
	f.setMode("hangup")
	if code, _, _ := runApprove(t, in, "--decide", "--socket", f.path); code != 3 {
		t.Errorf("no answer: exit %d, want 3", code)
	}
	if code, _, _ := runApprove(t, in, "--decide", "--socket", t.TempDir()+"/none.sock"); code != 3 {
		t.Errorf("no socket: exit %d, want 3", code)
	}
}

// Junk on stdin is a usage error and never reaches the broker.
func TestApproveDecideRefusesJunkWithoutBroker(t *testing.T) {
	it := signerItem("aaaaaaaaaaaaaaaa")
	id, hash := it.ID, it.Hash
	obj := func(extra string) string {
		return `{"item_id":"` + id + `","item_hash":"` + hash + `"` + extra + `}`
	}
	cases := map[string]string{
		"empty":               "",
		"whitespace":          " \n",
		"not json":            "approve aaaaaaaaaaaaaaaa",
		"array":               `["approve"]`,
		"string":              `"approve"`,
		"truncated":           `{"item_id":"` + id,
		"truncated after key": `{"item_id":`,
		"two objects":         obj(`,"decision":"deny"`) + obj(`,"decision":"deny"`),
		"trailing junk":       obj(`,"decision":"deny"`) + " x",
		"no decision":         obj(""),
		"bad decision":        obj(`,"decision":"yes"`),
		"decision case":       obj(`,"decision":"Approve"`),
		"unknown field":       obj(`,"decision":"deny","type":"decide"`),
		"case-folded key":     obj(`,"Decision":"deny"`),
		"duplicate key":       obj(`,"decision":"approve","decision":"deny"`),
		"number value":        `{"item_id":"` + id + `","item_hash":1,"decision":"deny"}`,
		"null value":          obj(`,"decision":null`),
		"no hash":             `{"item_id":"` + id + `","decision":"deny"}`,
		"short hash":          `{"item_id":"` + id + `","item_hash":"` + hash[:63] + `","decision":"deny"}`,
		"upper hash":          `{"item_id":"` + id + `","item_hash":"` + strings.ToUpper(hash) + `","decision":"deny"}`,
		"id not hash prefix":  `{"item_id":"bbbbbbbbbbbbbbbb","item_hash":"` + hash + `","decision":"deny"}`,
		"signature alone":     obj(`,"decision":"approve","signature":"` + testSig + `"`),
		"key alone":           obj(`,"decision":"approve","approver_key":"` + testKey + `"`),
		"empty signature":     obj(`,"decision":"approve","signature":"","approver_key":"` + testKey + `"`),
		"signature not b64":   obj(`,"decision":"approve","signature":"not base64!","approver_key":"` + testKey + `"`),
		"signature url b64":   obj(`,"decision":"approve","signature":"__8=","approver_key":"` + testKey + `"`),
		"signature with CRLF": obj(`,"decision":"approve","signature":"MEUC\r\nIQDx","approver_key":"` + testKey + `"`),
		"signature too long":  obj(`,"decision":"approve","signature":"` + strings.Repeat("A", 132) + `","approver_key":"` + testKey + `"`),
		"short key":           obj(`,"decision":"approve","signature":"` + testSig + `","approver_key":"abc"`),
		"oversized":           obj(`,"decision":"deny"`) + strings.Repeat(" ", maxDecisionInput),
		"control in key name": obj(`,"decision":"deny","\u001b[2A":"x"`),
	}
	f := startFakeApprover(t, it)
	for name, in := range cases {
		code, out, errs := runApprove(t, in, "--decide", "--socket", f.path)
		if code != 2 || out != "" || !strings.Contains(errs, "decision on stdin") {
			t.Errorf("%s: exit %d out %q err %q, want 2", name, code, out, errs)
		}
		if strings.ContainsRune(errs, '\x1b') {
			t.Errorf("%s: raw escape in stderr %q", name, errs)
		}
	}
	if f.requests != 0 {
		t.Errorf("junk reached the broker %d times", f.requests)
	}
}

// The approver at the terminal sees the same short code as the signer's
// dialog.
func TestApproveHumanOutputShowsShortCode(t *testing.T) {
	it := signerItem("aaaaaaaaaaaaaaaa")
	f := startFakeApprover(t, it)
	if code, out, _ := runApprove(t, "", "--list", "--socket", f.path); code != 0 || !strings.Contains(out, "=== aaaaaaaaaaaaaaaa ===\n  short code: ABCD-EFGH\n") {
		t.Errorf("--list: exit %d\n%s", code, out)
	}
	if code, out, _ := runApprove(t, "n\n", "--socket", f.path); code != 0 || !strings.Contains(out, "short code: ABCD-EFGH") {
		t.Errorf("interactive: exit %d\n%s", code, out)
	}
	g := startFakeApprover(t, sampleItem("bbbbbbbbbbbbbbbb"))
	if _, out, _ := runApprove(t, "", "--list", "--socket", g.path); strings.Contains(out, "short code") {
		t.Errorf("short code line without a code:\n%s", out)
	}
}
