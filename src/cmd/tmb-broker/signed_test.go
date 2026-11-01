package main

import (
	"encoding/base64"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"tmb-poc/internal/proto"
)

const approverHuman = humanUID

func human() RequesterID { return UIDRequester(approverHuman, 99) }

// lastEvent returns the last journal event of that name.
func lastEvent(t *testing.T, b *Broker, event string) map[string]any {
	t.Helper()
	evs := logEvents(t, b, event)
	if len(evs) == 0 {
		t.Fatalf("no %s event in the journal:\n%s", event, logText(t, b))
	}
	return evs[len(evs)-1]
}

// A queued item carries the payload, its short code and the payload's
// display fields; a decide signed over those bytes by a key in
// approver_keys approves it, and the approval event carries the proof.
func TestSignedDecideApproves(t *testing.T) {
	signer := newFakeSigner(t, "mac")
	b := newSignedBroker(t, true, signer)
	req := testReq(t, "signed-approve")
	item, done := queueRequest(t, b, req, UIDRequester(4242, 7))

	raw, err := base64.StdEncoding.DecodeString(item.Payload)
	if err != nil {
		t.Fatalf("payload not base64: %v", err)
	}
	p, err := proto.ParseApprovalPayload(raw)
	if err != nil {
		t.Fatalf("payload does not parse: %v", err)
	}
	if p.HostID != "test-host" || p.HostKey != testHostKey || p.ItemID != item.ID || p.RequestHash != req.Hash() ||
		p.Challenge != item.Challenge || p.Requester != "uid:4242" || p.Nonce != req.Nonce || p.Executable != item.Executable {
		t.Errorf("payload %+v does not describe item %+v", p, item)
	}
	if item.ShortCode != proto.ShortCode(raw) || item.HostID != "test-host" || item.HostKey != testHostKey || item.TokenTTLSeconds != 30 {
		t.Errorf("item display fields %+v do not match the payload", item)
	}
	if dl, err := time.Parse(time.RFC3339Nano, item.Deadline); err != nil || dl.UnixMilli() != p.Deadline {
		t.Errorf("item deadline %q, payload deadline %d", item.Deadline, p.Deadline)
	}
	if f := approverDo(t, b, human(), &proto.Request{Type: "list"}); len(f.Items) != 1 || f.Items[0].Payload != item.Payload {
		t.Fatalf("list: %+v", f)
	}

	sigReq := signer.decide(t, item, "approve")
	if f := approverDo(t, b, human(), sigReq); f.Type != "decided" {
		t.Fatalf("signed decide: %+v", f)
	}
	if f := <-done; f.Type != "approved" || f.Token != item.ID {
		t.Fatalf("requester got %+v, want approved", f)
	}
	ev := lastEvent(t, b, "approval")
	if ev["signed"] != true || ev["short_code"] != item.ShortCode || ev["payload"] != item.Payload {
		t.Errorf("approval event lacks the proof: %v", ev)
	}
	if k := strList(ev["approver_keys"]); len(k) != 1 || k[0] != signer.fp {
		t.Errorf("approver_keys %v, want [%s]", ev["approver_keys"], signer.fp)
	}
	if s := strList(ev["signatures"]); len(s) != 1 || s[0] != sigReq.Signature {
		t.Errorf("signatures %v", ev["signatures"])
	}
	if c, n := strList(ev["approver_key_classes"]), strList(ev["approver_key_names"]); len(c) != 1 || c[0] != "mac-se" || len(n) != 1 || n[0] != "mac" {
		t.Errorf("classes %v names %v", c, n)
	}
	if q := lastEvent(t, b, "queued"); q["short_code"] != item.ShortCode {
		t.Errorf("queued event short_code %v, want %s", q["short_code"], item.ShortCode)
	}
}

// approver_keys in the ADR 0007 format load; a reserved or unknown class,
// a repeated name or key, a key that is not P-256 SPKI, and
// require_signed_decision without any key are config errors. host_id
// defaults to the host name.
func TestLoadConfigApproverKeys(t *testing.T) {
	a, c := newFakeSigner(t, "mac-a"), newFakeSigner(t, "mac-b")
	entry := func(name, class, key string) map[string]string {
		return map[string]string{"name": name, "class": class, "public_key": key}
	}
	dir := t.TempDir()
	path := filepath.Join(dir, "config.json")
	writeJSONConfig(t, path, reloadConfig(dir, map[string]any{
		"approver_keys":           []any{entry("mac-a", "mac-se", a.spki), entry("mac-b", "mac-se", c.spki)},
		"require_signed_decision": true,
		"host_id":                 "build-01",
	}))
	cfg, err := loadConfig(path)
	if err != nil {
		t.Fatalf("valid config: %v", err)
	}
	keys := newPolicy(cfg, time.Minute).keys
	if cfg.HostID != "build-01" || len(keys) != 2 || keys[a.fp].name != "mac-a" || keys[c.fp].class != "mac-se" {
		t.Errorf("host_id %q keys %v", cfg.HostID, keys)
	}
	writeJSONConfig(t, path, reloadConfig(dir, nil))
	if cfg, err := loadConfig(path); err != nil || cfg.HostID == "" || cfg.RequireSignedDecision || len(cfg.ApproverKeys) != 0 {
		t.Errorf("defaults: %+v, %v; want the host name and no signer settings", cfg, err)
	}

	for name, c := range map[string]struct {
		over map[string]any
		want string
	}{
		"ios-se reserved":  {map[string]any{"approver_keys": []any{entry("phone", "ios-se", a.spki)}}, "reserved"},
		"u2f reserved":     {map[string]any{"approver_keys": []any{entry("fido", "u2f", a.spki)}}, "reserved"},
		"unknown class":    {map[string]any{"approver_keys": []any{entry("x", "tpm", a.spki)}}, "unknown class"},
		"empty name":       {map[string]any{"approver_keys": []any{entry("", "mac-se", a.spki)}}, "empty or repeated"},
		"repeated name":    {map[string]any{"approver_keys": []any{entry("m", "mac-se", a.spki), entry("m", "mac-se", c.spki)}}, "empty or repeated"},
		"repeated key":     {map[string]any{"approver_keys": []any{entry("m1", "mac-se", a.spki), entry("m2", "mac-se", a.spki)}}, "listed twice"},
		"bad key":          {map[string]any{"approver_keys": []any{entry("m", "mac-se", "AAAA")}}, `"m"`},
		"required no keys": {map[string]any{"require_signed_decision": true}, "require_signed_decision"},
	} {
		writeJSONConfig(t, path, reloadConfig(dir, c.over))
		if _, err := loadConfig(path); err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: %v, want an error with %q", name, err, c.want)
		}
	}
	// a Config built in code with a bad entry gets no keys at all
	if p := newPolicy(&Config{ApproverKeys: []ApproverKey{{Name: "x", Class: "u2f"}}}, time.Minute); len(p.keys) != 0 {
		t.Errorf("bad in-code entry kept keys %v", p.keys)
	}
}

// SIGHUP applies approver_keys and require_signed_decision: a key added by
// a reload signs, a removed key no longer does.
func TestReloadAppliesApproverKeys(t *testing.T) {
	signer := newFakeSigner(t, "mac")
	dir := t.TempDir()
	path := filepath.Join(dir, "config.json")
	writeJSONConfig(t, path, reloadConfig(dir, nil))
	b := reloadBroker(t, path, ModeQueue)
	item, done := queueRequest(t, b, testReq(t, "reload-keys"), UIDRequester(4242, 7))
	if f := approverDo(t, b, human(), signer.decide(t, item, "approve")); f.Reason != "approver_key_unknown" {
		t.Fatalf("before the reload: %+v, want approver_key_unknown", f)
	}
	writeJSONConfig(t, path, reloadConfig(dir, map[string]any{
		"approver_keys":           []ApproverKey{signer.entry()},
		"require_signed_decision": true,
	}))
	b.Reload(path)
	if ev := lastEvent(t, b, "reload"); !strings.Contains(strings.Join(strList(ev["changed"]), ","), "approver_keys,require_signed_decision") {
		t.Errorf("reload event %v", ev)
	}
	if f := approverDo(t, b, human(), &proto.Request{Type: "decide", ItemID: item.ID, ItemHash: item.Hash, Decision: "approve"}); f.Reason != "signature_required" {
		t.Errorf("unsigned after the reload: %+v, want signature_required", f)
	}
	if f := approverDo(t, b, human(), signer.decide(t, item, "approve")); f.Type != "decided" {
		t.Fatalf("after the reload: %+v", f)
	}
	if f := <-done; f.Type != "approved" {
		t.Fatalf("requester got %+v", f)
	}
}

// reencode parses the item's payload, lets edit change it and returns the
// re-encoded bytes: a payload the broker never built.
func reencode(t *testing.T, item proto.QueueItem, edit func(*proto.ApprovalPayload)) []byte {
	t.Helper()
	raw, _ := base64.StdEncoding.DecodeString(item.Payload)
	p, err := proto.ParseApprovalPayload(raw)
	if err != nil {
		t.Fatal(err)
	}
	edit(p)
	out, err := p.Encode()
	if err != nil {
		t.Fatal(err)
	}
	return out
}

// setClock moves the queue clock (decision deadlines) by d.
func setClock(b *Broker, d time.Duration) {
	b.queue.mu.Lock()
	b.queue.now = func() time.Time { return time.Now().Add(d) }
	b.queue.mu.Unlock()
}

// Every signed decide that does not prove the human saw exactly this item
// on this host before its deadline is refused, and the item keeps waiting
// for a valid decision.
func TestSignedDecideRejections(t *testing.T) {
	signer, stranger := newFakeSigner(t, "mac"), newFakeSigner(t, "stranger")
	b := newSignedBroker(t, true, signer)
	item, done := queueRequest(t, b, testReq(t, "signed-reject"), UIDRequester(4242, 7))
	other, otherDone := queueRequest(t, b, testReq(t, "signed-reject-other"), UIDRequester(4242, 7))

	withSig := func(it proto.QueueItem, sig, key string) *proto.Request {
		return &proto.Request{Type: "decide", ItemID: it.ID, ItemHash: it.Hash, Decision: "approve", Signature: sig, ApproverKey: key}
	}
	forged := func(edit func(*proto.ApprovalPayload)) string { return signer.signBytes(t, reencode(t, item, edit)) }
	cases := []struct {
		name   string
		req    *proto.Request
		reason string
	}{
		{"signature of another item", withSig(item, signer.sign(t, other), signer.fp), "signature_invalid"},
		{"another host_id", withSig(item, forged(func(p *proto.ApprovalPayload) { p.HostID = "other-host" }), signer.fp), "signature_invalid"},
		{"another host_key", withSig(item, forged(func(p *proto.ApprovalPayload) { p.HostKey = strings.Repeat("ab", 32) }), signer.fp), "signature_invalid"},
		{"another challenge", withSig(item, forged(func(p *proto.ApprovalPayload) { p.Challenge = strings.Repeat("0", 64) }), signer.fp), "signature_invalid"},
		{"a longer token TTL", withSig(item, forged(func(p *proto.ApprovalPayload) { p.TokenTTL = 3600 }), signer.fp), "signature_invalid"},
		{"signature by another key", withSig(item, stranger.sign(t, item), signer.fp), "signature_invalid"},
		{"key not in approver_keys", withSig(item, stranger.sign(t, item), stranger.fp), "approver_key_unknown"},
		{"signature without a key", withSig(item, signer.sign(t, item), ""), "approver_key_unknown"},
		{"key without a signature", withSig(item, "", signer.fp), "signature_invalid"},
		{"signature not base64", withSig(item, "not base64!", signer.fp), "signature_invalid"},
		{"unsigned approve", &proto.Request{Type: "decide", ItemID: item.ID, ItemHash: item.Hash, Decision: "approve"}, "signature_required"},
	}
	for _, c := range cases {
		if f := approverDo(t, b, human(), c.req); f.Type != "denied" || f.Reason != c.reason {
			t.Errorf("%s: %+v, want denied %s", c.name, f, c.reason)
		}
	}
	rejected := logEvents(t, b, "decision_rejected")
	if ev := rejected[len(rejected)-1]; ev["reason"] != "signature_required" || ev["approver_key"] != "" {
		t.Errorf("unsigned rejection event %v", ev)
	}
	if ev := rejected[len(rejected)-5]; ev["reason"] != "approver_key_unknown" || ev["approver_key"] != stranger.fp {
		t.Errorf("unknown key event %v, want approver_key %s", ev, stranger.fp)
	}

	// past the deadline signed in the payload nothing is accepted, not even
	// a valid signature
	setClock(b, 301*time.Second)
	if f := approverDo(t, b, human(), signer.decide(t, item, "approve")); f.Reason != "decision_expired" {
		t.Errorf("after the deadline: %+v, want decision_expired", f)
	}
	setClock(b, 0)

	if n := len(b.queue.list(signatureRule{})); n != 2 {
		t.Fatalf("%d items queued after the rejections, want both still waiting", n)
	}
	select {
	case f := <-done:
		t.Fatalf("requester answered by a rejected decision: %+v", f)
	default:
	}
	// an unsigned deny is accepted even with require_signed_decision
	for _, it := range []proto.QueueItem{item, other} {
		if f := approverDo(t, b, human(), &proto.Request{Type: "decide", ItemID: it.ID, ItemHash: it.Hash, Decision: "deny"}); f.Type != "decided" {
			t.Fatalf("unsigned deny: %+v", f)
		}
	}
	if f := <-done; f.Reason != "approval_denied_by_human" {
		t.Errorf("requester got %+v", f)
	}
	<-otherDone
	if ev := lastEvent(t, b, "approval"); ev["signed"] != false || len(strList(ev["signatures"])) != 0 {
		t.Errorf("unsigned deny recorded as signed: %v", ev)
	}
}

// A signed deny is verified like a signed approve: a deny naming a listed
// key with a signature that does not verify is refused
// (signature_invalid) and never journaled as signed by that key; the item
// keeps waiting. Without the check a forged deny would put the key
// holder's name on a decision they never took.
func TestForgedSignedDenyRefused(t *testing.T) {
	alice, mallory := newFakeSigner(t, "alice"), newFakeSigner(t, "mallory")
	for _, required := range []bool{true, false} {
		b := newSignedBroker(t, required, alice)
		item, done := queueRequest(t, b, testReq(t, "forged-deny"), UIDRequester(4242, 7))
		forged := alice.decide(t, item, "deny")
		forged.Signature = mallory.sign(t, item)
		if f := approverDo(t, b, human(), forged); f.Type != "denied" || f.Reason != "signature_invalid" {
			t.Fatalf("require_signed_decision=%v: forged signed deny: %+v, want denied signature_invalid", required, f)
		}
		if n := len(b.queue.list(signatureRule{})); n != 1 {
			t.Fatalf("require_signed_decision=%v: %d items queued, want the item still waiting", required, n)
		}
		if len(logEvents(t, b, "approval")) != 0 {
			t.Fatalf("require_signed_decision=%v: the forged deny decided the item", required)
		}
		if f := approverDo(t, b, human(), alice.decide(t, item, "deny")); f.Type != "decided" {
			t.Fatalf("genuine signed deny: %+v", f)
		}
		if f := <-done; f.Reason != "approval_denied_by_human" {
			t.Fatalf("requester got %+v", f)
		}
	}
}

// One signature decides one item once: replayed on the decided item it is
// already_decided, replayed on the same request queued again (a new
// challenge) it does not verify.
func TestSignedDecideReplay(t *testing.T) {
	signer := newFakeSigner(t, "mac")
	b := newSignedBroker(t, true, signer)
	req := testReq(t, "signed-replay")
	item, done := queueRequest(t, b, req, UIDRequester(4242, 7))
	first := signer.decide(t, item, "approve")
	if f := approverDo(t, b, human(), first); f.Type != "decided" {
		t.Fatalf("decide: %+v", f)
	}
	<-done
	if f := approverDo(t, b, human(), first); f.Reason != "already_decided" {
		t.Errorf("replay on the decided item: %+v, want already_decided", f)
	}
	again, againDone := queueRequest(t, b, req, UIDRequester(4242, 7))
	if again.ID != item.ID || again.Challenge == item.Challenge {
		t.Fatalf("requeued item %s challenge %s, want the same id with a new challenge", again.ID, again.Challenge)
	}
	if f := approverDo(t, b, human(), first); f.Reason != "signature_invalid" {
		t.Errorf("replay on the requeued item: %+v, want signature_invalid", f)
	}
	if f := approverDo(t, b, human(), signer.decide(t, again, "deny")); f.Type != "decided" {
		t.Fatalf("signed deny: %+v", f)
	}
	if f := <-againDone; f.Reason != "approval_denied_by_human" {
		t.Errorf("requester got %+v", f)
	}
	if ev := lastEvent(t, b, "approval"); ev["signed"] != true || ev["decision"] != "deny" {
		t.Errorf("signed deny event %v", ev)
	}
}

// Without require_signed_decision both kinds are accepted and the journal
// tells them apart; a signed decide is still verified.
func TestUnsignedAndSignedWithoutRequirement(t *testing.T) {
	signer := newFakeSigner(t, "mac")
	b := newSignedBroker(t, false, signer)

	item, done := queueRequest(t, b, testReq(t, "optional-unsigned"), UIDRequester(4242, 7))
	if f := approverDo(t, b, human(), &proto.Request{Type: "decide", ItemID: item.ID, ItemHash: item.Hash, Decision: "approve"}); f.Type != "decided" {
		t.Fatalf("unsigned approve: %+v", f)
	}
	if f := <-done; f.Type != "approved" {
		t.Fatalf("requester got %+v", f)
	}
	unsigned := lastEvent(t, b, "approval")

	item, done = queueRequest(t, b, testReq(t, "optional-signed"), UIDRequester(4242, 7))
	bad := signer.decide(t, item, "approve")
	bad.Signature = signer.signBytes(t, reencode(t, item, func(p *proto.ApprovalPayload) { p.HostID = "elsewhere" }))
	if f := approverDo(t, b, human(), bad); f.Reason != "signature_invalid" {
		t.Errorf("bad signature without the requirement: %+v, want signature_invalid", f)
	}
	if f := approverDo(t, b, human(), signer.decide(t, item, "approve")); f.Type != "decided" {
		t.Fatalf("signed approve: %+v", f)
	}
	if f := <-done; f.Type != "approved" {
		t.Fatalf("requester got %+v", f)
	}
	signed := lastEvent(t, b, "approval")

	if unsigned["signed"] != false || len(strList(unsigned["approver_keys"])) != 0 || unsigned["payload"] == "" || unsigned["short_code"] == "" {
		t.Errorf("unsigned approval event %v", unsigned)
	}
	if signed["signed"] != true || len(strList(signed["approver_keys"])) != 1 {
		t.Errorf("signed approval event %v", signed)
	}
}

// The token never lives longer than the TTL signed in the payload, even
// when a reload raises token_ttl_seconds while the item waits.
func TestTokenTTLCappedBySignedTTL(t *testing.T) {
	signer := newFakeSigner(t, "mac")
	b := newSignedBroker(t, true, signer)
	req := testReq(t, "signed-ttl")
	item, done := queueRequest(t, b, req, UIDRequester(4242, 7))
	b.setTokenTTL(time.Hour)
	if f := approverDo(t, b, human(), signer.decide(t, item, "approve")); f.Type != "decided" {
		t.Fatalf("decide: %+v", f)
	}
	if f := <-done; f.Type != "approved" || f.Detail != "one-shot token, ttl=30s" {
		t.Fatalf("requester got %+v, want the signed 30s TTL", f)
	}
	p, ok := b.peekPending(req.Hash())
	if !ok || time.Until(p.Expiry) > 30*time.Second {
		t.Fatalf("pending approval %v expires in %v, want at most the signed 30s", ok, time.Until(p.Expiry))
	}
}

// The signed token TTL is whole seconds rounded up, never zero; the target
// user is "" for a uid without a passwd entry.
func TestPayloadTerms(t *testing.T) {
	for d, want := range map[time.Duration]int{0: 1, 500 * time.Millisecond: 1, 30 * time.Second: 30, 1500 * time.Millisecond: 2} {
		if got := ttlSeconds(d); got != want {
			t.Errorf("ttlSeconds(%v) = %d, want %d", d, got, want)
		}
	}
	if u := userName(0); u != "root" {
		t.Errorf("userName(0) = %q, want root", u)
	}
	if u := userName(2147483600); u != "" {
		t.Errorf("userName of an unknown uid = %q, want empty", u)
	}
}

// A request whose payload cannot be built is refused before the queue: a
// path that is not UTF-8, or a broker without an identity key.
func TestPayloadUnbuildableRefusedBeforeQueue(t *testing.T) {
	b := newSignedBroker(t, false)
	req := testReq(t, "bad-payload")
	if out := b.queueApproval(req, UIDRequester(4242, 7), req.Executable, "/tmp/\xff", 1, 2, nil); out.reason != "approval_payload_invalid" || out.granted {
		t.Errorf("non-UTF-8 cwd: %+v, want approval_payload_invalid", out)
	}
	b.hostKey = ""
	if f := approveDo(t, b, req, UIDRequester(4242, 7)); f.Reason != "approval_payload_invalid" {
		t.Errorf("no identity key: %+v, want approval_payload_invalid", f)
	}
	if n := len(b.queue.list(signatureRule{})); n != 0 {
		t.Errorf("%d items queued", n)
	}
}

// The process runs with the environment the approver was shown and signed
// (the payload env), not one rebuilt from the config at claim time: a
// SIGHUP that changes fixed_env while the item waits, or between the
// decision and the claim, does not change what runs.
func TestExecEnvIsTheSignedEnv(t *testing.T) {
	envExe, err := filepath.EvalSymlinks("/usr/bin/env")
	if err != nil {
		t.Skipf("no /usr/bin/env: %v", err)
	}
	signer := newFakeSigner(t, "mac")
	dir := t.TempDir()
	path := filepath.Join(dir, "config.json")
	conf := func(mark string) map[string]any {
		return reloadConfig(dir, map[string]any{
			"approver_keys":           []ApproverKey{signer.entry()},
			"require_signed_decision": true,
			"fixed_env":               map[string]string{"PATH": "/usr/bin:/bin", "TMB_MARK": mark},
		})
	}
	writeJSONConfig(t, path, conf("signed"))
	b := reloadBroker(t, path, ModeQueue)
	req := &proto.Request{Executable: envExe, Argv: []string{envExe}, Cwd: "/tmp", Env: map[string]string{"LANG": "C"}, Nonce: "signed-env"}
	item, done := queueRequest(t, b, req, UIDRequester(4242, 7))
	if strings.Join(item.Env, " ") != "LANG=C PATH=/usr/bin:/bin TMB_MARK=signed" {
		t.Fatalf("item env %v", item.Env)
	}

	writeJSONConfig(t, path, conf("reloaded-before-decide"))
	b.Reload(path)
	if f := approverDo(t, b, human(), signer.decide(t, item, "approve")); f.Type != "decided" {
		t.Fatalf("decide: %+v", f)
	}
	if f := <-done; f.Type != "approved" {
		t.Fatalf("requester got %+v", f)
	}
	writeJSONConfig(t, path, conf("reloaded-before-claim"))
	b.Reload(path)

	res := claimStream(t, b, claimOfToken(req, item.ID), UIDRequester(4242, 8))
	if res.exit.Type != "exit" {
		t.Fatalf("claim: %+v", res.exit)
	}
	if got := res.stdout.String(); got != "LANG=C\nPATH=/usr/bin:/bin\nTMB_MARK=signed\n" {
		t.Errorf("the process ran with\n%s\nwant the signed env", got)
	}
}

// claimOfToken is req as a claim with the approval token.
func claimOfToken(req *proto.Request, token string) *proto.Request {
	c := *req
	c.Type = "claim"
	c.ClaimToken = token
	return &c
}
