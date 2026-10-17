package main

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"net"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"tmb-poc/internal/proto"
)

// policyBroker is a Broker that has only a policy: enough for the checks
// that read the config.
func policyBroker(cfg *Config) *Broker {
	b := &Broker{}
	b.pol.Store(newPolicy(cfg, time.Minute))
	return b
}

// setTokenTTL swaps in a policy with another token TTL (tests only).
func (b *Broker) setTokenTTL(ttl time.Duration) {
	p := *b.pol.Load()
	p.ttl = ttl
	b.pol.Store(&p)
}

// reloadConfig is a valid broker config as JSON fields; tests override some.
func reloadConfig(dir string, over map[string]any) map[string]any {
	c := map[string]any{
		"socket_path":            filepath.Join(dir, "tmb.sock"),
		"approver_socket_path":   filepath.Join(dir, "approve.sock"),
		"state_dir":              filepath.Join(dir, "state"),
		"log_path":               filepath.Join(dir, "broker.log"),
		"pid_file":               filepath.Join(dir, "broker.pid"),
		"allowed_requester_uids": []uint32{4242},
		"allowed_requester_keys": []string{strings.Repeat("aa", 32)},
		"approver_uids":          []uint32{1500},
		"allowed_cwd_roots":      []string{"/"},
		"allowed_env_keys":       []string{"LANG"},
		"fixed_env":              map[string]string{"PATH": "/usr/bin:/bin"},
		"token_ttl_seconds":      60,
	}
	for k, v := range over {
		if v == nil {
			delete(c, k)
		} else {
			c[k] = v
		}
	}
	return c
}

func writeJSONConfig(t *testing.T, path string, c map[string]any) {
	t.Helper()
	raw, err := json.Marshal(c)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}
}

// reloadBroker starts a broker from the config written at path, as main
// does, with its log in dir.
func reloadBroker(t *testing.T, path string, mode string) *Broker {
	t.Helper()
	cfg, err := loadConfig(path)
	if err != nil {
		t.Fatalf("loadConfig: %v", err)
	}
	log, err := NewLogger(cfg.LogPath)
	if err != nil {
		t.Fatalf("logger: %v", err)
	}
	t.Cleanup(log.Close)
	claims, err := NewClaimStore(cfg.StateDir, time.Duration(cfg.TokenTTLSeconds)*time.Second)
	if err != nil {
		t.Fatalf("claim store: %v", err)
	}
	return NewBroker(cfg, log, claims, mode, time.Duration(cfg.TokenTTLSeconds)*time.Second)
}

// logEvents returns the JSONL events of one kind.
func logEvents(t *testing.T, b *Broker, event string) []map[string]any {
	t.Helper()
	var out []map[string]any
	for _, line := range strings.Split(logText(t, b), "\n") {
		if line == "" {
			continue
		}
		var ev map[string]any
		if err := json.Unmarshal([]byte(line), &ev); err != nil {
			t.Fatalf("log line %q: %v", line, err)
		}
		if ev["event"] == event {
			out = append(out, ev)
		}
	}
	return out
}

func strList(v any) []string {
	var out []string
	for _, x := range v.([]any) {
		out = append(out, x.(string))
	}
	return out
}

// A valid reload swaps the allowlists, the approvers and the TTLs and logs
// one reload event that names exactly the changed fields.
func TestReloadValidConfigSwapsPolicy(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.json")
	writeJSONConfig(t, path, reloadConfig(dir, nil))
	b := reloadBroker(t, path, ModeQueue)
	fpA, fpB := strings.Repeat("aa", 32), strings.Repeat("bb", 32)
	if !b.allowedRequester(KeyRequester(fpA)) || b.allowedRequester(KeyRequester(fpB)) {
		t.Fatal("initial allowlist wrong")
	}

	writeJSONConfig(t, path, reloadConfig(dir, map[string]any{
		"allowed_requester_keys": []string{fpB},
		"approver_uids":          []uint32{1600},
		"token_ttl_seconds":      90,
		"approval_wait_seconds":  20,
	}))
	b.Reload(path)

	if b.allowedRequester(KeyRequester(fpA)) || !b.allowedRequester(KeyRequester(fpB)) {
		t.Error("allowlist not swapped")
	}
	if b.allowedApprover(UIDRequester(1500, 1)) || !b.allowedApprover(UIDRequester(1600, 1)) {
		t.Error("approver_uids not swapped")
	}
	if b.tokenTTL() != 90*time.Second || b.approvalWait() != 20*time.Second {
		t.Errorf("ttl %v wait %v, want 90s and 20s", b.tokenTTL(), b.approvalWait())
	}
	evs := logEvents(t, b, "reload")
	if len(evs) != 1 {
		t.Fatalf("%d reload events, want 1", len(evs))
	}
	want := []string{"allowed_requester_keys", "approval_wait_seconds", "approver_uids", "token_ttl_seconds"}
	if got := strList(evs[0]["changed"]); !reflect.DeepEqual(got, want) {
		t.Errorf("changed %v, want %v", got, want)
	}
	if got := evs[0]["ignored"].([]any); len(got) != 0 {
		t.Errorf("ignored %v, want none", got)
	}
}

// An unreadable, unparsable or invalid config changes nothing: the running
// policy object stays and reload_failed carries the reason.
func TestReloadInvalidConfigKeepsRunningPolicy(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.json")
	writeJSONConfig(t, path, reloadConfig(dir, nil))
	b := reloadBroker(t, path, ModeQueue)
	before := b.pol.Load()

	for name, write := range map[string]func(){
		"syntax": func() { os.WriteFile(path, []byte(`{"socket_path": `), 0o600) },
		"old fps": func() {
			writeJSONConfig(t, path, reloadConfig(dir, map[string]any{"allowed_requester_fps": []string{"aa"}}))
		},
		"relative cwd root": func() {
			writeJSONConfig(t, path, reloadConfig(dir, map[string]any{"allowed_cwd_roots": []string{"tmp"}}))
		},
		"missing": func() { os.Remove(path) },
	} {
		write()
		b.Reload(path)
		if b.pol.Load() != before {
			t.Errorf("%s: policy replaced by an invalid config", name)
		}
	}
	fails := logEvents(t, b, "reload_failed")
	if len(fails) != 4 {
		t.Fatalf("%d reload_failed events, want 4", len(fails))
	}
	for _, ev := range fails {
		if ev["error"] == "" || ev["error"] == nil {
			t.Errorf("reload_failed without a reason: %v", ev)
		}
	}
	if len(logEvents(t, b, "reload")) != 0 {
		t.Error("an invalid config logged a reload event")
	}
	if !b.allowedRequester(KeyRequester(strings.Repeat("aa", 32))) {
		t.Error("old allowlist no longer applies")
	}
}

// The startup-only fields are exactly the documented ones; every other
// field of Config is reloadable, which covers the fields the spec names.
func TestReloadFieldClassification(t *testing.T) {
	var startup []string
	for f := range startupOnlyFields {
		startup = append(startup, f)
	}
	sort.Strings(startup)
	want := []string{"approval_default", "approver_socket_path", "log_path", "pid_file", "socket_gid", "socket_path", "state_dir", "tls_addr"}
	if !reflect.DeepEqual(startup, want) {
		t.Errorf("startup-only fields %v, want %v", startup, want)
	}
	all := map[string]bool{}
	ct := reflect.TypeOf(Config{})
	for i := 0; i < ct.NumField(); i++ {
		all[strings.Split(ct.Field(i).Tag.Get("json"), ",")[0]] = true
	}
	for _, f := range startup {
		if !all[f] {
			t.Errorf("startup-only field %s is not a config field", f)
		}
	}
	for _, f := range []string{"allowed_requester_uids", "allowed_requester_keys", "approver_uids", "allowed_cwd_roots",
		"allowed_env_keys", "fixed_env", "shell_deny_list", "token_ttl_seconds", "approval_wait_seconds",
		"tls_ca_file", "tls_cert_file", "tls_key_file"} {
		if !all[f] || startupOnlyFields[f] {
			t.Errorf("%s must be a reloadable config field", f)
		}
	}
}

// Changed startup-only fields are reported one by one and keep their
// running values; the reloadable change in the same file still applies.
func TestReloadIgnoresStartupOnlyFields(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.json")
	writeJSONConfig(t, path, reloadConfig(dir, nil))
	b := reloadBroker(t, path, ModeQueue)
	running := *b.conf()

	writeJSONConfig(t, path, reloadConfig(dir, map[string]any{
		"socket_path":            filepath.Join(dir, "other.sock"),
		"approver_socket_path":   filepath.Join(dir, "other-approve.sock"),
		"socket_gid":             77,
		"state_dir":              filepath.Join(dir, "other-state"),
		"log_path":               filepath.Join(dir, "other.log"),
		"pid_file":               filepath.Join(dir, "other.pid"),
		"approval_default":       ModeMockApprove,
		"allowed_requester_uids": []uint32{4242, 4343},
	}))
	b.Reload(path)

	c := b.conf()
	if c.SocketPath != running.SocketPath || c.ApproverSocketPath != running.ApproverSocketPath || c.SocketGID != running.SocketGID ||
		c.StateDir != running.StateDir || c.LogPath != running.LogPath || c.PidFile != running.PidFile || c.ApprovalDefault != running.ApprovalDefault {
		t.Errorf("startup-only fields changed: %+v", c)
	}
	if !b.allowedRequester(UIDRequester(4343, 1)) {
		t.Error("the reloadable change was not applied")
	}
	var fields []string
	for _, ev := range logEvents(t, b, "reload_ignored_field") {
		fields = append(fields, ev["field"].(string))
		if ev["field"] == "socket_path" && (ev["running"] != running.SocketPath || ev["config"] != filepath.Join(dir, "other.sock")) {
			t.Errorf("socket_path event %v lacks running and config values", ev)
		}
	}
	want := []string{"approval_default", "approver_socket_path", "log_path", "pid_file", "socket_gid", "socket_path", "state_dir"}
	if !reflect.DeepEqual(fields, want) {
		t.Errorf("reload_ignored_field for %v, want %v", fields, want)
	}
	evs := logEvents(t, b, "reload")
	if len(evs) != 1 || !reflect.DeepEqual(strList(evs[0]["changed"]), []string{"allowed_requester_uids"}) ||
		!reflect.DeepEqual(strList(evs[0]["ignored"]), want) {
		t.Errorf("reload events %v", evs)
	}
}

// The -ttl override survives a reload that changes token_ttl_seconds, and a
// longer TTL extends the claim-file retention.
func TestReloadKeepsTTLFlagAndExtendsRetention(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.json")
	writeJSONConfig(t, path, reloadConfig(dir, nil))
	b := reloadBroker(t, path, ModeQueue)
	b.ttlFlag = 3 * time.Second
	writeJSONConfig(t, path, reloadConfig(dir, map[string]any{"token_ttl_seconds": 7200}))
	b.Reload(path)
	if b.tokenTTL() != 3*time.Second {
		t.Errorf("ttl %v, want the -ttl override 3s", b.tokenTTL())
	}
	b.ttlFlag = 0
	b.Reload(path)
	if b.tokenTTL() != 2*time.Hour {
		t.Errorf("ttl %v, want 2h from the config", b.tokenTTL())
	}
	if got := time.Duration(b.claims.retention.Load()); got != 2*time.Hour+ClaimGrace {
		t.Errorf("retention %v, want ttl + grace", got)
	}
}

func TestClaimStoreRetentionOnlyGrows(t *testing.T) {
	s, err := NewClaimStore(t.TempDir(), time.Minute)
	if err != nil {
		t.Fatalf("claim store: %v", err)
	}
	s.ExtendRetention(time.Second)
	if got := time.Duration(s.retention.Load()); got != time.Minute+ClaimGrace {
		t.Errorf("retention shrank to %v", got)
	}
	s.ExtendRetention(time.Hour)
	if got := time.Duration(s.retention.Load()); got != time.Hour+ClaimGrace {
		t.Errorf("retention %v, want 1h + grace", got)
	}
}

// Readers racing reloads see whole snapshots: the allowlist, the approvers
// and the TTL of one config, never a mix (run under -race).
func TestReloadSnapshotIsAtomic(t *testing.T) {
	dir := t.TempDir()
	pathA, pathB := filepath.Join(dir, "a.json"), filepath.Join(dir, "b.json")
	writeJSONConfig(t, pathA, reloadConfig(dir, map[string]any{
		"allowed_requester_uids": []uint32{1}, "approver_uids": []uint32{11}, "token_ttl_seconds": 1,
	}))
	writeJSONConfig(t, pathB, reloadConfig(dir, map[string]any{
		"allowed_requester_uids": []uint32{2}, "approver_uids": []uint32{22}, "token_ttl_seconds": 2,
	}))
	b := reloadBroker(t, pathA, ModeQueue)

	stop := make(chan struct{})
	var wg sync.WaitGroup
	errs := make(chan string, 8)
	for r := 0; r < 4; r++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-stop:
					return
				default:
				}
				p := b.pol.Load()
				u := p.cfg.AllowedRequesterUIDs[0]
				if p.cfg.ApproverUIDs[0] != u*11 || p.ttl != time.Duration(u)*time.Second {
					select {
					case errs <- "mixed snapshot":
					default:
					}
					return
				}
				b.allowedRequester(UIDRequester(u, 1))
			}
		}()
	}
	for i := 0; i < 200; i++ {
		if i%2 == 0 {
			b.Reload(pathB)
		} else {
			b.Reload(pathA)
		}
	}
	close(stop)
	wg.Wait()
	close(errs)
	for e := range errs {
		t.Error(e)
	}
}

// A queued request and a pending approval survive a reload: the queue item
// is decided after it, and the pending approval keeps its expiry.
func TestReloadKeepsQueueAndPending(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.json")
	writeJSONConfig(t, path, reloadConfig(dir, map[string]any{"approver_uids": []uint32{humanUID}}))
	b := reloadBroker(t, path, ModeQueue)
	b.ttlFlag = time.Minute
	req := testReq(t, "reload-queued")
	item, done := queueRequest(t, b, req, UIDRequester(4242, 7))

	writeJSONConfig(t, path, reloadConfig(dir, map[string]any{
		"approver_uids": []uint32{humanUID}, "allowed_requester_uids": []uint32{4343},
	}))
	b.Reload(path)
	if len(logEvents(t, b, "reload")) != 1 {
		t.Fatal("reload not logged")
	}
	if f := approverDo(t, b, UIDRequester(humanUID, 9), &proto.Request{Type: "list"}); f.Type != "queue" || len(f.Items) != 1 || f.Items[0].ID != item.ID {
		t.Fatalf("queue after reload: %+v", f)
	}
	if f := approverDo(t, b, UIDRequester(humanUID, 9), &proto.Request{Type: "decide", ItemID: item.ID, ItemHash: item.Hash, Decision: "approve"}); f.Type != "decided" {
		t.Fatalf("decide after reload: %+v", f)
	}
	if f := <-done; f.Type != "approved" {
		t.Fatalf("requester got %+v, want approved", f)
	}
	p, ok := b.peekPending(req.Hash())
	if !ok || !p.Requester.Equal(UIDRequester(4242, 0)) {
		t.Fatalf("pending approval missing or not bound to uid 4242: %+v", p)
	}
	expiry := p.Expiry
	writeJSONConfig(t, path, reloadConfig(dir, map[string]any{"approver_uids": []uint32{humanUID}, "token_ttl_seconds": 1}))
	b.ttlFlag = 0
	b.Reload(path)
	if p2, ok := b.peekPending(req.Hash()); !ok || p2.Expiry != expiry {
		t.Errorf("pending approval lost or its expiry moved by the reload")
	}
}

// TLS material comes from the snapshot per handshake: after a reload a new
// connection sees the reissued server certificate, a connection made
// before it keeps the old one and still completes a request; broken TLS
// files fail the reload and keep serving the current certificate.
func TestReloadTLSMaterial(t *testing.T) {
	dir := t.TempDir()
	ca := newTestCA(t)
	caFile := writePEM(t, filepath.Join(dir, "ca.crt"), "CERTIFICATE", ca.cert.Raw)
	serverCert, serverKey, derA := ca.issue(t, dir, "server", []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, []string{"localhost"})
	c1Cert, c1Key, c1DER := ca.issue(t, dir, "client1", []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}, nil)
	c1, _ := x509.ParseCertificate(c1DER)
	path := filepath.Join(dir, "config.json")
	writeJSONConfig(t, path, reloadConfig(dir, map[string]any{
		"allowed_requester_keys": []string{keyFingerprint(c1)},
		"tls_addr":               "127.0.0.1:0",
		"tls_ca_file":            caFile, "tls_cert_file": serverCert, "tls_key_file": serverKey,
	}))
	b := reloadBroker(t, path, ModeMockApprove)
	cfg, err := loadTLSConfig(caFile, serverCert, serverKey)
	if err != nil {
		t.Fatalf("loadTLSConfig: %v", err)
	}
	b.tlsCfg.Store(cfg)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()
	go b.ServeTLS(tls.NewListener(ln, b.listenerTLSConfig()))

	pool := x509.NewCertPool()
	pool.AddCert(ca.cert)
	clientCert, err := tls.LoadX509KeyPair(c1Cert, c1Key)
	if err != nil {
		t.Fatalf("client keypair: %v", err)
	}
	dial := func() *tls.Conn {
		conn, err := tls.Dial("tcp", ln.Addr().String(), &tls.Config{
			RootCAs: pool, ServerName: "localhost", Certificates: []tls.Certificate{clientCert}, MinVersion: tls.VersionTLS13,
		})
		if err != nil {
			t.Fatalf("tls dial: %v", err)
		}
		return conn
	}
	serial := func(c *tls.Conn) string { return c.ConnectionState().PeerCertificates[0].SerialNumber.String() }
	certA, _ := x509.ParseCertificate(derA)

	before := dial()
	defer before.Close()
	if serial(before) != certA.SerialNumber.String() {
		t.Fatal("first connection does not see the first certificate")
	}

	_, _, derB := ca.issue(t, dir, "server", []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, []string{"localhost"})
	certB, _ := x509.ParseCertificate(derB)
	b.Reload(path)
	evs := logEvents(t, b, "reload")
	if len(evs) != 1 || !reflect.DeepEqual(strList(evs[0]["changed"]), []string{"tls_material"}) {
		t.Fatalf("reload events %v, want changed [tls_material]", evs)
	}
	after := dial()
	if serial(after) != certB.SerialNumber.String() {
		t.Errorf("new connection sees serial %s, want the reissued %s", serial(after), certB.SerialNumber)
	}
	after.Close()

	req := testReq(t, "reload-tls-old-conn")
	req.Type = "exec"
	if err := proto.WriteFrame(before, req); err != nil {
		t.Fatalf("write: %v", err)
	}
	if term := readTerminalFrame(t, before); term.Type != "exit" || term.Code == nil || *term.Code != 0 {
		t.Fatalf("pre-reload connection: got %+v, want exit 0", term)
	}
	if serial(before) != certA.SerialNumber.String() {
		t.Error("pre-reload connection changed its certificate")
	}

	// A reload between the two renames of ca issue-server sees the new key
	// next to the old certificate: the pair does not match, nothing changes.
	_, otherKey, _ := ca.issue(t, dir, "other", []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, []string{"localhost"})
	if err := os.Rename(otherKey, serverKey); err != nil {
		t.Fatalf("swap key: %v", err)
	}
	b.Reload(path)
	if len(logEvents(t, b, "reload_failed")) != 1 {
		t.Error("a key that does not match the certificate did not fail the reload")
	}
	mixed := dial()
	if serial(mixed) != certB.SerialNumber.String() {
		t.Errorf("after a mismatched pair the listener serves serial %s, want %s", serial(mixed), certB.SerialNumber)
	}
	mixed.Close()

	if err := os.WriteFile(serverKey, []byte("not a key"), 0o600); err != nil {
		t.Fatalf("break key: %v", err)
	}
	b.Reload(path)
	if len(logEvents(t, b, "reload_failed")) != 2 {
		t.Error("broken TLS files did not fail the reload")
	}
	again := dial()
	defer again.Close()
	if serial(again) != certB.SerialNumber.String() {
		t.Errorf("after a failed reload the listener serves serial %s, want %s", serial(again), certB.SerialNumber)
	}

	writeJSONConfig(t, path, reloadConfig(dir, map[string]any{
		"allowed_requester_keys": []string{keyFingerprint(c1)}, "tls_addr": "127.0.0.1:0",
		"tls_ca_file": caFile, "tls_cert_file": serverCert,
	}))
	b.Reload(path)
	if len(logEvents(t, b, "reload_failed")) != 3 {
		t.Error("a TLS listener without tls_key_file did not fail the reload")
	}
}

func TestTLSMaterialChanged(t *testing.T) {
	a := &tls.Config{Certificates: []tls.Certificate{{Certificate: [][]byte{{1}}}}, ClientCAs: x509.NewCertPool()}
	same := &tls.Config{Certificates: []tls.Certificate{{Certificate: [][]byte{{1}}}}, ClientCAs: x509.NewCertPool()}
	for name, c := range map[string]struct {
		cur, next *tls.Config
		want      bool
	}{
		"same":       {a, same, false},
		"nil":        {nil, a, true},
		"both nil":   {nil, nil, false},
		"cert bytes": {a, &tls.Config{Certificates: []tls.Certificate{{Certificate: [][]byte{{2}}}}, ClientCAs: x509.NewCertPool()}, true},
		"chain len":  {a, &tls.Config{Certificates: []tls.Certificate{{Certificate: [][]byte{{1}, {3}}}}, ClientCAs: x509.NewCertPool()}, true},
		"cert count": {a, &tls.Config{ClientCAs: x509.NewCertPool()}, true},
		"client CAs": {a, &tls.Config{Certificates: a.Certificates, ClientCAs: nil}, true},
	} {
		if got := tlsMaterialChanged(c.cur, c.next); got != c.want {
			t.Errorf("%s: %v, want %v", name, got, c.want)
		}
	}
	if fieldValue(&Config{}, "no_such_field") != nil {
		t.Error("fieldValue of an unknown field")
	}
}
