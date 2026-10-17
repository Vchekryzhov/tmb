package main

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

var caNow = time.Date(2026, 10, 17, 0, 0, 0, 0, time.UTC)

func readCert(t *testing.T, path string) *x509.Certificate {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	block, _ := pem.Decode(b)
	if block == nil || block.Type != "CERTIFICATE" {
		t.Fatalf("%s: no PEM CERTIFICATE", path)
	}
	c, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatalf("parse %s: %v", path, err)
	}
	return c
}

func mode(t *testing.T, path string) os.FileMode {
	t.Helper()
	st, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat %s: %v", path, err)
	}
	return st.Mode().Perm()
}

func runCACmd(t *testing.T, stdin string, args ...string) (int, string, string) {
	t.Helper()
	var out, errb bytes.Buffer
	code := runCA(args, strings.NewReader(stdin), &out, &errb)
	return code, out.String(), errb.String()
}

func newSandboxKey(t *testing.T) (*ecdsa.PrivateKey, []byte) {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("key: %v", err)
	}
	der, err := x509.MarshalPKIXPublicKey(&k.PublicKey)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	return k, pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der})
}

func TestCAInit(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "ca")
	if err := caInit(dir, caNow); err != nil {
		t.Fatalf("init: %v", err)
	}
	if m := mode(t, filepath.Join(dir, "ca.key")); m != 0o600 {
		t.Errorf("ca.key mode %o, want 600", m)
	}
	c := readCert(t, filepath.Join(dir, "ca.crt"))
	if !c.IsCA || !c.BasicConstraintsValid || c.MaxPathLen != 0 || !c.MaxPathLenZero {
		t.Errorf("CA constraints: IsCA=%v valid=%v maxPathLen=%d zero=%v, want CA:TRUE pathlen 0", c.IsCA, c.BasicConstraintsValid, c.MaxPathLen, c.MaxPathLenZero)
	}
	if got := c.NotAfter.Sub(c.NotBefore); got != caValidity || !c.NotBefore.Equal(caNow) {
		t.Errorf("validity %v from %v, want 10 years from %v", got, c.NotBefore, caNow)
	}
	if c.KeyUsage&x509.KeyUsageCertSign == 0 {
		t.Errorf("CA lacks keyCertSign")
	}
	if _, ok := c.PublicKey.(*ecdsa.PublicKey); !ok {
		t.Errorf("CA key %T, want ECDSA", c.PublicKey)
	}
	if err := c.CheckSignatureFrom(c); err != nil {
		t.Errorf("not self-signed: %v", err)
	}
	if err := caInit(dir, caNow); err == nil || !strings.Contains(err.Error(), "refusing") {
		t.Errorf("second init = %v, want refusal to replace the key", err)
	}
}

func TestCAIssueServer(t *testing.T) {
	dir := t.TempDir()
	if err := caInit(dir, caNow); err != nil {
		t.Fatalf("init: %v", err)
	}
	out := filepath.Join(dir, "srv")
	crt, key, err := issueServer(dir, out, []string{"host.openshell.internal"}, []net.IP{net.ParseIP("192.0.2.7")}, caNow)
	if err != nil {
		t.Fatalf("issue-server: %v", err)
	}
	if m := mode(t, key); m != 0o600 {
		t.Errorf("server.key mode %o, want 600", m)
	}
	c := readCert(t, crt)
	if got := c.NotAfter.Sub(c.NotBefore); got != serverValidity {
		t.Errorf("validity %v, want 1 year", got)
	}
	if len(c.ExtKeyUsage) != 1 || c.ExtKeyUsage[0] != x509.ExtKeyUsageServerAuth || c.IsCA {
		t.Errorf("EKU %v IsCA %v, want ServerAuth only, not a CA", c.ExtKeyUsage, c.IsCA)
	}
	if len(c.DNSNames) != 1 || c.DNSNames[0] != "host.openshell.internal" || len(c.IPAddresses) != 1 || !c.IPAddresses[0].Equal(net.ParseIP("192.0.2.7")) {
		t.Errorf("SAN dns=%v ip=%v", c.DNSNames, c.IPAddresses)
	}
	ca := readCert(t, filepath.Join(dir, "ca.crt"))
	pool := x509.NewCertPool()
	pool.AddCert(ca)
	if _, err := c.Verify(x509.VerifyOptions{Roots: pool, DNSName: "host.openshell.internal", CurrentTime: caNow.Add(time.Hour)}); err != nil {
		t.Errorf("server cert does not verify for its name: %v", err)
	}
	if _, err := tls.LoadX509KeyPair(crt, key); err != nil {
		t.Errorf("server pair does not load: %v", err)
	}
}

func TestCAIssueSandboxSameKeySameFingerprint(t *testing.T) {
	dir := t.TempDir()
	if err := caInit(dir, caNow); err != nil {
		t.Fatalf("init: %v", err)
	}
	key, pubPEM := newSandboxKey(t)
	fp1, err := issueSandbox(dir, filepath.Join(dir, "a.crt"), pubPEM, "sbx", caNow)
	if err != nil {
		t.Fatalf("issue 1: %v", err)
	}
	fp2, err := issueSandbox(dir, filepath.Join(dir, "b.crt"), pubPEM, "sbx", caNow.Add(time.Hour))
	if err != nil {
		t.Fatalf("issue 2: %v", err)
	}
	_, otherPEM := newSandboxKey(t)
	fp3, err := issueSandbox(dir, filepath.Join(dir, "c.crt"), otherPEM, "sbx", caNow)
	if err != nil {
		t.Fatalf("issue 3: %v", err)
	}
	if fp1 != fp2 || len(fp1) != 64 {
		t.Errorf("same key: fingerprints %s and %s, want equal 64-hex", fp1, fp2)
	}
	if fp3 == fp1 {
		t.Errorf("different keys share fingerprint %s", fp1)
	}
	want, _ := spkiFingerprint(&key.PublicKey)
	if fp1 != want {
		t.Errorf("fingerprint %s, want SPKI SHA-256 %s", fp1, want)
	}
	a, b := readCert(t, filepath.Join(dir, "a.crt")), readCert(t, filepath.Join(dir, "b.crt"))
	if a.SerialNumber.Cmp(b.SerialNumber) == 0 {
		t.Errorf("two certificates share serial %v", a.SerialNumber)
	}
	if a.SerialNumber.BitLen() != 128 {
		t.Errorf("serial %d bits, want a random 128-bit number", a.SerialNumber.BitLen())
	}
	if got := a.NotAfter.Sub(a.NotBefore); got != sandboxValidity {
		t.Errorf("validity %v, want 7 days", got)
	}
	if len(a.ExtKeyUsage) != 1 || a.ExtKeyUsage[0] != x509.ExtKeyUsageClientAuth || a.IsCA {
		t.Errorf("EKU %v IsCA %v, want ClientAuth only", a.ExtKeyUsage, a.IsCA)
	}
	if a.Subject.CommonName != "sbx" {
		t.Errorf("subject %q, want CN sbx", a.Subject.CommonName)
	}
	ca := readCert(t, filepath.Join(dir, "ca.crt"))
	pool := x509.NewCertPool()
	pool.AddCert(ca)
	if _, err := a.Verify(x509.VerifyOptions{Roots: pool, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}, CurrentTime: caNow.Add(time.Hour)}); err != nil {
		t.Errorf("sandbox cert does not verify as client: %v", err)
	}
	if _, err := a.Verify(x509.VerifyOptions{Roots: pool, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}, CurrentTime: caNow.Add(8 * 24 * time.Hour)}); err == nil {
		t.Errorf("sandbox cert still valid after 8 days")
	}
}

func TestCAIssueSandboxFromCSR(t *testing.T) {
	dir := t.TempDir()
	if err := caInit(dir, caNow); err != nil {
		t.Fatalf("init: %v", err)
	}
	key, pubPEM := newSandboxKey(t)
	der, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{Subject: pkix.Name{CommonName: "ignored"}}, key)
	if err != nil {
		t.Fatalf("csr: %v", err)
	}
	csrPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der})
	fpCSR, err := issueSandbox(dir, filepath.Join(dir, "csr.crt"), csrPEM, "sbx", caNow)
	if err != nil {
		t.Fatalf("issue from CSR: %v", err)
	}
	fpKey, err := issueSandbox(dir, filepath.Join(dir, "key.crt"), pubPEM, "sbx", caNow)
	if err != nil {
		t.Fatalf("issue from key: %v", err)
	}
	if fpCSR != fpKey {
		t.Errorf("CSR and public key of one key give %s and %s", fpCSR, fpKey)
	}
	// a CSR whose signature does not verify is refused
	bad := append([]byte(nil), der...)
	bad[len(bad)-1] ^= 0xff
	if _, err := issueSandbox(dir, filepath.Join(dir, "bad.crt"), pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: bad}), "sbx", caNow); err == nil {
		t.Errorf("CSR with a broken signature accepted")
	}
	for _, in := range [][]byte{nil, []byte("junk"), pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: []byte{1}}), pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: []byte{1}}), pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: []byte{1}})} {
		if _, err := issueSandbox(dir, filepath.Join(dir, "x.crt"), in, "sbx", caNow); err == nil {
			t.Errorf("input %q accepted", in)
		}
	}
}

func TestCACommandLine(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "ca")
	if code, out, errs := runCACmd(t, "", "init", "--dir", dir); code != 0 || !strings.Contains(out, "ca.key") {
		t.Fatalf("init: code %d out %q err %q", code, out, errs)
	}
	if code, out, errs := runCACmd(t, "", "issue-server", "--dir", dir, "--dns", "host.openshell.internal", "--ip", "127.0.0.1"); code != 0 || !strings.Contains(out, filepath.Join(dir, "server.crt")) {
		t.Fatalf("issue-server: code %d out %q err %q", code, out, errs)
	}
	_, pubPEM := newSandboxKey(t)
	code, out, errs := runCACmd(t, string(pubPEM), "issue-sandbox", "--dir", dir, "--in", "-", "--name", "sbx1")
	if code != 0 || !strings.Contains(out, "fingerprint: ") || !strings.Contains(out, filepath.Join(dir, "sandbox-sbx1.crt")) {
		t.Fatalf("issue-sandbox: code %d out %q err %q", code, out, errs)
	}
	pubFile := filepath.Join(dir, "sbx.pub")
	if err := os.WriteFile(pubFile, pubPEM, 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	if code, out2, _ := runCACmd(t, "", "issue-sandbox", "--dir", dir, "--in", pubFile, "--name", "sbx1", "--out", filepath.Join(dir, "again.crt")); code != 0 || strings.Split(out2, "\n")[0] != strings.Split(out, "\n")[0] {
		t.Fatalf("reissue on the same key: code %d, fingerprint lines %q vs %q", code, out2, out)
	}
	// --config derives the default CA dir
	cfgDir := t.TempDir()
	if code, _, errs := runCACmd(t, "", "init", "--config", filepath.Join(cfgDir, "config.json")); code != 0 {
		t.Fatalf("init via --config: code %d err %q", code, errs)
	}
	if _, err := os.Stat(filepath.Join(cfgDir, "ca", "ca.crt")); err != nil {
		t.Errorf("default CA dir not under the config dir: %v", err)
	}
	for _, tc := range []struct {
		args []string
		code int
	}{
		{nil, 2},
		{[]string{"rotate"}, 2},
		{[]string{"init", "--bogus"}, 2},
		{[]string{"init", "extra"}, 2},
		{[]string{"issue-server", "--dir", dir}, 2},
		{[]string{"issue-server", "--dir", dir, "--dns", "x", "--ip", "nope"}, 2},
		{[]string{"issue-sandbox", "--dir", dir, "--name", "x"}, 2},
		{[]string{"issue-sandbox", "--dir", dir, "--name", "x", "--in", filepath.Join(dir, "missing.pub")}, 1},
		{[]string{"issue-server", "--dir", t.TempDir(), "--dns", "x"}, 1},
		{[]string{"issue-sandbox", "--dir", t.TempDir(), "--name", "x", "--in", pubFile}, 1},
	} {
		if code, _, _ := runCACmd(t, "", tc.args...); code != tc.code {
			t.Errorf("ca %q: exit %d, want %d", tc.args, code, tc.code)
		}
	}
}

func TestLoadCARejectsBadFiles(t *testing.T) {
	dir := t.TempDir()
	write := func(name, body string) {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o600); err != nil {
			t.Fatalf("write: %v", err)
		}
	}
	write("ca.crt", "junk")
	if _, _, err := loadCA(dir); err == nil {
		t.Errorf("junk ca.crt accepted")
	}
	write("ca.crt", string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: []byte{1}})))
	if _, _, err := loadCA(dir); err == nil {
		t.Errorf("unparsable ca.crt accepted")
	}
	good := t.TempDir()
	if err := caInit(good, caNow); err != nil {
		t.Fatalf("init: %v", err)
	}
	crt, _ := os.ReadFile(filepath.Join(good, "ca.crt"))
	write("ca.crt", string(crt))
	if _, _, err := loadCA(dir); err == nil {
		t.Errorf("missing ca.key accepted")
	}
	write("ca.key", "junk")
	if _, _, err := loadCA(dir); err == nil {
		t.Errorf("junk ca.key accepted")
	}
	write("ca.key", string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: []byte{1}})))
	if _, _, err := loadCA(dir); err == nil {
		t.Errorf("unparsable ca.key accepted")
	}
}

// Output that cannot be written fails the command instead of leaving a CA
// or certificate half made.
func TestCAWriteFailures(t *testing.T) {
	base := t.TempDir()
	file := filepath.Join(base, "file")
	if err := os.WriteFile(file, nil, 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	if err := caInit(filepath.Join(file, "ca"), caNow); err == nil {
		t.Errorf("init under a regular file succeeded")
	}
	dir := filepath.Join(base, "ca")
	if err := caInit(dir, caNow); err != nil {
		t.Fatalf("init: %v", err)
	}
	if _, _, err := issueServer(dir, filepath.Join(file, "out"), []string{"x"}, nil, caNow); err == nil {
		t.Errorf("issue-server into a path under a regular file succeeded")
	}
	_, pubPEM := newSandboxKey(t)
	if _, err := issueSandbox(dir, filepath.Join(file, "x.crt"), pubPEM, "sbx", caNow); err == nil {
		t.Errorf("issue-sandbox into a path under a regular file succeeded")
	}
	// ca.crt that cannot be written: init fails and takes the new key
	// back, so the CA is not left as a key without a certificate.
	half := filepath.Join(base, "half")
	if err := os.MkdirAll(filepath.Join(half, "ca.crt"), 0o700); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := caInit(half, caNow); err == nil {
		t.Errorf("init with an unwritable ca.crt succeeded")
	}
	if _, err := os.Stat(filepath.Join(half, "ca.key")); !os.IsNotExist(err) {
		t.Errorf("ca.key left behind after a failed init: %v", err)
	}
	if err := os.Remove(filepath.Join(half, "ca.crt")); err != nil {
		t.Fatalf("remove: %v", err)
	}
	if err := caInit(half, caNow); err != nil {
		t.Errorf("init after a failed init: %v", err)
	}
	if os.Geteuid() == 0 {
		return // root writes into read-only directories
	}
	ro := filepath.Join(base, "ro")
	if err := os.Mkdir(ro, 0o500); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := caInit(ro, caNow); err == nil {
		t.Errorf("init into a read-only directory succeeded")
	}
	if _, _, err := issueServer(dir, ro, []string{"x"}, nil, caNow); err == nil {
		t.Errorf("issue-server into a read-only directory succeeded")
	}
}

// --not-before backdates a sandbox certificate: one issued 30 days ago has
// already expired, as harness N30 needs.
func TestCAIssueSandboxNotBefore(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "ca")
	if code, _, errs := runCACmd(t, "", "init", "--dir", dir); code != 0 {
		t.Fatalf("init: %d %s", code, errs)
	}
	_, pubPEM := newSandboxKey(t)
	from := time.Now().Add(-30 * 24 * time.Hour).UTC().Format(time.RFC3339)
	out := filepath.Join(dir, "old.crt")
	if code, _, errs := runCACmd(t, string(pubPEM), "issue-sandbox", "--dir", dir, "--in", "-", "--name", "old", "--out", out, "--not-before", from); code != 0 {
		t.Fatalf("issue: %d %s", code, errs)
	}
	if c := readCert(t, out); !c.NotAfter.Before(time.Now()) {
		t.Errorf("backdated certificate valid until %v, want expired", c.NotAfter)
	}
	if code, _, _ := runCACmd(t, string(pubPEM), "issue-sandbox", "--dir", dir, "--in", "-", "--name", "x", "--not-before", "yesterday"); code != 2 {
		t.Errorf("bad --not-before: exit %d, want 2", code)
	}
}
