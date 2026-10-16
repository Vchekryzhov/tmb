package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"tmb-poc/internal/proto"
)

// --- test certificate authority ----------------------------------------------

type testCA struct {
	cert *x509.Certificate
	key  *ecdsa.PrivateKey
}

func newTestCA(t *testing.T) *testCA {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("ecdsa: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "tmb-unit-ca"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, key.Public(), key)
	if err != nil {
		t.Fatalf("ca cert: %v", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("ca parse: %v", err)
	}
	return &testCA{cert: cert, key: key}
}

func writePEM(t *testing.T, path, blockType string, der []byte) string {
	t.Helper()
	f, err := os.Create(path)
	if err != nil {
		t.Fatalf("create %s: %v", path, err)
	}
	defer f.Close()
	if err := pem.Encode(f, &pem.Block{Type: blockType, Bytes: der}); err != nil {
		t.Fatalf("pem %s: %v", path, err)
	}
	return path
}

// issue writes a leaf certificate + key signed by the CA and returns
// (certFile, keyFile, certDER).
func (ca *testCA) issue(t *testing.T, dir, name string, eku []x509.ExtKeyUsage, dnsNames []string) (string, string, []byte) {
	t.Helper()
	return ca.issueWith(t, dir, name, func(c *x509.Certificate) {
		c.ExtKeyUsage = eku
		c.DNSNames = dnsNames
	})
}

// issueWith is issue with full control over the leaf template: edit sees a
// one-hour certificate for name and may change any field.
func (ca *testCA) issueWith(t *testing.T, dir, name string, edit func(*x509.Certificate)) (string, string, []byte) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("ecdsa: %v", err)
	}
	serial, err := rand.Int(rand.Reader, big.NewInt(1<<62))
	if err != nil {
		t.Fatalf("serial: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: name},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}
	edit(tmpl)
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca.cert, key.Public(), ca.key)
	if err != nil {
		t.Fatalf("cert %s: %v", name, err)
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatalf("key %s: %v", name, err)
	}
	certFile := writePEM(t, filepath.Join(dir, name+".crt"), "CERTIFICATE", der)
	keyFile := writePEM(t, filepath.Join(dir, name+".key"), "EC PRIVATE KEY", keyDER)
	return certFile, keyFile, der
}

// --- fingerprint --------------------------------------------------------------

func TestCertFingerprintVector(t *testing.T) {
	// sha256("") known-good vector: the fingerprint is sha256 over the DER.
	if got, want := certFingerprint(nil),
		"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"; got != want {
		t.Errorf("certFingerprint(empty) = %s, want %s", got, want)
	}
}

// --- TLS listener end-to-end over a local 127.0.0.1 listener -------------------

func TestTLSListenerCertIdentity(t *testing.T) {
	dir := t.TempDir()
	ca := newTestCA(t)
	caFile := writePEM(t, filepath.Join(dir, "ca.crt"), "CERTIFICATE", ca.cert.Raw)
	serverCert, serverKey, _ := ca.issue(t, dir, "server",
		[]x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, []string{"localhost"})
	c1Cert, c1Key, c1DER := ca.issue(t, dir, "client1",
		[]x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}, nil)

	// client1's fingerprint is the only allowlisted identity.
	fp1 := certFingerprint(c1DER)
	cfg := &Config{
		AllowedRequesterFPs: []string{fp1},
		AllowedEnvKeys:      []string{"LANG"},
		FixedEnv:            map[string]string{"PATH": "/usr/bin:/bin"},
		AllowedCwdRoots:     []string{"/"},
	}
	log, err := NewLogger(filepath.Join(dir, "broker.log"))
	if err != nil {
		t.Fatalf("logger: %v", err)
	}
	claims, err := NewClaimStore(dir, time.Minute)
	if err != nil {
		t.Fatalf("claim store: %v", err)
	}
	b := NewBroker(cfg, log, claims, ModeMockApprove, 30*time.Second)

	tlsCfg, err := loadTLSConfig(caFile, serverCert, serverKey)
	if err != nil {
		t.Fatalf("loadTLSConfig: %v", err)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	go b.ServeTLS(tls.NewListener(ln, tlsCfg))
	defer ln.Close()
	addr := ln.Addr().String()

	dial := func(certFile, keyFile string) net.Conn {
		pool := x509.NewCertPool()
		pool.AddCert(ca.cert)
		clientCert, err := tls.LoadX509KeyPair(certFile, keyFile)
		if err != nil {
			t.Fatalf("client keypair: %v", err)
		}
		conn, err := tls.Dial("tcp", addr, &tls.Config{
			RootCAs:      pool,
			ServerName:   "localhost",
			Certificates: []tls.Certificate{clientCert},
			MinVersion:   tls.VersionTLS13,
		})
		if err != nil {
			t.Fatalf("tls dial: %v", err)
		}
		return conn
	}

	// 1. allowlisted fingerprint: full exec flow over TLS -> exit 0. The
	// broker derived the identity purely from the certificate, so reaching
	// execution proves the extracted fingerprint equals sha256(DER).
	req := testReq(t, "tls-unit-1")
	req.Type = "exec"
	conn := dial(c1Cert, c1Key)
	if err := proto.WriteFrame(conn, req); err != nil {
		t.Fatalf("write: %v", err)
	}
	term := readTerminalFrame(t, conn)
	if term.Type != "exit" || term.Code == nil || *term.Code != 0 {
		t.Fatalf("allowlisted exec: got %+v, want exit 0", term)
	}
	conn.Close()

	// 2. same CA but NOT allowlisted: denied before any approval with
	// requester_not_allowed.
	c2Cert, c2Key, _ := ca.issue(t, dir, "client2",
		[]x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}, nil)
	conn = dial(c2Cert, c2Key)
	if err := proto.WriteFrame(conn, req); err != nil {
		t.Fatalf("write: %v", err)
	}
	term = readTerminalFrame(t, conn)
	if term.Type != "denied" || term.Reason != "requester_not_allowed" {
		t.Fatalf("non-allowlisted exec: got %+v, want denied requester_not_allowed", term)
	}
	conn.Close()

	// 3. plaintext bytes to the TLS port: handshake fails, broker logs
	// tls_handshake_failed (no fingerprint available at that point).
	raw, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatalf("plain dial: %v", err)
	}
	raw.Write([]byte("PLAINTEXT-NOT-TLS\r\n"))
	raw.Close()
	deadline := time.Now().Add(3 * time.Second)
	var logBytes []byte
	for {
		logBytes, _ = os.ReadFile(filepath.Join(dir, "broker.log"))
		if strings.Contains(string(logBytes), `"event":"tls_handshake_failed"`) {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("tls_handshake_failed never logged; log:\n%s", logBytes)
		}
		time.Sleep(20 * time.Millisecond)
	}

	// 4. identity coverage in JSONL: every connection-phase event carries
	// requester_fp on the same line.
	got := string(logBytes)
	for _, ev := range []string{"request", "approval", "claim", "exec_start", "exec_exit"} {
		if !lineHasBoth(got, `"event":"`+ev+`"`, `"requester_fp":"`+fp1+`"`) {
			t.Errorf("event %s missing requester_fp=%s in log:\n%s", ev, fp1, got)
		}
	}
	if !lineHasBoth(got, `"event":"requester_denied"`, `"requester_fp":"`) {
		t.Errorf("requester_denied event missing requester_fp in log:\n%s", got)
	}
}

func readTerminalFrame(t *testing.T, conn net.Conn) *proto.Frame {
	t.Helper()
	for {
		f, err := proto.ReadFrame(conn)
		if err != nil {
			t.Fatalf("read frame: %v", err)
		}
		if f.Type == "exit" || f.Type == "denied" {
			return f
		}
	}
}

func lineHasBoth(log, a, b string) bool {
	for _, line := range strings.Split(log, "\n") {
		if strings.Contains(line, a) && strings.Contains(line, b) {
			return true
		}
	}
	return false
}
