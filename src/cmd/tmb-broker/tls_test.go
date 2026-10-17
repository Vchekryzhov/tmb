package main

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
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
		ExtKeyUsage:  eku,
		DNSNames:     dnsNames,
	}
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

// The broker's identity of a certificate is the fingerprint the CA prints
// for its key, and it is the same for every certificate on that key.
func TestKeyFingerprintSurvivesReissue(t *testing.T) {
	dir := t.TempDir()
	if err := caInit(dir, caNow); err != nil {
		t.Fatalf("init: %v", err)
	}
	_, pubPEM := newSandboxKey(t)
	fpA, err := issueSandbox(dir, filepath.Join(dir, "a.crt"), pubPEM, "sbx", caNow)
	if err != nil {
		t.Fatalf("issue a: %v", err)
	}
	if _, err := issueSandbox(dir, filepath.Join(dir, "b.crt"), pubPEM, "sbx", caNow.Add(time.Hour)); err != nil {
		t.Fatalf("issue b: %v", err)
	}
	a, b := readCert(t, filepath.Join(dir, "a.crt")), readCert(t, filepath.Join(dir, "b.crt"))
	if bytes.Equal(a.Raw, b.Raw) {
		t.Fatal("the two certificates are identical")
	}
	if keyFingerprint(a) != fpA || keyFingerprint(b) != fpA {
		t.Errorf("fingerprints %s / %s, want the CA's %s for both", keyFingerprint(a), keyFingerprint(b), fpA)
	}
	sum := sha256.Sum256(a.RawSubjectPublicKeyInfo)
	if keyFingerprint(a) != hex.EncodeToString(sum[:]) {
		t.Errorf("fingerprint is not SHA-256 of the SPKI")
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
	c1, err := x509.ParseCertificate(c1DER)
	if err != nil {
		t.Fatalf("parse client1: %v", err)
	}
	fp1 := keyFingerprint(c1)
	cfg := &Config{
		AllowedRequesterKeys: []string{fp1},
		AllowedEnvKeys:       []string{"LANG"},
		FixedEnv:             map[string]string{"PATH": "/usr/bin:/bin"},
		AllowedCwdRoots:      []string{"/"},
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
