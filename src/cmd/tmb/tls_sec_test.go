package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// serverCert returns a broker certificate signed by ca, with edit applied
// to a valid one-hour template.
func serverCert(t *testing.T, ca *x509.Certificate, caKey *ecdsa.PrivateKey, edit func(*x509.Certificate)) tls.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: "broker"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     []string{"localhost"},
	}
	edit(tmpl)
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca, key.Public(), caKey)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
}

// testAuthority is a CA the client trusts, written as a PEM file.
func testAuthority(t *testing.T, dir string) (*x509.Certificate, *ecdsa.PrivateKey, string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "tmb-client-trusted-ca"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, key.Public(), key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "trusted-ca.crt")
	if err := os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o600); err != nil {
		t.Fatal(err)
	}
	return cert, key, path
}

// tlsServer accepts TLS connections with cfg and completes handshakes.
func tlsServer(t *testing.T, cfg *tls.Config) string {
	t.Helper()
	ln, err := tls.Listen("tcp", "127.0.0.1:0", cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() { defer c.Close(); var b [1]byte; _, _ = c.Read(b[:]) }()
		}
	}()
	return ln.Addr().String()
}

// SEC-06: the client refuses a broker whose certificate does not name the
// dialled host, has expired, or that only speaks TLS 1.2. Each is a
// transport error (exit 3, FAIL CLOSED), never a usable connection.
func TestDialTLSRejectsBadBrokerEndpoint(t *testing.T) {
	dir := t.TempDir()
	ca, caKey, caFile := testAuthority(t, dir)
	_, certFile, keyFile := genTestCerts(t, dir)
	cases := []struct {
		name string
		srv  *tls.Config
		host string // dialled host name
		want string // in the error
	}{
		{"wrong SAN", &tls.Config{MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{
			serverCert(t, ca, caKey, func(c *x509.Certificate) { c.DNSNames = []string{"other.example"} })}},
			"localhost", "x509"},
		{"expired", &tls.Config{MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{
			serverCert(t, ca, caKey, func(c *x509.Certificate) {
				c.NotBefore, c.NotAfter = time.Now().Add(-48*time.Hour), time.Now().Add(-24*time.Hour)
			})}},
			"localhost", "expired"},
		{"TLS 1.2 only", &tls.Config{MinVersion: tls.VersionTLS12, MaxVersion: tls.VersionTLS12, Certificates: []tls.Certificate{
			serverCert(t, ca, caKey, func(*x509.Certificate) {})}},
			"localhost", "version"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, port, _ := net.SplitHostPort(tlsServer(t, c.srv))
			conn, err := dialTLS(net.JoinHostPort(c.host, port), caFile, certFile, keyFile)
			if err == nil {
				conn.Close()
				t.Fatal("dialTLS accepted the broker")
			}
			var te *transportErr
			if !errors.As(err, &te) || exitCodeFor(err) != 3 {
				t.Fatalf("error %v is not a transport error (exit 3)", err)
			}
			if !strings.Contains(err.Error(), c.want) || !strings.Contains(err.Error(), "FAIL CLOSED") {
				t.Fatalf("error %q, want it to mention %q and FAIL CLOSED", err, c.want)
			}
		})
	}

	// control: the same CA, host and TLS 1.3 connect fine
	_, port, _ := net.SplitHostPort(tlsServer(t, &tls.Config{MinVersion: tls.VersionTLS13,
		Certificates: []tls.Certificate{serverCert(t, ca, caKey, func(*x509.Certificate) {})}}))
	conn, err := dialTLS(net.JoinHostPort("localhost", port), caFile, certFile, keyFile)
	if err != nil {
		t.Fatalf("valid broker: %v", err)
	}
	conn.Close()
}
