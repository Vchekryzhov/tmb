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
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// --- test material ------------------------------------------------------------

func genTestCerts(t *testing.T, dir string) (caFile, certFile, keyFile string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("ecdsa: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "tmb-client-unit-ca"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, key.Public(), key)
	if err != nil {
		t.Fatalf("ca cert: %v", err)
	}
	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("ecdsa: %v", err)
	}
	leafTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: "tmb-client"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	leafDER, err := x509.CreateCertificate(rand.Reader, leafTmpl, tmpl, leafKey.Public(), key)
	if err != nil {
		t.Fatalf("leaf cert: %v", err)
	}
	leafKeyDER, err := x509.MarshalECPrivateKey(leafKey)
	if err != nil {
		t.Fatalf("leaf key: %v", err)
	}
	write := func(name, blockType string, der []byte) string {
		p := filepath.Join(dir, name)
		f, err := os.Create(p)
		if err != nil {
			t.Fatalf("create %s: %v", p, err)
		}
		defer f.Close()
		if err := pem.Encode(f, &pem.Block{Type: blockType, Bytes: der}); err != nil {
			t.Fatalf("pem %s: %v", p, err)
		}
		return p
	}
	return write("ca.crt", "CERTIFICATE", caDER),
		write("client.crt", "CERTIFICATE", leafDER),
		write("client.key", "EC PRIVATE KEY", leafKeyDER)
}

// --- endpoint selection / env validation ----------------------------------------

func TestDialEndpointRequiresCertMaterial(t *testing.T) {
	cases := []struct {
		name         string
		ep           endpoint
		wantInErr    string
		wantExitCode int
	}{
		{"no cert, no key", endpoint{}, "no connection attempted", 2},
		{"cert but no key", endpoint{cert: "/tmp/client.crt"}, "no connection attempted", 2},
		{"key but no cert", endpoint{key: "/tmp/client.key"}, "no connection attempted", 2},
		{"no CA", endpoint{cert: "/tmp/client.crt", key: "/tmp/client.key"}, "no connection attempted", 2},
		{"flag addr without flag cert", endpoint{addr: "h:1"}, "no connection attempted", 2},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv("TMB_ADDR", "host.openshell.internal:7600")
			t.Setenv("TMB_CA", "/tmp/ca.crt")
			t.Setenv("TMB_CERT", "")
			t.Setenv("TMB_KEY", "")
			if tc.name == "no CA" {
				t.Setenv("TMB_CA", "")
			}
			conn, err := dialEndpoint(tc.ep)
			if err == nil {
				conn.Close()
				t.Fatalf("dialEndpoint: want error, got connection")
			}
			if !strings.Contains(err.Error(), tc.wantInErr) {
				t.Errorf("error = %q, want it to contain %q", err, tc.wantInErr)
			}
			var te *transportErr
			if errors.As(err, &te) {
				t.Errorf("missing-cert material must be a usage error (exit 2), not transport (exit 3): %v", err)
			}
			if code := exitCodeFor(err); code != tc.wantExitCode {
				t.Errorf("exitCodeFor = %d, want %d", code, tc.wantExitCode)
			}
		})
	}
}

// --- tlsClientConfig --------------------------------------------------------------

func TestTLSClientConfigValidation(t *testing.T) {
	dir := t.TempDir()
	caFile, certFile, keyFile := genTestCerts(t, dir)

	if _, err := tlsClientConfig("host.openshell.internal:7600", filepath.Join(dir, "missing.crt"), certFile, keyFile); err == nil {
		t.Error("missing CA file must fail")
	}
	garbage := filepath.Join(dir, "garbage.crt")
	os.WriteFile(garbage, []byte("not a pem"), 0o600)
	if _, err := tlsClientConfig("h:1", garbage, certFile, keyFile); err == nil || !strings.Contains(err.Error(), "no certificates parsed") {
		t.Errorf("garbage CA: err = %v, want 'no certificates parsed'", err)
	}
	if _, err := tlsClientConfig("host.openshell.internal", caFile, certFile, keyFile); err == nil {
		t.Error("address without port must fail")
	}
	if _, err := tlsClientConfig("h:1", caFile, filepath.Join(dir, "missing.crt"), keyFile); err == nil {
		t.Error("missing client cert must fail")
	}

	cfg, err := tlsClientConfig("host.openshell.internal:7600", caFile, certFile, keyFile)
	if err != nil {
		t.Fatalf("valid config: %v", err)
	}
	if cfg.ServerName != "host.openshell.internal" {
		t.Errorf("ServerName = %q", cfg.ServerName)
	}
	if cfg.RootCAs == nil {
		t.Error("RootCAs must be set (no system-root fallback)")
	}
	if len(cfg.Certificates) != 1 {
		t.Errorf("client certificate not loaded: %d", len(cfg.Certificates))
	}
	if cfg.MinVersion != tls.VersionTLS13 {
		t.Errorf("MinVersion = %x, want TLS 1.3", cfg.MinVersion)
	}
	if cfg.InsecureSkipVerify {
		t.Error("InsecureSkipVerify must never be set")
	}
}

// --- transport failure mapping ------------------------------------------------------

func TestDialTLSRefusedIsTransportErr(t *testing.T) {
	dir := t.TempDir()
	caFile, certFile, keyFile := genTestCerts(t, dir)
	_, err := dialTLS("127.0.0.1:1", caFile, certFile, keyFile)
	if err == nil {
		t.Fatal("want error")
	}
	var te *transportErr
	if !errors.As(err, &te) {
		t.Fatalf("refused connection must be transportErr (exit 3): %v", err)
	}
	if !strings.Contains(err.Error(), "FAIL CLOSED") {
		t.Errorf("error must carry the FAIL CLOSED marker: %v", err)
	}
	if code := exitCodeFor(err); code != 3 {
		t.Errorf("exitCodeFor = %d, want 3", code)
	}
}

// TestDialTLSWrongCAIsTransportErrWithX509Reason proves the client verifies
// the broker chain: a server certified by a DIFFERENT CA fails the handshake
// with an x509 reason (exit 3), never a silent connection.
func TestDialTLSWrongCAIsTransportErrWithX509Reason(t *testing.T) {
	dir := t.TempDir()

	// unrelated server CA + server cert with a SAN
	srvCA := x509.NewCertPool()
	srvKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("ecdsa: %v", err)
	}
	caTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(9),
		Subject:               pkix.Name{CommonName: "other-ca"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, srvKey.Public(), srvKey)
	if err != nil {
		t.Fatalf("ca: %v", err)
	}
	srvCAcert, _ := x509.ParseCertificate(caDER)
	srvCA.AddCert(srvCAcert)
	srvTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(10),
		Subject:      pkix.Name{CommonName: "localhost"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     []string{"localhost"},
	}
	srvDER, err := x509.CreateCertificate(rand.Reader, srvTmpl, caTmpl, srvKey.Public(), srvKey)
	if err != nil {
		t.Fatalf("server cert: %v", err)
	}
	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{
		Certificates: []tls.Certificate{{Certificate: [][]byte{srvDER}, PrivateKey: srvKey}},
		MinVersion:   tls.VersionTLS13,
	})
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	// drive handshakes so the server actually presents its (foreign) cert
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() { defer c.Close(); var buf [1]byte; _, _ = c.Read(buf[:]) }()
		}
	}()
	defer ln.Close()

	caFile, certFile, keyFile := genTestCerts(t, dir) // client trusts only ITS OWN CA
	_, err = dialTLS(ln.Addr().String(), caFile, certFile, keyFile)
	if err == nil {
		t.Fatal("want handshake failure against a server from another CA")
	}
	var te *transportErr
	if !errors.As(err, &te) {
		t.Fatalf("verification failure must be transportErr (exit 3): %v", err)
	}
	if !strings.Contains(err.Error(), "x509") {
		t.Errorf("error must surface the x509 verification reason: %v", err)
	}
}

// tmb debug routes to the requester protocol steps; each one fails on its
// own input checks here, before any connection is attempted.
func TestDebugDispatchesProtocolSteps(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "missing.json")
	for _, tc := range []struct {
		args []string
		want string
	}{
		{[]string{"approve", "--json", missing}, "missing.json"},
		{[]string{"claim", "--json", missing}, "--token is required"},
		{[]string{"raw", "--json", missing}, "missing.json"},
	} {
		err := cmdDebug(tc.args)
		if err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("cmdDebug(%q) = %v, want error containing %q", tc.args, err, tc.want)
		}
	}
}
