package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"io"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// With TMB_DEBUG set, a TLS dial prints the serial of the broker
// certificate it was handshaken with (the N27 reload scenario reads it).
func TestDialTLSDebugPrintsBrokerSerial(t *testing.T) {
	dir := t.TempDir()
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("ecdsa: %v", err)
	}
	caTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "unit-ca"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		IsCA: true, KeyUsage: x509.KeyUsageCertSign, BasicConstraintsValid: true,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, caKey.Public(), caKey)
	if err != nil {
		t.Fatalf("ca: %v", err)
	}
	leaf := func(serial int64, cn string, eku x509.ExtKeyUsage) ([]byte, *ecdsa.PrivateKey) {
		k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatalf("ecdsa: %v", err)
		}
		der, err := x509.CreateCertificate(rand.Reader, &x509.Certificate{
			SerialNumber: big.NewInt(serial), Subject: pkix.Name{CommonName: cn},
			NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
			KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{eku}, DNSNames: []string{"localhost"},
		}, caTmpl, k.Public(), caKey)
		if err != nil {
			t.Fatalf("leaf: %v", err)
		}
		return der, k
	}
	srvDER, srvKey := leaf(0xABCDEF, "tmb-broker", x509.ExtKeyUsageServerAuth)
	cliDER, cliKey := leaf(7, "sbx", x509.ExtKeyUsageClientAuth)
	write := func(name, typ string, der []byte) string {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, pem.EncodeToMemory(&pem.Block{Type: typ, Bytes: der}), 0o600); err != nil {
			t.Fatalf("write: %v", err)
		}
		return p
	}
	cliKeyDER, err := x509.MarshalECPrivateKey(cliKey)
	if err != nil {
		t.Fatalf("client key: %v", err)
	}
	caFile := write("ca.crt", "CERTIFICATE", caDER)
	certFile := write("c.crt", "CERTIFICATE", cliDER)
	keyFile := write("c.key", "EC PRIVATE KEY", cliKeyDER)
	caCert, err := x509.ParseCertificate(caDER)
	if err != nil {
		t.Fatalf("parse ca: %v", err)
	}
	pool := x509.NewCertPool()
	pool.AddCert(caCert)
	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{
		Certificates: []tls.Certificate{{Certificate: [][]byte{srvDER}, PrivateKey: srvKey}},
		ClientAuth:   tls.RequireAndVerifyClientCert, ClientCAs: pool, MinVersion: tls.VersionTLS13,
	})
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()
	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		_ = c.(*tls.Conn).Handshake()
		var buf [1]byte
		_, _ = c.Read(buf[:])
	}()

	errFile, err := os.CreateTemp(dir, "stderr")
	if err != nil {
		t.Fatalf("stderr file: %v", err)
	}
	stderr := os.Stderr
	os.Stderr = errFile
	t.Cleanup(func() { os.Stderr = stderr })
	t.Setenv("TMB_DEBUG", "1")
	_, port, _ := strings.Cut(ln.Addr().String(), ":")
	conn, err := dialTLS("localhost:"+port, caFile, certFile, keyFile)
	os.Stderr = stderr
	if err != nil {
		t.Fatalf("dialTLS: %v", err)
	}
	conn.Close()
	defer errFile.Close()
	if _, err := errFile.Seek(0, io.SeekStart); err != nil {
		t.Fatalf("rewind stderr: %v", err)
	}
	got, err := io.ReadAll(errFile)
	if err != nil {
		t.Fatalf("read stderr: %v", err)
	}
	if !strings.Contains(string(got), "tmb: debug: broker certificate serial=ABCDEF subject=tmb-broker") {
		t.Errorf("stderr %q lacks the broker certificate serial", got)
	}

	var none strings.Builder
	debugBrokerCert(&none, tls.ConnectionState{})
	if none.Len() != 0 {
		t.Errorf("no peer certificate printed %q", none.String())
	}
}
