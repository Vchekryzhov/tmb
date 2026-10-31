package main

import (
	"crypto/tls"
	"crypto/x509"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"tmb-poc/internal/proto"
)

// tlsBroker runs ServeTLS on 127.0.0.1 with the given fingerprints
// allowlisted and returns its address and log path.
func tlsBroker(t *testing.T, ca *testCA, dir string, fps ...string) (addr string, b *Broker) {
	t.Helper()
	caFile := writePEM(t, filepath.Join(dir, "ca.crt"), "CERTIFICATE", ca.cert.Raw)
	srvCert, srvKey, _ := ca.issue(t, dir, "server", []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, []string{"localhost"})
	log, err := NewLogger(filepath.Join(dir, "broker.log"))
	if err != nil {
		t.Fatal(err)
	}
	claims, err := NewClaimStore(dir, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	cfg := &Config{AllowedRequesterKeys: fps, FixedEnv: map[string]string{"PATH": "/usr/bin:/bin"}, AllowedEnvKeys: []string{"LANG"}, AllowedCwdRoots: []string{"/"}}
	b = NewBroker(cfg, log, claims, ModeMockApprove, 30*time.Second)
	tlsCfg, err := loadTLSConfig(caFile, srvCert, srvKey)
	if err != nil {
		t.Fatal(err)
	}
	b.tlsCfg.Store(tlsCfg)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	// the production listener config, which takes the material from the
	// reloadable snapshot
	go b.ServeTLS(tls.NewListener(ln, b.listenerTLSConfig()))
	return ln.Addr().String(), b
}

func loadPair(t *testing.T, certFile, keyFile string) tls.Certificate {
	t.Helper()
	c, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

// execOverTLS sends an exec request with the given client config and
// returns the first frame, or the error that ended the connection.
func execOverTLS(t *testing.T, addr string, cfg *tls.Config) (*proto.Frame, error) {
	t.Helper()
	conn, err := tls.Dial("tcp", addr, cfg)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
	req := testReq(t, "tls-sec-"+proto.NewNonce())
	req.Type = "exec"
	if err := proto.WriteFrame(conn, req); err != nil {
		return nil, err
	}
	return proto.ReadFrame(conn)
}

func waitLog(t *testing.T, b *Broker, needle string) string {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for {
		log, _ := os.ReadFile(b.log.f.Name())
		if strings.Contains(string(log), needle) {
			return string(log)
		}
		if time.Now().After(deadline) {
			t.Fatalf("%s never logged; log:\n%s", needle, log)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

// M1 / SEC-06: the TLS listener verifies the client certificate chain
// before it looks at the fingerprint. A certificate that fails
// verification is refused in the handshake even when its fingerprint is
// allowlisted, and nothing runs.
func TestTLSListenerRejectsUnverifiedClientCerts(t *testing.T) {
	ca := newTestCA(t)
	clientEKU := []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}
	cases := []struct {
		name  string
		issue func(dir string) (string, string, []byte)
	}{
		{"foreign CA", func(dir string) (string, string, []byte) {
			return newTestCA(t).issue(t, dir, "foreign", clientEKU, nil)
		}},
		{"expired", func(dir string) (string, string, []byte) {
			return ca.issueWith(t, dir, "expired", func(c *x509.Certificate) {
				c.ExtKeyUsage = clientEKU
				c.NotBefore = time.Now().Add(-48 * time.Hour)
				c.NotAfter = time.Now().Add(-24 * time.Hour)
			})
		}},
		{"not yet valid", func(dir string) (string, string, []byte) {
			return ca.issueWith(t, dir, "future", func(c *x509.Certificate) {
				c.ExtKeyUsage = clientEKU
				c.NotBefore = time.Now().Add(24 * time.Hour)
				c.NotAfter = time.Now().Add(48 * time.Hour)
			})
		}},
		{"server-only usage", func(dir string) (string, string, []byte) {
			return ca.issue(t, dir, "serveronly", []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, nil)
		}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			dir := t.TempDir()
			certFile, keyFile, der := c.issue(dir)
			addr, b := tlsBroker(t, ca, dir, keyFingerprintOf(t, der))
			pool := x509.NewCertPool()
			pool.AddCert(ca.cert)
			f, err := execOverTLS(t, addr, &tls.Config{
				RootCAs: pool, ServerName: "localhost", MinVersion: tls.VersionTLS13,
				Certificates: []tls.Certificate{loadPair(t, certFile, keyFile)},
			})
			if err == nil {
				t.Fatalf("broker answered %+v to an unverified client certificate", f)
			}
			log := waitLog(t, b, `"event":"tls_handshake_failed"`)
			if strings.Contains(log, `"event":"request"`) || strings.Contains(log, `"event":"exec_start"`) {
				t.Fatalf("an unverified client reached the request stage:\n%s", log)
			}
		})
	}
}

// SEC-06: a client without a certificate, or one that cannot speak TLS
// 1.3, never reaches the request stage.
func TestTLSListenerRejectsMissingCertAndOldTLS(t *testing.T) {
	ca := newTestCA(t)
	dir := t.TempDir()
	certFile, keyFile, der := ca.issue(t, dir, "client", []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}, nil)
	addr, b := tlsBroker(t, ca, dir, keyFingerprintOf(t, der))
	pool := x509.NewCertPool()
	pool.AddCert(ca.cert)

	if f, err := execOverTLS(t, addr, &tls.Config{RootCAs: pool, ServerName: "localhost", MinVersion: tls.VersionTLS13}); err == nil {
		t.Fatalf("broker answered %+v to a client without a certificate", f)
	}
	if f, err := execOverTLS(t, addr, &tls.Config{
		RootCAs: pool, ServerName: "localhost",
		MinVersion: tls.VersionTLS12, MaxVersion: tls.VersionTLS12,
		Certificates: []tls.Certificate{loadPair(t, certFile, keyFile)},
	}); err == nil {
		t.Fatalf("broker answered %+v over TLS 1.2", f)
	}
	log := waitLog(t, b, `"event":"tls_handshake_failed"`)
	if strings.Contains(log, `"event":"request"`) {
		t.Fatalf("a rejected client reached the request stage:\n%s", log)
	}

	// the same certificate over TLS 1.3 is served: the rejections above were
	// about the certificate and the version, not a broken listener
	f, err := execOverTLS(t, addr, &tls.Config{
		RootCAs: pool, ServerName: "localhost", MinVersion: tls.VersionTLS13,
		Certificates: []tls.Certificate{loadPair(t, certFile, keyFile)},
	})
	if err != nil || f.Type != "approved" {
		t.Fatalf("valid client: %+v, %v; want approved", f, err)
	}
	// the broker goes on to claim and run after "approved": wait for it, so
	// the temp dir is not removed under its claim files
	waitLog(t, b, `"event":"exec_exit"`)
}

func TestLoadTLSConfigRejectsBadMaterial(t *testing.T) {
	dir := t.TempDir()
	ca := newTestCA(t)
	caFile := writePEM(t, filepath.Join(dir, "ca.crt"), "CERTIFICATE", ca.cert.Raw)
	cert, key, _ := ca.issue(t, dir, "server", []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, []string{"localhost"})
	garbage := filepath.Join(dir, "garbage.pem")
	if err := os.WriteFile(garbage, []byte("not pem"), 0o600); err != nil {
		t.Fatal(err)
	}
	cases := map[string][3]string{
		"missing CA":   {filepath.Join(dir, "none.crt"), cert, key},
		"garbage CA":   {garbage, cert, key},
		"missing cert": {caFile, filepath.Join(dir, "none.crt"), key},
		"key mismatch": {caFile, cert, garbage},
	}
	for name, files := range cases {
		if _, err := loadTLSConfig(files[0], files[1], files[2]); err == nil {
			t.Errorf("%s: loadTLSConfig succeeded", name)
		}
	}
	cfg, err := loadTLSConfig(caFile, cert, key)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.ClientAuth != tls.RequireAndVerifyClientCert || cfg.MinVersion != tls.VersionTLS13 {
		t.Fatalf("server TLS config: client auth %v, min version %x", cfg.ClientAuth, cfg.MinVersion)
	}
}

// keyFingerprintOf is the requester identity the listener derives from a
// certificate: the fingerprint of its public key.
func keyFingerprintOf(t *testing.T, der []byte) string {
	t.Helper()
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return keyFingerprint(cert)
}
