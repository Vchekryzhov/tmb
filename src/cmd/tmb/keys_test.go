package main

import (
	"bytes"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func runKeys(fn func([]string, *bytes.Buffer, *bytes.Buffer) int, args ...string) (int, string, string) {
	var out, errb bytes.Buffer
	code := fn(args, &out, &errb)
	return code, out.String(), errb.String()
}

func keygen(args []string, o, e *bytes.Buffer) int      { return cmdKeygen(args, o, e) }
func fingerprint(args []string, o, e *bytes.Buffer) int { return cmdFingerprint(args, o, e) }

// keygen writes a 0600 key, prints its public key and fingerprint, and
// every form of the same key (private, public, certificate, CSR) has that
// fingerprint.
func TestKeygenAndFingerprintAgree(t *testing.T) {
	dir := t.TempDir()
	keyPath := filepath.Join(dir, "sbx.key")
	code, out, errs := runKeys(keygen, "--out", keyPath)
	if code != 0 {
		t.Fatalf("keygen: %d %s", code, errs)
	}
	st, err := os.Stat(keyPath)
	if err != nil || st.Mode().Perm() != 0o600 {
		t.Fatalf("key file %v %v, want mode 0600", st, err)
	}
	if !strings.Contains(out, "-----BEGIN PUBLIC KEY-----") || strings.Contains(out, "PRIVATE") {
		t.Fatalf("keygen output must show the public key only:\n%s", out)
	}
	fp := strings.TrimPrefix(out[strings.Index(out, "fingerprint: "):], "fingerprint: ")
	fp = strings.TrimSpace(fp)
	if len(fp) != 64 {
		t.Fatalf("fingerprint %q", fp)
	}
	if code, _, _ := runKeys(keygen, "--out", keyPath); code != 1 {
		t.Errorf("keygen over an existing key: exit %d, want 1", code)
	}

	keyPEM, _ := os.ReadFile(keyPath)
	block, _ := pem.Decode(keyPEM)
	k, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		t.Fatalf("parse key: %v", err)
	}
	priv := k.(*ecdsa.PrivateKey)
	pubPEM := []byte(out[:strings.Index(out, "fingerprint: ")])
	ecDER, _ := x509.MarshalECPrivateKey(priv)
	csrDER, _ := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{Subject: pkix.Name{CommonName: "sbx"}}, priv)
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "sbx"}, NotBefore: time.Now(), NotAfter: time.Now().Add(time.Hour)}
	certDER, _ := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &priv.PublicKey, priv)
	for name, body := range map[string][]byte{
		"private":    keyPEM,
		"public":     pubPEM,
		"ec private": pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: ecDER}),
		"csr":        pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrDER}),
		"cert":       pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER}),
	} {
		p := filepath.Join(dir, strings.ReplaceAll(name, " ", "-")+".pem")
		if err := os.WriteFile(p, body, 0o600); err != nil {
			t.Fatalf("write: %v", err)
		}
		if code, got, errs := runKeys(fingerprint, p); code != 0 || strings.TrimSpace(got) != fp {
			t.Errorf("%s: fingerprint %q (exit %d %s), want %s", name, got, code, errs, fp)
		}
	}
}

func TestKeysUsageAndBadInput(t *testing.T) {
	dir := t.TempDir()
	for _, args := range [][]string{{}, {"--out"}, {"--out", "x", "extra"}} {
		if code, _, _ := runKeys(keygen, args...); code != 2 {
			t.Errorf("keygen %q: exit %d, want 2", args, code)
		}
	}
	if code, _, _ := runKeys(keygen, "--out", filepath.Join(dir, "missing", "k")); code != 1 {
		t.Errorf("keygen into a missing dir: want 1")
	}
	if code, _, _ := runKeys(fingerprint); code != 2 {
		t.Errorf("fingerprint without a file: want 2")
	}
	if code, _, _ := runKeys(fingerprint, filepath.Join(dir, "missing")); code != 1 {
		t.Errorf("fingerprint of a missing file: want 1")
	}
	for name, body := range map[string]string{
		"junk":  "junk",
		"type":  string(pem.EncodeToMemory(&pem.Block{Type: "RSA PARAMS", Bytes: []byte{1}})),
		"cert":  string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: []byte{1}})),
		"pub":   string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: []byte{1}})),
		"csr":   string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: []byte{1}})),
		"pkcs8": string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: []byte{1}})),
		"ec":    string(pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: []byte{1}})),
	} {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
			t.Fatalf("write: %v", err)
		}
		if code, _, _ := runKeys(fingerprint, p); code != 1 {
			t.Errorf("%s: exit %d, want 1", name, code)
		}
	}
	// a PKCS#8 key that cannot sign (X25519) is not a sandbox key
	xk, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("x25519: %v", err)
	}
	xDER, err := x509.MarshalPKCS8PrivateKey(xk)
	if err != nil {
		t.Fatalf("marshal x25519: %v", err)
	}
	p := filepath.Join(dir, "x25519")
	if err := os.WriteFile(p, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: xDER}), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	if code, _, errs := runKeys(fingerprint, p); code != 1 || !strings.Contains(errs, "unsupported key type") {
		t.Errorf("x25519: exit %d %q, want 1 and an unsupported key type", code, errs)
	}
}
