// PROTOTYPE CODE - throwaway PoC, not production.
package main

// tmb keygen and tmb fingerprint: the sandbox side of enrollment (ADR 0005).
// The key is born inside the sandbox and never leaves it; only the public
// key goes to the host, whose CA signs it. The fingerprint (SHA-256 of the
// DER SubjectPublicKeyInfo, hex) is what the broker allowlist lists.

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
)

func cmdKeygen(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("keygen", flag.ContinueOnError)
	fs.SetOutput(stderr)
	out := fs.String("out", "", "private key file to create (mode 0600, must not exist)")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if *out == "" || fs.NArg() > 0 {
		fmt.Fprintln(stderr, "usage: tmb keygen --out FILE")
		return 2
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		fmt.Fprintf(stderr, "tmb keygen: %v\n", err)
		return 1
	}
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		fmt.Fprintf(stderr, "tmb keygen: %v\n", err)
		return 1
	}
	f, err := os.OpenFile(*out, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		fmt.Fprintf(stderr, "tmb keygen: %v\n", err)
		return 1
	}
	if err := pem.Encode(f, &pem.Block{Type: "PRIVATE KEY", Bytes: der}); err != nil {
		f.Close()
		fmt.Fprintf(stderr, "tmb keygen: %v\n", err)
		return 1
	}
	if err := f.Close(); err != nil {
		fmt.Fprintf(stderr, "tmb keygen: %v\n", err)
		return 1
	}
	pubDER, _ := x509.MarshalPKIXPublicKey(&key.PublicKey)
	_ = pem.Encode(stdout, &pem.Block{Type: "PUBLIC KEY", Bytes: pubDER})
	fmt.Fprintf(stdout, "fingerprint: %s\n", spkiHex(pubDER))
	return 0
}

// cmdFingerprint prints the key fingerprint of a PEM private key, public
// key, certificate or CSR, so the human can check what goes into the
// allowlist.
func cmdFingerprint(args []string, stdout, stderr io.Writer) int {
	if len(args) != 1 {
		fmt.Fprintln(stderr, "usage: tmb fingerprint FILE (PEM key, public key, certificate or CSR)")
		return 2
	}
	b, err := os.ReadFile(args[0])
	if err != nil {
		fmt.Fprintf(stderr, "tmb fingerprint: %v\n", err)
		return 1
	}
	fp, err := pemFingerprint(b)
	if err != nil {
		fmt.Fprintf(stderr, "tmb fingerprint: %s: %v\n", args[0], err)
		return 1
	}
	fmt.Fprintln(stdout, fp)
	return 0
}

func pemFingerprint(b []byte) (string, error) {
	block, _ := pem.Decode(b)
	if block == nil {
		return "", errors.New("no PEM block")
	}
	var pub crypto.PublicKey
	switch block.Type {
	case "CERTIFICATE":
		c, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return "", err
		}
		return spkiHex(c.RawSubjectPublicKeyInfo), nil
	case "PUBLIC KEY":
		if _, err := x509.ParsePKIXPublicKey(block.Bytes); err != nil {
			return "", err
		}
		return spkiHex(block.Bytes), nil
	case "CERTIFICATE REQUEST":
		csr, err := x509.ParseCertificateRequest(block.Bytes)
		if err != nil {
			return "", err
		}
		return spkiHex(csr.RawSubjectPublicKeyInfo), nil
	case "PRIVATE KEY":
		k, err := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err != nil {
			return "", err
		}
		s, ok := k.(crypto.Signer)
		if !ok {
			return "", fmt.Errorf("unsupported key type %T", k)
		}
		pub = s.Public()
	case "EC PRIVATE KEY":
		k, err := x509.ParseECPrivateKey(block.Bytes)
		if err != nil {
			return "", err
		}
		pub = k.Public()
	default:
		return "", fmt.Errorf("PEM %q is not a key, certificate or CSR", block.Type)
	}
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return "", err
	}
	return spkiHex(der), nil
}

func spkiHex(spki []byte) string {
	sum := sha256.Sum256(spki)
	return hex.EncodeToString(sum[:])
}
