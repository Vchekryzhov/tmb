// PROTOTYPE CODE - throwaway PoC, not production.
package main

// tmb-broker ca: the minimal TMB certificate authority (spec #39, ADR 0005).
// It is a separate run mode of the binary: the broker serving requests never
// reads the CA key. Everything is standard PEM and X.509, so an external CA
// can replace it without broker changes.
//
//   ca init           CA key (ECDSA P-256, 0600) + self-signed cert, 10 years
//   ca issue-server   broker cert + key for the endpoint name(s), 1 year
//   ca issue-sandbox  sandbox cert for a public key or CSR, 7 days; prints the
//                     key fingerprint (SHA-256 of the SPKI, hex), which stays
//                     the same for every cert issued on that key

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"io"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"
)

const (
	caValidity      = 10 * 365 * 24 * time.Hour
	serverValidity  = 365 * 24 * time.Hour
	sandboxValidity = 7 * 24 * time.Hour
)

// errUsage marks a command-line mistake (exit 2).
var errUsage = errors.New("usage")

// runCA is the `tmb-broker ca ...` entry point; it returns the exit code.
func runCA(args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	err := caCommand(args, stdin, stdout, stderr, time.Now())
	switch {
	case err == nil:
		return 0
	case errors.Is(err, errUsage):
		fmt.Fprintf(stderr, "tmb-broker ca: %v\n%s", err, caUsage)
		return 2
	default:
		fmt.Fprintf(stderr, "tmb-broker ca: %v\n", err)
		return 1
	}
}

const caUsage = `usage:
  tmb-broker ca init          [--dir DIR]
  tmb-broker ca issue-server  [--dir DIR] --dns NAME [--dns NAME]... [--ip IP]... [--out DIR]
  tmb-broker ca issue-sandbox [--dir DIR] --in FILE|- --name NAME [--out FILE]
--dir defaults to <directory of --config>/ca (/etc/tmb/ca); --in takes a PEM
public key or a PEM CSR.
`

func caCommand(args []string, stdin io.Reader, stdout, stderr io.Writer, now time.Time) error {
	if len(args) == 0 {
		return fmt.Errorf("%w: expected init, issue-server or issue-sandbox", errUsage)
	}
	fs := flag.NewFlagSet("ca "+args[0], flag.ContinueOnError)
	fs.SetOutput(stderr)
	config := fs.String("config", "/etc/tmb/config.json", "broker config; the CA dir defaults to <its dir>/ca")
	dir := fs.String("dir", "", "CA directory")
	var dns, ips multiFlag
	var in, name, out *string
	switch args[0] {
	case "init":
	case "issue-server":
		fs.Var(&dns, "dns", "DNS name of the broker endpoint (repeatable)")
		fs.Var(&ips, "ip", "IP address of the broker endpoint (repeatable)")
		out = fs.String("out", "", "directory for server.crt and server.key (default: the CA dir)")
	case "issue-sandbox":
		in = fs.String("in", "", "PEM public key or CSR of the sandbox ('-' = stdin)")
		name = fs.String("name", "", "sandbox name, Subject only (not an identity)")
		out = fs.String("out", "", "certificate file (default: <CA dir>/sandbox-<name>.crt)")
	default:
		return fmt.Errorf("%w: unknown ca command %q", errUsage, args[0])
	}
	if err := fs.Parse(args[1:]); err != nil {
		return fmt.Errorf("%w: %v", errUsage, err)
	}
	if fs.NArg() > 0 {
		return fmt.Errorf("%w: unexpected arguments %q", errUsage, fs.Args())
	}
	if *dir == "" {
		*dir = filepath.Join(filepath.Dir(*config), "ca")
	}

	switch args[0] {
	case "init":
		if err := caInit(*dir, now); err != nil {
			return err
		}
		fmt.Fprintf(stdout, "ca key        : %s\nca certificate: %s\n", filepath.Join(*dir, "ca.key"), filepath.Join(*dir, "ca.crt"))
		return nil
	case "issue-server":
		if len(dns) == 0 {
			return fmt.Errorf("%w: issue-server needs at least one --dns", errUsage)
		}
		var addrs []net.IP
		for _, s := range ips {
			ip := net.ParseIP(s)
			if ip == nil {
				return fmt.Errorf("%w: --ip %q is not an IP address", errUsage, s)
			}
			addrs = append(addrs, ip)
		}
		if *out == "" {
			*out = *dir
		}
		crt, key, err := issueServer(*dir, *out, dns, addrs, now)
		if err != nil {
			return err
		}
		fmt.Fprintf(stdout, "server certificate: %s\nserver key        : %s\n", crt, key)
		return nil
	default: // issue-sandbox
		if *in == "" || *name == "" {
			return fmt.Errorf("%w: issue-sandbox needs --in and --name", errUsage)
		}
		var pemBytes []byte
		var err error
		if *in == "-" {
			pemBytes, err = io.ReadAll(io.LimitReader(stdin, 64<<10))
		} else {
			pemBytes, err = os.ReadFile(*in)
		}
		if err != nil {
			return fmt.Errorf("read --in: %w", err)
		}
		if *out == "" {
			*out = filepath.Join(*dir, "sandbox-"+*name+".crt")
		}
		fp, err := issueSandbox(*dir, *out, pemBytes, *name, now)
		if err != nil {
			return err
		}
		fmt.Fprintf(stdout, "fingerprint: %s\ncertificate: %s\n", fp, *out)
		return nil
	}
}

// caInit creates the CA key and self-signed certificate in dir. An existing
// key is never overwritten.
func caInit(dir string, now time.Time) error {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	keyPath := filepath.Join(dir, "ca.key")
	if _, err := os.Stat(keyPath); err == nil {
		return fmt.Errorf("%s already exists; refusing to replace the CA key", keyPath)
	}
	key := newP256Key()
	serial := randomSerial()
	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: "TMB CA"},
		NotBefore:             now,
		NotAfter:              now.Add(caValidity),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            0,
		MaxPathLenZero:        true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return err
	}
	if err := writeKey(keyPath, key); err != nil {
		return err
	}
	return writePEMFile(filepath.Join(dir, "ca.crt"), "CERTIFICATE", der, 0o644)
}

// loadCA reads the CA certificate and key from dir.
func loadCA(dir string) (*x509.Certificate, crypto.Signer, error) {
	certPEM, err := os.ReadFile(filepath.Join(dir, "ca.crt"))
	if err != nil {
		return nil, nil, fmt.Errorf("CA certificate: %w (run tmb-broker ca init)", err)
	}
	block, _ := pem.Decode(certPEM)
	if block == nil || block.Type != "CERTIFICATE" {
		return nil, nil, fmt.Errorf("CA certificate: no PEM CERTIFICATE in %s", filepath.Join(dir, "ca.crt"))
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, nil, fmt.Errorf("CA certificate: %w", err)
	}
	keyPEM, err := os.ReadFile(filepath.Join(dir, "ca.key"))
	if err != nil {
		return nil, nil, fmt.Errorf("CA key: %w", err)
	}
	kb, _ := pem.Decode(keyPEM)
	if kb == nil || kb.Type != "PRIVATE KEY" {
		return nil, nil, fmt.Errorf("CA key: no PEM PRIVATE KEY in %s", filepath.Join(dir, "ca.key"))
	}
	k, err := x509.ParsePKCS8PrivateKey(kb.Bytes)
	if err != nil {
		return nil, nil, fmt.Errorf("CA key: %w", err)
	}
	signer, ok := k.(crypto.Signer)
	if !ok {
		return nil, nil, fmt.Errorf("CA key: unsupported key type %T", k)
	}
	return cert, signer, nil
}

// issueServer writes server.crt and server.key (a fresh P-256 key) into out.
func issueServer(caDir, out string, dns []string, ips []net.IP, now time.Time) (string, string, error) {
	caCert, caKey, err := loadCA(caDir)
	if err != nil {
		return "", "", err
	}
	key := newP256Key()
	serial := randomSerial()
	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: dns[0]},
		NotBefore:             now,
		NotAfter:              now.Add(serverValidity),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		DNSNames:              dns,
		IPAddresses:           ips,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, caCert, &key.PublicKey, caKey)
	if err != nil {
		return "", "", err
	}
	if err := os.MkdirAll(out, 0o700); err != nil {
		return "", "", err
	}
	crtPath, keyPath := filepath.Join(out, "server.crt"), filepath.Join(out, "server.key")
	if err := writeKey(keyPath, key); err != nil {
		return "", "", err
	}
	return crtPath, keyPath, writePEMFile(crtPath, "CERTIFICATE", der, 0o644)
}

// issueSandbox signs the sandbox public key (from a PEM public key or a CSR,
// whose signature must verify) into a 7-day client certificate at out and
// returns the key fingerprint.
func issueSandbox(caDir, out string, pemBytes []byte, name string, now time.Time) (string, error) {
	pub, err := sandboxPublicKey(pemBytes)
	if err != nil {
		return "", err
	}
	caCert, caKey, err := loadCA(caDir)
	if err != nil {
		return "", err
	}
	tmpl := &x509.Certificate{
		SerialNumber:          randomSerial(),
		Subject:               pkix.Name{CommonName: name},
		NotBefore:             now,
		NotAfter:              now.Add(sandboxValidity),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, caCert, pub, caKey)
	if err != nil {
		return "", err
	}
	if err := writePEMFile(out, "CERTIFICATE", der, 0o644); err != nil {
		return "", err
	}
	return spkiFingerprint(pub)
}

// sandboxPublicKey extracts the public key from a PEM PUBLIC KEY or a PEM
// CERTIFICATE REQUEST; a CSR must carry a valid self-signature.
func sandboxPublicKey(pemBytes []byte) (crypto.PublicKey, error) {
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		return nil, errors.New("--in: no PEM block")
	}
	switch block.Type {
	case "PUBLIC KEY":
		pub, err := x509.ParsePKIXPublicKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("--in: public key: %w", err)
		}
		return pub, nil
	case "CERTIFICATE REQUEST":
		csr, err := x509.ParseCertificateRequest(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("--in: CSR: %w", err)
		}
		if err := csr.CheckSignature(); err != nil {
			return nil, fmt.Errorf("--in: CSR signature: %w", err)
		}
		return csr.PublicKey, nil
	default:
		return nil, fmt.Errorf("--in: PEM %q, want PUBLIC KEY or CERTIFICATE REQUEST", block.Type)
	}
}

// spkiFingerprint is the key fingerprint: SHA-256 of the DER
// SubjectPublicKeyInfo, lower-case hex without colons.
func spkiFingerprint(pub crypto.PublicKey) (string, error) {
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(der)
	return hex.EncodeToString(sum[:]), nil
}

// randomSerial is a random 128-bit serial number. crypto/rand.Read never
// returns an error (Go 1.24+); the top bit is set so the serial is positive
// and always 128 bits long.
func randomSerial() *big.Int {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	b[0] |= 0x80
	return new(big.Int).SetBytes(b)
}

// newP256Key generates an ECDSA P-256 key. It reads only crypto/rand, which
// never fails (Go 1.24+), so an error here is a broken runtime.
func newP256Key() *ecdsa.PrivateKey {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		panic(err)
	}
	return key
}

func writeKey(path string, key *ecdsa.PrivateKey) error {
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return err
	}
	return writePEMFile(path, "PRIVATE KEY", der, 0o600)
}

// writePEMFile writes one PEM block, creating the file with mode or replacing
// an existing file's content (its mode is then set to mode too).
func writePEMFile(path, blockType string, der []byte, mode os.FileMode) error {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, mode)
	if err != nil {
		return err
	}
	if err := f.Chmod(mode); err != nil {
		f.Close()
		return err
	}
	if err := pem.Encode(f, &pem.Block{Type: blockType, Bytes: der}); err != nil {
		f.Close()
		return err
	}
	return f.Close()
}

// multiFlag collects a repeatable string flag.
type multiFlag []string

func (m *multiFlag) String() string     { return strings.Join(*m, ",") }
func (m *multiFlag) Set(v string) error { *m = append(*m, v); return nil }
