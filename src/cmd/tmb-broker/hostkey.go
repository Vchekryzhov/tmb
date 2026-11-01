// PROTOTYPE CODE - throwaway PoC, not production.
package main

// The broker identity key (ADR 0007, R6): a P-256 key the broker keeps in
// state_dir and creates on its first start. Its SPKI fingerprint is the
// host_key of every approval payload, the value a trusted signer pins for
// this host. The broker signs nothing with it in this stage; the TLS key is
// not used, because the TCP listener is optional and a new TLS certificate
// must not break the pin. A reload does not touch it.

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"syscall"

	"tmb-poc/internal/proto"
)

// hostKeyFile is the identity key's file name in state_dir.
const hostKeyFile = "identity.key"

// loadHostKey returns the fingerprint of the identity key in stateDir,
// creating the key (0600, PKCS#8 PEM) when the file does not exist. An
// existing file must be a regular file owned by this user with no group or
// other permission bits and hold a P-256 key; anything else is an error,
// never a silent replacement.
func loadHostKey(stateDir string) (string, error) {
	path := filepath.Join(stateDir, hostKeyFile)
	fp, err := readHostKey(path)
	if errors.Is(err, os.ErrNotExist) {
		// O_EXCL: a broker or `tmb-broker identity` racing us keeps its key
		if err = createHostKey(stateDir, path); err == nil || errors.Is(err, os.ErrExist) {
			fp, err = readHostKey(path)
		}
	}
	if err != nil {
		return "", fmt.Errorf("identity key %s: %w", path, err)
	}
	return fp, nil
}

// createHostKey writes a new P-256 key to path (0600, O_EXCL).
func createHostKey(stateDir, path string) error {
	if err := os.MkdirAll(stateDir, 0o700); err != nil {
		return err
	}
	der, err := x509.MarshalPKCS8PrivateKey(newP256Key())
	if err == nil {
		err = writePEMFileFlags(path, "PRIVATE KEY", der, 0o600, os.O_EXCL)
	}
	return err
}

// readHostKey opens the key without following a symlink, checks the open
// file's owner and mode and returns the key's fingerprint.
func readHostKey(path string) (string, error) {
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return "", err
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil || !st.Mode().IsRegular() {
		return "", fmt.Errorf("not a regular file (%v)", err)
	}
	if st.Mode().Perm()&0o077 != 0 {
		return "", fmt.Errorf("mode %04o, want owner-only (0600)", st.Mode().Perm())
	}
	if sys, ok := st.Sys().(*syscall.Stat_t); !ok || int(sys.Uid) != os.Geteuid() {
		return "", fmt.Errorf("not owned by uid %d", os.Geteuid())
	}
	raw, err := io.ReadAll(io.LimitReader(f, 64*1024))
	block, _ := pem.Decode(raw)
	if err != nil || block == nil || block.Type != "PRIVATE KEY" {
		return "", fmt.Errorf("no PEM PRIVATE KEY (%v)", err)
	}
	k, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return "", err
	}
	key, ok := k.(*ecdsa.PrivateKey)
	if !ok || key.Curve != elliptic.P256() {
		return "", errors.New("not an ECDSA P-256 key")
	}
	spki, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	return proto.KeyFingerprint(spki), err
}

// runIdentity is `tmb-broker identity [--config PATH]`: it prints the
// identity key fingerprint (creating the key like a first start would) for
// the operator to compare with what a signer pinned.
func runIdentity(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("tmb-broker identity", flag.ContinueOnError)
	fs.SetOutput(stderr)
	cfgPath := fs.String("config", "/etc/tmb/config.json", "config file path")
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		return 2
	}
	if fs.NArg() != 0 {
		fmt.Fprintf(stderr, "tmb-broker identity: unexpected argument %q\n", fs.Arg(0))
		return 2
	}
	cfg, err := loadConfig(*cfgPath)
	if err != nil {
		fmt.Fprintf(stderr, "tmb-broker identity: config: %v\n", err)
		return 1
	}
	fp, err := loadHostKey(cfg.StateDir)
	if err != nil {
		fmt.Fprintf(stderr, "tmb-broker identity: %v\n", err)
		return 1
	}
	fmt.Fprintf(stdout, "host_id %s\nhost_key %s\n", cfg.HostID, fp)
	return 0
}
