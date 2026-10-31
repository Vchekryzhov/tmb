package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// The identity key is created once; every later start reads the same key.
func TestHostKeyCreatedOnceAndStable(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "state")
	fp, err := loadHostKey(dir)
	if err != nil {
		t.Fatalf("first start: %v", err)
	}
	if !regexp.MustCompile(`^[0-9a-f]{64}$`).MatchString(fp) {
		t.Errorf("fingerprint %q is not 64 lowercase hex", fp)
	}
	st, err := os.Stat(filepath.Join(dir, hostKeyFile))
	if err != nil || st.Mode().Perm() != 0o600 {
		t.Fatalf("key file %v, %v; want mode 0600", st, err)
	}
	again, err := loadHostKey(dir)
	if err != nil || again != fp {
		t.Fatalf("second start: %q, %v; want the same %q", again, err, fp)
	}
	other, err := loadHostKey(t.TempDir())
	if err != nil || other == fp {
		t.Fatalf("another state_dir: %q, %v; want a different key", other, err)
	}
}

// An existing key file that others may read, that is a symlink or that
// holds no P-256 key is a start error, never silently replaced.
func TestHostKeyRefusesBadFile(t *testing.T) {
	good := t.TempDir()
	if _, err := loadHostKey(good); err != nil {
		t.Fatal(err)
	}
	goodFile := filepath.Join(good, hostKeyFile)
	cases := map[string]func(dir string){
		"group readable": func(dir string) {
			copyFile(t, goodFile, filepath.Join(dir, hostKeyFile), 0o640)
		},
		"world readable": func(dir string) {
			copyFile(t, goodFile, filepath.Join(dir, hostKeyFile), 0o604)
		},
		"symlink": func(dir string) {
			if err := os.Symlink(goodFile, filepath.Join(dir, hostKeyFile)); err != nil {
				t.Fatal(err)
			}
		},
		"directory": func(dir string) {
			if err := os.Mkdir(filepath.Join(dir, hostKeyFile), 0o700); err != nil {
				t.Fatal(err)
			}
		},
		"not pem": func(dir string) {
			writeFile(t, filepath.Join(dir, hostKeyFile), "junk", 0o600)
		},
		"not pkcs8": func(dir string) {
			writeFile(t, filepath.Join(dir, hostKeyFile), "-----BEGIN PRIVATE KEY-----\nAAAA\n-----END PRIVATE KEY-----\n", 0o600)
		},
		"ed25519 key": func(dir string) {
			writeFile(t, filepath.Join(dir, hostKeyFile), ed25519KeyPEM(t), 0o600)
		},
	}
	for name, setup := range cases {
		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()
			setup(dir)
			before, _ := os.ReadFile(filepath.Join(dir, hostKeyFile))
			if fp, err := loadHostKey(dir); err == nil || !strings.Contains(err.Error(), "identity key") {
				t.Fatalf("loadHostKey = %q, %v; want an identity key error", fp, err)
			}
			if after, _ := os.ReadFile(filepath.Join(dir, hostKeyFile)); !bytes.Equal(before, after) {
				t.Errorf("the refused key file was changed")
			}
		})
	}
}

// A state_dir where the key cannot be created is an error, not a broker
// without an identity.
func TestHostKeyCreateFailure(t *testing.T) {
	file := filepath.Join(t.TempDir(), "file")
	writeFile(t, file, "", 0o600)
	if _, err := loadHostKey(filepath.Join(file, "state")); err == nil || !strings.Contains(err.Error(), "identity key") {
		t.Errorf("state_dir under a file: %v", err)
	}
	if os.Geteuid() == 0 {
		t.Skip("root writes into a read-only directory")
	}
	ro := t.TempDir()
	if err := os.Chmod(ro, 0o500); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(ro, 0o700) })
	if _, err := loadHostKey(ro); err == nil || !strings.Contains(err.Error(), "identity key") {
		t.Errorf("read-only state_dir: %v", err)
	}
}

// A key file with others' permissions stops the broker at start.
func TestBrokerRunRefusesOpenHostKey(t *testing.T) {
	noChown(t)
	cfgPath, cfg := brokerFiles(t, nil)
	if err := os.MkdirAll(cfg.StateDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if _, err := loadHostKey(cfg.StateDir); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(filepath.Join(cfg.StateDir, hostKeyFile), 0o644); err != nil {
		t.Fatal(err)
	}
	code, out := runBroker(t, "-config", cfgPath)
	if code != 1 || !strings.Contains(out, "identity key") || !strings.Contains(out, "owner-only") {
		t.Fatalf("code %d, want 1 with the identity key error:\n%s", code, out)
	}
}

// tmb-broker identity prints the same fingerprint the broker uses.
func TestIdentityCommand(t *testing.T) {
	cfgPath, cfg := brokerFiles(t, func(c *Config) { c.HostID = "build-01" })
	var out, errb bytes.Buffer
	if code := runIdentity([]string{"--config", cfgPath}, &out, &errb); code != 0 {
		t.Fatalf("exit %d: %s", code, errb.String())
	}
	fp, err := readHostKey(filepath.Join(cfg.StateDir, hostKeyFile))
	if err != nil {
		t.Fatal(err)
	}
	if out.String() != "host_id build-01\nhost_key "+fp+"\n" {
		t.Errorf("output %q, want host_id and host_key %s", out.String(), fp)
	}
	out.Reset()
	if code := runIdentity([]string{"--config", cfgPath}, &out, &errb); code != 0 || !strings.Contains(out.String(), fp) {
		t.Errorf("second run: exit %d, %q", code, out.String())
	}

	for _, c := range []struct {
		args []string
		code int
	}{
		{[]string{"--bogus"}, 2},
		{[]string{"-h"}, 0},
		{[]string{"--config", cfgPath, "extra"}, 2},
		{[]string{"--config", filepath.Join(t.TempDir(), "none.json")}, 1},
	} {
		if code := runIdentity(c.args, &out, &errb); code != c.code {
			t.Errorf("identity %v: exit %d, want %d", c.args, code, c.code)
		}
	}
	if err := os.Chmod(filepath.Join(cfg.StateDir, hostKeyFile), 0o640); err != nil {
		t.Fatal(err)
	}
	errb.Reset()
	if code := runIdentity([]string{"--config", cfgPath}, &out, &errb); code != 1 || !strings.Contains(errb.String(), "identity key") {
		t.Errorf("open key file: exit %d, stderr %q", code, errb.String())
	}
}

func ed25519KeyPEM(t *testing.T) string {
	t.Helper()
	_, key, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}))
}

func copyFile(t *testing.T, from, to string, mode os.FileMode) {
	t.Helper()
	b, err := os.ReadFile(from)
	if err != nil {
		t.Fatal(err)
	}
	writeFile(t, to, string(b), mode)
}

func writeFile(t *testing.T, path, content string, mode os.FileMode) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), mode); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, mode); err != nil { // umask may have cut it
		t.Fatal(err)
	}
}
