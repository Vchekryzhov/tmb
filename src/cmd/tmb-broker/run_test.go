package main

import (
	"bytes"
	"crypto/x509"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

// brokerFiles lays out a broker config under a short temp dir and returns
// the config path and the config itself for inspection.
func brokerFiles(t *testing.T, edit func(*Config)) (string, *Config) {
	t.Helper()
	dir, err := os.MkdirTemp("", "tmbb")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	cfg := &Config{
		SocketPath:         filepath.Join(dir, "run", "b.sock"),
		StateDir:           filepath.Join(dir, "state"),
		LogPath:            filepath.Join(dir, "log", "broker.log"),
		PidFile:            filepath.Join(dir, "broker.pid"),
		ApproverSocketPath: filepath.Join(dir, "run", "approve.sock"),
		ApprovalDefault:    ModeMockDeny,
	}
	if edit != nil {
		edit(cfg)
	}
	b, err := json.Marshal(cfg)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "config.json")
	if err := os.WriteFile(path, b, 0o600); err != nil {
		t.Fatal(err)
	}
	return path, cfg
}

// noChown makes run usable without root for the duration of the test.
func noChown(t *testing.T) {
	t.Helper()
	orig := chown
	chown = func(string, int, int) error { return nil }
	t.Cleanup(func() { chown = orig })
}

func runBroker(t *testing.T, args ...string) (int, string) {
	t.Helper()
	var out, errb bytes.Buffer
	stop := make(chan os.Signal)
	code := run(args, &out, &errb, stop, nil)
	return code, out.String() + errb.String()
}

func TestBrokerRunSetupFailures(t *testing.T) {
	noChown(t)
	file := filepath.Join(t.TempDir(), "file")
	if err := os.WriteFile(file, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name  string
		edit  func(*Config)
		args  []string
		code  int
		inOut string
	}{
		{"bad flag", nil, []string{"-bogus"}, 2, "flag provided but not defined"},
		{"help", nil, []string{"-h"}, 0, "Usage of tmb-broker"},
		{"unknown mode", nil, []string{"-approval", "maybe"}, 1, `unknown approval mode "maybe"`},
		{"log path", func(c *Config) { c.LogPath = filepath.Join(file, "broker.log") }, nil, 1, "tmb-broker: log:"},
		{"state dir", func(c *Config) { c.StateDir = file }, nil, 1, "tmb-broker: claim store:"},
		{"socket dir", func(c *Config) { c.SocketPath = filepath.Join(file, "b.sock") }, nil, 1, "tmb-broker: socket dir:"},
		{"tls without files", func(c *Config) { c.TLSAddr = "127.0.0.1:0" }, nil, 1, "requires tls_ca_file"},
		{"tls bad files", func(c *Config) {
			c.TLSAddr, c.TLSCAFile, c.TLSCertFile, c.TLSKeyFile = "127.0.0.1:0", file, file, file
		}, nil, 1, "tls ca"},
		{"pidfile", func(c *Config) { c.PidFile = filepath.Join(file, "pid") }, nil, 1, "tmb-broker: pidfile:"},
		{"approver socket", func(c *Config) { c.ApproverSocketPath = filepath.Join(file, "approve.sock") }, nil, 1, "tmb-broker: approver socket:"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			cfgPath, _ := brokerFiles(t, c.edit)
			code, out := runBroker(t, append([]string{"-config", cfgPath}, c.args...)...)
			if code != c.code || !strings.Contains(out, c.inOut) {
				t.Fatalf("code %d, want %d; output lacks %q:\n%s", code, c.code, c.inOut, out)
			}
		})
	}
	if code, out := runBroker(t, "-config", filepath.Join(t.TempDir(), "none.json")); code != 1 || !strings.Contains(out, "tmb-broker: config:") {
		t.Fatalf("missing config: code %d:\n%s", code, out)
	}
}

func TestBrokerRunChownFailureStops(t *testing.T) {
	orig := chown
	chown = func(string, int, int) error { return errors.New("operation not permitted") }
	t.Cleanup(func() { chown = orig })
	cfgPath, _ := brokerFiles(t, nil)
	if code, out := runBroker(t, "-config", cfgPath); code != 1 || !strings.Contains(out, "socket dir chown (gid 0)") {
		t.Fatalf("code %d:\n%s", code, out)
	}
}

func TestBrokerRunRefusesUnremovableSocketPath(t *testing.T) {
	noChown(t)
	cfgPath, cfg := brokerFiles(t, nil)
	if err := os.MkdirAll(filepath.Join(cfg.SocketPath, "busy"), 0o700); err != nil {
		t.Fatal(err)
	}
	if code, out := runBroker(t, "-config", cfgPath); code != 1 || !strings.Contains(out, "stale socket") {
		t.Fatalf("code %d:\n%s", code, out)
	}
}

// The broker serves both listeners until a stop signal, then removes its
// socket and pidfile and exits 0.
func TestBrokerRunServesUntilStopped(t *testing.T) {
	noChown(t)
	dir := t.TempDir()
	ca := newTestCA(t)
	caFile := writePEM(t, filepath.Join(dir, "ca.crt"), "CERTIFICATE", ca.cert.Raw)
	srvCert, srvKey, _ := ca.issue(t, dir, "server", []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, []string{"localhost"})
	cfgPath, cfg := brokerFiles(t, func(c *Config) {
		c.TLSAddr, c.TLSCAFile, c.TLSCertFile, c.TLSKeyFile = "127.0.0.1:0", caFile, srvCert, srvKey
	})
	if err := os.MkdirAll(filepath.Dir(cfg.SocketPath), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(cfg.SocketPath, nil, 0o600); err != nil { // stale socket from a crash
		t.Fatal(err)
	}
	if err := os.WriteFile(cfg.PidFile, []byte("1\n"), 0o644); err != nil { // stale pid file from an older broker
		t.Fatal(err)
	}

	var out, errb bytes.Buffer
	stop, hup := make(chan os.Signal, 1), make(chan os.Signal, 1)
	done := make(chan int)
	go func() {
		done <- run([]string{"-config", cfgPath, "-approval", ModeMockApprove, "-ttl", "7"}, &out, &errb, stop, hup)
	}()

	deadline := time.Now().Add(5 * time.Second)
	for {
		if st, err := os.Stat(cfg.SocketPath); err == nil && st.Mode()&os.ModeSocket != 0 {
			if b, err := os.ReadFile(cfg.PidFile); err == nil && string(b) != "1\n" { // rewritten, not the stale one
				break
			}
		}
		if time.Now().After(deadline) {
			t.Fatalf("broker never listened; stderr:\n%s", errb.String())
		}
		time.Sleep(10 * time.Millisecond)
	}
	if st, _ := os.Stat(cfg.SocketPath); st.Mode().Perm() != 0o660 {
		t.Errorf("socket mode %v, want 0660", st.Mode().Perm())
	}
	if st, _ := os.Stat(cfg.PidFile); st.Mode().Perm() != 0o600 {
		t.Errorf("pidfile mode %v, want 0600", st.Mode().Perm())
	}
	hup <- syscall.SIGHUP // reload while serving
	deadline = time.Now().Add(5 * time.Second)
	for {
		if log, _ := os.ReadFile(cfg.LogPath); strings.Contains(string(log), `"event":"reload"`) {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("SIGHUP did not reload the config")
		}
		time.Sleep(10 * time.Millisecond)
	}
	stop <- os.Interrupt
	select {
	case code := <-done:
		if code != 0 {
			t.Fatalf("exit %d after stop; stderr:\n%s", code, errb.String())
		}
	case <-time.After(5 * time.Second):
		t.Fatal("broker did not stop")
	}
	for _, p := range []string{cfg.SocketPath, cfg.PidFile} {
		if _, err := os.Stat(p); !os.IsNotExist(err) {
			t.Errorf("%s left behind after stop", p)
		}
	}
	if !strings.Contains(out.String(), "mode=mock-approve ttl=7s") || !strings.Contains(out.String(), "tls listening on 127.0.0.1:0") {
		t.Errorf("stdout:\n%s", out.String())
	}
	log, _ := os.ReadFile(cfg.LogPath)
	for _, ev := range []string{"broker_start", "tls_listen", "broker_stop"} {
		if !strings.Contains(string(log), `"event":"`+ev+`"`) {
			t.Errorf("log lacks %s:\n%s", ev, log)
		}
	}
}

func TestLastSlash(t *testing.T) {
	for in, want := range map[string]int{"/run/tmb/b.sock": 8, "b.sock": 0, "/b": 0} {
		if got := lastSlash(in); got != want {
			t.Errorf("lastSlash(%q) = %d, want %d", in, got, want)
		}
	}
}
