package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestLoadConfigTLSFields(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.json")
	body := `{
  "socket_path": "/run/tmb/tmb.sock",
  "state_dir": "/var/lib/tmb-proto",
  "log_path": "/var/log/tmb/broker.log",
  "allowed_requester_uids": [4242, 4343],
  "allowed_requester_keys": ["` + strings.Repeat("aa", 32) + `"],
  "tls_addr": ":7600",
  "tls_ca_file": "/etc/tmb/certs/ca.crt",
  "tls_cert_file": "/etc/tmb/certs/server.crt",
  "tls_key_file": "/etc/tmb/certs/server.key"
}`
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}
	c, err := loadConfig(path)
	if err != nil {
		t.Fatalf("loadConfig: %v", err)
	}
	if c.TLSAddr != ":7600" || c.TLSCAFile != "/etc/tmb/certs/ca.crt" ||
		c.TLSCertFile != "/etc/tmb/certs/server.crt" || c.TLSKeyFile != "/etc/tmb/certs/server.key" {
		t.Errorf("tls fields = %q %q %q %q", c.TLSAddr, c.TLSCAFile, c.TLSCertFile, c.TLSKeyFile)
	}
	if len(c.AllowedRequesterKeys) != 1 || c.AllowedRequesterKeys[0] != strings.Repeat("aa", 32) {
		t.Errorf("allowed_requester_keys = %v", c.AllowedRequesterKeys)
	}
	if len(c.AllowedRequesterUIDs) != 2 || c.AllowedRequesterUIDs[0] != 4242 {
		t.Errorf("allowed_requester_uids = %v", c.AllowedRequesterUIDs)
	}
	if c.TokenTTLSeconds != 60 {
		t.Errorf("token ttl default = %d, want 60", c.TokenTTLSeconds)
	}
	if c.PidFile != "/var/run/tmb-broker.pid" {
		t.Errorf("pidfile default = %q", c.PidFile)
	}
}

func TestLoadConfigTLSAbsentKeepsBrokerUnixOnly(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.json")
	body := `{"socket_path":"/run/tmb/tmb.sock","state_dir":"/s","log_path":"/l"}`
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}
	c, err := loadConfig(path)
	if err != nil {
		t.Fatalf("loadConfig: %v", err)
	}
	if c.TLSAddr != "" || c.TLSCAFile != "" || c.TLSCertFile != "" || c.TLSKeyFile != "" {
		t.Errorf("tls fields must default to empty (listener off), got %+v", c)
	}
}

// The old certificate-fingerprint allowlist is refused with a pointer to its
// replacement, not silently ignored.
func TestLoadConfigRejectsAllowedRequesterFPs(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.json")
	body := `{"socket_path": "/run/tmb/tmb.sock", "state_dir": "/s", "log_path": "/l", "allowed_requester_fps": ["aa"]}`
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}
	_, err := loadConfig(path)
	if err == nil || !strings.Contains(err.Error(), "allowed_requester_fps") || !strings.Contains(err.Error(), "allowed_requester_keys") {
		t.Fatalf("loadConfig = %v, want an error naming the old field and its replacement", err)
	}
}
