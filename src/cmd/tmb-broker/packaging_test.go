package main

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

// The deb/rpm files live in packaging/ at the repository root (spec #39,
// issue #44); these tests pin what the package promises the operator.

func packagingFile(t *testing.T, name string) string {
	t.Helper()
	p := filepath.Join("..", "..", "..", "packaging", name)
	if _, err := os.Stat(p); err != nil {
		t.Skipf("packaging/%s not next to src (copied tree): %v", name, err)
	}
	return p
}

func TestPackagedConfigExampleLoads(t *testing.T) {
	cfg, err := loadConfig(packagingFile(t, "config.json.example"))
	if err != nil {
		t.Fatalf("config.json.example does not load: %v", err)
	}
	if !reflect.DeepEqual(cfg.AllowedCwdRoots, []string{"/tmp"}) && !reflect.DeepEqual(cfg.AllowedCwdRoots, []string{"/private/tmp"}) {
		t.Errorf("allowed_cwd_roots = %v, want [/tmp]", cfg.AllowedCwdRoots)
	}
	if cfg.ApprovalDefault != ModeQueue {
		t.Errorf("approval_default = %q, want %q", cfg.ApprovalDefault, ModeQueue)
	}
	// the unit's directories and the logrotate glob
	for field, got := range map[string]string{
		"socket_path":          cfg.SocketPath,
		"approver_socket_path": cfg.ApproverSocketPath,
		"pid_file":             cfg.PidFile,
		"state_dir":            cfg.StateDir,
		"log_path":             cfg.LogPath,
	} {
		want := map[string]string{
			"socket_path": "/run/tmb/", "approver_socket_path": "/run/tmb/", "pid_file": "/run/tmb/",
			"state_dir": "/var/lib/tmb", "log_path": "/var/log/tmb/",
		}[field]
		if !strings.HasPrefix(got, want) {
			t.Errorf("%s = %q, want it under %s", field, got, want)
		}
	}
	if !strings.HasSuffix(cfg.LogPath, ".jsonl") {
		t.Errorf("log_path %q does not match the logrotate glob /var/log/tmb/*.jsonl", cfg.LogPath)
	}
	if len(cfg.AllowedRequesterUIDs)+len(cfg.AllowedRequesterKeys)+len(cfg.ApproverUIDs) != 0 {
		t.Error("the example must not grant anyone: allowlists and approver_uids stay empty")
	}
}

// unitDirectives parses key=value lines of a systemd unit (no sections kept).
func unitDirectives(t *testing.T, path string) map[string][]string {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	out := map[string][]string{}
	for _, line := range strings.Split(string(b), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";") || strings.HasPrefix(line, "[") {
			continue
		}
		k, v, ok := strings.Cut(line, "=")
		if !ok {
			t.Fatalf("unit line without '=': %q", line)
		}
		out[k] = append(out[k], v)
	}
	return out
}

func TestPackagedUnitDirectives(t *testing.T) {
	d := unitDirectives(t, packagingFile(t, "tmb-broker.service"))
	want := map[string]string{
		"Type":               "simple",
		"User":               "root",
		"ExecStart":          "/usr/bin/tmb-broker -config /etc/tmb/config.json",
		"ExecReload":         "/bin/kill -HUP $MAINPID",
		"Restart":            "on-failure",
		"KillMode":           "process",
		"RuntimeDirectory":   "tmb",
		"StateDirectory":     "tmb",
		"StateDirectoryMode": "0700",
		"LogsDirectory":      "tmb",
		"LogsDirectoryMode":  "0750",
	}
	for k, v := range want {
		if got := d[k]; len(got) != 1 || got[0] != v {
			t.Errorf("%s = %q, want exactly [%q]", k, got, v)
		}
	}
	pre := strings.Join(d["ExecStartPre"], "\n")
	if !strings.Contains(pre, "test -f /etc/tmb/config.json") || !strings.Contains(pre, "config.json.example") {
		t.Errorf("ExecStartPre must refuse to start without /etc/tmb/config.json and name the example; got %q", pre)
	}
	// no systemd sandboxing: the broker runs arbitrary approved commands as root
	for k := range d {
		if strings.HasPrefix(k, "Protect") || strings.HasPrefix(k, "Private") || k == "NoNewPrivileges" ||
			k == "ReadOnlyPaths" || k == "CapabilityBoundingSet" || k == "SystemCallFilter" {
			t.Errorf("unit sets sandboxing directive %s", k)
		}
	}
}
