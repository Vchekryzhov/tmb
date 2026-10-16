// PROTOTYPE CODE - throwaway PoC, not production.
package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
)

// Config is broker-side configuration (loaded from JSON). The env allowlist,
// shell deny list, and requester identity allowlists are BROKER POLICY -
// never request data. Allowlist entries are per identity kind: uids for the
// unix (SO_PEERCRED) listener, certificate fingerprints for the TLS
// listener.
type Config struct {
	SocketPath           string            `json:"socket_path"`
	StateDir             string            `json:"state_dir"`
	LogPath              string            `json:"log_path"`
	PidFile              string            `json:"pid_file"`
	AllowedRequesterUIDs []uint32          `json:"allowed_requester_uids"`
	AllowedRequesterFPs  []string          `json:"allowed_requester_fps"`
	SocketGID            uint32            `json:"socket_gid"`
	AllowedEnvKeys       []string          `json:"allowed_env_keys"`
	FixedEnv             map[string]string `json:"fixed_env"`
	ShellDenyList        []string          `json:"shell_deny_list"`
	// AllowedCwdRoots are the directories a request's cwd must lie in
	// (realpath equal to a root or below it). Empty denies every cwd.
	AllowedCwdRoots []string `json:"allowed_cwd_roots"`
	TokenTTLSeconds int      `json:"token_ttl_seconds"`
	ApprovalDefault string   `json:"approval_default"` // empty = queue
	// Approver role (ADR 0004): its own unix socket, SO_PEERCRED only, and
	// its own uid list, separate from the requester allowlist.
	ApproverSocketPath string   `json:"approver_socket_path"`
	ApproverUIDs       []uint32 `json:"approver_uids"`
	// TLS listener (second listener, mTLS only). When tls_addr is set (config
	// or -tls-addr flag), all three files must be set as well; empty
	// tls_addr keeps the broker unix-socket-only.
	TLSAddr     string `json:"tls_addr"`
	TLSCAFile   string `json:"tls_ca_file"`
	TLSCertFile string `json:"tls_cert_file"`
	TLSKeyFile  string `json:"tls_key_file"`
}

func loadConfig(path string) (*Config, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var c Config
	if err := json.Unmarshal(b, &c); err != nil {
		return nil, err
	}
	if c.SocketPath == "" || c.StateDir == "" || c.LogPath == "" {
		return nil, fmt.Errorf("config: socket_path/state_dir/log_path are required")
	}
	if c.TokenTTLSeconds <= 0 {
		c.TokenTTLSeconds = 60
	}
	if c.PidFile == "" {
		c.PidFile = "/var/run/tmb-broker.pid"
	}
	if c.ApprovalDefault == "" {
		c.ApprovalDefault = ModeQueue
	}
	if c.ApproverSocketPath == "" {
		c.ApproverSocketPath = "/run/tmb/approve.sock"
	}
	if c.ApproverSocketPath == c.SocketPath {
		return nil, fmt.Errorf("config: approver_socket_path must differ from socket_path")
	}
	for _, k := range c.AllowedEnvKeys {
		if k == "PATH" {
			return nil, fmt.Errorf("config: allowed_env_keys must not contain PATH: the search path comes only from fixed_env")
		}
	}
	roots, err := normalizeCwdRoots(c.AllowedCwdRoots)
	if err != nil {
		return nil, err
	}
	c.AllowedCwdRoots = roots
	return &c, nil
}

// normalizeCwdRoots cleans every root and resolves it to its realpath, so the
// check compares realpaths on both sides. A relative root is a config error.
// A root that does not exist yet keeps its cleaned path: no existing cwd can
// resolve below it until it is created.
func normalizeCwdRoots(roots []string) ([]string, error) {
	out := make([]string, 0, len(roots))
	for _, r := range roots {
		if !filepath.IsAbs(r) {
			return nil, fmt.Errorf("config: allowed_cwd_roots entry %q is not an absolute path", r)
		}
		clean := filepath.Clean(r)
		if real, err := filepath.EvalSymlinks(clean); err == nil {
			clean = real
		} else if !os.IsNotExist(err) {
			return nil, fmt.Errorf("config: allowed_cwd_roots entry %q: %v", r, err)
		}
		out = append(out, clean)
	}
	return out, nil
}
