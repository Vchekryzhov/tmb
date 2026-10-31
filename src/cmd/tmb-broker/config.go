// PROTOTYPE CODE - throwaway PoC, not production.
package main

import (
	"crypto/ecdsa"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"tmb-poc/internal/proto"
)

// Config is broker-side configuration (loaded from JSON). The env allowlist,
// shell deny list, and requester identity allowlists are BROKER POLICY -
// never request data. Allowlist entries are per identity kind: uids for the
// unix (SO_PEERCRED) listener, public key fingerprints (SHA-256 of the
// SubjectPublicKeyInfo, ADR 0005) for the TLS listener.
type Config struct {
	SocketPath           string            `json:"socket_path"`
	StateDir             string            `json:"state_dir"`
	LogPath              string            `json:"log_path"`
	PidFile              string            `json:"pid_file"`
	AllowedRequesterUIDs []uint32          `json:"allowed_requester_uids"`
	AllowedRequesterKeys []string          `json:"allowed_requester_keys"` // key fingerprints (SPKI SHA-256)
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
	// ApprovalWaitSeconds bounds how long a queued request waits for a
	// decision (default 300); independent of token_ttl_seconds.
	ApprovalWaitSeconds int `json:"approval_wait_seconds"`
	// TLS listener (second listener, mTLS only). When tls_addr is set, all
	// three files must be set as well; empty tls_addr keeps the broker
	// unix-socket-only.
	TLSAddr     string `json:"tls_addr"`
	TLSCAFile   string `json:"tls_ca_file"`
	TLSCertFile string `json:"tls_cert_file"`
	TLSKeyFile  string `json:"tls_key_file"`
	// Trusted signer (ADR 0006, ADR 0007). host_id names this host in every
	// approval payload (default: the host name). approver_keys are the
	// public keys whose signature over a payload counts as a decision; with
	// require_signed_decision an unsigned approve is refused.
	// required_signatures (default 1) is how many signatures by different
	// keys approve an item (ADR 0007, Р2). All four reload on SIGHUP.
	HostID                string        `json:"host_id"`
	ApproverKeys          []ApproverKey `json:"approver_keys"`
	RequireSignedDecision bool          `json:"require_signed_decision"`
	RequiredSignatures    int           `json:"required_signatures"`
}

// ApproverKey is one approver_keys entry (ADR 0007, Р1): a name for the
// journal, the key class and the base64 DER SubjectPublicKeyInfo of an
// ECDSA P-256 key. A signed decide names the key by its fingerprint
// (SHA-256 of that SPKI, ADR 0005).
type ApproverKey struct {
	Name      string `json:"name"`
	Class     string `json:"class"`
	PublicKey string `json:"public_key"`
}

// Approver key classes (ADR 0007, Р1). Only mac-se is implemented; ios-se
// and u2f are reserved, and a config that lists them is refused.
const (
	KeyClassMacSE = "mac-se"
	KeyClassIOSSE = "ios-se"
	KeyClassU2F   = "u2f"
)

// approverKey is a parsed approver_keys entry.
type approverKey struct {
	name, class, fp string
	pub             *ecdsa.PublicKey
}

// parseApproverKeys checks approver_keys and indexes them by fingerprint:
// every class is implemented, every name and every key appears once.
func parseApproverKeys(entries []ApproverKey) (map[string]approverKey, error) {
	out := map[string]approverKey{}
	names := map[string]bool{}
	for i, e := range entries {
		switch e.Class {
		case KeyClassMacSE:
		case KeyClassIOSSE, KeyClassU2F:
			return nil, fmt.Errorf("config: approver_keys[%d] %q: class %s is reserved and not implemented", i, e.Name, e.Class)
		default:
			return nil, fmt.Errorf("config: approver_keys[%d] %q: unknown class %q (want %s)", i, e.Name, e.Class, KeyClassMacSE)
		}
		if e.Name == "" || names[e.Name] {
			return nil, fmt.Errorf("config: approver_keys[%d]: name %q is empty or repeated", i, e.Name)
		}
		names[e.Name] = true
		pub, fp, err := proto.ParseApproverPublicKey(e.PublicKey)
		if err != nil {
			return nil, fmt.Errorf("config: approver_keys[%d] %q: %v", i, e.Name, err)
		}
		if _, dup := out[fp]; dup {
			return nil, fmt.Errorf("config: approver_keys[%d] %q: the same key is listed twice", i, e.Name)
		}
		out[fp] = approverKey{name: e.Name, class: e.Class, fp: fp, pub: pub}
	}
	return out, nil
}

// checkThreshold applies the ADR 0007 Р2 rules to required_signatures
// (0 means the default 1): a threshold above 1 counts signatures, so it
// needs require_signed_decision, and with signed decisions required the
// threshold must be reachable with the listed keys.
func checkThreshold(c *Config, keys int) error {
	if c.RequiredSignatures < 0 {
		return fmt.Errorf("config: required_signatures %d is negative", c.RequiredSignatures)
	}
	if c.RequiredSignatures == 0 {
		c.RequiredSignatures = 1
	}
	if c.RequiredSignatures > 1 && !c.RequireSignedDecision {
		return fmt.Errorf("config: required_signatures %d needs require_signed_decision: an unsigned approve would bypass the threshold", c.RequiredSignatures)
	}
	if c.RequireSignedDecision && c.RequiredSignatures > keys {
		return fmt.Errorf("config: require_signed_decision with required_signatures %d needs at least %d approver_keys entries, have %d: no approve could ever be accepted", c.RequiredSignatures, c.RequiredSignatures, keys)
	}
	return nil
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
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(b, &fields); err == nil {
		if _, old := fields["allowed_requester_fps"]; old {
			return nil, fmt.Errorf("config: allowed_requester_fps was replaced by allowed_requester_keys: list key fingerprints (SHA-256 of the public key; tmb fingerprint FILE or tmb-broker ca issue-sandbox prints them)")
		}
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
	if c.ApprovalWaitSeconds <= 0 {
		c.ApprovalWaitSeconds = 300
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
	if c.HostID == "" {
		h, err := os.Hostname()
		if err != nil || h == "" {
			return nil, fmt.Errorf("config: host_id is empty and the host name is unknown (%v)", err)
		}
		c.HostID = h
	}
	keys, err := parseApproverKeys(c.ApproverKeys)
	if err != nil {
		return nil, err
	}
	if err := checkThreshold(&c, len(keys)); err != nil {
		return nil, err
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
