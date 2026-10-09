// PROTOTYPE CODE - throwaway PoC, not production.
package main

import (
	"encoding/json"
	"fmt"
	"os"
)

// Config is broker-side configuration (loaded from JSON). The env allowlist,
// shell deny list, and requester uid allowlist are BROKER POLICY - never
// request data.
type Config struct {
	SocketPath           string            `json:"socket_path"`
	StateDir             string            `json:"state_dir"`
	LogPath              string            `json:"log_path"`
	PidFile              string            `json:"pid_file"`
	AllowedRequesterUIDs []uint32          `json:"allowed_requester_uids"`
	SocketGID            uint32            `json:"socket_gid"`
	AllowedEnvKeys       []string          `json:"allowed_env_keys"`
	FixedEnv             map[string]string `json:"fixed_env"`
	ShellDenyList        []string          `json:"shell_deny_list"`
	TokenTTLSeconds      int               `json:"token_ttl_seconds"`
	ApprovalDefault      string            `json:"approval_default"`
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
	return &c, nil
}
