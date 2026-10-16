package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"tmb-poc/internal/proto"
)

func envBroker() *Broker {
	return &Broker{cfg: &Config{
		AllowedEnvKeys: []string{"LANG", "TZ"},
		FixedEnv:       map[string]string{"PATH": "/usr/bin:/bin", "LANG": "C.UTF-8"},
	}}
}

func TestCheckEnvPolicy(t *testing.T) {
	b := envBroker()
	for _, tc := range []struct {
		name string
		env  map[string]string
		deny string
	}{
		{"allowed key", map[string]string{"TZ": "UTC"}, ""},
		{"no env", nil, ""},
		{"empty key", map[string]string{"": "x"}, "env_key_invalid"},
		{"key with =", map[string]string{"A=B": "x"}, "env_key_invalid"},
		{"key with NUL", map[string]string{"A\x00": "x"}, "env_key_invalid"},
		{"fixed and allowlisted", map[string]string{"LANG": "ru_RU.UTF-8"}, "env_fixed_key"},
		{"fixed with its own value", map[string]string{"LANG": "C.UTF-8"}, "env_fixed_key"},
		{"fixed PATH", map[string]string{"PATH": "/evil"}, "env_key_not_allowed"},
		{"not allowlisted", map[string]string{"LD_PRELOAD": "/x.so"}, "env_key_not_allowed"},
		{"newline", map[string]string{"TZ": "UTC\nX=1"}, "env_value_invalid"},
		{"NUL", map[string]string{"TZ": "UTC\x00"}, "env_value_invalid"},
		{"4096 bytes", map[string]string{"TZ": strings.Repeat("a", 4096)}, ""},
		{"4097 bytes", map[string]string{"TZ": strings.Repeat("a", 4097)}, "env_value_too_long"},
		// key checks come before value checks, and keys are checked sorted
		{"fixed key with bad value", map[string]string{"LANG": "a\nb"}, "env_fixed_key"},
		{"sorted keys", map[string]string{"TZ": "a\nb", "LD_PRELOAD": "x"}, "env_key_not_allowed"},
	} {
		if deny, _ := b.checkEnv(tc.env); deny != tc.deny {
			t.Errorf("%s: deny = %q, want %q", tc.name, deny, tc.deny)
		}
	}
}

// PATH can never be requested, with or without a fixed value.
func TestCheckEnvPathNotRequestable(t *testing.T) {
	b := &Broker{cfg: &Config{AllowedEnvKeys: []string{"LANG"}}}
	if deny, detail := b.checkEnv(map[string]string{"PATH": "/evil"}); deny != "env_key_not_allowed" || detail != "PATH" {
		t.Fatalf("PATH request: deny=%q detail=%q, want env_key_not_allowed PATH", deny, detail)
	}
}

// The fixed value wins over a requested one whatever the map iteration
// order, and an allowlisted non-fixed key passes through.
func TestBuildEnvFixedKeyWins(t *testing.T) {
	b := envBroker()
	req := &proto.Request{Env: map[string]string{"LANG": "ru_RU.UTF-8", "TZ": "UTC", "PATH": "/evil", "LD_PRELOAD": "/x.so"}}
	want := "LANG=C.UTF-8,PATH=/usr/bin:/bin,TZ=UTC"
	for i := 0; i < 50; i++ {
		if got := strings.Join(b.buildEnv(req), ","); got != want {
			t.Fatalf("buildEnv = %s, want %s", got, want)
		}
	}
}

func TestLoadConfigRejectsPathInAllowedEnvKeys(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.json")
	body := `{"socket_path": "/run/tmb/tmb.sock", "state_dir": "/var/lib/tmb-proto",
  "log_path": "/var/log/tmb/broker.log", "allowed_env_keys": ["LANG", "PATH"]}`
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}
	if _, err := loadConfig(path); err == nil || !strings.Contains(err.Error(), "PATH") {
		t.Fatalf("loadConfig = %v, want an error naming PATH", err)
	}
}

// The env policy runs in validation, before any approval.
func TestValidateRequestAppliesEnvPolicy(t *testing.T) {
	b := newTestBroker(t)
	b.cfg.FixedEnv = map[string]string{"PATH": "/usr/bin:/bin", "LANG": "C.UTF-8"}
	req := testReq(t, "env-policy-1")
	if _, _, _, _, deny, detail := b.validateRequest(req); deny != "env_fixed_key" || detail != "LANG" {
		t.Fatalf("validateRequest: deny=%q detail=%q, want env_fixed_key LANG", deny, detail)
	}
}
