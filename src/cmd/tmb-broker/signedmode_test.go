package main

import (
	"path/filepath"
	"strings"
	"testing"
)

// require_signed_decision binds only the queue: a broker whose approval
// mode is another one (approval_default or -approval) would approve
// without any signature, so it does not start with the setting, and a
// reload that turns it on there is refused (reload_failed).
func TestRequireSignedNeedsQueueMode(t *testing.T) {
	noChown(t)
	a := newFakeSigner(t, "mac")
	signed := func(mode string) func(*Config) {
		return func(c *Config) {
			c.ApprovalDefault = mode
			c.RequireSignedDecision = true
			c.ApproverKeys = []ApproverKey{a.entry()}
		}
	}
	for name, c := range map[string]struct {
		edit func(*Config)
		args []string
	}{
		"approval_default manual":       {signed(ModeManual), nil},
		"approval_default mock-approve": {signed(ModeMockApprove), nil},
		"-approval manual":              {signed(ModeQueue), []string{"-approval", ModeManual}},
		"-approval mock-approve":        {signed(ModeQueue), []string{"-approval", ModeMockApprove}},
	} {
		path, _ := brokerFiles(t, c.edit)
		code, out := runBroker(t, append([]string{"-config", path}, c.args...)...)
		if code != 1 || !strings.Contains(out, "require_signed_decision") {
			t.Errorf("%s: exit %d, %q; want exit 1 naming require_signed_decision", name, code, out)
		}
	}

	dir := t.TempDir()
	path := filepath.Join(dir, "config.json")
	writeJSONConfig(t, path, reloadConfig(dir, nil))
	b := reloadBroker(t, path, ModeManual)
	writeJSONConfig(t, path, reloadConfig(dir, map[string]any{"approver_keys": []ApproverKey{a.entry()}, "require_signed_decision": true}))
	b.Reload(path)
	if ev := lastEvent(t, b, "reload_failed"); !strings.Contains(ev["error"].(string), "require_signed_decision") {
		t.Errorf("reload_failed %v", ev)
	}
	if b.conf().RequireSignedDecision {
		t.Error("the reload turned require_signed_decision on in manual mode")
	}
}
