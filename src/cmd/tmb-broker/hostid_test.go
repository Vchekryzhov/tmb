package main

import (
	"errors"
	"path/filepath"
	"strings"
	"testing"
)

// Without host_id in the config and without a readable host name the
// broker does not start and a reload fails: host_id is never empty.
func TestHostIDDefaultNeedsAHostName(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.json")
	writeJSONConfig(t, path, reloadConfig(dir, map[string]any{"host_id": "build-01"}))
	b := reloadBroker(t, path, ModeQueue)

	orig := hostname
	t.Cleanup(func() { hostname = orig })
	for name, h := range map[string]func() (string, error){
		"error": func() (string, error) { return "", errors.New("injected") },
		"empty": func() (string, error) { return "", nil },
	} {
		hostname = h
		writeJSONConfig(t, path, reloadConfig(dir, nil))
		if _, err := loadConfig(path); err == nil || !strings.Contains(err.Error(), "host_id is empty") {
			t.Errorf("%s: loadConfig %v, want a host_id error", name, err)
		}
		b.Reload(path)
		if ev := lastEvent(t, b, "reload_failed"); !strings.Contains(ev["error"].(string), "host_id is empty") {
			t.Errorf("%s: reload_failed %v", name, ev)
		}
		if b.conf().HostID != "build-01" {
			t.Errorf("%s: host_id %q after a failed reload", name, b.conf().HostID)
		}
	}
}
