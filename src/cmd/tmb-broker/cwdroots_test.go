package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func writeConfig(t *testing.T, roots string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "config.json")
	body := `{"socket_path": "/run/tmb/tmb.sock", "state_dir": "/var/lib/tmb-proto",
  "log_path": "/var/log/tmb/broker.log", "allowed_cwd_roots": ` + roots + `}`
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}
	return path
}

func TestLoadConfigNormalizesCwdRoots(t *testing.T) {
	dir, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatalf("realpath: %v", err)
	}
	real := filepath.Join(dir, "work")
	if err := os.Mkdir(real, 0o750); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	link := filepath.Join(dir, "link")
	if err := os.Symlink(real, link); err != nil {
		t.Fatalf("symlink: %v", err)
	}
	missing := filepath.Join(dir, "missing")
	c, err := loadConfig(writeConfig(t, `["`+link+`/", "`+real+`/./", "`+missing+`/../missing"]`))
	if err != nil {
		t.Fatalf("loadConfig: %v", err)
	}
	want := []string{real, real, missing}
	if strings.Join(c.AllowedCwdRoots, ",") != strings.Join(want, ",") {
		t.Fatalf("roots = %q, want %q", c.AllowedCwdRoots, want)
	}
}

func TestLoadConfigRejectsRelativeCwdRoot(t *testing.T) {
	_, err := loadConfig(writeConfig(t, `["/tmp", "work/dir"]`))
	if err == nil || !strings.Contains(err.Error(), `"work/dir"`) {
		t.Fatalf("loadConfig = %v, want an error naming work/dir", err)
	}
}

func TestLoadConfigWithoutCwdRootsAllowsNothing(t *testing.T) {
	c, err := loadConfig(writeConfig(t, `[]`))
	if err != nil {
		t.Fatalf("loadConfig: %v", err)
	}
	b := &Broker{cfg: c}
	if b.cwdAllowed("/tmp") || b.cwdAllowed("/") {
		t.Fatalf("empty allowed_cwd_roots must deny every cwd")
	}
}

func TestCwdAllowedMatchesRootOrBelow(t *testing.T) {
	b := &Broker{cfg: &Config{AllowedCwdRoots: []string{"/srv/work", "/opt"}}}
	for cwd, want := range map[string]bool{
		"/srv/work":     true,
		"/srv/work/a/b": true,
		"/srv/workshop": false, // prefix without a separator is not inside
		"/srv":          false,
		"/opt/x":        true,
		"/etc":          false,
	} {
		if got := b.cwdAllowed(cwd); got != want {
			t.Errorf("cwdAllowed(%q) = %v, want %v", cwd, got, want)
		}
	}
	root := &Broker{cfg: &Config{AllowedCwdRoots: []string{"/"}}}
	if !root.cwdAllowed("/etc") {
		t.Errorf("root / must allow every cwd")
	}
}

// A cwd outside the roots is denied in validation, before any approval, with
// the resolved realpath as detail: a symlink inside a root does not help.
func TestValidateRequestDeniesCwdOutsideRoots(t *testing.T) {
	b := newTestBroker(t)
	inside, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatalf("realpath: %v", err)
	}
	outside, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatalf("realpath: %v", err)
	}
	link := filepath.Join(inside, "escape")
	if err := os.Symlink(outside, link); err != nil {
		t.Fatalf("symlink: %v", err)
	}
	b.cfg.AllowedCwdRoots = []string{inside}

	req := testReq(t, "cwd-roots-1")
	req.Cwd = link
	if _, _, _, _, deny, detail := b.validateRequest(req); deny != "cwd_not_allowed" || detail != outside {
		t.Fatalf("symlink out of root: deny=%q detail=%q, want cwd_not_allowed %q", deny, detail, outside)
	}
	req.Cwd = inside
	if _, _, _, _, deny, _ := b.validateRequest(req); deny != "" {
		t.Fatalf("cwd at the root: deny=%q, want none", deny)
	}
}
