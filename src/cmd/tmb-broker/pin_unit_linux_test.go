package main

import (
	"os"
	"path/filepath"
	"syscall"
	"testing"
)

func statID(t *testing.T, path string) (uint64, uint64) {
	t.Helper()
	st, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	s := st.Sys().(*syscall.Stat_t)
	return uint64(s.Dev), uint64(s.Ino)
}

// Pinning fails closed when the executable or cwd is gone by the time the
// broker pins them.
func TestPinApprovalFailsClosed(t *testing.T) {
	dir := t.TempDir()
	exe := trueExe(t)
	dev, ino := statID(t, exe)

	p := &pendingApproval{}
	if code, _ := pinApproval(p, filepath.Join(dir, "gone"), dir, dev, ino); code != "exe_changed" {
		t.Fatalf("missing exe: code %q, want exe_changed", code)
	}
	p = &pendingApproval{}
	if code, _ := pinApproval(p, exe, filepath.Join(dir, "gone"), dev, ino); code != "cwd_invalid" {
		t.Fatalf("missing cwd: code %q, want cwd_invalid", code)
	}
	if p.ExeFile != nil {
		t.Fatal("a failed pin left the exe fd open")
	}
	if cwdStillPinned(filepath.Join(dir, "gone"), 1, 1) {
		t.Fatal("a missing cwd counts as still pinned")
	}
}

// When the stat seen at validation differs from the opened file, the pin
// is accepted only if the path now settles on exactly the opened file.
func TestPinExeAcceptsSettledPathOnly(t *testing.T) {
	exe := trueExe(t)
	dev, ino := statID(t, exe)
	f, pdev, pino, deny := pinExe(exe, dev, ino+1) // validation saw another inode
	if deny != "" || pdev != dev || pino != ino {
		t.Fatalf("settled path: deny %q, pinned %d/%d, want the file on disk", deny, pdev, pino)
	}
	f.Close()
}

func TestExecTargetWithoutPinUsesPath(t *testing.T) {
	p := &pendingApproval{ExePath: "/usr/bin/true"}
	if target, viaFd := p.execTarget(); target != "/usr/bin/true" || viaFd {
		t.Fatalf("execTarget = %q, %v; want the path, not an fd", target, viaFd)
	}
}
