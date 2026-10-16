package main

import (
	"os"
	"path/filepath"
	"testing"
)

// The log holds request argv and env, so a broker-created log and its
// directory must be owner-only.
func TestNewLoggerCreatesOwnerOnly(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "log")
	path := filepath.Join(dir, "broker.log")
	l, err := NewLogger(path)
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	for p, want := range map[string]os.FileMode{dir: 0o700, path: 0o600} {
		st, err := os.Stat(p)
		if err != nil {
			t.Fatal(err)
		}
		if got := st.Mode().Perm(); got != want {
			t.Errorf("%s mode = %o, want %o", p, got, want)
		}
	}
}

func TestNewLoggerMkdirFails(t *testing.T) {
	file := filepath.Join(t.TempDir(), "file")
	if err := os.WriteFile(file, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := NewLogger(filepath.Join(file, "sub", "broker.log")); err == nil {
		t.Fatal("NewLogger under a regular file: want error")
	}
}
