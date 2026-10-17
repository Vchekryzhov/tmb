package main

import (
	"os"
	"path/filepath"
	"testing"

	"tmb-poc/internal/buildinfo"
)

// TestMainPrintsVersion runs main with -version: it prints
// "tmb-broker <version>" and returns before reading any config.
func TestMainPrintsVersion(t *testing.T) {
	oldArgs, oldOut, oldVer := os.Args, os.Stdout, buildinfo.Version
	defer func() { os.Args, os.Stdout, buildinfo.Version = oldArgs, oldOut, oldVer }()
	out, err := os.Create(filepath.Join(t.TempDir(), "stdout"))
	if err != nil {
		t.Fatal(err)
	}
	defer out.Close()
	buildinfo.Version = "v9.8.7"
	os.Args, os.Stdout = []string{"tmb-broker", "-version"}, out
	main()
	os.Stdout = oldOut
	got, err := os.ReadFile(out.Name())
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "tmb-broker v9.8.7\n" {
		t.Fatalf("tmb-broker -version printed %q", got)
	}
}
