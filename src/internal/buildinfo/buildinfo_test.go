package buildinfo

import (
	"bytes"
	"testing"
)

func TestHandleVersion(t *testing.T) {
	old := Version
	Version = "v1.2.3"
	defer func() { Version = old }()
	for _, args := range [][]string{{"-version"}, {"--version"}, {"version"}} {
		var out bytes.Buffer
		if !HandleVersion("tmb-broker", args, &out) {
			t.Fatalf("%v: not handled", args)
		}
		if got := out.String(); got != "tmb-broker v1.2.3\n" {
			t.Fatalf("%v: printed %q", args, got)
		}
	}
	for _, args := range [][]string{nil, {"-config", "x"}, {"-version", "extra"}, {"exec"}, {"-v"}} {
		var out bytes.Buffer
		if HandleVersion("tmb", args, &out) || out.Len() != 0 {
			t.Fatalf("%v: handled or printed %q", args, out.String())
		}
	}
}

func TestDefaultVersion(t *testing.T) {
	if Version != "dev" {
		t.Fatalf("default Version %q, want dev (set only by -ldflags -X)", Version)
	}
}
