package sbom

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

// self is the running test binary: a real Go executable with build info.
func self(t *testing.T) string {
	t.Helper()
	p, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func TestWriteDescribesArtifactAndBinary(t *testing.T) {
	dir := t.TempDir()
	art := filepath.Join(dir, "tmb_1.2.3-1_amd64.deb")
	if err := os.WriteFile(art, []byte("package"), 0o600); err != nil {
		t.Fatal(err)
	}
	a := Artifact{Path: art, Type: "deb", Name: "tmb", Version: "1.2.3~dev+abc-1", Arch: "amd64"}
	o := Options{Version: "v1.2.3-dev+abc", Time: time.Unix(1700000000, 0), Supplier: "TMB", URL: "https://example.invalid/tmb"}
	var one, two bytes.Buffer
	if err := Write(&one, a, []Binary{{Name: "/usr/bin/tmb", Path: self(t)}}, o); err != nil {
		t.Fatal(err)
	}
	if err := Write(&two, a, []Binary{{Name: "/usr/bin/tmb", Path: self(t)}}, o); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(one.Bytes(), two.Bytes()) {
		t.Fatal("two BOMs of the same inputs differ")
	}

	var b bom
	if err := json.Unmarshal(one.Bytes(), &b); err != nil {
		t.Fatal(err)
	}
	if b.Format != "CycloneDX" || b.SpecVersion != "1.6" || !strings.HasPrefix(b.SerialNumber, "urn:uuid:") || len(b.SerialNumber) != 45 {
		t.Fatalf("header: %+v", b)
	}
	if b.Metadata.Timestamp != "2023-11-14T22:13:20Z" {
		t.Fatalf("timestamp %q, want the given commit time", b.Metadata.Timestamp)
	}
	root := b.Metadata.Component
	if sum, _ := fileSHA256(art); root.Purl != "pkg:deb/tmb@1.2.3~dev%2Babc-1?arch=amd64" || len(root.Hashes) != 1 || root.Hashes[0].Content != sum {
		t.Fatalf("root component: %+v", root)
	}
	var bin, std *component
	for i, c := range b.Components {
		switch {
		case c.Ref == "file:/usr/bin/tmb":
			bin = &b.Components[i]
		case c.Name == "stdlib":
			std = &b.Components[i]
		}
	}
	if bin == nil || std == nil {
		t.Fatalf("binary or stdlib component missing: %+v", b.Components)
	}
	if !strings.HasPrefix(bin.Purl, "pkg:golang/") || !strings.Contains(bin.Purl, "@v1.2.3-dev%2Babc") || bin.Version != o.Version {
		t.Fatalf("binary component: %+v", bin)
	}
	if want := "v" + strings.TrimPrefix(runtime.Version(), "go"); std.Version != want {
		t.Fatalf("stdlib version %q, want %q", std.Version, want)
	}
	deps := map[string][]string{}
	for _, d := range b.Dependencies {
		deps[d.Ref] = d.DependsOn
	}
	if len(deps[root.Ref]) != 1 || deps[root.Ref][0] != bin.Ref {
		t.Fatalf("root dependsOn %v", deps[root.Ref])
	}
	if !contains(deps[bin.Ref], std.Ref) {
		t.Fatalf("binary dependsOn %v, want stdlib", deps[bin.Ref])
	}
	if d, ok := deps[std.Ref]; !ok || len(d) != 0 {
		t.Fatalf("stdlib must be listed with no dependencies, got %v %v", d, ok)
	}
}

func contains(s []string, v string) bool {
	for _, x := range s {
		if x == v {
			return true
		}
	}
	return false
}

func TestSerialFollowsArtifact(t *testing.T) {
	if serial("a") == serial("b") {
		t.Fatal("different artifacts share a serial number")
	}
	if s := serial("a"); s[23] != '5' {
		t.Fatalf("%s is not version 5 shaped", s)
	}
}

func TestWriteRejectsBadInput(t *testing.T) {
	dir := t.TempDir()
	art := filepath.Join(dir, "a")
	notGo := filepath.Join(dir, "plain")
	for _, f := range []string{art, notGo} {
		if err := os.WriteFile(f, []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	good := Artifact{Path: art, Type: "rpm", Name: "tmb", Version: "1-1", Arch: "x86_64"}
	bin := []Binary{{Name: "/usr/bin/tmb", Path: self(t)}}
	o := Options{Version: "v1.0.0"}
	cases := map[string]func() error{
		"unknown type":     func() error { a := good; a.Type = "zip"; return Write(&bytes.Buffer{}, a, bin, o) },
		"archive needs OS": func() error { a := good; a.Type = "archive"; return Write(&bytes.Buffer{}, a, bin, o) },
		"no binaries":      func() error { return Write(&bytes.Buffer{}, good, nil, o) },
		"no version":       func() error { return Write(&bytes.Buffer{}, good, bin, Options{}) },
		"missing artifact": func() error {
			a := good
			a.Path = filepath.Join(dir, "missing")
			return Write(&bytes.Buffer{}, a, bin, o)
		},
		"not a Go binary": func() error { return Write(&bytes.Buffer{}, good, []Binary{{Name: "x", Path: notGo}}, o) },
		"duplicate binary": func() error {
			return Write(&bytes.Buffer{}, good, append(bin, bin[0]), o)
		},
	}
	for name, f := range cases {
		if err := f(); err == nil {
			t.Errorf("%s: no error", name)
		}
	}
}
