package dist

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"io"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestWriteTarGzIsDeterministic(t *testing.T) {
	dir := t.TempDir()
	a := filepath.Join(dir, "a")
	b := filepath.Join(dir, "b")
	if err := os.WriteFile(a, []byte("client"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(b, []byte("readme"), 0o644); err != nil {
		t.Fatal(err)
	}
	mtime := time.Unix(1700000000, 0)
	var one, two bytes.Buffer
	if err := WriteTarGz(&one, []File{{Name: "tmb", Path: a, Mode: 0o755}, {Name: "README", Path: b, Mode: 0o644}}, mtime); err != nil {
		t.Fatal(err)
	}
	// different order, different file mtimes on disk: same bytes
	if err := os.Chtimes(a, time.Now(), time.Now()); err != nil {
		t.Fatal(err)
	}
	if err := WriteTarGz(&two, []File{{Name: "README", Path: b, Mode: 0o644}, {Name: "tmb", Path: a, Mode: 0o755}}, mtime); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(one.Bytes(), two.Bytes()) {
		t.Fatal("two archives of the same files differ")
	}

	gz, err := gzip.NewReader(bytes.NewReader(one.Bytes()))
	if err != nil {
		t.Fatal(err)
	}
	if gz.Name != "" || !gz.ModTime.IsZero() {
		t.Fatalf("gzip header carries name %q / time %v", gz.Name, gz.ModTime)
	}
	tr := tar.NewReader(gz)
	var names []string
	for {
		h, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		names = append(names, h.Name)
		if h.Uid != 0 || h.Gid != 0 || h.Uname != "root" || !h.ModTime.Equal(mtime) {
			t.Fatalf("%s: owner %d:%d %s, mtime %v", h.Name, h.Uid, h.Gid, h.Uname, h.ModTime)
		}
		if h.Name == "tmb" && h.Mode != 0o755 {
			t.Fatalf("tmb mode %o", h.Mode)
		}
	}
	if len(names) != 2 || names[0] != "README" || names[1] != "tmb" {
		t.Fatalf("entries %v, want sorted [README tmb]", names)
	}
}

func TestWriteTarGzErrors(t *testing.T) {
	var buf bytes.Buffer
	if err := WriteTarGz(&buf, []File{{Name: "x", Path: filepath.Join(t.TempDir(), "missing")}}, time.Unix(0, 0)); err == nil {
		t.Fatal("missing file accepted")
	}
	p := filepath.Join(t.TempDir(), "f")
	if err := os.WriteFile(p, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := WriteTarGz(&buf, []File{{Name: "x", Path: p}, {Name: "x", Path: p}}, time.Unix(0, 0)); err == nil {
		t.Fatal("duplicate entry accepted")
	}
}

func TestParseFile(t *testing.T) {
	f, err := ParseFile("tmb=out/tmb-linux-amd64")
	if err != nil || f.Name != "tmb" || f.Path != "out/tmb-linux-amd64" || f.Mode != 0o755 {
		t.Fatalf("got %+v, %v", f, err)
	}
	for _, bad := range []string{"tmb", "=x", "tmb=", "/abs=x", "../up=x"} {
		if _, err := ParseFile(bad); err == nil {
			t.Fatalf("%q accepted", bad)
		}
	}
}
