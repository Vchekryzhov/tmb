package coverage_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"tmb-ci/internal/coverage"
)

const unitProfile = `mode: atomic
m/a/a.go:1.1,2.2 3 1
m/a/a.go:4.1,5.2 2 0
m/b/b.go:1.1,3.2 4 0
`

// the integration binary links only m/a and m/c
const integProfile = `mode: atomic
m/a/a.go:1.1,2.2 3 2
m/a/a.go:4.1,5.2 2 5
m/c/c.go:1.1,2.2 1 1
`

func TestMergeIsTheUnion(t *testing.T) {
	u, i := profile(t, unitProfile), profile(t, integProfile)
	m, err := coverage.Merge(u, i)
	if err != nil {
		t.Fatal(err)
	}
	if got := m.Total(); got.Covered != 6 || got.Total != 10 {
		t.Fatalf("merged total %+v, want 6 of 10", got)
	}
	if n := i.OnlyIn(u); n != 3 {
		t.Fatalf("integration-only statements %d, want 3 (a.go:4 and c.go)", n)
	}
	var sb strings.Builder
	if err := m.Write(&sb); err != nil {
		t.Fatal(err)
	}
	want := "mode: atomic\nm/a/a.go:1.1,2.2 3 3\nm/a/a.go:4.1,5.2 2 5\nm/b/b.go:1.1,3.2 4 0\nm/c/c.go:1.1,2.2 1 1\n"
	if sb.String() != want {
		t.Fatalf("written profile:\n%s\nwant:\n%s", sb.String(), want)
	}
	if back := profile(t, sb.String()); back.Total() != m.Total() {
		t.Fatal("written profile does not read back to the same totals")
	}
}

func TestMergeRejectsIncomparableProfiles(t *testing.T) {
	u := profile(t, unitProfile)
	if _, err := coverage.Merge(u, profile(t, strings.Replace(integProfile, "atomic", "set", 1))); err == nil {
		t.Fatal("different modes merged")
	}
	if _, err := coverage.Merge(u, profile(t, "mode: atomic\nm/a/a.go:1.1,2.2 4 1\n")); err == nil {
		t.Fatal("one block with different statement counts merged")
	}
	if _, err := coverage.Merge(); err == nil {
		t.Fatal("empty merge accepted")
	}
}

func write(t *testing.T, path, text string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(text), 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestAccountCovdata(t *testing.T) {
	dir := t.TempDir()
	// host: broker 10 stopped with counters, 11 killed (no stop, no counters),
	// 12 started twice in two journal files, counters present
	write(t, filepath.Join(dir, "host", "covdata", "covmeta.abc"), "")
	write(t, filepath.Join(dir, "host", "covdata", "covcounters.abc.10.1"), "")
	write(t, filepath.Join(dir, "host", "covdata", "covcounters.abc.12.2"), "")
	write(t, filepath.Join(dir, "host", "covdata", "covcounters.abc.99.3"), "") // a client without journal events
	write(t, filepath.Join(dir, "host", "journal", "broker.log"),
		`{"event":"broker_start","pid":10}`+"\n"+`{"event":"broker_stop","pid":10}`+"\n"+`{"event":"broker_start","pid":11}`+"\nnot json\n"+`{"event":"broker_start","pid":12}`+"\n")
	write(t, filepath.Join(dir, "host", "journal", "broker.log.1"), `{"event":"broker_start","pid":12}`+"\n")
	write(t, filepath.Join(dir, "sandbox", "covdata", "covcounters.def.5.1"), "")
	r, err := coverage.AccountCovdata(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(r.Problems) != 0 || len(r.Containers) != 2 {
		t.Fatalf("report %+v", r)
	}
	h := r.Containers[0]
	if h.Name != "host" || h.Counters != 3 || h.Brokers != 3 || len(h.Killed) != 1 || h.Killed[0] != 11 {
		t.Fatalf("host %+v", h)
	}
	if s := r.Containers[1]; s.Counters != 1 || s.Brokers != 0 {
		t.Fatalf("sandbox %+v", s)
	}

	// a stopped broker without counters and a container without any counters
	write(t, filepath.Join(dir, "host", "journal", "broker.log.2"), `{"event":"broker_start","pid":13}`+"\n"+`{"event":"broker_stop","pid":13}`+"\n")
	write(t, filepath.Join(dir, "empty", "covdata", "covmeta.abc"), "")
	r, err = coverage.AccountCovdata(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(r.Problems) != 2 || !strings.Contains(strings.Join(r.Problems, "\n"), "pid 13") {
		t.Fatalf("problems %v", r.Problems)
	}
	if _, err := coverage.AccountCovdata(filepath.Join(dir, "missing")); err == nil {
		t.Fatal("missing directory accepted")
	}
	if r, _ := coverage.AccountCovdata(t.TempDir()); len(r.Problems) != 1 {
		t.Fatalf("empty directory: %v", r.Problems)
	}
}
