package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"tmb-ci/internal/result"
)

const sha = "0123456789abcdef0123456789abcdef01234567"

// tmbci runs the CLI in-process with a fixed SHA, run and date, and returns
// the exit code, combined output and the result it wrote for check.
func tmbci(t *testing.T, check string, args ...string) (int, string, *result.Result) {
	t.Helper()
	out := t.TempDir()
	t.Setenv("TMB_CI_SHA", sha)
	t.Setenv("TMB_CI_RUN_ID", "7")
	t.Setenv("TMB_CI_TODAY", "2026-10-16")
	var buf strings.Builder
	code := run(append(args, "-out", out), &buf)
	if check == "" {
		return code, buf.String(), nil
	}
	f, err := os.Open(filepath.Join(out, strings.ReplaceAll(check, "/", "__")+".json"))
	if err != nil {
		t.Fatalf("no result for %s: %v\n%s", check, err, buf.String())
	}
	defer f.Close()
	r, err := result.Read(f)
	if err != nil {
		t.Fatal(err)
	}
	if r.SHA != sha || r.RunID != "7" || r.Schema != result.SchemaV1 {
		t.Fatalf("result not stamped with this run: %+v", r)
	}
	return code, buf.String(), &r
}

func td(name string) string { return filepath.Join("testdata", name) }

func TestGoTestFixtures(t *testing.T) {
	code, out, r := tmbci(t, "test/x", "gotest", "-check", "test/x", "-json", td("failing-test.json"), "-junit", filepath.Join(t.TempDir(), "j.xml"))
	if code != 1 || r.Status != result.Fail || !strings.Contains(out, "TestDial failed") {
		t.Fatalf("failing test: code %d status %s\n%s", code, r.Status, out)
	}
	code, out, r = tmbci(t, "test/x", "gotest", "-check", "test/x", "-json", td("passing-test.json"), "-junit", filepath.Join(t.TempDir(), "j.xml"))
	if code != 0 || r.Status != result.Pass {
		t.Fatalf("passing test: code %d status %s\n%s", code, r.Status, out)
	}
	code, _, r = tmbci(t, "test/x", "gotest", "-check", "test/x", "-json", td("missing.json"), "-junit", filepath.Join(t.TempDir(), "j.xml"))
	if code != 2 || r.Status != result.Error {
		t.Fatalf("unreadable report must be ERROR with a result: code %d status %s", code, r.Status)
	}
}

func TestScanFixtures(t *testing.T) {
	code, out, r := tmbci(t, "security/gosec", "scan", "-check", "security/gosec", "-scanner", "gosec", "-report", td("gosec-finding.json"), "-exceptions", td("exceptions-empty.json"), "-root", "/w/")
	if code != 1 || r.Status != result.Fail || !strings.Contains(out, "G204") {
		t.Fatalf("synthetic finding: code %d status %s\n%s", code, r.Status, out)
	}
	code, out, r = tmbci(t, "security/gosec", "scan", "-check", "security/gosec", "-scanner", "gosec", "-report", td("gosec-finding.json"), "-exceptions", td("exceptions-expired.json"), "-root", "/w/")
	if code != 1 || !strings.Contains(out, "expired") {
		t.Fatalf("expired exception: code %d status %s\n%s", code, r.Status, out)
	}
	code, _, r = tmbci(t, "security/gosec", "scan", "-check", "security/gosec", "-scanner", "gosec", "-report", td("empty.cov"), "-exceptions", td("exceptions-empty.json"), "-root", "/w/")
	if code != 2 || r.Status != result.Error {
		t.Fatalf("scanner output that is not a report must be ERROR: code %d status %s", code, r.Status)
	}
}

func TestCoverageFixtures(t *testing.T) {
	args := func(head, metaBase string) []string {
		return []string{"coverage", "-head", td(head), "-base", td("base.cov"), "-head-meta", td("meta.json"), "-base-meta", td(metaBase),
			"-diff", td("empty.diff"), "-module", "tmb-poc=src", "-policy", td("policy.json"), "-packages", td("packages.txt")}
	}
	code, out, r := tmbci(t, "coverage/compare", args("head-drop.cov", "meta.json")...)
	if code != 1 || r.Status != result.Fail || !strings.Contains(out, "total 100.0% -> 50.0%") {
		t.Fatalf("coverage drop: code %d status %s\n%s", code, r.Status, out)
	}
	code, _, r = tmbci(t, "coverage/compare", args("base.cov", "meta-darwin.json")...)
	if code != 2 || r.Status != result.Error {
		t.Fatalf("incomparable base must be ERROR: code %d status %s", code, r.Status)
	}
	code, _, r = tmbci(t, "coverage/compare", args("empty.cov", "meta.json")...)
	if code != 2 || r.Status != result.Error {
		t.Fatalf("empty head profile must be ERROR: code %d status %s", code, r.Status)
	}
	_, _, r = tmbci(t, "coverage/diff", args("base.cov", "meta.json")...)
	if r.Status != result.NotApplicable || r.Reason == "" {
		t.Fatalf("empty diff: status %s reason %q", r.Status, r.Reason)
	}
}

func TestGateFixtures(t *testing.T) {
	results := t.TempDir()
	write := func(check string, st result.Status, runID string) {
		r := result.Result{Schema: result.SchemaV1, Check: check, Status: st, SHA: sha, RunID: runID, Reason: "fixture"}
		if _, err := result.Write(results, r); err != nil {
			t.Fatal(err)
		}
	}
	gate := func(needs string) (int, string) {
		t.Setenv("TMB_CI_NEEDS", needs)
		code, out, _ := tmbci(t, "", "gate", "-requirements", td("required.json"), "-event", "pull_request", "-results", results, "-summary", filepath.Join(t.TempDir(), "s.md"))
		return code, out
	}
	ok := `{"lint":{"result":"success"},"coverage":{"result":"success"}}`

	write("lint/gofmt", result.Pass, "7")
	write("coverage/diff", result.NotApplicable, "7")
	if code, out := gate(ok); code != 0 {
		t.Fatalf("all green: code %d\n%s", code, out)
	}
	if code, out := gate(`{"lint":{"result":"success"},"coverage":{"result":"skipped"}}`); code != 1 || !strings.Contains(out, "job coverage: skipped") {
		t.Fatalf("skipped job: code %d\n%s", code, out)
	}
	write("lint/gofmt", result.Pass, "6")
	if code, out := gate(ok); code != 1 || !strings.Contains(out, "stale report") {
		t.Fatalf("stale report: code %d\n%s", code, out)
	}
	if code, out := gate(`not json`); code != 2 {
		t.Fatalf("unreadable needs context: code %d\n%s", code, out)
	}
}

func TestScanUnionOfReports(t *testing.T) {
	// linux and darwin builds are scanned separately; a finding in either
	// report counts, and an exception only needs to match one of them
	code, out, r := tmbci(t, "security/gosec", "scan", "-check", "security/gosec", "-scanner", "gosec",
		"-report", td("gosec-finding.json"), "-report", td("gosec-clean.json"), "-exceptions", td("exceptions-empty.json"), "-root", "/w/")
	if code != 1 || r.Status != result.Fail || !strings.Contains(out, "G204") {
		t.Fatalf("finding in the first report: code %d status %s\n%s", code, r.Status, out)
	}
}

func TestBadges(t *testing.T) {
	dir := t.TempDir()
	code, out, _ := tmbci(t, "", "badges", "-mode", "results", "-results", td("badges"), "-dir", dir)
	if code != 0 {
		t.Fatalf("results badges: code %d\n%s", code, out)
	}
	want := map[string]string{
		"coverage":    `"message": "46.6%"`,
		"image-vulns": `"message": "0 blocking, 70 informational"`,
		"gosec":       `"message": "0 blocking, 34 excepted, 33 informational"`,
		"govulncheck": `"message": "0 reachable"`,
		"secrets":     `"message": "0 blocking"`,
		"ci-results":  `"message": "8e3988abe1c2, run 38964567597"`,
	}
	for name, frag := range want {
		data, err := os.ReadFile(filepath.Join(dir, name+".json"))
		if err != nil || !strings.Contains(string(data), frag) || !strings.Contains(string(data), `"schemaVersion": 1`) {
			t.Errorf("%s: want %s, got %v\n%s", name, frag, err, data)
		}
	}
	if data, _ := os.ReadFile(filepath.Join(dir, "coverage.json")); !strings.Contains(string(data), `"color": "orange"`) {
		t.Errorf("46.6%% coverage must be orange:\n%s", data)
	}

	pins := td("badges/pins")
	tools := t.TempDir()
	code, out, _ = tmbci(t, "", "badges", "-mode", "tools", "-dir", tools, "-go-version", filepath.Join(pins, "go-version"), "-tools-lock", filepath.Join(pins, "tools.lock"), "-tools-dir", filepath.Join(pins, "tools"))
	if code != 0 {
		t.Fatalf("tool badges: code %d\n%s", code, out)
	}
	for name, msg := range map[string]string{"go": "1.27.2", "trivy": "0.75.0", "gitleaks": "8.30.1", "staticcheck": "v0.8.2", "gosec": "v2.29.0", "govulncheck": "v1.8.0", "actionlint": "v1.7.12"} {
		data, err := os.ReadFile(filepath.Join(tools, "tool-"+name+".json"))
		if err != nil || !strings.Contains(string(data), `"message": "`+msg+`"`) {
			t.Errorf("%s: want %s, got %v\n%s", name, msg, err, data)
		}
	}
	checkArgs := []string{"badges", "-mode", "tools", "-check", "-dir", tools, "-go-version", filepath.Join(pins, "go-version"), "-tools-lock", filepath.Join(pins, "tools.lock"), "-tools-dir", filepath.Join(pins, "tools")}
	if code, out, _ = tmbci(t, "", checkArgs...); code != 0 {
		t.Fatalf("fresh tool badges must pass -check: code %d\n%s", code, out)
	}
	if err := os.WriteFile(filepath.Join(tools, "tool-trivy.json"), []byte("{}\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if code, out, _ = tmbci(t, "", checkArgs...); code != 1 || !strings.Contains(out, "tool-trivy.json: differs") {
		t.Fatalf("stale tool badge must fail -check: code %d\n%s", code, out)
	}
}

func TestArchive(t *testing.T) {
	dir := t.TempDir()
	bin := filepath.Join(dir, "tmb")
	if err := os.WriteFile(bin, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	a, b := filepath.Join(dir, "a.tar.gz"), filepath.Join(dir, "b.tar.gz")
	for _, out := range []string{a, b} {
		if code, msg, _ := tmbci(t, "", "archive", "-file-out", out, "-mtime", "1700000000", "-file", "tmb="+bin); code != 0 {
			t.Fatalf("archive: code %d\n%s", code, msg)
		}
	}
	x, _ := os.ReadFile(a)
	y, _ := os.ReadFile(b)
	if len(x) == 0 || string(x) != string(y) {
		t.Fatal("two archives of one file differ or are empty")
	}
	for _, args := range [][]string{
		{"archive", "-mtime", "1", "-file", "tmb=" + bin},
		{"archive", "-file-out", a, "-file", "tmb=" + bin},
		{"archive", "-file-out", a, "-mtime", "1", "-file", "/abs=" + bin},
		{"archive", "-file-out", a, "-mtime", "1", "-file", "tmb=" + filepath.Join(dir, "missing")},
		{"archive", "-file-out", filepath.Join(dir, "no", "dir.tar.gz"), "-mtime", "1", "-file", "tmb=" + bin},
		{"archive", "-bogus"},
	} {
		if code, _, _ := tmbci(t, "", args...); code != 2 {
			t.Fatalf("%v: code %d, want 2", args, code)
		}
	}
}

func TestSBOM(t *testing.T) {
	dir := t.TempDir()
	art := filepath.Join(dir, "tmb.deb")
	if err := os.WriteFile(art, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	bin, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	a, b := filepath.Join(dir, "a.cdx.json"), filepath.Join(dir, "b.cdx.json")
	common := []string{"-artifact", art, "-type", "deb", "-name", "tmb", "-pkg-version", "1.0.0-1", "-arch", "amd64", "-version", "v1.0.0", "-mtime", "1700000000"}
	for _, out := range []string{a, b} {
		args := append([]string{"sbom", "-file-out", out, "-binary", "/usr/bin/tmb=" + bin}, common...)
		if code, msg, _ := tmbci(t, "", args...); code != 0 {
			t.Fatalf("sbom: code %d\n%s", code, msg)
		}
	}
	x, _ := os.ReadFile(a)
	y, _ := os.ReadFile(b)
	if !strings.Contains(string(x), `"bomFormat": "CycloneDX"`) || string(x) != string(y) {
		t.Fatal("two SBOMs of one artifact differ or are not CycloneDX")
	}
	for _, args := range [][]string{
		append([]string{"sbom", "-binary", "/usr/bin/tmb=" + bin}, common...),
		{"sbom", "-file-out", a, "-binary", "/usr/bin/tmb=" + bin, "-type", "deb"},
		append([]string{"sbom", "-file-out", a, "-binary", "nopath"}, common...),
		append([]string{"sbom", "-file-out", filepath.Join(dir, "no", "x.json"), "-binary", "/usr/bin/tmb=" + bin}, common...),
		{"sbom", "-bogus"},
	} {
		if code, _, _ := tmbci(t, "", args...); code != 2 {
			t.Fatalf("%v: code %d, want 2", args, code)
		}
	}
}

func TestCoverageMerge(t *testing.T) {
	dir := t.TempDir()
	unit, integ, out := filepath.Join(dir, "unit.cov"), filepath.Join(dir, "integ.cov"), filepath.Join(dir, "merged.cov")
	if err := os.WriteFile(unit, []byte("mode: atomic\nm/a/a.go:1.1,2.2 3 1\nm/a/a.go:4.1,5.2 2 0\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(integ, []byte("mode: atomic\nm/a/a.go:4.1,5.2 2 7\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	code, msg, r := tmbci(t, "coverage/merged", "coverage-merge", "-check", "coverage/merged", "-unit", unit, "-integration", integ, "-file-out", out)
	if code != 0 || r.Status != result.Pass || !strings.Contains(r.Reason, "= 100.0%") {
		t.Fatalf("code %d %+v\n%s", code, r, msg)
	}
	if b, _ := os.ReadFile(out); string(b) != "mode: atomic\nm/a/a.go:1.1,2.2 3 1\nm/a/a.go:4.1,5.2 2 7\n" {
		t.Fatalf("merged profile:\n%s", b)
	}
	if code, _, r := tmbci(t, "coverage/merged", "coverage-merge", "-check", "coverage/merged", "-unit", unit, "-integration", filepath.Join(dir, "none"), "-file-out", out); code != 2 || r.Status != result.Error {
		t.Fatalf("missing integration profile: code %d %+v", code, r)
	}
}

func TestCovdata(t *testing.T) {
	dir := t.TempDir()
	for _, f := range []string{"host/covdata/covcounters.a.10.1", "sbx/covdata/covcounters.b.4.1"} {
		p := filepath.Join(dir, f)
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, nil, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	j := filepath.Join(dir, "host", "journal")
	if err := os.MkdirAll(j, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(j, "broker.log"), []byte(`{"event":"broker_start","pid":10}`+"\n"+`{"event":"broker_start","pid":11}`+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	code, msg, r := tmbci(t, "harness/coverage-data", "covdata", "-check", "harness/coverage-data", "-dir", dir)
	if code != 0 || !strings.Contains(r.Reason, "2 processes") || !strings.Contains(strings.Join(r.Summary, "\n"), "pids [11]") {
		t.Fatalf("code %d %+v\n%s", code, r, msg)
	}
	if err := os.WriteFile(filepath.Join(j, "broker.log.1"), []byte(`{"event":"broker_start","pid":12}`+"\n"+`{"event":"broker_stop","pid":12}`+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if code, _, r := tmbci(t, "harness/coverage-data", "covdata", "-check", "harness/coverage-data", "-dir", dir); code != 1 || r.Status != result.Fail {
		t.Fatalf("stopped broker without counters: code %d %+v", code, r)
	}
	if code, _, _ := tmbci(t, "harness/coverage-data", "covdata", "-check", "harness/coverage-data", "-dir", filepath.Join(dir, "none")); code != 2 {
		t.Fatalf("missing dir: code %d", code)
	}
}
