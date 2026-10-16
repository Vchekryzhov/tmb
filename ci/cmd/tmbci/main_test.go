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
