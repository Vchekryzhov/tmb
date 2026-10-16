package fuzz_test

import (
	"strings"
	"testing"
	"time"

	"tmb-ci/internal/fuzz"
	"tmb-ci/internal/result"
)

var today = time.Date(2026, 10, 16, 0, 0, 0, 0, time.UTC)

// listOutput is `go test -list '^Fuzz' ./...` output.
const listOutput = `FuzzReadFrame
ok  	tmb-poc/internal/proto	0.010s
ok  	tmb-poc/cmd/tmb	0.005s
?   	tmb-poc/cmd/x	[no test files]
`

func gap() *fuzz.Gap {
	return &fuzz.Gap{Owner: "Vchekryzhov", Issue: "https://github.com/Vchekryzhov/tmb/issues/15", Due: "2026-11-15"}
}

func TestParseList(t *testing.T) {
	got, err := fuzz.ParseList(strings.NewReader(listOutput))
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0] != (fuzz.Target{Package: "tmb-poc/internal/proto", Name: "FuzzReadFrame"}) {
		t.Fatalf("got %v", got)
	}
}

func TestParseListRejectsFailedListing(t *testing.T) {
	if _, err := fuzz.ParseList(strings.NewReader("FAIL\ttmb-poc/cmd/tmb [build failed]\n")); err == nil {
		t.Fatal("a failed listing must be an error")
	}
}

func TestCheck(t *testing.T) {
	declared := []fuzz.Target{{Package: "tmb-poc/internal/proto", Name: "FuzzReadFrame"}}
	reg := func(entries ...fuzz.Entry) fuzz.Registry {
		return fuzz.Registry{Schema: fuzz.SchemaV1, Targets: entries}
	}
	frame := fuzz.Entry{Package: "tmb-poc/internal/proto", Name: "FuzzReadFrame"}
	json := fuzz.Entry{Package: "tmb-poc/internal/proto", Name: "FuzzDecodeRequest", Gap: gap()}

	r := fuzz.Check(reg(frame, json), declared, today)
	if r.Status != result.Pass || len(r.Run) != 1 || len(r.Gaps) != 1 {
		t.Fatalf("status %s run %v gaps %v problems %v", r.Status, r.Run, r.Gaps, r.Problems)
	}

	cases := []struct {
		name    string
		reg     fuzz.Registry
		problem string
	}{
		{"required target missing", reg(frame, fuzz.Entry{Package: "tmb-poc/internal/proto", Name: "FuzzDecodeRequest"}), "FuzzDecodeRequest: required target is not declared"},
		{"declared target not registered", reg(json), "FuzzReadFrame: declared but not in the fuzz registry"},
		{"GAP kept after the target exists", reg(fuzz.Entry{Package: frame.Package, Name: frame.Name, Gap: gap()}, json), "FuzzReadFrame: target exists, remove its GAP"},
		{"empty registry", reg(), "empty fuzz registry"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			r := fuzz.Check(c.reg, declared, today)
			if r.Status != result.Fail || !strings.Contains(strings.Join(r.Problems, "\n"), c.problem) {
				t.Fatalf("status %s problems %v, want %q", r.Status, r.Problems, c.problem)
			}
		})
	}
}
