package manifest_test

import (
	"strings"
	"testing"
	"time"

	"tmb-ci/internal/manifest"
	"tmb-ci/internal/result"
)

var today = time.Date(2026, 10, 16, 0, 0, 0, 0, time.UTC)

type evidence map[string]bool

func (e evidence) Passed(id string) bool { return e[id] }

func gap(due string) *manifest.Gap {
	return &manifest.Gap{What: "concurrent claim stress test", Owner: "Vchekryzhov", Issue: "https://github.com/Vchekryzhov/tmb/issues/15", Due: due}
}

// full returns a manifest whose every required case is a valid GAP, so each
// test can change one case and observe only that change.
func full() manifest.Manifest {
	m := manifest.Manifest{Schema: manifest.SchemaV1}
	for _, id := range manifest.RequiredIDs {
		m.Cases = append(m.Cases, manifest.Case{ID: id, Gap: gap("2026-11-15")})
	}
	return m
}

func set(m *manifest.Manifest, id string, c manifest.Case) {
	c.ID = id
	for i := range m.Cases {
		if m.Cases[i].ID == id {
			m.Cases[i] = c
		}
	}
}

func verify(m manifest.Manifest, tests, scenarios evidence) manifest.Report {
	return manifest.Verify(m, tests, scenarios, today)
}

func TestVerifyPassesWhenDeclaredEvidenceRan(t *testing.T) {
	m := full()
	set(&m, "SEC-06", manifest.Case{Tests: []string{"tmb-poc/cmd/tmb.TestDialTLSWrongCA"}})
	set(&m, "SEC-01", manifest.Case{Scenarios: []string{"N3a", "TTL"}})
	r := verify(m, evidence{"tmb-poc/cmd/tmb.TestDialTLSWrongCA": true}, evidence{"N3a": true, "TTL": true})
	if r.Status != result.Pass {
		t.Fatalf("status %s: %v", r.Status, r.Problems)
	}
	if len(r.Gaps) != len(manifest.RequiredIDs)-2 {
		t.Fatalf("gaps must stay visible: got %d", len(r.Gaps))
	}
}

func TestVerifyFails(t *testing.T) {
	cases := []struct {
		name    string
		edit    func(*manifest.Manifest)
		problem string
	}{
		{"declared test did not run", func(m *manifest.Manifest) {
			set(m, "SEC-06", manifest.Case{Tests: []string{"p.TestGone"}})
		}, "SEC-06: p.TestGone did not run or did not pass"},
		{"declared scenario did not run", func(m *manifest.Manifest) {
			set(m, "SEC-13", manifest.Case{Scenarios: []string{"N7"}})
		}, "SEC-13: scenario N7 did not run or did not pass"},
		{"case without evidence or gap", func(m *manifest.Manifest) {
			set(m, "SEC-02", manifest.Case{})
		}, "SEC-02: neither evidence nor a GAP"},
		{"required case missing", func(m *manifest.Manifest) {
			m.Cases = m.Cases[1:]
		}, "SEC-01: missing from manifest"},
		{"expired gap", func(m *manifest.Manifest) {
			set(m, "SEC-04", manifest.Case{Gap: gap("2026-10-15")})
		}, "SEC-04: GAP expired on 2026-10-15"},
		{"gap without owner", func(m *manifest.Manifest) {
			g := gap("2026-11-15")
			g.Owner = ""
			set(m, "SEC-04", manifest.Case{Gap: g})
		}, "SEC-04: GAP needs owner"},
		{"gap pointing outside the repository", func(m *manifest.Manifest) {
			g := gap("2026-11-15")
			g.Issue = "https://example.com/15"
			set(m, "SEC-04", manifest.Case{Gap: g})
		}, "SEC-04: GAP issue"},
		{"gap with malformed due date", func(m *manifest.Manifest) {
			set(m, "SEC-04", manifest.Case{Gap: gap("soon")})
		}, "SEC-04: GAP due"},
		{"unknown schema", func(m *manifest.Manifest) { m.Schema = "x" }, "schema"},
		{"duplicate case", func(m *manifest.Manifest) {
			m.Cases = append(m.Cases, manifest.Case{ID: "SEC-01", Gap: gap("2026-11-15")})
		}, "SEC-01: duplicate"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			m := full()
			c.edit(&m)
			r := verify(m, evidence{}, evidence{})
			if r.Status != result.Fail {
				t.Fatalf("status %s, want FAIL", r.Status)
			}
			if !strings.Contains(strings.Join(r.Problems, "\n"), c.problem) {
				t.Fatalf("problems %v lack %q", r.Problems, c.problem)
			}
		})
	}
}

func TestVerifyDefersOpenShellOnlyEvidence(t *testing.T) {
	m := full()
	set(&m, "SEC-14", manifest.Case{Level: manifest.OpenShell, Scenarios: []string{"O4"}})
	r := verify(m, evidence{}, evidence{})
	if r.Status != result.Pass {
		t.Fatalf("portable verify must not demand OpenShell evidence: %v", r.Problems)
	}
	if len(r.Deferred) != 1 || !strings.Contains(r.Deferred[0], "SEC-14") {
		t.Fatalf("deferred %v", r.Deferred)
	}
}

func TestVerifyDefersVMOnlyEvidence(t *testing.T) {
	m := full()
	set(&m, "SEC-27", manifest.Case{Level: manifest.VM, Scenarios: []string{"V6"}})
	r := verify(m, evidence{}, evidence{})
	if r.Status != result.Pass {
		t.Fatalf("portable verify must not demand VM evidence: %v", r.Problems)
	}
	if len(r.Deferred) != 1 || !strings.Contains(r.Deferred[0], "SEC-27") || !strings.Contains(r.Deferred[0], "run-vm.sh") {
		t.Fatalf("deferred %v", r.Deferred)
	}
}

func TestVerifyRejectsUnknownLevel(t *testing.T) {
	m := full()
	set(&m, "SEC-27", manifest.Case{Level: "bare-metal", Scenarios: []string{"V6"}})
	r := verify(m, evidence{}, evidence{})
	if r.Status != result.Fail || !strings.Contains(strings.Join(r.Problems, "\n"), "unknown level") {
		t.Fatalf("unknown level accepted: %s %v", r.Status, r.Problems)
	}
}
