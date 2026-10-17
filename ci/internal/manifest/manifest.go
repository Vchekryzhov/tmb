// Package manifest checks the security manifest: each required case of the
// CI spec (#13, Testing Decisions) maps to tests or scenarios that actually
// ran and passed, or to an accountable GAP.
package manifest

import (
	"encoding/json"
	"fmt"
	"io"
	"time"

	"tmb-ci/internal/accountable"
	"tmb-ci/internal/result"
)

const SchemaV1 = "tmb-ci/security-manifest/v1"

// RequiredIDs are the security behaviours spec #13 makes mandatory.
var RequiredIDs = []string{
	"SEC-01", "SEC-02", "SEC-03", "SEC-04", "SEC-05", "SEC-06", "SEC-07", "SEC-08",
	"SEC-09", "SEC-10", "SEC-11", "SEC-12", "SEC-13", "SEC-14", "SEC-15", "SEC-16",
	// spec #27: cwd roots, env policy, held cwd fd, claim GC, approver role, queue wait
	"SEC-17", "SEC-18", "SEC-19", "SEC-20", "SEC-21", "SEC-22",
	"SEC-23", // spec #39: identity by public key
}

// Level says where a case's evidence can be produced.
type Level string

const (
	Portable  Level = ""          // Go tests and Linux N/pair harnesses
	OpenShell Level = "openshell" // only the full OpenShell acceptance rig
)

type Gap struct {
	What  string `json:"what"`
	Owner string `json:"owner"`
	Issue string `json:"issue"`
	Due   string `json:"due"`
}

type Case struct {
	ID        string   `json:"id"`
	Title     string   `json:"title,omitempty"`
	Level     Level    `json:"level,omitempty"`
	Tests     []string `json:"tests,omitempty"`
	Scenarios []string `json:"scenarios,omitempty"`
	Gap       *Gap     `json:"gap,omitempty"`
}

type Manifest struct {
	Schema string `json:"schema"`
	Cases  []Case `json:"cases"`
}

// Evidence answers whether a test ("pkg.TestName") or scenario ran and passed.
type Evidence interface{ Passed(id string) bool }

type Report struct {
	Status   result.Status
	Problems []string
	Gaps     []string
	Deferred []string
	Proven   []string
}

func Read(r io.Reader) (Manifest, error) {
	var m Manifest
	dec := json.NewDecoder(io.LimitReader(r, 1<<20))
	dec.DisallowUnknownFields()
	err := dec.Decode(&m)
	return m, err
}

func Verify(m Manifest, tests, scenarios Evidence, today time.Time) Report {
	var r Report
	bad := func(format string, a ...any) { r.Problems = append(r.Problems, fmt.Sprintf(format, a...)) }
	if m.Schema != SchemaV1 {
		bad("manifest schema %q, want %q", m.Schema, SchemaV1)
	}
	seen := map[string]bool{}
	for _, c := range m.Cases {
		if seen[c.ID] {
			bad("%s: duplicate case", c.ID)
			continue
		}
		seen[c.ID] = true
		if len(c.Tests)+len(c.Scenarios) == 0 && c.Gap == nil {
			bad("%s: neither evidence nor a GAP", c.ID)
		}
		if c.Gap != nil {
			r.Problems = append(r.Problems, accountable.Problems(c.ID+": GAP", c.Gap.Owner, c.Gap.Issue, c.Gap.Due, today)...)
			r.Gaps = append(r.Gaps, fmt.Sprintf("%s: %s (owner %s, %s, due %s)", c.ID, c.Gap.What, c.Gap.Owner, c.Gap.Issue, c.Gap.Due))
		}
		if c.Level == OpenShell {
			if len(c.Tests)+len(c.Scenarios) > 0 {
				r.Deferred = append(r.Deferred, fmt.Sprintf("%s: %v proven only by the full OpenShell acceptance", c.ID, append(c.Tests, c.Scenarios...)))
			}
			continue
		}
		for _, id := range c.Tests {
			if !tests.Passed(id) {
				bad("%s: %s did not run or did not pass", c.ID, id)
			} else {
				r.Proven = append(r.Proven, c.ID+": "+id)
			}
		}
		for _, id := range c.Scenarios {
			if !scenarios.Passed(id) {
				bad("%s: scenario %s did not run or did not pass", c.ID, id)
			} else {
				r.Proven = append(r.Proven, c.ID+": scenario "+id)
			}
		}
	}
	for _, id := range RequiredIDs {
		if !seen[id] {
			bad("%s: missing from manifest", id)
		}
	}
	r.Status = result.Pass
	if len(r.Problems) > 0 {
		r.Status = result.Fail
	}
	return r
}
