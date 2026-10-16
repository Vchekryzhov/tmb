// Package fuzz checks the declared fuzz targets against ci/fuzz-targets.json:
// every required target exists (or is an accountable GAP) and nothing
// declared escapes the registry, so a missing target is never a PASS.
package fuzz

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"time"

	"tmb-ci/internal/accountable"
	"tmb-ci/internal/result"
)

const SchemaV1 = "tmb-ci/fuzz-targets/v1"

type Target struct{ Package, Name string }

type Gap struct {
	Owner string `json:"owner"`
	Issue string `json:"issue"`
	Due   string `json:"due"`
}

type Entry struct {
	Package string `json:"package"`
	Name    string `json:"name"`
	Gap     *Gap   `json:"gap,omitempty"`
}

type Registry struct {
	Schema  string  `json:"schema"`
	Targets []Entry `json:"targets"`
}

func ReadRegistry(r io.Reader) (Registry, error) {
	var reg Registry
	dec := json.NewDecoder(io.LimitReader(r, 1<<20))
	dec.DisallowUnknownFields()
	err := dec.Decode(&reg)
	return reg, err
}

// ParseList reads `go test -list '^Fuzz' ./...`: names precede their
// package's "ok" line.
func ParseList(r io.Reader) ([]Target, error) {
	var out []Target
	var pending []string
	sc := bufio.NewScanner(r)
	for sc.Scan() {
		line := sc.Text()
		f := strings.Fields(line)
		switch {
		case len(f) == 0:
		case f[0] == "ok" && len(f) >= 2:
			for _, n := range pending {
				out = append(out, Target{Package: f[1], Name: n})
			}
			pending = nil
		case f[0] == "?":
		case f[0] == "FAIL" || strings.HasPrefix(line, "#"):
			return nil, fmt.Errorf("listing failed: %s", line)
		case strings.HasPrefix(f[0], "Fuzz") && len(f) == 1:
			pending = append(pending, f[0])
		default:
			return nil, fmt.Errorf("unexpected listing line %q", line)
		}
	}
	if len(pending) > 0 {
		return nil, fmt.Errorf("targets %v without a package line", pending)
	}
	return out, sc.Err()
}

type Report struct {
	Status   result.Status
	Problems []string
	Gaps     []string
	Run      []Target // registered targets that exist and must be fuzzed
}

func Check(reg Registry, declared []Target, today time.Time) Report {
	var r Report
	bad := func(format string, a ...any) { r.Problems = append(r.Problems, fmt.Sprintf(format, a...)) }
	if reg.Schema != SchemaV1 {
		bad("fuzz registry schema %q, want %q", reg.Schema, SchemaV1)
	}
	if len(reg.Targets) == 0 {
		bad("empty fuzz registry")
	}
	have := map[Target]bool{}
	for _, t := range declared {
		have[t] = true
	}
	registered := map[Target]bool{}
	for _, e := range reg.Targets {
		t := Target{Package: e.Package, Name: e.Name}
		registered[t] = true
		id := e.Package + "." + e.Name
		switch {
		case have[t] && e.Gap != nil:
			bad("%s: target exists, remove its GAP", id)
		case have[t]:
			r.Run = append(r.Run, t)
		case e.Gap == nil:
			bad("%s: required target is not declared", id)
		default:
			r.Problems = append(r.Problems, accountable.Problems(id+": GAP", e.Gap.Owner, e.Gap.Issue, e.Gap.Due, today)...)
			r.Gaps = append(r.Gaps, fmt.Sprintf("%s: not written yet (owner %s, %s, due %s)", id, e.Gap.Owner, e.Gap.Issue, e.Gap.Due))
		}
	}
	for _, t := range declared {
		if !registered[t] {
			bad("%s.%s: declared but not in the fuzz registry", t.Package, t.Name)
		}
	}
	r.Status = result.Pass
	if len(r.Problems) > 0 {
		r.Status = result.Fail
	}
	return r
}
