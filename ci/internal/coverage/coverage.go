// Package coverage implements the coverage rules of spec #13 section C:
// whole-module statement coverage, no decrease against a comparable base,
// diff coverage weighted by statements, and targets that are either reached
// and pinned or carried as an accountable GAP.
package coverage

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"path"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"tmb-ci/internal/accountable"
	"tmb-ci/internal/result"
)

// Ratio is covered/total statements; compare ratios, not rounded percents.
type Ratio struct{ Covered, Total int }

func (r Ratio) Percent() float64 {
	if r.Total == 0 {
		return 0
	}
	return 100 * float64(r.Covered) / float64(r.Total)
}

func (r Ratio) String() string { return fmt.Sprintf("%.1f%%", r.Percent()) }

// less reports r < o exactly.
func (r Ratio) less(o Ratio) bool { return r.Covered*o.Total < o.Covered*r.Total }

// atLeast reports r >= min percent exactly.
func (r Ratio) atLeast(min float64) bool { return float64(r.Covered)*100 >= min*float64(r.Total) }

type block struct {
	file       string // import-path file name as the profile prints it
	start, end int    // lines
	stmts      int
	count      int
}

type Profile struct {
	Mode   string
	blocks map[string]*block
}

var blockRe = regexp.MustCompile(`^(.+\.go):(\d+)\.(\d+),(\d+)\.(\d+) (\d+) (-?\d+)$`)

// ParseProfile reads a Go cover profile; one that is empty, malformed or
// has no statements is an error, never a zero-percent PASS.
func ParseProfile(r io.Reader) (Profile, error) {
	p := Profile{blocks: map[string]*block{}}
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 64*1024), 4*1024*1024)
	for n := 1; sc.Scan(); n++ {
		line := strings.TrimSpace(sc.Text())
		if line == "" {
			continue
		}
		if p.Mode == "" {
			mode, ok := strings.CutPrefix(line, "mode: ")
			if !ok {
				return p, fmt.Errorf("line %d: profile does not start with a mode line", n)
			}
			p.Mode = mode
			continue
		}
		if strings.HasPrefix(line, "mode: ") {
			continue // concatenated profiles repeat the mode line
		}
		m := blockRe.FindStringSubmatch(line)
		if m == nil {
			return p, fmt.Errorf("line %d: not a coverage block: %q", n, line)
		}
		start, _ := strconv.Atoi(m[2])
		end, _ := strconv.Atoi(m[4])
		stmts, _ := strconv.Atoi(m[6])
		count, _ := strconv.Atoi(m[7])
		if count < 0 || stmts < 0 || end < start {
			return p, fmt.Errorf("line %d: invalid block %q", n, line)
		}
		key := m[1] + ":" + m[2] + "." + m[3] + "," + m[4] + "." + m[5]
		if b, ok := p.blocks[key]; ok {
			b.count += count
			continue
		}
		p.blocks[key] = &block{file: m[1], start: start, end: end, stmts: stmts, count: count}
	}
	if err := sc.Err(); err != nil {
		return p, err
	}
	if p.Mode == "" {
		return p, fmt.Errorf("empty profile")
	}
	if p.Total().Total == 0 {
		return p, fmt.Errorf("profile has no statements")
	}
	return p, nil
}

func (p Profile) ratio(keep func(*block) bool) Ratio {
	var r Ratio
	for _, b := range p.blocks {
		if keep(b) {
			r.Total += b.stmts
			if b.count > 0 {
				r.Covered += b.stmts
			}
		}
	}
	return r
}

func (p Profile) Total() Ratio { return p.ratio(func(*block) bool { return true }) }

// Packages maps import path to its ratio.
func (p Profile) Packages() map[string]Ratio {
	out := map[string]Ratio{}
	for _, b := range p.blocks {
		r := out[path.Dir(b.file)]
		r.Total += b.stmts
		if b.count > 0 {
			r.Covered += b.stmts
		}
		out[path.Dir(b.file)] = r
	}
	return out
}

// MissingPackages returns the listed packages with no block in the profile.
func (p Profile) MissingPackages(pkgs []string) []string {
	have := p.Packages()
	var missing []string
	for _, pkg := range pkgs {
		if _, ok := have[pkg]; !ok {
			missing = append(missing, pkg)
		}
	}
	return missing
}

type Comparison struct {
	Status   result.Status
	Problems []string
	Notes    []string
}

// Compare applies the no-decrease rule: total and every package present in
// both profiles must not lose coverage. Callers guarantee comparability
// (same GOOS/GOARCH, toolchain and mode).
func Compare(base, head Profile) Comparison {
	var c Comparison
	if base.Mode != head.Mode {
		c.Status = result.Error
		c.Problems = append(c.Problems, fmt.Sprintf("modes differ: base %s, head %s", base.Mode, head.Mode))
		return c
	}
	if bt, ht := base.Total(), head.Total(); ht.less(bt) {
		c.Problems = append(c.Problems, fmt.Sprintf("total %s -> %s", bt, ht))
	}
	bp, hp := base.Packages(), head.Packages()
	for _, pkg := range sortedKeys(hp) {
		b, ok := bp[pkg]
		switch {
		case !ok:
			c.Notes = append(c.Notes, fmt.Sprintf("%s: new package, %s (judged by diff coverage)", pkg, hp[pkg]))
		case hp[pkg].less(b):
			c.Problems = append(c.Problems, fmt.Sprintf("%s %s -> %s", pkg, b, hp[pkg]))
		}
	}
	for _, pkg := range sortedKeys(bp) {
		if _, ok := hp[pkg]; !ok {
			c.Notes = append(c.Notes, fmt.Sprintf("%s: deleted or renamed", pkg))
		}
	}
	c.Status = result.Pass
	if len(c.Problems) > 0 {
		c.Status = result.Fail
	}
	return c
}

// AddedLines maps a repository path to its added line numbers in head.
type AddedLines map[string][]int

var hunkRe = regexp.MustCompile(`^@@ -\d+(?:,\d+)? \+(\d+)(?:,(\d+))? @@`)

// ParseUnifiedDiff extracts added lines from `git diff -M` output.
func ParseUnifiedDiff(r io.Reader) (AddedLines, error) {
	out := AddedLines{}
	var file string
	next := 0
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 64*1024), 4*1024*1024)
	for sc.Scan() {
		line := sc.Text()
		switch {
		case strings.HasPrefix(line, "diff --git "):
			file = ""
		case strings.HasPrefix(line, "+++ "):
			file = ""
			if f, ok := strings.CutPrefix(line, "+++ b/"); ok {
				file = f
			}
		case strings.HasPrefix(line, "--- "):
		case strings.HasPrefix(line, "@@"):
			m := hunkRe.FindStringSubmatch(line)
			if m == nil {
				return nil, fmt.Errorf("malformed hunk header %q", line)
			}
			next, _ = strconv.Atoi(m[1])
		case file == "":
		case strings.HasPrefix(line, "+"):
			out[file] = append(out[file], next)
			next++
		case strings.HasPrefix(line, " "):
			next++
		}
	}
	return out, sc.Err()
}

type DiffResult struct {
	Ratio     Ratio
	Uncovered []string
}

// Diff weights every head block that intersects an added line by its
// statement count. repoPath maps a profile file name to the diff's path.
func Diff(head Profile, added AddedLines, repoPath func(string) string) DiffResult {
	var d DiffResult
	keys := make([]string, 0, len(head.blocks))
	for k := range head.blocks {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		b := head.blocks[k]
		p := repoPath(b.file)
		touched := false
		for _, l := range added[p] {
			if l >= b.start && l <= b.end {
				touched = true
				break
			}
		}
		if !touched || b.stmts == 0 {
			continue
		}
		d.Ratio.Total += b.stmts
		if b.count > 0 {
			d.Ratio.Covered += b.stmts
		} else {
			d.Uncovered = append(d.Uncovered, fmt.Sprintf("%s:%d-%d (%d statements)", p, b.start, b.end, b.stmts))
		}
	}
	return d
}

// Status: NOT_APPLICABLE when no executable statement changed.
func (d DiffResult) Status(min float64) result.Status {
	switch {
	case d.Ratio.Total == 0:
		return result.NotApplicable
	case d.Ratio.atLeast(min):
		return result.Pass
	}
	return result.Fail
}

const PolicySchemaV1 = "tmb-ci/coverage-policy/v1"

type Gap struct {
	Owner string `json:"owner"`
	Issue string `json:"issue"`
	Due   string `json:"due"`
}

// Target is an absolute coverage goal over the whole profile or over the
// files whose import path starts with one of Files.
type Target struct {
	Name     string   `json:"name"`
	Min      float64  `json:"min"`
	Files    []string `json:"files,omitempty"`
	Enforced bool     `json:"enforced,omitempty"`
	Gap      *Gap     `json:"gap,omitempty"`
}

type Policy struct {
	Schema  string   `json:"schema"`
	DiffMin float64  `json:"diff_min"`
	Targets []Target `json:"targets"`
}

// ReadPolicy rejects unknown fields, so no exclusion list can be smuggled in.
func ReadPolicy(r io.Reader) (Policy, error) {
	var p Policy
	dec := json.NewDecoder(io.LimitReader(r, 1<<20))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&p); err != nil {
		return p, err
	}
	if p.Schema != PolicySchemaV1 {
		return p, fmt.Errorf("policy schema %q, want %q", p.Schema, PolicySchemaV1)
	}
	return p, nil
}

type TargetReport struct {
	Status   result.Status
	Problems []string
	Gaps     []string
	Rows     []string
}

func CheckTargets(pol Policy, p Profile, today time.Time) TargetReport {
	var r TargetReport
	bad := func(format string, a ...any) { r.Problems = append(r.Problems, fmt.Sprintf(format, a...)) }
	for _, t := range pol.Targets {
		got := p.ratio(func(b *block) bool {
			if len(t.Files) == 0 {
				return true
			}
			for _, f := range t.Files {
				if strings.HasPrefix(b.file, f) {
					return true
				}
			}
			return false
		})
		state := "GAP"
		reached := got.atLeast(t.Min)
		switch {
		case got.Total == 0:
			bad("%s: matches no statements", t.Name)
		case t.Enforced && !reached:
			bad("%s: %s below enforced %.1f%%", t.Name, got, t.Min)
			state = "FAIL"
		case t.Enforced:
			state = "ENFORCED"
		case reached:
			bad("%s: target %.1f%% reached (%s): set enforced: true and drop the GAP to pin it", t.Name, t.Min, got)
			state = "REACHED-UNPINNED"
		case t.Gap == nil:
			bad("%s: %s < %.1f%% and no GAP", t.Name, got, t.Min)
		default:
			r.Problems = append(r.Problems, accountable.Problems(t.Name+": GAP", t.Gap.Owner, t.Gap.Issue, t.Gap.Due, today)...)
			r.Gaps = append(r.Gaps, fmt.Sprintf("%s: %s < %.1f%% (owner %s, %s, due %s)", t.Name, got, t.Min, t.Gap.Owner, t.Gap.Issue, t.Gap.Due))
		}
		r.Rows = append(r.Rows, fmt.Sprintf("%-10s %6s of %d statements, target %.0f%%: %s", t.Name, got, got.Total, t.Min, state))
	}
	r.Status = result.Pass
	if len(r.Problems) > 0 {
		r.Status = result.Fail
	}
	return r
}

func sortedKeys(m map[string]Ratio) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}
