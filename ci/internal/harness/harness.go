// Package harness verifies a scenario log of harness/run*.sh against the
// scenario registry: every expected scenario ran with only passing checks,
// the summary and exit code agree with the checks, and the log is fresh.
package harness

import (
	"bufio"
	"fmt"
	"io"
	"regexp"
	"strconv"
	"strings"
	"time"

	"tmb-ci/internal/result"
)

var (
	headerRe  = regexp.MustCompile(`^== TMB .*RUNNER.* \((\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ)\)$`)
	sectionRe = regexp.MustCompile(`^== (?:SCENARIO ([^:]+)|(STAGE \d+)):`)
	summaryRe = regexp.MustCompile(`^PASS: (\d+)  FAIL: (\d+)$`)
	resultRe  = regexp.MustCompile(`^RESULT: (GREEN|RED)\b`)
)

type section struct{ pass, fail, warn int }

type Report struct {
	Status    result.Status
	Problems  []string
	Scenarios map[string]result.Status
	Pass      int
	Fail      int
}

// Passed reports whether the registered scenario ran with only passing checks.
func (r Report) Passed(id string) bool { return r.Scenarios[id] == result.Pass }

// Verify reads one runner log. rc is the runner's exit code and since the
// moment this CI run started; anything older is a leftover log.
func Verify(log io.Reader, registry []string, rc int, since time.Time) Report {
	r := Report{Scenarios: map[string]result.Status{}}
	bad := func(format string, a ...any) { r.Problems = append(r.Problems, fmt.Sprintf(format, a...)) }

	sections := map[string]*section{}
	var order []string
	var cur *section
	depth := 0 // 1 = this runner, >1 = a nested runner's output
	var summary []int
	var verdict string

	sc := bufio.NewScanner(log)
	sc.Buffer(make([]byte, 64*1024), 4*1024*1024)
	for sc.Scan() {
		line := strings.TrimRight(sc.Text(), "\r")
		if m := headerRe.FindStringSubmatch(line); m != nil {
			depth++
			if depth == 1 {
				ts, err := time.Parse(time.RFC3339, m[1])
				if err != nil || ts.Before(since) {
					bad("runner header %s is older than this run (%s)", m[1], since.Format(time.RFC3339))
				}
			}
			continue
		}
		if depth != 1 {
			if depth > 1 && resultRe.MatchString(line) {
				depth--
			}
			continue
		}
		if m := sectionRe.FindStringSubmatch(line); m != nil {
			id := m[1] + m[2]
			if _, dup := sections[id]; dup {
				bad("%s: section appears twice", id)
			}
			cur = &section{}
			sections[id] = cur
			order = append(order, id)
			continue
		}
		if strings.HasPrefix(line, "== SUMMARY") {
			cur = nil
			continue
		}
		switch {
		case strings.HasPrefix(line, "CHECK PASS: "):
			r.Pass++
			if cur != nil {
				cur.pass++
			}
		case strings.HasPrefix(line, "CHECK FAIL: "):
			r.Fail++
			if cur != nil {
				cur.fail++
			}
		case strings.HasPrefix(line, "CHECK WARN: "):
			// a passing scenario that proved less than its name claims
			if cur != nil {
				cur.warn++
			}
		}
		if m := summaryRe.FindStringSubmatch(line); m != nil {
			p, _ := strconv.Atoi(m[1])
			f, _ := strconv.Atoi(m[2])
			summary = []int{p, f}
		}
		if m := resultRe.FindStringSubmatch(line); m != nil {
			verdict = m[1]
		}
	}
	if err := sc.Err(); err != nil {
		bad("reading log: %v", err)
	}
	if depth == 0 {
		bad("no runner header: empty or foreign log")
	}

	registered := map[string]bool{}
	for _, id := range registry {
		registered[id] = true
		s, ok := sections[id]
		switch {
		case !ok:
			bad("%s: did not run", id)
			r.Scenarios[id] = result.NotRun
		case s.fail > 0:
			bad("%s: %d failed check(s)", id, s.fail)
			r.Scenarios[id] = result.Fail
		case s.pass == 0:
			bad("%s: no checks executed", id)
			r.Scenarios[id] = result.Fail
		case s.warn > 0:
			bad("%s: NOT_PROVEN (%d CHECK WARN): the runner stayed green but the property was not shown", id, s.warn)
			r.Scenarios[id] = result.Fail
		default:
			r.Scenarios[id] = result.Pass
		}
	}
	for _, id := range order {
		if !registered[id] && sections[id].pass+sections[id].fail > 0 {
			bad("%s: not in the scenario registry", id)
		}
	}

	switch {
	case summary == nil:
		bad("no summary line: the runner aborted before finishing")
	case summary[0] != r.Pass || summary[1] != r.Fail:
		bad("summary PASS=%d FAIL=%d, counted PASS=%d FAIL=%d", summary[0], summary[1], r.Pass, r.Fail)
	}
	if rc != 0 {
		bad("runner exit code %d", rc)
	}
	if summary != nil && verdict != "GREEN" {
		bad("runner verdict %q, want GREEN", verdict)
	}
	if len(registry) == 0 {
		bad("empty scenario registry")
	}
	r.Status = result.Pass
	if len(r.Problems) > 0 {
		r.Status = result.Fail
	}
	return r
}
