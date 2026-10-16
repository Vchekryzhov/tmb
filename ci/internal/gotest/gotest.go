// Package gotest reads a `go test -json` stream: which tests ran and passed,
// whether anything failed, raced or never finished, and a JUnit rendering.
package gotest

import (
	"bufio"
	"encoding/json"
	"encoding/xml"
	"fmt"
	"io"
	"sort"
	"strings"

	"tmb-ci/internal/result"
)

type event struct {
	Action      string
	Package     string
	Test        string
	Output      string
	Elapsed     float64
	FailedBuild string
}

type Counts struct{ Pass, Fail, Skip int }

type testCase struct {
	pkg, name string
	outcome   string // pass, fail, skip, or "" when it never finished
	elapsed   float64
	output    strings.Builder
}

type Summary struct {
	cases    map[string]*testCase
	order    []string
	failPkgs []string
	race     []string
}

// Parse reads the whole stream; a line that is not a test2json event is an error.
func Parse(r io.Reader) (Summary, error) {
	s := Summary{cases: map[string]*testCase{}}
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 64*1024), 16*1024*1024)
	for line := 1; sc.Scan(); line++ {
		raw := strings.TrimSpace(sc.Text())
		if raw == "" {
			continue
		}
		var e event
		if err := json.Unmarshal([]byte(raw), &e); err != nil || e.Action == "" {
			return s, fmt.Errorf("line %d: not a go test -json event", line)
		}
		s.add(e)
	}
	return s, sc.Err()
}

func (s *Summary) add(e event) {
	if e.Test == "" {
		if e.Action == "fail" {
			s.failPkgs = append(s.failPkgs, e.Package)
		}
		return
	}
	id := e.Package + "." + e.Test
	c, ok := s.cases[id]
	if !ok {
		c = &testCase{pkg: e.Package, name: e.Test}
		s.cases[id] = c
		s.order = append(s.order, id)
	}
	switch e.Action {
	case "pass", "fail", "skip":
		c.outcome = e.Action
		c.elapsed = e.Elapsed
	case "output":
		c.output.WriteString(e.Output)
		if strings.Contains(e.Output, "WARNING: DATA RACE") {
			s.race = append(s.race, id)
		}
	}
}

// Passed reports whether the test (package.Test[/sub]) ran and passed.
func (s Summary) Passed(id string) bool {
	c, ok := s.cases[id]
	return ok && c.outcome == "pass"
}

func (s Summary) Counts() Counts {
	var n Counts
	for _, c := range s.cases {
		switch c.outcome {
		case "pass":
			n.Pass++
		case "fail":
			n.Fail++
		case "skip":
			n.Skip++
		}
	}
	return n
}

func (s Summary) Problems() []string {
	var p []string
	for _, id := range s.order {
		switch s.cases[id].outcome {
		case "fail":
			p = append(p, id+" failed")
		case "":
			p = append(p, id+" did not finish (timeout, panic or killed run)")
		}
	}
	for _, id := range s.race {
		p = append(p, id+": data race")
	}
	for _, pkg := range s.failPkgs {
		p = append(p, pkg+": package failed")
	}
	if len(s.cases) == 0 {
		p = append(p, "no tests ran")
	}
	return p
}

// Status: ERROR when the run is incomplete, FAIL on any failure or race.
func (s Summary) Status() result.Status {
	for _, c := range s.cases {
		if c.outcome == "" {
			return result.Error
		}
	}
	switch {
	case len(s.failPkgs) > 0 || len(s.race) > 0 || s.Counts().Fail > 0:
		return result.Fail
	case len(s.cases) == 0:
		return result.Error
	}
	return result.Pass
}

type junitCase struct {
	Name    string    `xml:"name,attr"`
	Class   string    `xml:"classname,attr"`
	Time    string    `xml:"time,attr"`
	Failure *junitMsg `xml:"failure,omitempty"`
	Skipped *junitMsg `xml:"skipped,omitempty"`
}

type junitMsg struct {
	Message string `xml:"message,attr,omitempty"`
	Body    string `xml:",chardata"`
}

type junitSuite struct {
	Name     string      `xml:"name,attr"`
	Tests    int         `xml:"tests,attr"`
	Failures int         `xml:"failures,attr"`
	Skipped  int         `xml:"skipped,attr"`
	Cases    []junitCase `xml:"testcase"`
}

// WriteJUnit renders one <testsuite> per package, cases in run order.
func (s Summary) WriteJUnit(w io.Writer) error {
	suites := map[string]*junitSuite{}
	var names []string
	for _, id := range s.order {
		c := s.cases[id]
		su, ok := suites[c.pkg]
		if !ok {
			su = &junitSuite{Name: c.pkg}
			suites[c.pkg] = su
			names = append(names, c.pkg)
		}
		jc := junitCase{Name: c.name, Class: c.pkg, Time: fmt.Sprintf("%.3f", c.elapsed)}
		switch c.outcome {
		case "fail", "":
			jc.Failure = &junitMsg{Message: "failed or did not finish", Body: c.output.String()}
			su.Failures++
		case "skip":
			jc.Skipped = &junitMsg{}
			su.Skipped++
		}
		su.Tests++
		su.Cases = append(su.Cases, jc)
	}
	sort.Strings(names)
	doc := struct {
		XMLName xml.Name      `xml:"testsuites"`
		Suites  []*junitSuite `xml:"testsuite"`
	}{}
	for _, n := range names {
		doc.Suites = append(doc.Suites, suites[n])
	}
	if _, err := io.WriteString(w, xml.Header); err != nil {
		return err
	}
	enc := xml.NewEncoder(w)
	enc.Indent("", "  ")
	return enc.Encode(doc)
}
