package gotest_test

import (
	"encoding/xml"
	"strings"
	"testing"

	"tmb-ci/internal/gotest"
	"tmb-ci/internal/result"
)

// Streams below are trimmed copies of real `go test -json` output.
const green = `{"Action":"start","Package":"tmb-poc/cmd/tmb"}
{"Action":"run","Package":"tmb-poc/cmd/tmb","Test":"TestDial"}
{"Action":"output","Package":"tmb-poc/cmd/tmb","Test":"TestDial","Output":"=== RUN   TestDial\n"}
{"Action":"run","Package":"tmb-poc/cmd/tmb","Test":"TestDial/no_cert"}
{"Action":"pass","Package":"tmb-poc/cmd/tmb","Test":"TestDial/no_cert","Elapsed":0}
{"Action":"pass","Package":"tmb-poc/cmd/tmb","Test":"TestDial","Elapsed":0.01}
{"Action":"run","Package":"tmb-poc/cmd/tmb","Test":"TestSkipped"}
{"Action":"skip","Package":"tmb-poc/cmd/tmb","Test":"TestSkipped","Elapsed":0}
{"Action":"pass","Package":"tmb-poc/cmd/tmb","Elapsed":0.3}
{"Action":"start","Package":"tmb-poc/internal/proto"}
{"Action":"output","Package":"tmb-poc/internal/proto","Output":"?   \ttmb-poc/internal/proto\t[no test files]\n"}
{"Action":"skip","Package":"tmb-poc/internal/proto","Elapsed":0}
`

func parse(t *testing.T, stream string) gotest.Summary {
	t.Helper()
	s, err := gotest.Parse(strings.NewReader(stream))
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func TestParseGreenRun(t *testing.T) {
	s := parse(t, green)
	if s.Status() != result.Pass {
		t.Fatalf("status %s, problems %v", s.Status(), s.Problems())
	}
	for _, id := range []string{"tmb-poc/cmd/tmb.TestDial", "tmb-poc/cmd/tmb.TestDial/no_cert"} {
		if !s.Passed(id) {
			t.Errorf("%s not recorded as passed", id)
		}
	}
	if s.Passed("tmb-poc/cmd/tmb.TestSkipped") {
		t.Error("a skipped test must not count as passed")
	}
	if s.Counts() != (gotest.Counts{Pass: 2, Skip: 1}) {
		t.Errorf("counts %+v", s.Counts())
	}
}

func TestParseFailures(t *testing.T) {
	cases := []struct {
		name, stream, problem string
		want                  result.Status
	}{
		{"failing test", `{"Action":"run","Package":"p","Test":"TestA"}
{"Action":"fail","Package":"p","Test":"TestA","Elapsed":0}
{"Action":"fail","Package":"p","Elapsed":0}
`, "p.TestA failed", result.Fail},
		{"data race", `{"Action":"run","Package":"p","Test":"TestA"}
{"Action":"output","Package":"p","Test":"TestA","Output":"WARNING: DATA RACE\n"}
{"Action":"output","Package":"p","Test":"TestA","Output":"    testing.go:1617: race detected during execution of test\n"}
{"Action":"fail","Package":"p","Test":"TestA","Elapsed":0}
{"Action":"fail","Package":"p","Elapsed":0}
`, "data race", result.Fail},
		{"build failure", `{"Action":"start","Package":"p"}
{"Action":"output","Package":"p","Output":"FAIL\tp [build failed]\n"}
{"Action":"fail","Package":"p","Elapsed":0,"FailedBuild":"p"}
`, "p: package failed", result.Fail},
		{"test never finished (timeout or crash)", `{"Action":"run","Package":"p","Test":"TestA"}
{"Action":"output","Package":"p","Test":"TestA","Output":"panic: test timed out after 1s\n"}
`, "p.TestA did not finish", result.Error},
		{"no tests at all", "", "no tests ran", result.Error},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			s := parse(t, c.stream)
			if s.Status() != c.want {
				t.Fatalf("status %s, want %s (%v)", s.Status(), c.want, s.Problems())
			}
			if !strings.Contains(strings.Join(s.Problems(), "\n"), c.problem) {
				t.Fatalf("problems %v lack %q", s.Problems(), c.problem)
			}
		})
	}
}

func TestParseRejectsGarbage(t *testing.T) {
	if _, err := gotest.Parse(strings.NewReader("not json\n")); err == nil {
		t.Fatal("want error for a non-JSON line")
	}
}

func TestJUnit(t *testing.T) {
	var buf strings.Builder
	if err := parse(t, green).WriteJUnit(&buf); err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Suites []struct {
			Name  string `xml:"name,attr"`
			Tests int    `xml:"tests,attr"`
			Cases []struct {
				Name    string    `xml:"name,attr"`
				Skipped *struct{} `xml:"skipped"`
			} `xml:"testcase"`
		} `xml:"testsuite"`
	}
	if err := xml.Unmarshal([]byte(buf.String()), &doc); err != nil {
		t.Fatalf("invalid JUnit XML: %v\n%s", err, buf.String())
	}
	if len(doc.Suites) != 1 || doc.Suites[0].Name != "tmb-poc/cmd/tmb" || doc.Suites[0].Tests != 3 {
		t.Fatalf("unexpected suites: %+v", doc.Suites)
	}
	if doc.Suites[0].Cases[2].Name != "TestSkipped" || doc.Suites[0].Cases[2].Skipped == nil {
		t.Fatalf("skipped case not marked: %+v", doc.Suites[0].Cases)
	}
}
