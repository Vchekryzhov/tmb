package scan_test

import (
	"strings"
	"testing"
	"time"

	"tmb-ci/internal/result"
	"tmb-ci/internal/scan"
)

var today = time.Date(2026, 10, 16, 0, 0, 0, 0, time.UTC)

// Report shapes are trimmed copies of real scanner output.
const gosecJSON = `{"Golang errors":{},"Issues":[
 {"severity":"MEDIUM","confidence":"HIGH","rule_id":"G304","details":"Potential file inclusion via variable","file":"/w/tmb/src/cmd/tmb-broker/config.go","code":"37: \tdata, err := os.ReadFile(path)\n38: \tif err != nil {\n","line":"38"},
 {"severity":"LOW","confidence":"HIGH","rule_id":"G104","details":"Errors unhandled","file":"/w/tmb/src/cmd/tmb/main.go","code":"10: \tf.Close()\n","line":"10"}
],"Stats":{"files":12}}`

const govulnJSON = `{"config":{"scanner_name":"govulncheck","scanner_version":"v1.8.0","db":"https://vuln.go.dev","db_last_modified":"2026-10-08T22:31:09Z","go_version":"go1.27.2","scan_level":"symbol","scan_mode":"source"}}
{"osv":{"id":"GO-2026-0001"}}
{"finding":{"osv":"GO-2026-0001","fixed_version":"v1.27.3","trace":[{"module":"stdlib","version":"v1.27.2","package":"crypto/tls","function":"Conn.Handshake"},{"module":"tmb-poc","package":"tmb-poc/cmd/tmb","function":"dial"}]}}
{"finding":{"osv":"GO-2026-0002","trace":[{"module":"stdlib","version":"v1.27.2","package":"net/mail"}]}}
`

const trivyJSON = `{"SchemaVersion":2,"ArtifactName":"tmb-ci/host-sim:abc","Results":[
 {"Target":"tmb-ci/host-sim (ubuntu 24.04)","Class":"os-pkgs","Vulnerabilities":[
  {"VulnerabilityID":"CVE-2026-1111","PkgName":"openssl","InstalledVersion":"3.0.13","Severity":"HIGH"},
  {"VulnerabilityID":"CVE-2026-2222","PkgName":"zlib","InstalledVersion":"1.3","Severity":"MEDIUM"}]},
 {"Target":"Dockerfile.host","Class":"config","Misconfigurations":[
  {"ID":"DS-0002","Title":"Image user should not be 'root'","Severity":"HIGH","Status":"FAIL"},
  {"ID":"DS-0026","Title":"No HEALTHCHECK defined","Severity":"LOW","Status":"FAIL"},
  {"ID":"DS-0001","Severity":"MEDIUM","Status":"PASS"}]}]}`

const gitleaksJSON = `[{"RuleID":"generic-api-key","File":"harness/run.sh","StartLine":12,"Secret":"REDACTED","Match":"key=REDACTED","Fingerprint":"abc:harness/run.sh:generic-api-key:12"}]`

func parse(t *testing.T, scanner, report string) []scan.Finding {
	t.Helper()
	f, err := scan.Parse(scanner, strings.NewReader(report), "/w/tmb/")
	if err != nil {
		t.Fatal(err)
	}
	return f
}

func TestParseClassifiesBlockingFindings(t *testing.T) {
	cases := []struct {
		scanner, report string
		blocking        []string // Rule@Location of blocking findings
		info            int
	}{
		// LOW (G104 unhandled errors) is reported but does not block.
		{"gosec", gosecJSON, []string{"G304@src/cmd/tmb-broker/config.go"}, 1},
		// Only the symbol-level (reachable) vulnerability blocks.
		{"govulncheck", govulnJSON, []string{"GO-2026-0001@stdlib"}, 1},
		{"trivy", trivyJSON, []string{"CVE-2026-1111@openssl", "DS-0002@Dockerfile.host"}, 2},
		{"gitleaks", gitleaksJSON, []string{"generic-api-key@harness/run.sh"}, 0},
	}
	for _, c := range cases {
		t.Run(c.scanner, func(t *testing.T) {
			var blocking []string
			info := 0
			for _, f := range parse(t, c.scanner, c.report) {
				if f.Blocking {
					blocking = append(blocking, f.Rule+"@"+f.Location)
				} else {
					info++
				}
			}
			if strings.Join(blocking, ",") != strings.Join(c.blocking, ",") || info != c.info {
				t.Fatalf("blocking %v info %d, want %v info %d", blocking, info, c.blocking, c.info)
			}
		})
	}
}

func TestParseRejectsBrokenReports(t *testing.T) {
	for _, c := range []struct{ scanner, report string }{
		{"gosec", ""},
		{"gosec", `{"Golang errors":{"/w/x.go":[{"error":"type error"}]},"Issues":[]}`},
		{"govulncheck", `{"progress":{"message":"x"}}`}, // no config: scan did not complete
		{"trivy", `not json`},
		{"gitleaks", `{"oops":1}`},
		{"semgrep", `[]`},
	} {
		if _, err := scan.Parse(c.scanner, strings.NewReader(c.report), "/w/tmb/"); err == nil {
			t.Errorf("%s %q: want error", c.scanner, c.report)
		}
	}
}

func exc(scanner, rule, loc, match, expires string) scan.Exception {
	return scan.Exception{Scanner: scanner, Rule: rule, Location: loc, Match: match,
		Reason: "socket must be group-accessible", Owner: "Vchekryzhov",
		Issue: "https://github.com/Vchekryzhov/tmb/issues/15", Expires: expires}
}

func TestEvaluate(t *testing.T) {
	findings := parse(t, "gosec", gosecJSON)
	both := scan.Exceptions{Schema: scan.ExceptionsSchemaV1, Exceptions: []scan.Exception{
		exc("gosec", "G304", "src/cmd/tmb-broker/config.go", "os.ReadFile(path)", "2026-12-31"),
		exc("gosec", "G104", "src/cmd/tmb/main.go", "f.Close()", "2026-12-31"),
	}}
	r := scan.Evaluate("gosec", findings, both, today, true)
	if r.Status != result.Pass || len(r.Excepted) != 2 {
		t.Fatalf("status %s problems %v excepted %v", r.Status, r.Problems, r.Excepted)
	}

	cases := []struct {
		name    string
		ex      []scan.Exception
		problem string
	}{
		{"unexcepted blocking finding", both.Exceptions[1:], "G304 src/cmd/tmb-broker/config.go"},
		{"expired exception", []scan.Exception{both.Exceptions[1], exc("gosec", "G304", "src/cmd/tmb-broker/config.go", "os.ReadFile(path)", "2026-10-15")}, "expired on 2026-10-15"},
		{"wildcard rule", []scan.Exception{both.Exceptions[1], exc("gosec", "*", "src/cmd/tmb-broker/config.go", "os.ReadFile(path)", "2026-12-31")}, "rule must name one rule"},
		{"directory-wide location", []scan.Exception{both.Exceptions[1], exc("gosec", "G304", "src/cmd/", "os.ReadFile(path)", "2026-12-31")}, "location must be one file"},
		{"missing code match for a code finding", []scan.Exception{both.Exceptions[1], exc("gosec", "G304", "src/cmd/tmb-broker/config.go", "", "2026-12-31")}, "needs match"},
		{"expiry too far ahead", []scan.Exception{both.Exceptions[1], exc("gosec", "G304", "src/cmd/tmb-broker/config.go", "os.ReadFile(path)", "2027-12-31")}, "more than 180 days"},
		{"no reason", func() []scan.Exception {
			e := exc("gosec", "G304", "src/cmd/tmb-broker/config.go", "os.ReadFile(path)", "2026-12-31")
			e.Reason = ""
			return []scan.Exception{both.Exceptions[1], e}
		}(), "needs reason"},
		{"exception matching nothing", append(both.Exceptions[:2:2], exc("gosec", "G301", "src/cmd/tmb-broker/log.go", "MkdirAll", "2026-12-31")), "matches no finding"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			r := scan.Evaluate("gosec", findings, scan.Exceptions{Schema: scan.ExceptionsSchemaV1, Exceptions: c.ex}, today, true)
			if r.Status != result.Fail || !strings.Contains(strings.Join(r.Problems, "\n"), c.problem) {
				t.Fatalf("status %s problems %v, want %q", r.Status, r.Problems, c.problem)
			}
		})
	}
}

func TestEvaluateIgnoresOtherScannersExceptions(t *testing.T) {
	ex := scan.Exceptions{Schema: scan.ExceptionsSchemaV1, Exceptions: []scan.Exception{
		exc("trivy", "DS-0002", "harness/images/Dockerfile.host", "", "2026-12-31"),
	}}
	r := scan.Evaluate("gitleaks", nil, ex, today, true)
	if r.Status != result.Pass {
		t.Fatalf("a trivy exception must not be judged by the gitleaks run: %v", r.Problems)
	}
}

func TestTrivyDBFreshness(t *testing.T) {
	now := time.Date(2026, 10, 16, 12, 0, 0, 0, time.UTC)
	fresh := `{"Version":"0.75.0","VulnerabilityDB":{"Version":2,"UpdatedAt":"2026-10-16T06:10:00Z","DownloadedAt":"2026-10-16T11:58:00Z"}}`
	if err := scan.TrivyDBFresh(strings.NewReader(fresh), now); err != nil {
		t.Fatalf("fresh DB rejected: %v", err)
	}
	stale := `{"Version":"0.75.0","VulnerabilityDB":{"Version":2,"UpdatedAt":"2026-10-14T06:10:00Z","DownloadedAt":"2026-10-16T11:58:00Z"}}`
	if err := scan.TrivyDBFresh(strings.NewReader(stale), now); err == nil {
		t.Fatal("a DB built 54h ago must not count as fresh")
	}
	if err := scan.TrivyDBFresh(strings.NewReader(`{"Version":"0.75.0"}`), now); err == nil {
		t.Fatal("missing DB metadata must not count as fresh")
	}
}

func TestLintChecksEveryException(t *testing.T) {
	ex := scan.Exceptions{Schema: scan.ExceptionsSchemaV1, Exceptions: []scan.Exception{
		exc("gosek", "G304", "src/cmd/tmb-broker/config.go", "os.ReadFile(path)", "2026-12-31"),
		exc("trivy", "DS-0002", "Dockerfile.host", "", "2026-10-01"),
	}}
	got := strings.Join(scan.Lint(ex, today), "\n")
	for _, want := range []string{"unknown scanner \"gosek\"", "expired on 2026-10-01"} {
		if !strings.Contains(got, want) {
			t.Errorf("lint %q lacks %q", got, want)
		}
	}
}
