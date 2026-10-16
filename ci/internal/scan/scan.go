// Package scan normalises scanner reports into findings, decides which
// findings block, and applies the addressed, expiring exceptions of
// ci/exceptions.json (spec #13 section E).
package scan

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"tmb-ci/internal/accountable"
	"tmb-ci/internal/result"
)

type Finding struct {
	Scanner  string
	Rule     string // rule, advisory or misconfiguration ID
	Location string // repository file, Go module or OS package
	Snippet  string // code or redacted match, when the scanner gives one
	Severity string
	Detail   string
	Blocking bool
}

func (f Finding) String() string {
	return fmt.Sprintf("%s %s %s [%s] %s", f.Scanner, f.Rule, f.Location, f.Severity, f.Detail)
}

const maxReport = 64 << 20

// Parse reads one report. root is stripped from absolute file paths so
// locations are repository-relative. A report that shows an incomplete
// scan is an error, never an empty list of findings.
func Parse(scanner string, r io.Reader, root string) ([]Finding, error) {
	data, err := io.ReadAll(io.LimitReader(r, maxReport))
	if err != nil {
		return nil, err
	}
	switch scanner {
	case "gosec":
		return parseGosec(data, root)
	case "govulncheck":
		return parseGovulncheck(data)
	case "trivy":
		return parseTrivy(data)
	case "gitleaks":
		return parseGitleaks(data)
	case "staticcheck":
		return parseStaticcheck(data, root)
	}
	return nil, fmt.Errorf("unknown scanner %q", scanner)
}

func strict(data []byte, v any) error {
	dec := json.NewDecoder(strings.NewReader(string(data)))
	return dec.Decode(v)
}

func parseGosec(data []byte, root string) ([]Finding, error) {
	var rep struct {
		Errors map[string]json.RawMessage `json:"Golang errors"`
		Issues *[]struct {
			Severity string `json:"severity"`
			Rule     string `json:"rule_id"`
			Details  string `json:"details"`
			File     string `json:"file"`
			Code     string `json:"code"`
			Line     string `json:"line"`
		} `json:"Issues"`
	}
	if err := strict(data, &rep); err != nil {
		return nil, fmt.Errorf("gosec: %w", err)
	}
	if rep.Issues == nil {
		return nil, fmt.Errorf("gosec: report has no Issues list")
	}
	if len(rep.Errors) > 0 {
		return nil, fmt.Errorf("gosec: %d package(s) failed to load, scan incomplete", len(rep.Errors))
	}
	var out []Finding
	for _, i := range *rep.Issues {
		out = append(out, Finding{Scanner: "gosec", Rule: i.Rule, Location: strings.TrimPrefix(i.File, root),
			Snippet: i.Code, Severity: i.Severity, Detail: i.Details + " (line " + i.Line + ")",
			// MEDIUM and HIGH block; LOW stays in the report
			Blocking: i.Severity == "MEDIUM" || i.Severity == "HIGH" || i.Severity == "CRITICAL"})
	}
	return out, nil
}

func parseGovulncheck(data []byte) ([]Finding, error) {
	var out []Finding
	sawConfig := false
	dec := json.NewDecoder(strings.NewReader(string(data)))
	for {
		var msg struct {
			Config *struct {
				ScanLevel string `json:"scan_level"`
			} `json:"config"`
			Finding *struct {
				OSV   string `json:"osv"`
				Fixed string `json:"fixed_version"`
				Trace []struct {
					Module   string `json:"module"`
					Package  string `json:"package"`
					Function string `json:"function"`
				} `json:"trace"`
			} `json:"finding"`
		}
		err := dec.Decode(&msg)
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("govulncheck: %w", err)
		}
		if msg.Config != nil {
			sawConfig = true
			if msg.Config.ScanLevel != "symbol" {
				return nil, fmt.Errorf("govulncheck: scan level %q, want symbol", msg.Config.ScanLevel)
			}
		}
		if f := msg.Finding; f != nil && len(f.Trace) > 0 {
			top := f.Trace[0]
			// A function in the innermost frame means a vulnerable symbol is
			// reachable; module/package-only findings are informational.
			out = append(out, Finding{Scanner: "govulncheck", Rule: f.OSV, Location: top.Module,
				Severity: "n/a", Detail: fmt.Sprintf("%s %s fixed in %s", top.Package, top.Function, f.Fixed),
				Blocking: top.Function != ""})
		}
	}
	if !sawConfig {
		return nil, fmt.Errorf("govulncheck: no config message, scan did not complete")
	}
	return dedupe(out), nil
}

// dedupe keeps one finding per rule/location, blocking if any trace was.
func dedupe(in []Finding) []Finding {
	idx := map[string]int{}
	var out []Finding
	for _, f := range in {
		k := f.Rule + "@" + f.Location
		if i, ok := idx[k]; ok {
			out[i].Blocking = out[i].Blocking || f.Blocking
			continue
		}
		idx[k] = len(out)
		out = append(out, f)
	}
	return out
}

func blockingSeverity(s string) bool { return s == "HIGH" || s == "CRITICAL" }

func parseTrivy(data []byte) ([]Finding, error) {
	var rep struct {
		SchemaVersion int
		Results       []struct {
			Target          string
			Vulnerabilities []struct {
				VulnerabilityID, PkgName, InstalledVersion, FixedVersion, Severity string
			}
			Misconfigurations []struct {
				ID, Title, Severity, Status string
			}
		}
	}
	if err := strict(data, &rep); err != nil {
		return nil, fmt.Errorf("trivy: %w", err)
	}
	if rep.SchemaVersion != 2 {
		return nil, fmt.Errorf("trivy: schema version %d, want 2", rep.SchemaVersion)
	}
	var out []Finding
	for _, res := range rep.Results {
		for _, v := range res.Vulnerabilities {
			out = append(out, Finding{Scanner: "trivy", Rule: v.VulnerabilityID, Location: v.PkgName, Severity: v.Severity,
				Detail:   fmt.Sprintf("%s %s in %s (fixed: %s)", v.PkgName, v.InstalledVersion, res.Target, orNone(v.FixedVersion)),
				Blocking: blockingSeverity(v.Severity)})
		}
		for _, m := range res.Misconfigurations {
			if m.Status != "FAIL" {
				continue
			}
			out = append(out, Finding{Scanner: "trivy", Rule: m.ID, Location: res.Target, Severity: m.Severity,
				Detail: m.Title, Blocking: blockingSeverity(m.Severity)})
		}
	}
	return out, nil
}

func orNone(s string) string {
	if s == "" {
		return "none"
	}
	return s
}

func parseGitleaks(data []byte) ([]Finding, error) {
	var leaks []struct {
		RuleID      string
		File        string
		StartLine   int
		Match       string
		Fingerprint string
	}
	if err := strict(data, &leaks); err != nil {
		return nil, fmt.Errorf("gitleaks: %w", err)
	}
	var out []Finding
	for _, l := range leaks {
		out = append(out, Finding{Scanner: "gitleaks", Rule: l.RuleID, Location: l.File, Snippet: l.Match,
			Severity: "secret", Detail: fmt.Sprintf("line %d (%s)", l.StartLine, l.Fingerprint), Blocking: true})
	}
	return out, nil
}

// parseStaticcheck reads `staticcheck -f json` (one object per line). The
// flagged source line becomes the snippet an exception's match refers to.
// A "compile" diagnostic means the code could not be analysed: an error.
func parseStaticcheck(data []byte, root string) ([]Finding, error) {
	var out []Finding
	dec := json.NewDecoder(strings.NewReader(string(data)))
	for {
		var d struct {
			Code     string
			Severity string
			Message  string
			Location struct {
				File string
				Line int
			}
		}
		err := dec.Decode(&d)
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("staticcheck: %w", err)
		}
		if d.Code == "compile" || d.Code == "" {
			return nil, fmt.Errorf("staticcheck could not analyse the code: %s", d.Message)
		}
		snippet := ""
		if src, err := os.ReadFile(d.Location.File); err == nil {
			if lines := strings.Split(string(src), "\n"); d.Location.Line >= 1 && d.Location.Line <= len(lines) {
				snippet = lines[d.Location.Line-1]
			}
		}
		out = append(out, Finding{Scanner: "staticcheck", Rule: d.Code, Location: strings.TrimPrefix(d.Location.File, root),
			Snippet: snippet, Severity: d.Severity, Detail: fmt.Sprintf("%s (line %d)", d.Message, d.Location.Line), Blocking: true})
	}
	return out, nil
}

const ExceptionsSchemaV1 = "tmb-ci/exceptions/v1"

// maxHorizon caps how far ahead an exception may expire.
const maxHorizon = 180 * 24 * time.Hour

type Exception struct {
	Scanner  string `json:"scanner"`
	Rule     string `json:"rule"`
	Location string `json:"location"`
	Match    string `json:"match,omitempty"`
	Reason   string `json:"reason"`
	Owner    string `json:"owner"`
	Issue    string `json:"issue"`
	Expires  string `json:"expires"`
}

type Exceptions struct {
	Schema     string      `json:"schema"`
	Exceptions []Exception `json:"exceptions"`
}

func ReadExceptions(r io.Reader) (Exceptions, error) {
	var e Exceptions
	dec := json.NewDecoder(io.LimitReader(r, 1<<20))
	dec.DisallowUnknownFields()
	err := dec.Decode(&e)
	return e, err
}

// codeScanners report code snippets; their exceptions must name the code.
var codeScanners = map[string]bool{"gosec": true, "gitleaks": true, "staticcheck": true}

func (e Exception) problems(today time.Time) []string {
	name := fmt.Sprintf("exception %s %s %s", e.Scanner, e.Rule, e.Location)
	p := accountable.Problems(name, e.Owner, e.Issue, e.Expires, today)
	if e.Reason == "" {
		p = append(p, name+" needs reason")
	}
	if e.Rule == "" || strings.ContainsAny(e.Rule, "*?") {
		p = append(p, name+": rule must name one rule or advisory")
	}
	if e.Location == "" || strings.HasSuffix(e.Location, "/") || strings.ContainsAny(e.Location, "*?") || e.Location == "." {
		p = append(p, name+": location must be one file or package")
	}
	if codeScanners[e.Scanner] && strings.TrimSpace(e.Match) == "" {
		p = append(p, name+" needs match: the code it covers")
	}
	if d, err := time.Parse(time.DateOnly, e.Expires); err == nil && d.Sub(today) > maxHorizon {
		p = append(p, name+": expires more than 180 days ahead")
	}
	return p
}

func (e Exception) covers(f Finding) bool {
	return e.Scanner == f.Scanner && e.Rule == f.Rule && e.Location == f.Location &&
		(e.Match == "" || strings.Contains(f.Snippet, e.Match))
}

// Scanners are the scanners an exception may name.
var Scanners = []string{"gosec", "govulncheck", "trivy", "gitleaks", "staticcheck"}

// Lint validates every exception, including ones for scanners that no run
// would otherwise judge.
func Lint(ex Exceptions, today time.Time) []string {
	var p []string
	if ex.Schema != ExceptionsSchemaV1 {
		p = append(p, fmt.Sprintf("exceptions schema %q, want %q", ex.Schema, ExceptionsSchemaV1))
	}
	for _, e := range ex.Exceptions {
		known := false
		for _, s := range Scanners {
			known = known || s == e.Scanner
		}
		if !known {
			p = append(p, fmt.Sprintf("exception %s %s: unknown scanner %q", e.Rule, e.Location, e.Scanner))
		}
		p = append(p, e.problems(today)...)
	}
	return p
}

type Report struct {
	Status   result.Status
	Problems []string
	Blocking []string
	Excepted []string
	Info     []string
}

// Evaluate judges one scanner's findings. With strictUnused an exception
// for this scanner that covers no finding is itself a problem.
func Evaluate(scanner string, findings []Finding, ex Exceptions, today time.Time, strictUnused bool) Report {
	var r Report
	if ex.Schema != ExceptionsSchemaV1 {
		r.Problems = append(r.Problems, fmt.Sprintf("exceptions schema %q, want %q", ex.Schema, ExceptionsSchemaV1))
	}
	var mine []Exception
	for _, e := range ex.Exceptions {
		if e.Scanner == scanner {
			mine = append(mine, e)
			r.Problems = append(r.Problems, e.problems(today)...)
		}
	}
	used := make([]bool, len(mine))
	for _, f := range findings {
		excepted := false
		for i, e := range mine {
			if e.covers(f) {
				used[i], excepted = true, true
			}
		}
		switch {
		case excepted:
			r.Excepted = append(r.Excepted, f.String())
		case f.Blocking:
			r.Blocking = append(r.Blocking, f.String())
			r.Problems = append(r.Problems, f.String())
		default:
			r.Info = append(r.Info, f.String())
		}
	}
	if strictUnused {
		for i, e := range mine {
			if !used[i] {
				r.Problems = append(r.Problems, fmt.Sprintf("exception %s %s %s matches no finding: remove it", e.Scanner, e.Rule, e.Location))
			}
		}
	}
	r.Status = result.Pass
	if len(r.Problems) > 0 {
		r.Status = result.Fail
	}
	return r
}

// TrivyDBFresh checks `trivy version --format json`: the vulnerability DB
// must have been built at the source within 24 hours.
func TrivyDBFresh(r io.Reader, now time.Time) error {
	var v struct {
		VulnerabilityDB *struct {
			UpdatedAt    time.Time
			DownloadedAt time.Time
		}
	}
	if err := json.NewDecoder(bufio.NewReader(io.LimitReader(r, 1<<20))).Decode(&v); err != nil {
		return err
	}
	if v.VulnerabilityDB == nil || v.VulnerabilityDB.UpdatedAt.IsZero() {
		return fmt.Errorf("trivy reports no vulnerability DB metadata")
	}
	if age := now.Sub(v.VulnerabilityDB.UpdatedAt); age > 24*time.Hour {
		return fmt.Errorf("trivy DB built %s ago (limit 24h)", age.Round(time.Minute))
	}
	return nil
}
