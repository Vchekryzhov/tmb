// Command tmbci turns tool output into TMB CI check results and computes the
// ci-gate verdict. The same binary runs locally and in GitHub Actions (see
// ci/run.sh). Exit codes: 0 PASS or NOT_APPLICABLE, 1 FAIL, 2 ERROR or other.
//
// Every check subcommand writes <out>/<check>.json stamped with TMB_CI_SHA
// and TMB_CI_RUN_ID, even when its input is missing or broken.
package main

import (
	"bufio"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"sort"
	"strings"
	"time"

	"tmb-ci/internal/badges"
	"tmb-ci/internal/coverage"
	"tmb-ci/internal/dist"
	"tmb-ci/internal/fuzz"
	"tmb-ci/internal/gate"
	"tmb-ci/internal/gotest"
	"tmb-ci/internal/harness"
	"tmb-ci/internal/manifest"
	"tmb-ci/internal/result"
	"tmb-ci/internal/sbom"
	"tmb-ci/internal/scan"
)

func main() { os.Exit(run(os.Args[1:], os.Stdout)) }

var commands = map[string]func(*env, []string) int{
	"result":          cmdResult,
	"gotest":          cmdGoTest,
	"scan":            cmdScan,
	"trivy-db":        cmdTrivyDB,
	"exceptions-lint": cmdExceptionsLint,
	"coverage":        cmdCoverage,
	"coverage-merge":  cmdCoverageMerge,
	"covdata":         cmdCovdata,
	"harness":         cmdHarness,
	"manifest":        cmdManifest,
	"fuzz":            cmdFuzz,
	"gate":            cmdGate,
	"badges":          cmdBadges,
	"archive":         cmdArchive,
	"sbom":            cmdSBOM,
}

func run(args []string, w io.Writer) int {
	if len(args) == 0 || commands[args[0]] == nil {
		names := make([]string, 0, len(commands))
		for n := range commands {
			names = append(names, n)
		}
		sort.Strings(names)
		fmt.Fprintf(w, "usage: tmbci <%s> [flags]\n", strings.Join(names, "|"))
		return 2
	}
	e := &env{w: w, sha: os.Getenv("TMB_CI_SHA"), runID: os.Getenv("TMB_CI_RUN_ID"), today: time.Now().UTC()}
	if e.sha == "" {
		if out, err := exec.Command("git", "rev-parse", "HEAD").Output(); err == nil {
			e.sha = strings.TrimSpace(string(out))
		}
	}
	if e.runID == "" {
		e.runID = "local"
	}
	if d := os.Getenv("TMB_CI_TODAY"); d != "" {
		t, err := time.Parse(time.DateOnly, d)
		if err != nil {
			fmt.Fprintf(w, "TMB_CI_TODAY: %v\n", err)
			return 2
		}
		e.today = t
	}
	return commands[args[0]](e, args[1:])
}

type env struct {
	w          io.Writer
	sha, runID string
	today      time.Time
	out        string
	tools      multi
}

type multi []string

func (m *multi) String() string     { return strings.Join(*m, ",") }
func (m *multi) Set(v string) error { *m = append(*m, v); return nil }

// flags returns a flag set carrying the common -out and -tool flags.
func (e *env) flags(name string) *flag.FlagSet {
	fs := flag.NewFlagSet(name, flag.ContinueOnError)
	fs.SetOutput(e.w)
	fs.StringVar(&e.out, "out", "out/ci/results", "directory for result JSON")
	fs.Var(&e.tools, "tool", "name=version of a tool used (repeatable)")
	return fs
}

func exitCode(s result.Status) int {
	switch s {
	case result.Pass, result.NotApplicable:
		return 0
	case result.Fail:
		return 1
	}
	return 2
}

// emit writes and prints one result and returns its exit code.
func (e *env) emit(check string, st result.Status, reason string, summary ...string) int {
	r := result.Result{Schema: result.SchemaV1, Check: check, Status: st, SHA: e.sha, RunID: e.runID, Reason: reason, Summary: summary}
	if len(e.tools) > 0 {
		r.Tools = map[string]string{}
		for _, t := range e.tools {
			k, v, _ := strings.Cut(t, "=")
			r.Tools[k] = v
		}
	}
	if check == "" {
		fmt.Fprintln(e.w, "tmbci: -check is required")
		return 2
	}
	if _, err := result.Write(e.out, r); err != nil {
		fmt.Fprintf(e.w, "tmbci: writing result: %v\n", err)
		return 2
	}
	fmt.Fprintf(e.w, "%s: %s %s\n", check, st, reason)
	for _, s := range summary {
		fmt.Fprintf(e.w, "  %s\n", s)
	}
	return exitCode(st)
}

func (e *env) fail(check string, err error) int {
	return e.emit(check, result.Error, err.Error())
}

func statusOf(problems []string) result.Status {
	if len(problems) > 0 {
		return result.Fail
	}
	return result.Pass
}

func readJSON(path string, v any) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	dec := json.NewDecoder(io.LimitReader(f, 1<<20))
	dec.DisallowUnknownFields()
	return dec.Decode(v)
}

// cmdResult records a check whose verdict a script already knows.
func cmdResult(e *env, args []string) int {
	fs := e.flags("result")
	check := fs.String("check", "", "check id")
	status := fs.String("status", "", "PASS|FAIL|ERROR|NOT_RUN|UNAVAILABLE|NOT_APPLICABLE")
	reason := fs.String("reason", "", "short reason")
	summaryFile := fs.String("summary-file", "", "file whose lines become the summary")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	st := result.Status(*status)
	if !st.Valid() {
		return e.emit(*check, result.Error, fmt.Sprintf("invalid status %q", *status))
	}
	var summary []string
	if *summaryFile != "" {
		data, err := os.ReadFile(*summaryFile)
		if err != nil {
			return e.fail(*check, err)
		}
		for _, l := range strings.Split(strings.TrimRight(string(data), "\n"), "\n") {
			if l != "" && len(summary) < 200 {
				summary = append(summary, l)
			}
		}
	}
	return e.emit(*check, st, *reason, summary...)
}

func cmdGoTest(e *env, args []string) int {
	fs := e.flags("gotest")
	check := fs.String("check", "", "check id")
	jsonPath := fs.String("json", "", "go test -json output")
	junit := fs.String("junit", "", "JUnit XML to write")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	f, err := os.Open(*jsonPath)
	if err != nil {
		return e.fail(*check, err)
	}
	s, err := gotest.Parse(f)
	f.Close()
	if err != nil {
		return e.fail(*check, err)
	}
	if *junit != "" {
		jf, err := os.Create(*junit)
		if err != nil {
			return e.fail(*check, err)
		}
		err = s.WriteJUnit(jf)
		if cerr := jf.Close(); err == nil {
			err = cerr
		}
		if err != nil {
			return e.fail(*check, err)
		}
	}
	n := s.Counts()
	return e.emit(*check, s.Status(), fmt.Sprintf("pass=%d fail=%d skip=%d", n.Pass, n.Fail, n.Skip), s.Problems()...)
}

func cmdScan(e *env, args []string) int {
	fs := e.flags("scan")
	check := fs.String("check", "", "check id")
	scanner := fs.String("scanner", "", strings.Join(scan.Scanners, "|"))
	var reports multi
	fs.Var(&reports, "report", "scanner JSON report (repeatable; findings are united)")
	exPath := fs.String("exceptions", "ci/exceptions.json", "exceptions file")
	root := fs.String("root", "", "prefix stripped from absolute file paths")
	strictUnused := fs.Bool("strict-unused", false, "fail on exceptions that cover nothing")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	var ex scan.Exceptions
	if err := readJSON(*exPath, &ex); err != nil {
		return e.fail(*check, fmt.Errorf("exceptions: %w", err))
	}
	if len(reports) == 0 {
		return e.fail(*check, errors.New("no -report given"))
	}
	var findings []scan.Finding
	seen := map[string]bool{}
	for _, p := range reports {
		f, err := os.Open(p)
		if err != nil {
			return e.fail(*check, err)
		}
		got, err := scan.Parse(*scanner, f, *root)
		f.Close()
		if err != nil {
			return e.fail(*check, fmt.Errorf("%s: %w", p, err))
		}
		for _, fd := range got {
			if k := fd.String() + fd.Snippet; !seen[k] {
				seen[k] = true
				findings = append(findings, fd)
			}
		}
	}
	r := scan.Evaluate(*scanner, findings, ex, e.today, *strictUnused)
	var summary []string
	summary = append(summary, prefixed("BLOCKING ", r.Problems)...)
	summary = append(summary, prefixed("excepted ", r.Excepted)...)
	summary = append(summary, prefixed("info ", r.Info)...)
	reason := fmt.Sprintf("%d blocking, %d excepted, %d informational", len(r.Blocking), len(r.Excepted), len(r.Info))
	return e.emit(*check, r.Status, reason, summary...)
}

func prefixed(p string, lines []string) []string {
	out := make([]string, len(lines))
	for i, l := range lines {
		out[i] = p + l
	}
	return out
}

func cmdTrivyDB(e *env, args []string) int {
	fs := e.flags("trivy-db")
	check := fs.String("check", "", "check id")
	version := fs.String("version-json", "", "trivy version --format json output")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	f, err := os.Open(*version)
	if err != nil {
		return e.fail(*check, err)
	}
	defer f.Close()
	if err := scan.TrivyDBFresh(f, time.Now().UTC()); err != nil {
		return e.emit(*check, result.Error, err.Error())
	}
	return e.emit(*check, result.Pass, fmt.Sprintf("vulnerability DB built within %gh", scan.TrivyDBMaxAge.Hours()))
}

func cmdExceptionsLint(e *env, args []string) int {
	fs := e.flags("exceptions-lint")
	check := fs.String("check", "", "check id")
	exPath := fs.String("exceptions", "ci/exceptions.json", "exceptions file")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	var ex scan.Exceptions
	if err := readJSON(*exPath, &ex); err != nil {
		return e.fail(*check, err)
	}
	p := scan.Lint(ex, e.today)
	return e.emit(*check, statusOf(p), fmt.Sprintf("%d exceptions", len(ex.Exceptions)), p...)
}

type covMeta struct {
	GOOS   string `json:"goos"`
	GOARCH string `json:"goarch"`
	Go     string `json:"go"`
	Mode   string `json:"mode"`
	SHA    string `json:"sha"`
}

func readProfile(path string) (coverage.Profile, error) {
	f, err := os.Open(path)
	if err != nil {
		return coverage.Profile{}, err
	}
	defer f.Close()
	return coverage.ParseProfile(f)
}

func readLines(path string) ([]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	var out []string
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		l := strings.TrimSpace(sc.Text())
		if l != "" && !strings.HasPrefix(l, "#") {
			out = append(out, l)
		}
	}
	return out, sc.Err()
}

// cmdCoverage writes coverage/compare, coverage/diff and coverage/targets.
func cmdCoverage(e *env, args []string) int {
	fs := e.flags("coverage")
	headPath := fs.String("head", "", "head profile")
	basePath := fs.String("base", "", "base profile (empty with -bootstrap)")
	headMeta := fs.String("head-meta", "", "head measurement metadata")
	baseMeta := fs.String("base-meta", "", "base measurement metadata")
	bootstrap := fs.String("bootstrap", "", "reason the base has no product (first baseline)")
	skipCompare := fs.Bool("skip-compare", false, "the caller already recorded coverage/compare (base unusable)")
	diffPath := fs.String("diff", "", "git diff -U0 -M base...head")
	module := fs.String("module", "tmb-poc=src", "importpath=repodir")
	policyPath := fs.String("policy", "ci/coverage-policy.json", "coverage policy")
	pkgsPath := fs.String("packages", "", "go list ./... output: packages that must be in the profile")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	const cCompare, cDiff, cTargets = "coverage/compare", "coverage/diff", "coverage/targets"
	errorAll := func(err error) int {
		for _, c := range []string{cCompare, cDiff, cTargets} {
			e.fail(c, err)
		}
		return 2
	}
	head, err := readProfile(*headPath)
	if err != nil {
		return errorAll(fmt.Errorf("head profile: %w", err))
	}
	var hm covMeta
	if err := readJSON(*headMeta, &hm); err != nil {
		return errorAll(fmt.Errorf("head metadata: %w", err))
	}
	pkgs, err := readLines(*pkgsPath)
	if err != nil {
		return errorAll(fmt.Errorf("package list: %w", err))
	}
	if len(pkgs) == 0 {
		return errorAll(errors.New("empty package list"))
	}
	pol, err := func() (coverage.Policy, error) {
		f, err := os.Open(*policyPath)
		if err != nil {
			return coverage.Policy{}, err
		}
		defer f.Close()
		return coverage.ReadPolicy(f)
	}()
	if err != nil {
		return errorAll(fmt.Errorf("policy: %w", err))
	}
	importPrefix, repoDir, _ := strings.Cut(*module, "=")
	repoPath := func(f string) string {
		return repoDir + strings.TrimPrefix(f, importPrefix)
	}

	worst := 0
	note := func(code int) {
		if code > worst {
			worst = code
		}
	}
	pkgTable := []string{fmt.Sprintf("head total %s (%d statements)", head.Total(), head.Total().Total)}
	hp := head.Packages()
	names := make([]string, 0, len(hp))
	for p := range hp {
		names = append(names, p)
	}
	sort.Strings(names)
	for _, p := range names {
		pkgTable = append(pkgTable, fmt.Sprintf("%-40s %6s of %d", p, hp[p], hp[p].Total))
	}

	// compare
	switch missing := head.MissingPackages(pkgs); {
	case *skipCompare:
	case len(missing) > 0:
		note(e.emit(cCompare, result.Error, "packages absent from the profile (excluded or not measured): "+strings.Join(missing, ", ")))
	case *bootstrap != "":
		note(e.emit(cCompare, result.Pass, "BOOTSTRAP: "+*bootstrap+"; head recorded as the first baseline", pkgTable...))
	default:
		var bm covMeta
		base, err := readProfile(*basePath)
		if err == nil {
			err = readJSON(*baseMeta, &bm)
		}
		switch {
		case err != nil:
			note(e.fail(cCompare, fmt.Errorf("base: %w", err)))
		case bm.GOOS != hm.GOOS || bm.GOARCH != hm.GOARCH || bm.Go != hm.Go || bm.Mode != hm.Mode:
			note(e.emit(cCompare, result.Error, fmt.Sprintf("base %s/%s %s %s is not comparable with head %s/%s %s %s",
				bm.GOOS, bm.GOARCH, bm.Go, bm.Mode, hm.GOOS, hm.GOARCH, hm.Go, hm.Mode)))
		default:
			c := coverage.Compare(base, head)
			summary := append(append(c.Problems, c.Notes...), pkgTable...)
			note(e.emit(cCompare, c.Status, fmt.Sprintf("base %s %s -> head %s", short(bm.SHA), base.Total(), head.Total()), summary...))
		}
	}

	// diff
	if f, err := os.Open(*diffPath); err != nil {
		note(e.fail(cDiff, err))
	} else {
		added, err := coverage.ParseUnifiedDiff(f)
		f.Close()
		if err != nil {
			note(e.fail(cDiff, err))
		} else {
			d := coverage.Diff(head, added, repoPath)
			st := d.Status(pol.DiffMin)
			reason := fmt.Sprintf("%s of %d changed statements covered (min %.0f%%)", d.Ratio, d.Ratio.Total, pol.DiffMin)
			if st == result.NotApplicable {
				reason = "no executable statements changed (tests, docs or comments only)"
			}
			note(e.emit(cDiff, st, reason, prefixed("uncovered ", d.Uncovered)...))
		}
	}

	// targets
	t := coverage.CheckTargets(pol, head, e.today)
	note(e.emit(cTargets, t.Status, fmt.Sprintf("%d targets, %d GAP", len(pol.Targets), len(t.Gaps)), append(append(t.Problems, t.Rows...), prefixed("GAP ", t.Gaps)...)...))
	return worst
}

// cmdCovdata accounts for the coverage data the harness collected
// (harness/coverage-data): counters per container and every broker process
// from the journal, either with counters or listed as killed.
func cmdCovdata(e *env, args []string) int {
	fs := e.flags("covdata")
	check := fs.String("check", "", "check id")
	dir := fs.String("dir", "", "TMB_COVER_DIR of the harness run")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	r, err := coverage.AccountCovdata(*dir)
	if err != nil {
		return e.fail(*check, err)
	}
	var rows []string
	procs, killed := 0, 0
	for _, c := range r.Containers {
		procs += c.Counters
		killed += len(c.Killed)
		row := fmt.Sprintf("%s: %d processes with counters, %d brokers started", c.Name, c.Counters, c.Brokers)
		if len(c.Killed) > 0 {
			row += fmt.Sprintf(", %d killed without counters (pids %v)", len(c.Killed), c.Killed)
		}
		rows = append(rows, row)
	}
	st := statusOf(r.Problems)
	return e.emit(*check, st, fmt.Sprintf("%d processes left counters; %d brokers killed by SIGKILL left none (listed)", procs, killed), append(r.Problems, rows...)...)
}

// cmdCoverageMerge merges the Go-test profile with the integration profile
// of the harness binaries (coverage/merged). It reports both and the union;
// no threshold applies to the union.
func cmdCoverageMerge(e *env, args []string) int {
	fs := e.flags("coverage-merge")
	check := fs.String("check", "", "check id")
	unitPath := fs.String("unit", "", "Go-test profile (ci/run.sh coverage)")
	integPath := fs.String("integration", "", "integration profile (go tool covdata textfmt)")
	outFile := fs.String("file-out", "", "merged profile to write")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	unit, err := readProfile(*unitPath)
	if err != nil {
		return e.fail(*check, fmt.Errorf("unit profile: %w", err))
	}
	integ, err := readProfile(*integPath)
	if err != nil {
		return e.fail(*check, fmt.Errorf("integration profile: %w", err))
	}
	m, err := coverage.Merge(unit, integ)
	if err != nil {
		return e.fail(*check, err)
	}
	var buf strings.Builder
	if err := m.Write(&buf); err != nil {
		return e.fail(*check, err)
	}
	if err := os.WriteFile(*outFile, []byte(buf.String()), 0o644); err != nil {
		return e.fail(*check, err)
	}
	rows := []string{
		fmt.Sprintf("go test     %s", unit.Total()),
		fmt.Sprintf("integration %s (packages linked into tmb and tmb-broker)", integ.Total()),
		fmt.Sprintf("merged      %s; %d statements covered only by the harness", m.Total(), integ.OnlyIn(unit)),
	}
	mp := m.Packages()
	names := make([]string, 0, len(mp))
	for p := range mp {
		names = append(names, p)
	}
	sort.Strings(names)
	for _, p := range names {
		rows = append(rows, fmt.Sprintf("%-40s %6s of %d", p, mp[p], mp[p].Total))
	}
	return e.emit(*check, result.Pass, fmt.Sprintf("go test %s + harness %s = %s", unit.Total(), integ.Total(), m.Total()), rows...)
}

func short(sha string) string {
	if len(sha) > 12 {
		return sha[:12]
	}
	return sha
}

// scenarioFile carries verified scenario verdicts from harness to manifest.
type scenarioFile struct {
	Schema    string                   `json:"schema"`
	SHA       string                   `json:"sha"`
	RunID     string                   `json:"run_id"`
	Scenarios map[string]result.Status `json:"scenarios"`
}

const scenariosSchemaV1 = "tmb-ci/scenarios/v1"

func cmdHarness(e *env, args []string) int {
	fs := e.flags("harness")
	check := fs.String("check", "", "check id")
	logPath := fs.String("log", "", "runner log")
	registryPath := fs.String("registry", "", "expected scenario ids, one per line")
	rc := fs.Int("rc", -1, "runner exit code")
	since := fs.String("since", "", "RFC3339 start of this CI run")
	scenariosOut := fs.String("scenarios-out", "", "write verified scenario verdicts here")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	start, err := time.Parse(time.RFC3339, *since)
	if err != nil {
		return e.fail(*check, fmt.Errorf("-since: %w", err))
	}
	registry, err := readLines(*registryPath)
	if err != nil {
		return e.fail(*check, err)
	}
	f, err := os.Open(*logPath)
	if err != nil {
		return e.fail(*check, err)
	}
	r := harness.Verify(f, registry, *rc, start)
	f.Close()
	if *scenariosOut != "" {
		data, _ := json.MarshalIndent(scenarioFile{Schema: scenariosSchemaV1, SHA: e.sha, RunID: e.runID, Scenarios: r.Scenarios}, "", "  ")
		if err := os.WriteFile(*scenariosOut, append(data, '\n'), 0o644); err != nil {
			return e.fail(*check, err)
		}
	}
	reason := fmt.Sprintf("%d registered scenarios, checks PASS=%d FAIL=%d, rc=%d", len(registry), r.Pass, r.Fail, *rc)
	return e.emit(*check, r.Status, reason, r.Problems...)
}

type passedSet map[string]bool

func (p passedSet) Passed(id string) bool { return p[id] }

func cmdManifest(e *env, args []string) int {
	fs := e.flags("manifest")
	check := fs.String("check", "", "check id")
	mPath := fs.String("manifest", "ci/security-manifest.json", "security manifest")
	var testFiles, scenarioFiles multi
	fs.Var(&testFiles, "tests", "go test -json stream (repeatable)")
	fs.Var(&scenarioFiles, "scenarios", "harness scenarios file (repeatable)")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	f, err := os.Open(*mPath)
	if err != nil {
		return e.fail(*check, err)
	}
	m, err := manifest.Read(f)
	f.Close()
	if err != nil {
		return e.fail(*check, err)
	}
	tests := passedSet{}
	for _, p := range testFiles {
		tf, err := os.Open(p)
		if err != nil {
			return e.fail(*check, err)
		}
		s, err := gotest.Parse(tf)
		tf.Close()
		if err != nil {
			return e.fail(*check, fmt.Errorf("%s: %w", p, err))
		}
		for _, c := range m.Cases {
			for _, id := range c.Tests {
				if s.Passed(id) {
					tests[id] = true
				}
			}
		}
	}
	scen := passedSet{}
	for _, p := range scenarioFiles {
		var sf scenarioFile
		if err := readJSON(p, &sf); err != nil {
			return e.fail(*check, fmt.Errorf("%s: %w", p, err))
		}
		if sf.Schema != scenariosSchemaV1 || sf.SHA != e.sha || sf.RunID != e.runID {
			return e.emit(*check, result.Error, fmt.Sprintf("%s is not from this run (sha %s run %s)", p, short(sf.SHA), sf.RunID))
		}
		for id, st := range sf.Scenarios {
			if st == result.Pass {
				scen[id] = true
			}
		}
	}
	r := manifest.Verify(m, tests, scen, e.today)
	summary := append(append(append(r.Problems, prefixed("proven ", r.Proven)...), prefixed("GAP ", r.Gaps)...), prefixed("deferred ", r.Deferred)...)
	reason := fmt.Sprintf("%d cases: %d proofs, %d GAP, %d deferred to OpenShell or the VM proof", len(m.Cases), len(r.Proven), len(r.Gaps), len(r.Deferred))
	return e.emit(*check, r.Status, reason, summary...)
}

func cmdFuzz(e *env, args []string) int {
	fs := e.flags("fuzz")
	check := fs.String("check", "", "check id")
	regPath := fs.String("registry", "ci/fuzz-targets.json", "fuzz registry")
	listPath := fs.String("list", "", "go test -list '^Fuzz' ./... output")
	targetsOut := fs.String("targets-out", "", "write 'package Name' lines of targets to fuzz")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	rf, err := os.Open(*regPath)
	if err != nil {
		return e.fail(*check, err)
	}
	reg, err := fuzz.ReadRegistry(rf)
	rf.Close()
	if err != nil {
		return e.fail(*check, err)
	}
	lf, err := os.Open(*listPath)
	if err != nil {
		return e.fail(*check, err)
	}
	declared, err := fuzz.ParseList(lf)
	lf.Close()
	if err != nil {
		return e.fail(*check, err)
	}
	r := fuzz.Check(reg, declared, e.today)
	if *targetsOut != "" {
		var b strings.Builder
		for _, t := range r.Run {
			fmt.Fprintf(&b, "%s %s\n", t.Package, t.Name)
		}
		if err := os.WriteFile(*targetsOut, []byte(b.String()), 0o644); err != nil {
			return e.fail(*check, err)
		}
	}
	return e.emit(*check, r.Status, fmt.Sprintf("%d to fuzz, %d GAP", len(r.Run), len(r.Gaps)), append(r.Problems, prefixed("GAP ", r.Gaps)...)...)
}

// cmdGate reads every result and the needs context (TMB_CI_NEEDS, passed
// as an environment variable so job data never becomes shell code).
func cmdGate(e *env, args []string) int {
	fs := e.flags("gate")
	reqPath := fs.String("requirements", "ci/required-checks.json", "required checks per event")
	event := fs.String("event", "", "GitHub event name")
	results := fs.String("results", "out/ci/results", "directory of result JSON")
	summaryPath := fs.String("summary", "", "write a Markdown summary here")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	var all map[string]gate.Requirements
	if err := readJSON(*reqPath, &all); err != nil {
		fmt.Fprintf(e.w, "ci-gate: ERROR requirements: %v\n", err)
		return 2
	}
	req, ok := all[*event]
	if !ok {
		fmt.Fprintf(e.w, "ci-gate: ERROR no requirements for event %q\n", *event)
		return 2
	}
	var needs map[string]struct {
		Result string `json:"result"`
	}
	if err := json.Unmarshal([]byte(os.Getenv("TMB_CI_NEEDS")), &needs); err != nil {
		fmt.Fprintf(e.w, "ci-gate: ERROR needs context: %v\n", err)
		return 2
	}
	jobs := map[string]string{}
	for k, v := range needs {
		jobs[k] = v.Result
	}
	rs, err := result.ReadDir(*results)
	if err != nil {
		fmt.Fprintf(e.w, "ci-gate: ERROR reading results: %v\n", err)
		return 2
	}
	v := gate.Evaluate(req, rs, gate.Expect{SHA: e.sha, RunID: e.runID, Jobs: jobs})
	verdict := "GREEN"
	if !v.Green {
		verdict = "RED"
	}
	var md strings.Builder
	fmt.Fprintf(&md, "## ci-gate: %s\n\nevent `%s`, tested SHA `%s`, run `%s`, %d required checks, %d jobs\n\n", verdict, *event, e.sha, e.runID, len(req.Checks), len(req.Jobs))
	if len(v.Problems) > 0 {
		md.WriteString("### Problems\n\n")
		for _, p := range v.Problems {
			fmt.Fprintf(&md, "- %s\n", p)
		}
		md.WriteString("\n")
	}
	md.WriteString("### Checks\n\n```\n")
	for _, r := range v.Rows {
		md.WriteString(r + "\n")
	}
	md.WriteString("```\n")
	fmt.Fprint(e.w, md.String())
	if *summaryPath != "" {
		if err := os.WriteFile(*summaryPath, []byte(md.String()), 0o644); err != nil {
			fmt.Fprintf(e.w, "ci-gate: ERROR summary: %v\n", err)
			return 2
		}
	}
	if !v.Green {
		return 1
	}
	return 0
}

// cmdBadges writes shields.io endpoint JSON under -dir: tool versions from
// the pins (mode tools; -check only compares) or the badges of one run's
// results (mode results). It is not a check and writes no result.
func cmdBadges(e *env, args []string) int {
	fs := e.flags("badges") // -out is accepted for uniformity and unused
	mode := fs.String("mode", "", "tools or results")
	dir := fs.String("dir", "docs/badges", "badge directory")
	check := fs.Bool("check", false, "tools: compare with the files instead of writing")
	results := fs.String("results", "out/ci/results", "results: directory of result JSON")
	goVersion := fs.String("go-version", ".go-version", "tools: Go version file")
	lock := fs.String("tools-lock", "ci/tools.lock", "tools: binary tool pins")
	toolsDir := fs.String("tools-dir", "ci/tools", "tools: Go tool modules")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	var set map[string]badges.Badge
	var err error
	switch *mode {
	case "tools":
		set, err = badges.FromPins(*goVersion, *lock, *toolsDir)
	case "results":
		var rs map[string]result.Result
		rs, err = badges.ReadResults(*results)
		if err == nil {
			set = badges.FromResults(rs)
		}
	default:
		err = fmt.Errorf("-mode must be tools or results")
	}
	if err != nil {
		fmt.Fprintf(e.w, "badges: ERROR %v\n", err)
		return 2
	}
	if *check {
		problems := badges.Check(*dir, set)
		for _, p := range problems {
			fmt.Fprintln(e.w, p)
		}
		if len(problems) > 0 {
			return 1
		}
		fmt.Fprintf(e.w, "badges: %d tool badges match the pins\n", len(set))
		return 0
	}
	paths, err := badges.Write(*dir, set)
	if err != nil {
		fmt.Fprintf(e.w, "badges: ERROR %v\n", err)
		return 2
	}
	for _, p := range paths {
		fmt.Fprintln(e.w, p)
	}
	return 0
}

// cmdArchive writes a deterministic tar.gz of the given files (release
// archives of the tmb client, ci/run.sh dist). It is not a check and writes
// no result.
func cmdArchive(e *env, args []string) int {
	fs := e.flags("archive") // -out is accepted for uniformity and unused
	outFile := fs.String("file-out", "", "archive to write")
	mtime := fs.Int64("mtime", -1, "entry mtime, Unix seconds (SOURCE_DATE_EPOCH)")
	var specs multi
	fs.Var(&specs, "file", "name=path of an entry (repeatable)")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if *outFile == "" || *mtime < 0 || len(specs) == 0 {
		fmt.Fprintln(e.w, "archive: -file-out, -mtime and at least one -file are required")
		return 2
	}
	var files []dist.File
	for _, s := range specs {
		f, err := dist.ParseFile(s)
		if err != nil {
			fmt.Fprintf(e.w, "archive: %v\n", err)
			return 2
		}
		files = append(files, f)
	}
	var buf strings.Builder
	if err := dist.WriteTarGz(&buf, files, time.Unix(*mtime, 0)); err != nil {
		fmt.Fprintf(e.w, "archive: %v\n", err)
		return 2
	}
	if err := os.WriteFile(*outFile, []byte(buf.String()), 0o644); err != nil {
		fmt.Fprintf(e.w, "archive: %v\n", err)
		return 2
	}
	fmt.Fprintln(e.w, *outFile)
	return 0
}

// cmdSBOM writes the CycloneDX SBOM of one release file (deb, rpm or
// tar.gz) and the Go binaries in it (ci/run.sh dist). It is not a check and
// writes no result.
func cmdSBOM(e *env, args []string) int {
	fs := e.flags("sbom") // -out is accepted for uniformity and unused
	outFile := fs.String("file-out", "", "SBOM to write")
	var a sbom.Artifact
	var o sbom.Options
	fs.StringVar(&a.Path, "artifact", "", "release file the SBOM describes")
	fs.StringVar(&a.Type, "type", "", "deb, rpm or archive")
	fs.StringVar(&a.Name, "name", "", "package name")
	fs.StringVar(&a.Version, "pkg-version", "", "version as the package carries it")
	fs.StringVar(&a.OS, "os", "", "archive only: target OS")
	fs.StringVar(&a.Arch, "arch", "", "architecture as the file names it")
	fs.StringVar(&o.Version, "version", "", "product version of the binaries")
	fs.StringVar(&o.Supplier, "supplier", "", "supplier name")
	fs.StringVar(&o.URL, "url", "", "source repository")
	mtime := fs.Int64("mtime", -1, "BOM timestamp, Unix seconds (SOURCE_DATE_EPOCH)")
	var specs multi
	fs.Var(&specs, "binary", "name=path of a Go binary in the artifact (repeatable)")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if *outFile == "" || *mtime < 0 {
		fmt.Fprintln(e.w, "sbom: -file-out and -mtime are required")
		return 2
	}
	o.Time = time.Unix(*mtime, 0)
	var bins []sbom.Binary
	for _, s := range specs {
		name, path, ok := strings.Cut(s, "=")
		if !ok || name == "" || path == "" {
			fmt.Fprintf(e.w, "sbom: binary %q: want name=path\n", s)
			return 2
		}
		bins = append(bins, sbom.Binary{Name: name, Path: path})
	}
	var buf strings.Builder
	if err := sbom.Write(&buf, a, bins, o); err != nil {
		fmt.Fprintf(e.w, "sbom: %v\n", err)
		return 2
	}
	if err := os.WriteFile(*outFile, []byte(buf.String()), 0o644); err != nil {
		fmt.Fprintf(e.w, "sbom: %v\n", err)
		return 2
	}
	fmt.Fprintln(e.w, *outFile)
	return 0
}
