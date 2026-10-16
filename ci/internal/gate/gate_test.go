package gate_test

import (
	"strings"
	"testing"

	"tmb-ci/internal/gate"
	"tmb-ci/internal/result"
)

const sha = "0123456789abcdef0123456789abcdef01234567"

func pass(check string) result.Result {
	return result.Result{Schema: result.SchemaV1, Check: check, Status: result.Pass, SHA: sha, RunID: "42"}
}

func TestGateGreenWhenEveryRequiredCheckPassed(t *testing.T) {
	req := gate.Requirements{Checks: []gate.Required{{Check: "build"}, {Check: "test/linux-amd64"}}}
	v := gate.Evaluate(req, []result.Result{pass("build"), pass("test/linux-amd64")}, gate.Expect{SHA: sha, RunID: "42"})
	if !v.Green {
		t.Fatalf("want green, got red: %v", v.Problems)
	}
}

func TestGateRed(t *testing.T) {
	req := gate.Requirements{Checks: []gate.Required{
		{Check: "build"},
		{Check: "fuzz", AllowNotApplicable: true},
	}}
	exp := gate.Expect{SHA: sha, RunID: "42"}
	with := func(f func(*result.Result)) []result.Result {
		r := pass("build")
		f(&r)
		return []result.Result{r, pass("fuzz")}
	}
	cases := []struct {
		name    string
		results []result.Result
		problem string
	}{
		{"missing required check", []result.Result{pass("fuzz")}, "build: missing"},
		{"failed check", with(func(r *result.Result) { r.Status = result.Fail }), "build: FAIL"},
		{"scanner error", with(func(r *result.Result) { r.Status = result.Error }), "build: ERROR"},
		{"not run", with(func(r *result.Result) { r.Status = result.NotRun }), "build: NOT_RUN"},
		{"unavailable", with(func(r *result.Result) { r.Status = result.Unavailable }), "build: UNAVAILABLE"},
		{"not applicable where not allowed", with(func(r *result.Result) { r.Status = result.NotApplicable }), "build: NOT_APPLICABLE"},
		{"report from another commit", with(func(r *result.Result) { r.SHA = strings.Repeat("f", 40) }), "build: tested SHA"},
		{"report from an older run", with(func(r *result.Result) { r.RunID = "41" }), "build: run"},
		{"unknown schema", with(func(r *result.Result) { r.Schema = "v0" }), "build: schema"},
		{"unknown status", with(func(r *result.Result) { r.Status = "GREEN" }), "build: status"},
		{"duplicate report", append(with(func(*result.Result) {}), pass("build")), "build: duplicate"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			v := gate.Evaluate(req, c.results, exp)
			if v.Green {
				t.Fatal("want red, got green")
			}
			if !strings.Contains(strings.Join(v.Problems, "\n"), c.problem) {
				t.Fatalf("problems %q lack %q", v.Problems, c.problem)
			}
		})
	}
}

func TestGateAllowsNotApplicableOnlyWhereDeclared(t *testing.T) {
	req := gate.Requirements{Checks: []gate.Required{{Check: "diff-coverage", AllowNotApplicable: true}}}
	na := pass("diff-coverage")
	na.Status = result.NotApplicable
	na.Reason = "no executable lines changed"
	if v := gate.Evaluate(req, []result.Result{na}, gate.Expect{SHA: sha, RunID: "42"}); !v.Green {
		t.Fatalf("want green, got %v", v.Problems)
	}
	na.Reason = ""
	if v := gate.Evaluate(req, []result.Result{na}, gate.Expect{SHA: sha, RunID: "42"}); v.Green {
		t.Fatal("NOT_APPLICABLE without a reason must be red")
	}
}

func TestGateRedWhenRequiredJobDidNotSucceed(t *testing.T) {
	req := gate.Requirements{Checks: []gate.Required{{Check: "build"}}, Jobs: []string{"build", "pair"}}
	exp := gate.Expect{SHA: sha, RunID: "42", Jobs: map[string]string{"build": "success", "pair": "cancelled"}}
	v := gate.Evaluate(req, []result.Result{pass("build")}, exp)
	if v.Green || !strings.Contains(strings.Join(v.Problems, "\n"), "job pair: cancelled") {
		t.Fatalf("want red for cancelled job, got green=%v %v", v.Green, v.Problems)
	}
	exp.Jobs = map[string]string{"build": "success"}
	v = gate.Evaluate(req, []result.Result{pass("build")}, exp)
	if v.Green || !strings.Contains(strings.Join(v.Problems, "\n"), "job pair: missing") {
		t.Fatalf("want red for missing job, got green=%v %v", v.Green, v.Problems)
	}
}

func TestGateRedOnEmptyRequirements(t *testing.T) {
	if v := gate.Evaluate(gate.Requirements{}, nil, gate.Expect{SHA: sha, RunID: "42"}); v.Green {
		t.Fatal("an empty requirement list must never be green")
	}
}
