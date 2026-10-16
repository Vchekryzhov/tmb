// Package gate decides the single required ci-gate verdict from check reports.
package gate

import (
	"fmt"
	"sort"

	"tmb-ci/internal/result"
)

// Required is one check the gate expects a report for.
type Required struct {
	Check string `json:"check"`
	// AllowNotApplicable accepts NOT_APPLICABLE when the report gives a reason.
	AllowNotApplicable bool `json:"allow_not_applicable,omitempty"`
}

// Requirements lists what one event must produce.
type Requirements struct {
	Checks []Required `json:"checks"`
	// Jobs are workflow jobs whose conclusion must be "success".
	Jobs []string `json:"jobs"`
}

// Expect is what the gate knows independently of the reports.
type Expect struct {
	SHA   string
	RunID string
	// Jobs maps job id to its conclusion (the needs context).
	Jobs map[string]string
}

type Verdict struct {
	Green    bool
	Problems []string
	Rows     []string
}

func Evaluate(req Requirements, results []result.Result, exp Expect) Verdict {
	var v Verdict
	bad := func(format string, a ...any) { v.Problems = append(v.Problems, fmt.Sprintf(format, a...)) }

	if len(req.Checks) == 0 {
		bad("requirements: empty check list")
	}
	byCheck := map[string]result.Result{}
	for _, r := range results {
		if _, dup := byCheck[r.Check]; dup {
			bad("%s: duplicate report", r.Check)
			continue
		}
		byCheck[r.Check] = r
	}
	for _, q := range req.Checks {
		r, ok := byCheck[q.Check]
		if !ok {
			bad("%s: missing report", q.Check)
			v.Rows = append(v.Rows, fmt.Sprintf("%-40s MISSING", q.Check))
			continue
		}
		v.Rows = append(v.Rows, fmt.Sprintf("%-40s %s %s", q.Check, r.Status, r.Reason))
		switch {
		case r.Schema != result.SchemaV1:
			bad("%s: schema %q, want %q", q.Check, r.Schema, result.SchemaV1)
		case !r.Status.Valid():
			bad("%s: status %q is not part of the contract", q.Check, r.Status)
		case r.SHA != exp.SHA:
			bad("%s: tested SHA %s, want %s", q.Check, r.SHA, exp.SHA)
		case r.RunID != exp.RunID:
			bad("%s: run %s, want %s (stale report)", q.Check, r.RunID, exp.RunID)
		case r.Status == result.Pass:
		case r.Status == result.NotApplicable && q.AllowNotApplicable && r.Reason != "":
		default:
			bad("%s: %s %s", q.Check, r.Status, r.Reason)
		}
	}
	jobs := append([]string(nil), req.Jobs...)
	sort.Strings(jobs)
	for _, j := range jobs {
		c, ok := exp.Jobs[j]
		switch {
		case !ok:
			bad("job %s: missing", j)
		case c != "success":
			bad("job %s: %s", j, c)
		}
	}
	v.Green = len(v.Problems) == 0
	return v
}
