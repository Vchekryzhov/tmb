package harness_test

import (
	"strings"
	"testing"
	"time"

	"tmb-ci/internal/harness"
	"tmb-ci/internal/result"
)

var since = time.Date(2026, 10, 16, 10, 0, 0, 0, time.UTC)

// greenLog follows the exact line shapes harness/run.sh prints.
const greenLog = `
================================================================
== TMB BROKER PROTOTYPE RUNNER (2026-10-16T10:05:00Z)
================================================================
docker 27.0 (linux/amd64)

================================================================
== STAGE 0: idempotent teardown + build images + start containers
================================================================
CHECK PASS: containers up (sandbox uid=4242, host uid=0)

================================================================
== SCENARIO HAPPY: mock-approve, tmb exec --root -- /usr/bin/id -u
================================================================
CHECK PASS: HAPPY: exit code 0 (rc=0)
CHECK PASS: HAPPY: stdout is exactly '0' (stdout='0')

================================================================
== SCENARIO N1: spent token presented with DIFFERENT argv -> deny
================================================================
CHECK PASS: N1: deny

================================================================
== SUMMARY
================================================================
PASS | HAPPY: exit code 0 (rc=0)
PASS: 4  FAIL: 0
RESULT: GREEN - all scenarios behaved exactly as designed
`

var registry = []string{"STAGE 0", "HAPPY", "N1"}

func check(log string, rc int) harness.Report {
	return harness.Verify(strings.NewReader(log), registry, rc, since)
}

func TestVerifyGreenLog(t *testing.T) {
	r := check(greenLog, 0)
	if r.Status != result.Pass {
		t.Fatalf("status %s: %v", r.Status, r.Problems)
	}
	for _, id := range registry {
		if !r.Passed(id) {
			t.Errorf("scenario %s not passed", id)
		}
	}
}

func TestVerifyRed(t *testing.T) {
	cases := []struct {
		name    string
		log     string
		rc      int
		problem string
	}{
		{"failing check", strings.Replace(greenLog, "CHECK PASS: N1: deny", "CHECK FAIL: N1: deny (want rc=125, got 0)", 1), 0, "N1: 1 failed check"},
		{"expected scenario missing", strings.Replace(greenLog, "== SCENARIO N1:", "== NOTE N1:", 1), 0, "N1: did not run"},
		{"scenario without any check", strings.Replace(greenLog, "CHECK PASS: N1: deny\n", "", 1), 0, "N1: no checks"},
		{"unregistered scenario", strings.Replace(greenLog, "== SCENARIO N1:", "== SCENARIO N99:", 1), 0, "N99: not in the scenario registry"},
		{"nonzero exit despite green text", greenLog, 1, "exit code 1"},
		{"summary disagrees with checks", strings.Replace(greenLog, "PASS: 4  FAIL: 0", "PASS: 9  FAIL: 0", 1), 0, "summary PASS=9 FAIL=0, counted PASS=4 FAIL=0"},
		{"no summary (runner aborted)", greenLog[:strings.Index(greenLog, "== SUMMARY")], 0, "no summary"},
		{"stale log from an earlier run", strings.Replace(greenLog, "2026-10-16T10:05:00Z", "2026-10-15T23:00:00Z", 1), 0, "older than this run"},
		{"empty log", "", 0, "no runner header"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			r := check(c.log, c.rc)
			if r.Status == result.Pass {
				t.Fatal("want red, got PASS")
			}
			if !strings.Contains(strings.Join(r.Problems, "\n"), c.problem) {
				t.Fatalf("problems %v lack %q", r.Problems, c.problem)
			}
		})
	}
}

func TestVerifyIgnoresNestedRunnerOutput(t *testing.T) {
	// run-pair.sh re-runs run.sh in its STAGE 4; that nested output is
	// verified from run.sh's own log, not attributed to pair scenarios.
	nested := `
================================================================
== STAGE 4: N-series regression
================================================================
================================================================
== TMB BROKER PROTOTYPE RUNNER (2026-10-16T10:06:00Z)
================================================================
================================================================
== SCENARIO N7: wrong uid
================================================================
CHECK PASS: N7: deny
PASS: 1  FAIL: 0
RESULT: GREEN - all scenarios behaved exactly as designed
CHECK PASS: REGRESSION: harness/run.sh exited 0
`
	log := strings.Replace(greenLog, "\n================================================================\n== SUMMARY", nested+"\n================================================================\n== SUMMARY", 1)
	log = strings.Replace(log, "PASS: 4  FAIL: 0", "PASS: 5  FAIL: 0", 1)
	r := harness.Verify(strings.NewReader(log), append(registry, "STAGE 4"), 0, since)
	if r.Status != result.Pass {
		t.Fatalf("status %s: %v", r.Status, r.Problems)
	}
	if r.Passed("N7") {
		t.Fatal("nested N7 must not be attributed to this log")
	}
}

func TestVerifyWarnMeansNotProven(t *testing.T) {
	// run-openshell.sh prints CHECK WARN when O4's sandbox was dropped and
	// recreated: the runner stays green, the acceptance must not.
	log := strings.Replace(greenLog, "CHECK PASS: N1: deny\n", "CHECK PASS: N1: deny\nCHECK WARN: N1: persistence NOT PROVEN this run\n", 1)
	r := check(log, 0)
	if r.Status != result.Fail || r.Passed("N1") || !strings.Contains(strings.Join(r.Problems, "\n"), "N1: NOT_PROVEN") {
		t.Fatalf("status %s problems %v", r.Status, r.Problems)
	}
}
