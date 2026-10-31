package gate_test

import (
	"encoding/json"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"

	"tmb-ci/internal/gate"
)

const repo = "../../.."

func readRequirements(t *testing.T) map[string]gate.Requirements {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(repo, "ci/required-checks.json"))
	if err != nil {
		t.Fatal(err)
	}
	var req map[string]gate.Requirements
	if err := json.Unmarshal(data, &req); err != nil {
		t.Fatal(err)
	}
	return req
}

// ciWorkflow returns the job ids of ci.yml and the needs list of ci-gate.
func ciWorkflow(t *testing.T) (jobs map[string]bool, gateNeeds []string) {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(repo, ".github/workflows/ci.yml"))
	if err != nil {
		t.Fatal(err)
	}
	jobs = map[string]bool{}
	for _, m := range regexp.MustCompile(`(?m)^  ([a-z0-9-]+):\s*$`).FindAllStringSubmatch(string(data), -1) {
		jobs[m[1]] = true
	}
	m := regexp.MustCompile(`(?ms)^  ci-gate:\s*$.*?^    needs: \[([^\]]*)\]`).FindStringSubmatch(string(data))
	if m == nil {
		t.Fatal("ci.yml: no needs list under ci-gate")
	}
	for _, j := range strings.Split(m[1], ",") {
		gateNeeds = append(gateNeeds, strings.TrimSpace(j))
	}
	return jobs, gateNeeds
}

// TestGateNeedsMatchRequiredJobs: a job the gate requires but does not
// wait for is "missing" on every run, and a job the gate waits for but no
// event requires is unchecked. Both sides must list the same ci.yml jobs.
func TestGateNeedsMatchRequiredJobs(t *testing.T) {
	jobs, needs := ciWorkflow(t)
	needed := map[string]bool{}
	for _, j := range needs {
		if !jobs[j] {
			t.Errorf("ci-gate needs %q, which is not a job of ci.yml", j)
		}
		needed[j] = true
	}
	required := map[string]bool{}
	for event, r := range readRequirements(t) {
		if event == "openshell" { // openshell-acceptance.yml, not ci.yml
			continue
		}
		for _, j := range r.Jobs {
			required[j] = true
			if !needed[j] {
				t.Errorf("%s requires job %q, but ci-gate does not need it", event, j)
			}
		}
	}
	var extra []string
	for j := range needed {
		if !required[j] {
			extra = append(extra, j)
		}
	}
	sort.Strings(extra)
	if len(extra) > 0 {
		t.Errorf("ci-gate needs jobs no event requires: %v", extra)
	}
}

// TestSignerIsRequiredOnPullRequest: ADR 0007 R8 makes the signer build and
// tests a required pull_request check; trusted events keep it too.
func TestSignerIsRequiredOnPullRequest(t *testing.T) {
	req := readRequirements(t)
	for _, event := range []string{"pull_request", "merge_group", "push", "workflow_dispatch", "schedule"} {
		r := req[event]
		if !contains(r.Jobs, "signer") {
			t.Errorf("%s: job signer is not required", event)
		}
		checks := map[string]gate.Required{}
		for _, c := range r.Checks {
			checks[c.Check] = c
		}
		bt, ok := checks["signer/build-test"]
		if !ok || bt.AllowNotApplicable {
			t.Errorf("%s: signer/build-test must be required without NOT_APPLICABLE, got %+v (present %v)", event, bt, ok)
		}
		if _, ok := checks["signer/entitlements"]; !ok {
			t.Errorf("%s: signer/entitlements is not required", event)
		}
	}
}

func contains(list []string, s string) bool {
	for _, v := range list {
		if v == s {
			return true
		}
	}
	return false
}
