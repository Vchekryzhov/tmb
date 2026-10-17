package harness_test

import (
	"bufio"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"tmb-ci/internal/harness"
	"tmb-ci/internal/result"
)

const repo = "../../.."

// runners maps each scenario registry in ci/scenarios to the script whose
// sections it lists.
var runners = map[string]string{
	"n-series.txt":  "harness/run.sh",
	"pair.txt":      "harness/run-pair.sh",
	"openshell.txt": "harness/run-openshell.sh",
	"v-series.txt":  "harness/run-vm.sh",
}

func readRegistry(t *testing.T, name string) []string {
	t.Helper()
	f, err := os.Open(filepath.Join(repo, "ci/scenarios", name))
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	var ids []string
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		l := strings.TrimSpace(sc.Text())
		if l != "" && !strings.HasPrefix(l, "#") {
			ids = append(ids, l)
		}
	}
	if err := sc.Err(); err != nil {
		t.Fatal(err)
	}
	return ids
}

var sectionDecl = regexp.MustCompile(`(?m)^log "(?:SCENARIO ([^:"]+)|(STAGE \d+)):`)

// TestRegistriesMatchRunners: every registry in ci/scenarios belongs to a
// runner, and every id it lists is a section that runner prints.
func TestRegistriesMatchRunners(t *testing.T) {
	files, err := filepath.Glob(filepath.Join(repo, "ci/scenarios", "*.txt"))
	if err != nil || len(files) == 0 {
		t.Fatalf("no registries: %v", err)
	}
	for _, f := range files {
		name := filepath.Base(f)
		script, ok := runners[name]
		if !ok {
			t.Errorf("%s: registry without a runner in this test", name)
			continue
		}
		src, err := os.ReadFile(filepath.Join(repo, script))
		if err != nil {
			t.Fatal(err)
		}
		declared := map[string]bool{}
		for _, m := range sectionDecl.FindAllStringSubmatch(string(src), -1) {
			declared[m[1]+m[2]] = true
		}
		for _, id := range readRegistry(t, name) {
			if !declared[id] {
				t.Errorf("%s: %s is not a section of %s", name, id, script)
			}
		}
	}
}

// TestVSeriesRegistryIsComplete: run-vm.sh has no section outside its
// registry, so a new V scenario cannot go unverified.
func TestVSeriesRegistryIsComplete(t *testing.T) {
	src, err := os.ReadFile(filepath.Join(repo, runners["v-series.txt"]))
	if err != nil {
		t.Fatal(err)
	}
	reg := map[string]bool{}
	for _, id := range readRegistry(t, "v-series.txt") {
		reg[id] = true
	}
	for _, m := range sectionDecl.FindAllStringSubmatch(string(src), -1) {
		if id := m[1] + m[2]; !reg[id] {
			t.Errorf("run-vm.sh section %s is not in ci/scenarios/v-series.txt", id)
		}
	}
	for _, v := range []string{"V0", "V1", "V2", "V3", "V4", "V5", "V6", "V7", "V8", "V9"} {
		if !reg[v] {
			t.Errorf("v-series.txt lacks %s", v)
		}
	}
}

// TestCommittedVMLogIsGreen: CI cannot run Lima, so the VM proof is the
// committed harness/last-vm-run.log; it must verify against the current
// registry like a fresh harness log does (any age accepted).
func TestCommittedVMLogIsGreen(t *testing.T) {
	f, err := os.Open(filepath.Join(repo, "harness/last-vm-run.log"))
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	data, err := os.ReadFile(f.Name())
	if err != nil {
		t.Fatal(err)
	}
	rc := 1
	if regexp.MustCompile(`(?m)^RESULT: GREEN\b`).Match(data) {
		rc = 0
	}
	r := harness.Verify(f, readRegistry(t, "v-series.txt"), rc, time.Time{})
	if r.Status != result.Pass {
		t.Fatalf("harness/last-vm-run.log does not prove the V-series: %v", r.Problems)
	}
}
