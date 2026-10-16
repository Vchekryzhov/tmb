package coverage_test

import (
	"slices"
	"strings"
	"testing"
	"time"

	"tmb-ci/internal/coverage"
	"tmb-ci/internal/result"
)

var today = time.Date(2026, 10, 16, 0, 0, 0, 0, time.UTC)

func profile(t *testing.T, text string) coverage.Profile {
	t.Helper()
	p, err := coverage.ParseProfile(strings.NewReader(text))
	if err != nil {
		t.Fatal(err)
	}
	return p
}

// base: proto has 10 statements, 6 covered; broker has 10, 5 covered.
const baseProfile = `mode: atomic
m/internal/proto/proto.go:10.1,12.2 4 1
m/internal/proto/proto.go:14.1,16.2 2 3
m/internal/proto/proto.go:20.1,25.2 4 0
m/cmd/b/b.go:5.1,9.2 5 2
m/cmd/b/b.go:11.1,14.2 5 0
`

func TestProfileTotals(t *testing.T) {
	p := profile(t, baseProfile)
	if got := p.Total(); got != (coverage.Ratio{Covered: 11, Total: 20}) {
		t.Fatalf("total %+v, want 11/20", got)
	}
	if got := p.Packages()["m/internal/proto"]; got != (coverage.Ratio{Covered: 6, Total: 10}) {
		t.Fatalf("proto %+v, want 6/10", got)
	}
}

func TestProfileMergesRepeatedBlocks(t *testing.T) {
	// -coverpkg=./... repeats a block once per test binary; a block is
	// covered when any binary executed it, and counted once.
	p := profile(t, "mode: atomic\nm/a/a.go:1.1,2.2 3 0\nm/a/a.go:1.1,2.2 3 7\n")
	if got := p.Total(); got != (coverage.Ratio{Covered: 3, Total: 3}) {
		t.Fatalf("total %+v, want 3/3", got)
	}
}

func TestProfileRejectsBrokenInput(t *testing.T) {
	for name, text := range map[string]string{
		"empty":           "",
		"no mode":         "m/a/a.go:1.1,2.2 3 0\n",
		"garbage line":    "mode: atomic\nnot a block\n",
		"zero statements": "mode: atomic\n",
		"negative count":  "mode: atomic\nm/a/a.go:1.1,2.2 3 -1\n",
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := coverage.ParseProfile(strings.NewReader(text)); err == nil {
				t.Fatal("want error")
			}
		})
	}
}

func TestCompareNoDecrease(t *testing.T) {
	base := profile(t, baseProfile)
	same := coverage.Compare(base, base)
	if same.Status != result.Pass {
		t.Fatalf("identical profiles: %s %v", same.Status, same.Problems)
	}
	// head loses coverage in proto: block 14-16 no longer executed.
	head := profile(t, strings.Replace(baseProfile, "14.1,16.2 2 3", "14.1,16.2 2 0", 1))
	c := coverage.Compare(base, head)
	if c.Status != result.Fail {
		t.Fatalf("want FAIL on decrease, got %s", c.Status)
	}
	got := strings.Join(c.Problems, "\n")
	for _, want := range []string{"total 55.0% -> 45.0%", "m/internal/proto 60.0% -> 40.0%"} {
		if !strings.Contains(got, want) {
			t.Errorf("problems %q lack %q", got, want)
		}
	}
}

func TestCompareNewAndDeletedPackages(t *testing.T) {
	base := profile(t, baseProfile)
	head := profile(t, baseProfile+"m/cmd/newpkg/n.go:1.1,3.2 2 0\n")
	c := coverage.Compare(base, head)
	// The new package lowers the total; that alone is a FAIL, and the new
	// package is named so the author knows why.
	if c.Status != result.Fail || !strings.Contains(strings.Join(c.Notes, "\n"), "m/cmd/newpkg: new package") {
		t.Fatalf("status %s notes %v problems %v", c.Status, c.Notes, c.Problems)
	}
	noB := profile(t, "mode: atomic\nm/internal/proto/proto.go:10.1,12.2 4 1\nm/internal/proto/proto.go:14.1,16.2 2 3\nm/internal/proto/proto.go:20.1,25.2 4 0\n")
	d := coverage.Compare(base, noB)
	if !strings.Contains(strings.Join(d.Notes, "\n"), "m/cmd/b: deleted") {
		t.Fatalf("deleted package not reported: %v", d.Notes)
	}
}

const headProfile = `mode: atomic
m/cmd/b/b.go:5.1,9.2 5 2
m/cmd/b/b.go:11.1,14.2 5 0
m/cmd/b/b.go:20.1,30.2 8 1
`

func paths(importPath string) string { return strings.Replace(importPath, "m/", "src/", 1) }

func TestDiffCoverageWeightsBlocksTouchingAddedLines(t *testing.T) {
	head := profile(t, headProfile)
	// Lines 7 (inside the covered 5-stmt block) and 25 (inside the covered
	// 8-stmt block) were added; the uncovered block 11-14 was untouched.
	added := coverage.AddedLines{"src/cmd/b/b.go": {7, 25}}
	d := coverage.Diff(head, added, paths)
	if d.Ratio != (coverage.Ratio{Covered: 13, Total: 13}) || d.Status(90) != result.Pass {
		t.Fatalf("diff %+v status %s", d.Ratio, d.Status(90))
	}
	// Now the uncovered block's last line is added too: 13/18 = 72%.
	added["src/cmd/b/b.go"] = []int{7, 14, 25}
	d = coverage.Diff(head, added, paths)
	if d.Ratio != (coverage.Ratio{Covered: 13, Total: 18}) || d.Status(90) != result.Fail {
		t.Fatalf("diff %+v status %s", d.Ratio, d.Status(90))
	}
	if !strings.Contains(strings.Join(d.Uncovered, "\n"), "src/cmd/b/b.go:11-14") {
		t.Fatalf("uncovered blocks not listed: %v", d.Uncovered)
	}
}

func TestDiffCoverageNotApplicableWithoutExecutableChanges(t *testing.T) {
	head := profile(t, headProfile)
	for name, added := range map[string]coverage.AddedLines{
		"no changes":             {},
		"comment-only lines":     {"src/cmd/b/b.go": {2, 3, 16}},
		"non-product file added": {"README.md": {1, 2}},
	} {
		t.Run(name, func(t *testing.T) {
			d := coverage.Diff(head, added, paths)
			if d.Status(90) != result.NotApplicable {
				t.Fatalf("status %s ratio %+v", d.Status(90), d.Ratio)
			}
		})
	}
}

func TestParseUnifiedDiff(t *testing.T) {
	// git diff -U0 -M output: a modified file, a renamed file with one
	// changed line, a deleted file and a new file.
	diff := `diff --git a/src/cmd/b/b.go b/src/cmd/b/b.go
index 1..2 100644
--- a/src/cmd/b/b.go
+++ b/src/cmd/b/b.go
@@ -7 +7,2 @@ func f() {
-	old()
+	new()
+	more()
@@ -30,2 +31,0 @@ func g() {
-	gone()
-	gone()
diff --git a/src/cmd/old/o.go b/src/cmd/renamed/o.go
similarity index 95%
rename from src/cmd/old/o.go
rename to src/cmd/renamed/o.go
--- a/src/cmd/old/o.go
+++ b/src/cmd/renamed/o.go
@@ -4 +4 @@
-	x := 1
+	x := 2
diff --git a/src/cmd/dead/d.go b/src/cmd/dead/d.go
deleted file mode 100644
--- a/src/cmd/dead/d.go
+++ /dev/null
@@ -1,3 +0,0 @@
-package dead
-
-func D() {}
diff --git a/src/cmd/n/n.go b/src/cmd/n/n.go
new file mode 100644
--- /dev/null
+++ b/src/cmd/n/n.go
@@ -0,0 +1,3 @@
+package n
+
+func N() {}
`
	got, err := coverage.ParseUnifiedDiff(strings.NewReader(diff))
	if err != nil {
		t.Fatal(err)
	}
	want := coverage.AddedLines{
		"src/cmd/b/b.go":       {7, 8},
		"src/cmd/renamed/o.go": {4},
		"src/cmd/n/n.go":       {1, 2, 3},
	}
	if len(got) != len(want) {
		t.Fatalf("got %v, want %v", got, want)
	}
	for f, lines := range want {
		if !slices.Equal(got[f], lines) {
			t.Errorf("%s: got %v, want %v", f, got[f], lines)
		}
	}
}

func TestTargets(t *testing.T) {
	p := profile(t, baseProfile) // total 55%, proto 60%
	gap := &coverage.Gap{Owner: "Vchekryzhov", Issue: "https://github.com/Vchekryzhov/tmb/issues/15", Due: "2026-11-15"}
	policy := coverage.Policy{Schema: coverage.PolicySchemaV1, Targets: []coverage.Target{
		{Name: "overall", Min: 80, Gap: gap},
		{Name: "proto", Min: 90, Files: []string{"m/internal/proto/"}, Gap: gap},
	}}
	r := coverage.CheckTargets(policy, p, today)
	if r.Status != result.Pass || len(r.Gaps) != 2 {
		t.Fatalf("unreached targets with valid GAPs must be visible, not red: %s %v gaps=%v", r.Status, r.Problems, r.Gaps)
	}

	cases := []struct {
		name    string
		edit    func(*coverage.Policy)
		problem string
	}{
		{"unreached target without GAP", func(p *coverage.Policy) { p.Targets[0].Gap = nil }, "overall: 55.0% < 80.0% and no GAP"},
		{"expired GAP", func(p *coverage.Policy) {
			g := *gap
			g.Due = "2026-10-01"
			p.Targets[0].Gap = &g
		}, "overall: GAP expired"},
		{"enforced floor broken", func(p *coverage.Policy) { p.Targets[0].Enforced = true; p.Targets[0].Gap = nil }, "overall: 55.0% below enforced 80.0%"},
		{"reached target not pinned", func(p *coverage.Policy) { p.Targets[0].Min = 50 }, "overall: target 50.0% reached (55.0%): set enforced"},
		{"target matching no code", func(p *coverage.Policy) { p.Targets[1].Files = []string{"m/nowhere/"} }, "proto: matches no statements"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			pol := coverage.Policy{Schema: policy.Schema, Targets: append([]coverage.Target(nil), policy.Targets...)}
			c.edit(&pol)
			r := coverage.CheckTargets(pol, p, today)
			if r.Status != result.Fail || !strings.Contains(strings.Join(r.Problems, "\n"), c.problem) {
				t.Fatalf("status %s problems %v, want %q", r.Status, r.Problems, c.problem)
			}
		})
	}
}

func TestPolicyRejectsExclusions(t *testing.T) {
	_, err := coverage.ReadPolicy(strings.NewReader(`{"schema":"` + coverage.PolicySchemaV1 + `","targets":[],"exclude":["m/cmd/b"]}`))
	if err == nil {
		t.Fatal("a package exclusion list must be rejected")
	}
}

func TestEveryPackageMustBeInProfile(t *testing.T) {
	p := profile(t, baseProfile)
	if missing := p.MissingPackages([]string{"m/internal/proto", "m/cmd/b", "m/cmd/ghost"}); len(missing) != 1 || missing[0] != "m/cmd/ghost" {
		t.Fatalf("missing %v", missing)
	}
}
