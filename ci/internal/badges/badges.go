// Package badges renders shields.io endpoint JSON for the README: CI
// results of one run (coverage, scanner findings) and the pinned tool
// versions. The files are committed under docs/badges; the README embeds
// them through https://img.shields.io/endpoint, so no write token or
// third-party service is needed.
package badges

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"tmb-ci/internal/result"
)

// Badge is the shields.io endpoint schema (schemaVersion 1).
type Badge struct {
	SchemaVersion int    `json:"schemaVersion"`
	Label         string `json:"label"`
	Message       string `json:"message"`
	Color         string `json:"color"`
}

const (
	green  = "brightgreen"
	yellow = "yellow"
	orange = "orange"
	red    = "red"
	grey   = "lightgrey"
	blue   = "blue"
)

// Encode renders b as the JSON file shields.io reads.
func Encode(b Badge) []byte {
	b.SchemaVersion = 1
	data, _ := json.MarshalIndent(b, "", "  ")
	return append(data, '\n')
}

// ReadResults loads every check report under dir, including the nested
// results-* directories of a downloaded Actions run. Only files named
// <check>__<rest>.json are reports; scanner output next to them is ignored.
func ReadResults(dir string) (map[string]result.Result, error) {
	out := map[string]result.Result{}
	err := filepath.WalkDir(dir, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		name := d.Name()
		if d.IsDir() || !strings.HasSuffix(name, ".json") || !strings.Contains(name, "__") {
			return nil
		}
		f, err := os.Open(p)
		if err != nil {
			return err
		}
		defer f.Close()
		r, err := result.Read(f)
		if err != nil {
			return fmt.Errorf("%s: %w", p, err)
		}
		if prev, dup := out[r.Check]; dup && !sameResult(prev, r) {
			return fmt.Errorf("%s: check %s reported twice with different content", p, r.Check)
		}
		out[r.Check] = r
		return nil
	})
	if err != nil {
		return nil, err
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("no check reports under %s", dir)
	}
	return out, nil
}

func sameResult(a, b result.Result) bool {
	ja, _ := json.Marshal(a)
	jb, _ := json.Marshal(b)
	return string(ja) == string(jb)
}

var (
	percentRe = regexp.MustCompile(`(\d+(?:\.\d+)?)%`)
	scanRe    = regexp.MustCompile(`(\d+) blocking, (\d+) excepted, (\d+) informational`)
)

// FromResults derives the result badges (file name without .json -> badge).
// A missing or red check gives a grey or red badge, never a green guess.
func FromResults(res map[string]result.Result) map[string]Badge {
	out := map[string]Badge{}
	out["coverage"] = coverageBadge(res["coverage/compare"])
	out["image-vulns"] = scanBadge("image vulns", res, "images/vulns-host", "images/vulns-sandbox")
	out["gosec"] = scanBadge("gosec", res, "security/gosec")
	out["govulncheck"] = passBadge("govulncheck", "0 reachable", res, "security/govulncheck-source", "security/govulncheck-binaries")
	out["secrets"] = scanBadge("gitleaks", res, "secrets/tree")
	out["ci-results"] = provenance(res)
	return out
}

func coverageBadge(r result.Result) Badge {
	b := Badge{Label: "coverage", Message: "unknown", Color: grey}
	if r.Check == "" || len(r.Summary) == 0 {
		return b
	}
	m := percentRe.FindStringSubmatch(r.Summary[0])
	if m == nil {
		return b
	}
	pct, _ := strconv.ParseFloat(m[1], 64)
	b.Message = m[1] + "%"
	switch {
	case r.Status != result.Pass:
		b.Color = red
	case pct >= 80:
		b.Color = green
	case pct >= 60:
		b.Color = yellow
	default:
		b.Color = orange
	}
	return b
}

// scanBadge sums "N blocking, M excepted, K informational" over checks.
func scanBadge(label string, res map[string]result.Result, checks ...string) Badge {
	var blocking, excepted, info int
	for _, c := range checks {
		r, ok := res[c]
		if !ok {
			return Badge{Label: label, Message: "no result", Color: grey}
		}
		m := scanRe.FindStringSubmatch(r.Reason)
		if m == nil || r.Status == result.Error || r.Status == result.NotRun || r.Status == result.Unavailable {
			return Badge{Label: label, Message: strings.ToLower(string(r.Status)), Color: grey}
		}
		b, _ := strconv.Atoi(m[1])
		e, _ := strconv.Atoi(m[2])
		i, _ := strconv.Atoi(m[3])
		blocking += b
		excepted += e
		info += i
	}
	parts := []string{fmt.Sprintf("%d blocking", blocking)}
	if excepted > 0 {
		parts = append(parts, fmt.Sprintf("%d excepted", excepted))
	}
	if info > 0 {
		parts = append(parts, fmt.Sprintf("%d informational", info))
	}
	color := green
	if blocking > 0 {
		color = red
	}
	return Badge{Label: label, Message: strings.Join(parts, ", "), Color: color}
}

// passBadge shows ok when every check passed, otherwise the worst status.
func passBadge(label, ok string, res map[string]result.Result, checks ...string) Badge {
	for _, c := range checks {
		r, found := res[c]
		if !found {
			return Badge{Label: label, Message: "no result", Color: grey}
		}
		if r.Status == result.Fail {
			return Badge{Label: label, Message: "findings", Color: red}
		}
		if r.Status != result.Pass {
			return Badge{Label: label, Message: strings.ToLower(string(r.Status)), Color: grey}
		}
	}
	return Badge{Label: label, Message: ok, Color: green}
}

// provenance names the commit and run the result badges come from.
func provenance(res map[string]result.Result) Badge {
	var sha, run string
	for _, r := range res {
		sha, run = r.SHA, r.RunID
		break
	}
	if len(sha) > 12 {
		sha = sha[:12]
	}
	return Badge{Label: "ci results", Message: fmt.Sprintf("%s, run %s", sha, run), Color: blue}
}

// goModule maps a tool directory under ci/tools to the module whose
// version is the tool version.
var goModule = map[string]string{
	"staticcheck": "honnef.co/go/tools",
	"gosec":       "github.com/securego/gosec/v2",
	"govulncheck": "golang.org/x/vuln",
	"actionlint":  "github.com/rhysd/actionlint",
}

// FromPins derives the tool badges (file name tool-<name>) from .go-version,
// ci/tools.lock and the ci/tools/<name>/go.mod modules.
func FromPins(goVersion, toolsLock, toolsDir string) (map[string]Badge, error) {
	out := map[string]Badge{}
	v, err := os.ReadFile(goVersion)
	if err != nil {
		return nil, err
	}
	out["tool-go"] = Badge{Label: "go", Message: strings.TrimPrefix(strings.TrimSpace(string(v)), "go"), Color: blue}

	f, err := os.Open(toolsLock)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		fields := strings.Fields(sc.Text())
		if len(fields) < 2 || strings.HasPrefix(fields[0], "#") {
			continue
		}
		name, ver := fields[0], fields[1]
		if b, ok := out["tool-"+name]; ok && b.Message != ver {
			return nil, fmt.Errorf("%s: %s pinned as %s and %s", toolsLock, name, b.Message, ver)
		}
		out["tool-"+name] = Badge{Label: name, Message: ver, Color: blue}
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}

	names := make([]string, 0, len(goModule))
	for n := range goModule {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, n := range names {
		ver, err := moduleVersion(filepath.Join(toolsDir, n, "go.mod"), goModule[n])
		if err != nil {
			return nil, err
		}
		out["tool-"+n] = Badge{Label: n, Message: ver, Color: blue}
	}
	return out, nil
}

func moduleVersion(gomod, module string) (string, error) {
	f, err := os.Open(gomod)
	if err != nil {
		return "", err
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		fields := strings.Fields(sc.Text())
		if len(fields) >= 2 && fields[0] == module && strings.HasPrefix(fields[1], "v") {
			return fields[1], nil
		}
	}
	if err := sc.Err(); err != nil {
		return "", err
	}
	return "", fmt.Errorf("%s: no require line for %s", gomod, module)
}

// Write stores every badge as dir/<name>.json and returns the paths.
func Write(dir string, badges map[string]Badge) ([]string, error) {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return nil, err
	}
	var paths []string
	for name, b := range badges {
		p := filepath.Join(dir, name+".json")
		if err := os.WriteFile(p, Encode(b), 0o644); err != nil {
			return nil, err
		}
		paths = append(paths, p)
	}
	sort.Strings(paths)
	return paths, nil
}

// Check compares the badges with the files in dir; every difference or
// missing file is one problem line.
func Check(dir string, badges map[string]Badge) []string {
	names := make([]string, 0, len(badges))
	for n := range badges {
		names = append(names, n)
	}
	sort.Strings(names)
	var problems []string
	for _, n := range names {
		p := filepath.Join(dir, n+".json")
		have, err := os.ReadFile(p)
		switch {
		case err != nil:
			problems = append(problems, fmt.Sprintf("%s: missing (%v)", p, err))
		case string(have) != string(Encode(badges[n])):
			problems = append(problems, fmt.Sprintf("%s: differs from the pins; run ci/run.sh badges tools", p))
		}
	}
	return problems
}
