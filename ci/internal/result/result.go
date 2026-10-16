// Package result is the report every TMB CI check writes and ci-gate reads.
package result

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// SchemaV1 identifies the report format; ci-gate rejects anything else.
const SchemaV1 = "tmb-ci/result/v1"

type Status string

const (
	Pass          Status = "PASS"
	Fail          Status = "FAIL"
	Error         Status = "ERROR"
	NotRun        Status = "NOT_RUN"
	Unavailable   Status = "UNAVAILABLE"
	NotApplicable Status = "NOT_APPLICABLE"
)

// Valid reports whether s is one of the six statuses of the CI contract.
func (s Status) Valid() bool {
	switch s {
	case Pass, Fail, Error, NotRun, Unavailable, NotApplicable:
		return true
	}
	return false
}

// Result is one check's verdict for one tested commit and run.
type Result struct {
	Schema   string            `json:"schema"`
	Check    string            `json:"check"`
	Status   Status            `json:"status"`
	SHA      string            `json:"sha"`
	RunID    string            `json:"run_id"`
	Reason   string            `json:"reason,omitempty"`
	Tools    map[string]string `json:"tools,omitempty"`
	Evidence []string          `json:"evidence,omitempty"`
	Summary  []string          `json:"summary,omitempty"`
}

// maxReport bounds a report file so a hostile artifact cannot exhaust memory.
const maxReport = 1 << 20

// Read decodes one report, rejecting oversized or unknown-field input.
func Read(r io.Reader) (Result, error) {
	var res Result
	data, err := io.ReadAll(io.LimitReader(r, maxReport+1))
	if err != nil {
		return res, err
	}
	if len(data) > maxReport {
		return res, fmt.Errorf("report larger than %d bytes", maxReport)
	}
	dec := json.NewDecoder(strings.NewReader(string(data)))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&res); err != nil {
		return res, err
	}
	return res, nil
}

// ReadDir reads every *.json report under dir (recursively, sorted).
func ReadDir(dir string) ([]Result, error) {
	var paths []string
	err := filepath.WalkDir(dir, func(p string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if !d.IsDir() && strings.HasSuffix(p, ".json") {
			paths = append(paths, p)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	sort.Strings(paths)
	var out []Result
	for _, p := range paths {
		f, err := os.Open(p)
		if err != nil {
			return nil, err
		}
		r, err := Read(f)
		f.Close()
		if err != nil {
			return nil, fmt.Errorf("%s: %w", p, err)
		}
		out = append(out, r)
	}
	return out, nil
}

// Write stores r as dir/<check with / replaced>.json.
func Write(dir string, r Result) (string, error) {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return "", err
	}
	p := filepath.Join(dir, strings.ReplaceAll(r.Check, "/", "__")+".json")
	data, err := json.MarshalIndent(r, "", "  ")
	if err != nil {
		return "", err
	}
	return p, os.WriteFile(p, append(data, '\n'), 0o644)
}
