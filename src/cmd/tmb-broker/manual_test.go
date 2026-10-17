package main

import (
	"strings"
	"testing"

	"tmb-poc/internal/proto"
)

// The manual console escapes requester-chosen fields as tmb approve does: an
// ESC, C1 or bidi rune in the nonce, cwd or argv shows as an escape and never
// reaches the operator's terminal raw.
func TestManualPromptEscapesRequesterFields(t *testing.T) {
	req := &proto.Request{
		Executable: "/usr/bin/id\x1b]0;x\a",
		Argv:       []string{"/usr/bin/id", "\xc2\x9b2A"},
		Cwd:        "/tmp/\xe2\x80\xaeevil",
		Nonce:      "n\x1b[2A\xc2\x9b1K\xe2\x80\xaex",
	}
	id := RequesterID{Kind: KindUID, UID: 1000, PID: 42}
	var sb strings.Builder
	printManualPrompt(&sb, req, id, "/usr/bin/id", 1, 2, []string{"A=\xe2\x81\xa6b"})
	out := sb.String()
	for _, raw := range []string{"\x1b", "\xc2\x9b", "\xe2\x80\xae", "\xe2\x81\xa6", "\a"} {
		if strings.Contains(out, raw) {
			t.Errorf("prompt carries raw %q:\n%s", raw, out)
		}
	}
	for _, want := range []string{
		"nonce     : \"n\\x1b[2A\\u009b1K\\u202ex\"",
		"cwd       : \"/tmp/\\u202eevil\"",
		"executable: \"/usr/bin/id\\x1b]0;x\\a\" (realpath /usr/bin/id, dev=1 ino=2)",
		"argv      : [\"/usr/bin/id\",\"\\u009b2A\"]",
		"env       : [\"A=\\u2066b\"]",
		"requester : uid=1000 pid=42 (kernel SO_PEERCRED)",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("prompt lacks %s:\n%s", want, out)
		}
	}
}
