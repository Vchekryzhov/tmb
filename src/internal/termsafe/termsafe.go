// Package termsafe renders requester-controlled strings for a terminal. The
// requester chooses the nonce, argv, env and the paths; a control sequence in
// any of them must not redraw the lines an approver reads before deciding.
// tmb approve and the broker's manual console share it.
package termsafe

import (
	"fmt"
	"strconv"
	"strings"
	"unicode/utf16"
	"unicode/utf8"
)

// Text returns s as is when it is valid UTF-8 made only of printable
// characters, and Go-quoted otherwise, so control, format (bidi) and invalid
// bytes show as escapes instead of reaching the terminal.
func Text(s string) string {
	if !utf8.ValidString(s) {
		return strconv.Quote(s)
	}
	for _, r := range s {
		if !strconv.IsPrint(r) {
			return strconv.Quote(s)
		}
	}
	return s
}

// JSON escapes, as JSON \u sequences, the non-printable characters that
// json.Marshal leaves raw (DEL, C1 controls, bidi and other format runes).
func JSON(b []byte) string {
	var sb strings.Builder
	for _, r := range string(b) {
		if strconv.IsPrint(r) {
			sb.WriteRune(r)
			continue
		}
		if r > 0xffff {
			r1, r2 := utf16.EncodeRune(r)
			fmt.Fprintf(&sb, "\\u%04x\\u%04x", r1, r2)
			continue
		}
		fmt.Fprintf(&sb, "\\u%04x", r)
	}
	return sb.String()
}
