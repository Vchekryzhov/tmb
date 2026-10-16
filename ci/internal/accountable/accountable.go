// Package accountable validates the owner/issue/expiry triple that every
// GAP and scanner exception must carry.
package accountable

import (
	"fmt"
	"regexp"
	"time"
)

// IssuePattern: GAPs and exceptions are tracked in this repository's issues.
var IssuePattern = regexp.MustCompile(`^https://github\.com/Vchekryzhov/tmb/issues/[1-9][0-9]*$`)

// Problems lists what is wrong with one owner/issue/due triple; prefix
// names the entry in messages.
func Problems(prefix, owner, issue, due string, today time.Time) []string {
	var p []string
	if owner == "" {
		p = append(p, prefix+" needs owner")
	}
	if !IssuePattern.MatchString(issue) {
		p = append(p, fmt.Sprintf("%s issue %q is not an issue of this repository", prefix, issue))
	}
	d, err := time.Parse(time.DateOnly, due)
	switch {
	case err != nil:
		p = append(p, fmt.Sprintf("%s due %q is not YYYY-MM-DD", prefix, due))
	case d.Before(today.Truncate(24 * time.Hour)):
		p = append(p, fmt.Sprintf("%s expired on %s", prefix, due))
	}
	return p
}
