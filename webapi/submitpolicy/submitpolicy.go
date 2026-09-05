// Package submitpolicy applies operator-supplied submit-file directives
// to every job this API submits, whatever surface it came from.
//
// It exists because an access point can impose requirements a user
// cannot reasonably be expected to know. On one deployment the schedd
// refuses any job whose `log =` does not resolve inside the submitter's
// home directory, and the refusal arrives only at commit time as an
// opaque transaction failure. An operator needs a way to satisfy that
// centrally rather than asking every user, and every template, to get it
// right.
//
// Two hooks, because "supply a value when the user did not" and "insist
// on a value regardless" are different operations:
//
//	Defaults  — apply where the submit file is silent
//	Overrides — win over whatever the submit file says
//
// Both fall out of submit-file semantics rather than any parsing on our
// part. Submit commands are macro assignments evaluated when `queue` is
// reached, so the LAST assignment before `queue` is the effective one.
// Defaults are therefore prepended, where anything the user writes later
// beats them, and overrides are spliced in just before `queue`, where
// they beat everything above. That is the same mechanism
// HTTP_API_INTERACTIVE_EXTRA_SUBMIT already relies on, and it means
// neither hook needs to understand submit-file syntax -- there is no
// parser here to disagree with condor_submit's.
package submitpolicy

import "strings"

// Policy is the operator's submit-file configuration. The zero value
// applies nothing and returns submit files byte-for-byte unchanged.
//
// Trust model: both fields come from operator-only configuration and are
// spliced in verbatim -- no whitelist, no quoting. This is the
// operator's hook into job admission policy, equivalent in privilege to
// writing the schedd's site_local config.
type Policy struct {
	// Defaults are submit-file lines applied only where the submit file
	// is silent. Typical use: give every job a `log =` under the home
	// directory so a site that demands one is satisfied, while leaving a
	// user who set their own alone.
	Defaults string
	// Overrides are submit-file lines that take effect regardless of
	// what the submit file says. Use for requirements that are not the
	// user's to opt out of -- an accounting group, a mandatory
	// concurrency limit, a log location the schedd would otherwise
	// reject.
	Overrides string
}

// IsZero reports whether the policy would change nothing.
func (p Policy) IsZero() bool {
	return strings.TrimSpace(p.Defaults) == "" && strings.TrimSpace(p.Overrides) == ""
}

const (
	defaultsHeader  = "# --- Site submit defaults (HTTP_API_SUBMIT_FILE_DEFAULTS) ---"
	defaultsFooter  = "# --- End site submit defaults; anything below overrides them ---"
	overridesHeader = "# --- Site submit overrides (HTTP_API_SUBMIT_FILE_OVERRIDES) ---"
	overridesFooter = "# --- End site submit overrides ---"
)

// Apply returns submitFile with the policy applied. An unconfigured
// policy returns the input unchanged -- deliberately byte-for-byte, so a
// deployment that sets neither knob cannot be affected by this code at
// all, not even by a stray marker comment.
func (p Policy) Apply(submitFile string) string {
	if p.IsZero() {
		return submitFile
	}

	out := submitFile
	if block := blockOf(p.Overrides, overridesHeader, overridesFooter); block != "" {
		out = insertBeforeQueue(out, block)
	}
	if block := blockOf(p.Defaults, defaultsHeader, defaultsFooter); block != "" {
		out = block + ensureTrailingNewline(out)
	}
	return out
}

// blockOf wraps operator content in marker comments so the resulting
// submit file says where the lines came from. Someone looking at a job
// with an unexpected accounting group should not have to guess.
func blockOf(content, header, footer string) string {
	if strings.TrimSpace(content) == "" {
		return ""
	}
	return header + "\n" + ensureTrailingNewline(content) + footer + "\n"
}

func ensureTrailingNewline(s string) string {
	if s == "" || strings.HasSuffix(s, "\n") {
		return s
	}
	return s + "\n"
}

// insertBeforeQueue splices block in ahead of the FIRST queue statement,
// which is where an assignment still affects that queue and every one
// after it. A submit file with no queue statement gets the block
// appended: the templates path builds its `queue ... from (...)` line
// after this runs, so appending still lands ahead of it.
func insertBeforeQueue(submitFile, block string) string {
	lines := strings.Split(submitFile, "\n")
	for i, line := range lines {
		if !isQueueLine(line) {
			continue
		}
		head := strings.Join(lines[:i], "\n")
		tail := strings.Join(lines[i:], "\n")
		return ensureTrailingNewline(head) + block + tail
	}
	return ensureTrailingNewline(submitFile) + block
}

// isQueueLine reports whether a line is a queue statement. Matches the
// bare word `queue` and its argument forms ("queue 5",
// "queue name from (...)"), case-insensitively, since submit-file
// command names are not case-sensitive.
//
// Deliberately exact on the first token: a line whose first word merely
// starts with "queue" -- a hypothetical "queuedepth = 4" -- is not a
// queue statement, and splicing overrides above it would put them in the
// wrong place.
func isQueueLine(line string) bool {
	trimmed := strings.TrimSpace(line)
	if trimmed == "" || strings.HasPrefix(trimmed, "#") {
		return false
	}
	first := trimmed
	if i := strings.IndexAny(trimmed, " \t"); i >= 0 {
		first = trimmed[:i]
	}
	return strings.EqualFold(first, "queue")
}
