package issues

import (
	"regexp"
	"strings"
)

// Masking: turn the parts of a message that identify one occurrence into
// placeholders, so what is left identifies the KIND of occurrence.
//
// This is the half of log-template mining that does the real work on
// HTCondor hold reasons. A single root cause on an access point looks
// like this on the wire:
//
//	Error from slot1_40@glidein_181693_77062752@a529.anvil.rcac.purdue.edu: memory usage exceeded request_memory
//	Error from slot1_13@IU-Jetstream2-Backfill.green-7b499568d4-pbfjk: memory usage exceeded request_memory
//
// -- thousands of distinct strings, every one of them the same problem.
// Grouping by exact text says there are thousands of issues; grouping by
// HoldReasonCode says there is one issue covering every memory overrun,
// every transfer failure and every policy hold at the site. Neither is
// what a facilitator is looking at the page to find out.
//
// The rules are ordered most-specific first, because an earlier rule's
// placeholder must not be re-matched by a later one: a URL has to go
// before the path rule, and a version before the number rule.

type maskRule struct {
	re   *regexp.Regexp
	with string
	// needs is a byte the token must contain for the rule to have any
	// chance of matching. Checking it is a scan of a short string with
	// no allocation, where running the regex is neither.
	needs byte
	// digits says the rule cannot match without one.
	digits bool
}

// spacedTimestamp is the one pattern that can span a token boundary,
// because a timestamp is sometimes written with a space between the date
// and the time. It runs over the whole message; everything else runs per
// token, which is what keeps masking off the critical path.
var spacedTimestamp = regexp.MustCompile(`\b\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}(\.\d+)?Z?\b`)

var maskRules = []maskRule{
	// A quoted or bracketed URL is the single most common variable part
	// of a file-transfer hold, and it carries the user's whole directory
	// layout with it.
	{re: regexp.MustCompile(`\b[a-zA-Z][a-zA-Z0-9+.-]*://[^\s,)"'|]+`), with: "<url>", needs: ':'},
	// ISO-8601-ish timestamps, before the number rule gets at them.
	{re: regexp.MustCompile(`\b\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(\.\d+)?Z?\b`), with: "<time>", needs: '-', digits: true},
	{re: regexp.MustCompile(`\b\d{4}-\d{2}-\d{2}\b`), with: "<date>", needs: '-', digits: true},
	// A slot name on an execute node: the most-varying token in the most
	// common hold reason there is.
	{re: regexp.MustCompile(`\bslot\d+(_\d+)?@\S+`), with: "<slot>", needs: '@', digits: true},
	// glidein_<n>_<n>@host and other user@host forms.
	{re: regexp.MustCompile(`\b[\w.-]+@[\w.-]+\b`), with: "<host>", needs: '@'},
	// Software versions, before numbers.
	{re: regexp.MustCompile(`\bv?\d+\.\d+(\.\d+)+\b`), with: "<ver>", needs: '.', digits: true},
	// IPv4 with an optional port.
	{re: regexp.MustCompile(`\b\d{1,3}(\.\d{1,3}){3}(:\d+)?\b`), with: "<ip>", needs: '.', digits: true},
	// Absolute paths. Two segments minimum so a bare "/" or a sentence's
	// "and/or" is left alone.
	{re: regexp.MustCompile(`(/[\w.+-]+){2,}/?`), with: "<path>", needs: '/'},
	// A dotted hostname. Requires a letter so it cannot eat a decimal
	// number, and two dots so "request_memory." survives.
	{re: regexp.MustCompile(`\b[a-zA-Z][\w-]*(\.[\w-]+){2,}\b`), with: "<host>", needs: '.'},
	// Hex blobs: job ids, container digests, temp-directory suffixes.
	{re: regexp.MustCompile(`\b[0-9a-fA-F]{8,}\b`), with: "<hex>"},
	// A bare number, before the mixed-token rule below can claim it:
	// both are variables, but a template reading "<num>:<num>:<num>" is
	// something a person recognises as a duration and "<id>:<id>:<id>"
	// is not. These templates are read by facilitators, so the
	// placeholder names have to mean something.
	{re: regexp.MustCompile(`\b\d+\b`), with: "<num>", digits: true},
	// Mixed alphanumeric run with at least one digit -- glide_AGd9bW,
	// dir_260525, osgvo-docker-pilot-ospool-665dff69c8-phctx. These are
	// per-occurrence names, and leaving them in splits one issue into as
	// many clusters as there were execute nodes.
	{re: regexp.MustCompile(`\b(?:[a-zA-Z]+[_-]?)*\d[\w-]*\b`), with: "<id>", digits: true},
}

// MaskedTokens is the clusterer's entry point: split a message and mask
// each piece.
//
// Masking per token rather than per message is what makes this cheap
// enough to run over tens of thousands of records on a page load. Every
// rule here is anchored inside one token -- a slot name, a path, a
// version -- so running twelve regexes over a two-kilobyte string only
// to have them match a few dozen characters was twelve full scans of
// mostly prose. A token of prose is rejected by a byte scan instead, and
// the regexes only ever see the tokens that could match one.
//
// The message itself is untouched and kept as the cluster's example, so
// nothing a facilitator needs to read is lost to masking.
func MaskedTokens(message string) []string {
	// The one rule that spans a token boundary has to run first, over
	// the whole string.
	if hasDigit(message) && strings.IndexByte(message, '-') >= 0 {
		message = spacedTimestamp.ReplaceAllString(message, "<time>")
	}
	fields := splitFields(message)
	out := fields[:0]
	for _, f := range fields {
		// Trailing sentence punctuation is noise for the comparison and
		// would make "request_memory" and "request_memory." different
		// tokens.
		f = strings.Trim(f, ".:;")
		if f == "" {
			continue
		}
		out = append(out, maskToken(f))
	}
	return out
}

// maskToken applies the rules to one token, skipping the ones that
// cannot match it.
func maskToken(tok string) string {
	if !maybeVariable(tok) {
		return tok
	}
	for i := range maskRules {
		r := &maskRules[i]
		if r.digits && !hasDigit(tok) {
			continue
		}
		if r.needs != 0 && strings.IndexByte(tok, r.needs) < 0 {
			continue
		}
		tok = r.re.ReplaceAllString(tok, r.with)
	}
	return tok
}

// maybeVariable is the first gate: a token of ordinary prose cannot
// match any rule, and most tokens are ordinary prose.
//
// The hex rule is the one that can fire without a digit or punctuation
// (a run of eight or more letters that all happen to be a-f), so a long
// all-hex token counts as interesting too.
func maybeVariable(tok string) bool {
	hex := len(tok) >= 8
	for i := 0; i < len(tok); i++ {
		c := tok[i]
		switch {
		case c >= '0' && c <= '9':
			return true
		case c == '@' || c == '/' || c == '.' || c == ':':
			return true
		}
		if hex && !isHexLetter(c) {
			hex = false
		}
	}
	return hex
}

func isHexLetter(c byte) bool {
	return (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')
}

func hasDigit(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] >= '0' && s[i] <= '9' {
			return true
		}
	}
	return false
}

// Mask is the whole-message form, kept for the tests and for anything
// that wants to look at a masked message rather than its tokens. It is
// the same pipeline, so the two cannot drift.
func Mask(message string) string {
	return strings.Join(MaskedTokens(message), " ")
}

// splitFields cuts a message into tokens.
//
// HTCondor hold reasons are punctuated prose with machine detail wedged
// into them, so the separators are wider than whitespace: the "|" that
// FILETRANSFER uses to join its layers, and the brackets and commas that
// wrap URLs, would otherwise glue a placeholder to the word beside it
// and make two occurrences of one issue look different.
func splitFields(message string) []string {
	return strings.FieldsFunc(message, func(r rune) bool {
		switch r {
		case ' ', '\t', '\n', '\r', '|', ',', '(', ')', '[', ']', '"', '\'':
			return true
		}
		return false
	})
}

// tokenize is splitFields plus the trimming, for callers that have
// already-masked text.
func tokenize(masked string) []string {
	fields := splitFields(masked)
	out := fields[:0]
	for _, f := range fields {
		if f = strings.Trim(f, ".:;"); f != "" {
			out = append(out, f)
		}
	}
	return out
}
