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
}

var maskRules = []maskRule{
	// A quoted or bracketed URL is the single most common variable part
	// of a file-transfer hold, and it carries the user's whole directory
	// layout with it.
	{regexp.MustCompile(`\b[a-zA-Z][a-zA-Z0-9+.-]*://[^\s,)"'|]+`), "<url>"},
	// ISO-8601-ish timestamps, before the number rule gets at them.
	{regexp.MustCompile(`\b\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(\.\d+)?Z?\b`), "<time>"},
	{regexp.MustCompile(`\b\d{4}-\d{2}-\d{2}\b`), "<date>"},
	// A slot name on an execute node: the most-varying token in the most
	// common hold reason there is.
	{regexp.MustCompile(`\bslot\d+(_\d+)?@\S+`), "<slot>"},
	// glidein_<n>_<n>@host and other user@host forms.
	{regexp.MustCompile(`\b[\w.-]+@[\w.-]+\b`), "<host>"},
	// Software versions, before numbers.
	{regexp.MustCompile(`\bv?\d+\.\d+(\.\d+)+\b`), "<ver>"},
	// IPv4 with an optional port.
	{regexp.MustCompile(`\b\d{1,3}(\.\d{1,3}){3}(:\d+)?\b`), "<ip>"},
	// Absolute paths. Two segments minimum so a bare "/" or a sentence's
	// "and/or" is left alone.
	{regexp.MustCompile(`(/[\w.+-]+){2,}/?`), "<path>"},
	// A dotted hostname. Requires a letter so it cannot eat a decimal
	// number, and two dots so "request_memory." survives.
	{regexp.MustCompile(`\b[a-zA-Z][\w-]*(\.[\w-]+){2,}\b`), "<host>"},
	// Hex blobs: job ids, container digests, temp-directory suffixes.
	{regexp.MustCompile(`\b[0-9a-fA-F]{8,}\b`), "<hex>"},
	// A bare number, before the mixed-token rule below can claim it:
	// both are variables, but a template reading "<num>:<num>:<num>" is
	// something a person recognises as a duration and "<id>:<id>:<id>"
	// is not. These templates are read by facilitators, so the
	// placeholder names have to mean something.
	{regexp.MustCompile(`\b\d+\b`), "<num>"},
	// Mixed alphanumeric run with at least one digit -- glide_AGd9bW,
	// dir_260525, osgvo-docker-pilot-ospool-665dff69c8-phctx. These are
	// per-occurrence names, and leaving them in splits one issue into as
	// many clusters as there were execute nodes.
	{regexp.MustCompile(`\b(?:[a-zA-Z]+[_-]?)*\d[\w-]*\b`), "<id>"},
}

// Mask applies the rules in order. The result is what the clusterer
// tokenizes; the original message is kept as the cluster's example, so
// nothing a facilitator needs to read is lost to masking.
func Mask(message string) string {
	out := message
	for _, r := range maskRules {
		out = r.re.ReplaceAllString(out, r.with)
	}
	return out
}

// tokenize splits a masked message into the tokens the parse tree walks.
//
// HTCondor hold reasons are punctuated prose with machine detail wedged
// into them, so the separators are wider than whitespace: the "|" that
// FILETRANSFER uses to join its layers, and the brackets and commas that
// wrap URLs, would otherwise glue a placeholder to the word beside it
// and make two occurrences of one issue look different.
func tokenize(masked string) []string {
	fields := strings.FieldsFunc(masked, func(r rune) bool {
		switch r {
		case ' ', '\t', '\n', '\r', '|', ',', '(', ')', '[', ']', '"', '\'':
			return true
		}
		return false
	})
	out := fields[:0]
	for _, f := range fields {
		// Trailing sentence punctuation is noise for the comparison and
		// would make "request_memory" and "request_memory." different
		// tokens.
		f = strings.Trim(f, ".:;")
		if f != "" {
			out = append(out, f)
		}
	}
	return out
}
