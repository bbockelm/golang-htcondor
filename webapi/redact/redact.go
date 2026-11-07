// Package redact masks credential-shaped text before it leaves this
// access point.
//
// What this is for, and what it is not for.
//
// A job that prints its own credential -- `cat $_CONDOR_CREDS/x.use`, a
// `curl -v` that echoes its Authorization header, a framework that logs
// its config at startup -- puts that credential in the job's stdout. An
// agent reading that output through MCP then has the credential in its
// context, from where it travels to a model provider, a transcript, and
// whatever the client logs. Nobody chose that; it is an accident, and it
// is the accident this package exists to make less likely.
//
// It is NOT a security boundary. A caller who can run code in a job can
// transform a credential into something no pattern matches -- reverse it,
// base64 it, print it one character per line -- and read it back out.
// Anyone who WANTS the credential will get it. GitHub Actions' log masking
// has exactly this property and is still worth having, for the same
// reason: the common case is not an attacker, it is a stack trace.
//
// The design follows from that:
//
//   - Known formats only. Every rule keys off a published prefix, a
//     structural marker, or a field name. There is no entropy heuristic,
//     because scientific job output is full of hashes, UUIDs, base64
//     payloads and accession numbers, and a redactor that eats those is
//     one an operator turns off.
//
//   - Keep the part that is not secret. A JWT's header and claims say
//     which issuer, which subject, which scopes and when it expires --
//     which is the whole answer to "why was my transfer denied". Only the
//     signature is secret, so only the signature goes. An X.509 proxy's
//     certificates are public; only the private key goes.
//
//   - Say so. A result that was changed carries a note. Output that
//     silently differs from what the job wrote is worse than output with
//     a hole in it, because the reader draws conclusions from it.
package redact

import (
	"bytes"
	"fmt"
	"path"
	"regexp"
	"sort"
	"strings"
)

// Marker is the text a redacted value is replaced with. The rule's id
// follows the colon, so a reader can tell a masked token from a masked
// private key without the original.
//
// Deliberately contains no character sequence any rule matches, so
// redacting an already-redacted string is a no-op rather than a second
// round of markers inside markers.
func Marker(ruleID string) string { return "[REDACTED:" + ruleID + "]" }

// markerPrefix is what a value already redacted starts with. Rules that
// replace a named field's value check for it so that re-running over the
// same text neither double-counts nor nests.
const markerPrefix = "[REDACTED:"

// Rule is one credential format.
//
// A rule is either Pattern-based (the common case) or Fn-based (for the
// two formats whose structure a single RE2 expression cannot express).
type Rule struct {
	// ID names the format and appears in the marker. Stable: an operator
	// turns a rule off by this name, and it shows up in results.
	ID string

	// What describes the format for the note a caller reads. A phrase,
	// not a sentence: the note joins several of them.
	What string

	// Needles are literal substrings, at least one of which must appear
	// before the pattern is run at all.
	//
	// This is the whole performance story. A megabyte of job output with
	// no credential in it is the overwhelmingly common case, and it costs
	// one substring search per needle rather than one pass of a pattern
	// over the text. Go's regexp has no DFA, so a wide alternation costs
	// O(text x program) when it does run, and keeping it from running is
	// worth more than making it faster. Every rule here has a needle.
	Needles []string

	// Require are substrings that must ALL appear, on top of one of the
	// Needles. For a format whose only distinctive mark is common on its
	// own -- "://" matches any URL, and a URL with a password in it also
	// has an "@" -- a second cheap literal is what keeps the pattern from
	// running over every result that mentions a URL.
	Require []string

	// Pattern matches one instance of the format.
	Pattern *regexp.Regexp

	// Anchored says Pattern begins exactly where one of the Needles
	// does, so it is run at each needle occurrence rather than over the
	// whole text.
	//
	// This is for the rules whose pattern is a wide alternation. Go's
	// regexp simulates an NFA, so an unanchored pass costs the length of
	// the text times the size of the program, and the credential-field
	// rule's program is most of the rule set -- measured at 15ms per
	// 100KB of output that contained no credential at all, because the
	// word "token" appeared on every line. Anchoring makes the cost
	// proportional to the number of places worth looking, which is the
	// property this needs: the text being scanned is arbitrary output
	// from somebody's job, and a filter whose cost an input can drive is
	// one an input can stall.
	Anchored bool

	// Groups are the submatch indexes that may hold the secret; the
	// first one that participated in the match is what gets replaced,
	// and the rest of the match is left in place. Empty means the whole
	// match.
	//
	// More than one is needed where the value's quoting is an
	// alternation: a credential field written as JSON, as a shell
	// assignment and as a bare INI value is three branches of one
	// pattern, and exactly one of them participates in any given match.
	Groups []int

	// Skip rejects a match the pattern could not exclude on its own,
	// given the text and the match indices from FindAllStringSubmatchIndex.
	// RE2 has no lookaround, so the boundary conditions that matter --
	// "not part of a longer token", "not a JWE" -- are checked here.
	Skip func(src string, loc []int) bool

	// Fn redacts every instance in one pass, for formats with no regular
	// expression. It calls mark for each secret it removes and returns
	// the rewritten text.
	Fn func(src string, mark func(original string) string) string
}

// Result reports what a redaction changed. A nil *Result means nothing
// matched, which is the caller's signal to hand back the original value
// rather than the identical rewritten one.
type Result struct {
	// rules counts the matches each rule made, keyed by rule id.
	rules map[string]int

	// what holds each matching rule's What, for the note.
	what map[string]string

	// values is the set of distinct secrets masked. A count of MATCHES
	// is the wrong number to report: one credential printed in both the
	// text block and the structured payload is two matches and one
	// secret, and a reader told "2" goes looking for a second one that
	// does not exist.
	values map[string]struct{}
}

// Redactor applies a set of rules.
//
// Safe for concurrent use: rules are immutable once built, and nothing is
// cached between calls.
type Redactor struct {
	rules []Rule
	// needles is every rule's needles, deduplicated, for the whole-payload
	// prescan that decides whether to walk a result at all.
	needles []string
}

// New builds a Redactor from rules, dropping any whose id matches one of
// disabled (shell globs, as in the operator's setting). It returns the
// ids it dropped so the caller can log what a site turned off, and the
// patterns that matched nothing so a typo is reported rather than
// silently leaving a rule enabled.
func New(rules []Rule, disabled []string) (*Redactor, []string, []string) {
	var kept []Rule
	var dropped []string
	used := make(map[string]bool, len(disabled))
	for _, r := range rules {
		off := false
		for _, pat := range disabled {
			// Shell globs, the same shape as the operator's other
			// by-name settings, so "github-*" turns off a family.
			ok, err := path.Match(pat, r.ID)
			if err != nil {
				continue
			}
			if ok {
				off, used[pat] = true, true
			}
		}
		if off {
			dropped = append(dropped, r.ID)
			continue
		}
		kept = append(kept, r)
	}
	var unmatched []string
	for _, pat := range disabled {
		if !used[pat] {
			unmatched = append(unmatched, pat)
		}
	}

	seen := map[string]bool{}
	var needles []string
	for _, r := range kept {
		for _, n := range r.Needles {
			if !seen[n] {
				seen[n] = true
				needles = append(needles, n)
			}
		}
	}
	return &Redactor{rules: kept, needles: needles}, dropped, unmatched
}

// Rules returns the ids of the rules in force, sorted. For the startup
// log line and for tests that assert the set.
func (r *Redactor) Rules() []string {
	ids := make([]string, 0, len(r.rules))
	for _, rule := range r.rules {
		ids = append(ids, rule.ID)
	}
	sort.Strings(ids)
	return ids
}

// MightContain reports whether raw is worth examining closely.
//
// Run over a whole marshalled result before anything is decoded or
// walked: no needle anywhere means no rule can match anywhere, and the
// result is handed back untouched. Needles are chosen to survive JSON
// encoding -- all are plain ASCII that an encoder does not escape -- so
// scanning the marshalled form finds what scanning the decoded strings
// would find.
func (r *Redactor) MightContain(raw []byte) bool {
	for _, n := range r.needles {
		if bytes.Contains(raw, []byte(n)) {
			return true
		}
	}
	return false
}

// Redact masks every credential it recognises in s.
//
// res is nil when nothing matched, which is the caller's signal to return
// the original value rather than the (identical) rewritten one.
func (r *Redactor) Redact(s string) (string, *Result) {
	if s == "" {
		return s, nil
	}
	var res *Result
	mark := func(id, what, original string) string {
		if res == nil {
			res = newResult()
		}
		res.record(id, what, original)
		return Marker(id)
	}

	for i := range r.rules {
		rule := &r.rules[i]
		if !containsAny(s, rule.Needles) || !containsAll(s, rule.Require) {
			continue
		}
		if rule.Fn != nil {
			s = rule.Fn(s, func(original string) string {
				return mark(rule.ID, rule.What, original)
			})
			continue
		}
		s = replaceGroup(s, rule, locateMatches(s, rule), func(original string) string {
			return mark(rule.ID, rule.What, original)
		})
	}
	return s, res
}

// replaceGroup rewrites every match of rule.Pattern, replacing only the
// submatch rule.Group and leaving the rest of the match in place.
//
// Hand-rolled rather than ReplaceAllStringFunc because that hands the
// callback the matched TEXT, and a rule that keeps part of its match
// needs the submatch boundaries -- as does Skip, which decides on the
// characters either side of the match.
func replaceGroup(s string, rule *Rule, locs [][]int, mark func(string) string) string {
	if len(locs) == 0 {
		return s
	}
	var b strings.Builder
	b.Grow(len(s))
	last := 0
	for _, loc := range locs {
		if rule.Skip != nil && rule.Skip(s, loc) {
			continue
		}
		start, end := secretSpan(rule.Groups, loc)
		if start < 0 {
			continue
		}
		secret := s[start:end]
		// Text that already holds a marker is left exactly as it is.
		//
		// This is what lets the rules that keep the useful half of a
		// credential survive the blunter rules that run after them. A
		// SciToken written as `access_token: eyJ…` is matched twice:
		// once by the JWT rule, which takes the signature and leaves the
		// issuer and scopes, and then by the credential-field rule,
		// whose idea of the value is everything up to the next
		// delimiter. Without this the second match would swallow the
		// claims the first one deliberately kept -- and leave a stray
		// bracket behind, because the marker it would be replacing is
		// not entirely inside the span.
		//
		// Also what makes redaction idempotent, which matters because a
		// result can pass a redactor more than once.
		if strings.Contains(secret, markerPrefix) {
			continue
		}
		b.WriteString(s[last:start])
		b.WriteString(mark(secret))
		last = end
	}
	if last == 0 {
		return s
	}
	b.WriteString(s[last:])
	return b.String()
}

// secretSpan picks the span replaceGroup replaces: the first of the
// rule's groups that participated in this match, or the whole match when
// the rule names none.
func secretSpan(groups []int, loc []int) (int, int) {
	if len(groups) == 0 {
		return loc[0], loc[1]
	}
	for _, g := range groups {
		i := 2 * g
		if i+1 < len(loc) && loc[i] >= 0 {
			return loc[i], loc[i+1]
		}
	}
	return -1, -1
}

// locateMatches finds every match of a rule's pattern, as
// FindAllStringSubmatchIndex would, by whichever of the two strategies
// the rule asks for.
func locateMatches(s string, rule *Rule) [][]int {
	if !rule.Anchored {
		return rule.Pattern.FindAllStringSubmatchIndex(s, -1)
	}
	var locs [][]int
	end := 0 // one past the last match, so matches never overlap
	for _, at := range needleOffsets(s, rule.Needles) {
		if at < end {
			continue
		}
		stop := min(at+anchorWindow, len(s))
		loc := rule.Pattern.FindStringSubmatchIndex(s[at:stop])
		// The pattern has to match AT the needle, not merely somewhere
		// in the window: the needle is the field name, and a match
		// starting later in the window belongs to a different one, which
		// this loop will reach on its own offset.
		if loc == nil || loc[0] != 0 {
			continue
		}
		for i := range loc {
			if loc[i] >= 0 {
				loc[i] += at
			}
		}
		locs = append(locs, loc)
		end = loc[1]
	}
	return locs
}

// anchorWindow bounds how far past a needle an anchored pattern may
// match. Comfortably longer than any credential written on one line --
// an RS256 JWT is about 800 bytes -- and short enough that a pathological
// input cannot turn each candidate into a scan of the whole text.
const anchorWindow = 4096

// needleOffsets returns every offset at which any needle occurs, in
// increasing order.
//
// One pass per needle and then a sort, rather than a merge of running
// searches: searching from each match for the nearest of several needles
// re-scans the same bytes once per needle per match, which is quadratic
// in exactly the case this is meant to make fast.
func needleOffsets(s string, needles []string) []int {
	var offsets []int
	for _, n := range needles {
		for from := 0; ; {
			i := strings.Index(s[from:], n)
			if i < 0 {
				break
			}
			offsets = append(offsets, from+i)
			from += i + 1
		}
	}
	sort.Ints(offsets)
	return offsets
}

func containsAll(s string, needles []string) bool {
	for _, n := range needles {
		if !strings.Contains(s, n) {
			return false
		}
	}
	return true
}

func containsAny(s string, needles []string) bool {
	for _, n := range needles {
		if strings.Contains(s, n) {
			return true
		}
	}
	return false
}

// --- Result ---------------------------------------------------------------

func newResult() *Result {
	return &Result{
		rules:  map[string]int{},
		what:   map[string]string{},
		values: map[string]struct{}{},
	}
}

func (r *Result) record(id, what, original string) {
	r.rules[id]++
	r.what[id] = what
	r.values[original] = struct{}{}
}

// Changed reports whether anything was redacted. Safe on a nil Result,
// so a caller can test the return of Redact without a nil check first.
func (r *Result) Changed() bool { return r != nil && len(r.rules) > 0 }

// Values is how many distinct secrets were masked.
func (r *Result) Values() int {
	if r == nil {
		return 0
	}
	return len(r.values)
}

// Kinds names the formats that matched, sorted, for the structured
// payload and the note.
func (r *Result) Kinds() []string {
	if r == nil {
		return nil
	}
	ids := make([]string, 0, len(r.rules))
	for id := range r.rules {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	return ids
}

// Merge folds another redaction's tally into this one, so a walk over a
// whole tool result reports one count rather than one per string. The
// distinct-value set is what makes this correct across strings: the same
// credential in two fields stays one value.
func (r *Result) Merge(other *Result) *Result {
	if other == nil {
		return r
	}
	if r == nil {
		r = newResult()
	}
	for id, n := range other.rules {
		r.rules[id] += n
	}
	for id, w := range other.what {
		r.what[id] = w
	}
	for v := range other.values {
		r.values[v] = struct{}{}
	}
	return r
}

// Note is the sentence appended to a result whose content was changed.
//
// It states what happened and closes the two questions it otherwise
// raises: whether the rest of the output can be trusted (it is unchanged)
// and whether the original is worth chasing (it is not reachable from
// here). Without the second, an agent reasonably spends a turn trying
// another tool to get at the same bytes.
func (r *Result) Note() string {
	if !r.Changed() {
		return ""
	}
	kinds := make([]string, 0, len(r.what))
	for _, w := range r.what {
		kinds = append(kinds, w)
	}
	sort.Strings(kinds)
	n := r.Values()
	subject, verb := fmt.Sprintf("%d values", n), "were"
	if n == 1 {
		subject, verb = "1 value", "was"
	}
	return fmt.Sprintf(
		"Note: %s matching a known credential format (%s) %s replaced with [REDACTED:...] "+
			"by the access point before this result was returned. Everything else is as the job wrote it. "+
			"The originals are not retrievable through this interface, so do not reach for another tool to "+
			"recover them; if one is genuinely needed, the person running the job can read it on the access point.",
		subject, strings.Join(kinds, ", "), verb)
}
