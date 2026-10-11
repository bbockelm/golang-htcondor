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
//
// The one thing an override placed there cannot beat is a custom
// attribute: `+AccountingGroup = "x"` (or `MY.AccountingGroup`) is
// applied after every submit command, in condor_submit
// (SetForcedAttributes runs last so that it trumps them) and in this
// module's submit engine alike. So Apply also refuses a submit file
// that sets, as a custom attribute, a job attribute the overrides
// control. Which attributes those are is learned by running the
// overrides through the submit engine, not from a table that would
// drift from it.
package submitpolicy

import (
	"fmt"
	"strings"
	"sync"

	htcondor "github.com/bbockelm/golang-htcondor"
)

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
//
// It fails where Check does.
func (p Policy) Apply(submitFile string) (string, error) {
	if p.IsZero() {
		return submitFile, nil
	}
	if err := p.Check(submitFile); err != nil {
		return "", err
	}

	out := submitFile
	if block := blockOf(p.Overrides, overridesHeader, overridesFooter); block != "" {
		out = insertBeforeQueue(out, block)
	}
	if block := blockOf(p.Defaults, defaultsHeader, defaultsFooter); block != "" {
		out = block + ensureTrailingNewline(out)
	}
	return out, nil
}

// Check refuses a submit file that sets, as a custom attribute (`+Name`
// or `MY.Name`, any case), a job attribute the overrides control: that
// assignment would beat the override wherever the override sits.
// Callers that splice the overrides in themselves (the DAG tool's inline
// node descriptions) call it directly.
//
// The scan is by line rather than by parse because the text may be a
// DAG node description that condor_submit, not this module, will read,
// and every line counts wherever it sits relative to a queue statement.
func (p Policy) Check(submitFile string) error {
	if strings.TrimSpace(p.Overrides) == "" {
		return nil
	}
	controlled, err := overriddenAttributes(p.Overrides)
	if err != nil {
		return err
	}
	for _, name := range customAttributeNames(submitFile) {
		if _, ok := controlled[strings.ToLower(name)]; ok {
			return &ControlledAttributeError{Attribute: name}
		}
	}
	return nil
}

// ControlledAttributeError is Check's refusal: the submit file sets, as
// a custom attribute, a job attribute the site's overrides set. It is
// the submitter's to fix, so an HTTP surface answers it with 400.
type ControlledAttributeError struct {
	// Attribute is the name as the submit file spelled it.
	Attribute string
}

func (e *ControlledAttributeError) Error() string {
	return fmt.Sprintf("the submit file sets job attribute %s, which this access point's "+
		"site policy sets for every job; remove that line", e.Attribute)
}

// overrideProbePrefix gives the probe submit files the one command the
// submit engine will not build a job ad without.
const overrideProbePrefix = "executable = /bin/true\n"

// overrideAttrCache memoizes overriddenAttributes per overrides text.
// The text is operator configuration, so it holds one or two entries for
// the life of the process.
var overrideAttrCache sync.Map // string -> overrideAttrResult

type overrideAttrResult struct {
	attrs map[string]struct{}
	err   error
}

// overriddenAttributes returns the job attributes, lower-cased, that the
// overrides decide: those whose value differs, or that are present in
// one ad and not the other, between a job ad built from the overrides
// alone and one built from an empty submit file.
//
// The overrides run out of context, so one that refers to a user macro
// sees it empty. That changes the value it produces, not which attribute
// it sets, and only the names are used. An override whose value equals
// the engine's default is not detected.
func overriddenAttributes(overrides string) (map[string]struct{}, error) {
	if v, ok := overrideAttrCache.Load(overrides); ok {
		r := v.(overrideAttrResult)
		return r.attrs, r.err
	}
	attrs, err := probeOverriddenAttributes(overrides)
	overrideAttrCache.Store(overrides, overrideAttrResult{attrs: attrs, err: err})
	return attrs, err
}

func probeOverriddenAttributes(overrides string) (map[string]struct{}, error) {
	base, err := probeJobAd(overrideProbePrefix + "queue\n")
	if err != nil {
		return nil, fmt.Errorf("site submit policy: building the reference job ad: %w", err)
	}
	forced, err := probeJobAd(overrideProbePrefix + ensureTrailingNewline(overrides) + "queue\n")
	if err != nil {
		return nil, fmt.Errorf("site submit policy: HTTP_API_SUBMIT_FILE_OVERRIDES does not build a job ad: %w", err)
	}

	attrs := make(map[string]struct{})
	for name, value := range forced {
		if baseValue, ok := base[name]; !ok || baseValue != value {
			attrs[name] = struct{}{}
		}
	}
	for name := range base {
		if _, ok := forced[name]; !ok {
			attrs[name] = struct{}{}
		}
	}
	// Stamped from the clock, so the two probes may disagree on it.
	delete(attrs, "qdate")
	return attrs, nil
}

// probeJobAd builds the job ad for submitText and returns its attributes
// as lower-cased name -> unparsed value.
func probeJobAd(submitText string) (map[string]string, error) {
	sf, err := htcondor.ParseSubmitFile(strings.NewReader(submitText))
	if err != nil {
		return nil, err
	}
	ad, err := sf.MakeJobAd(htcondor.JobID{Cluster: 1, Proc: 0}, nil)
	if err != nil {
		return nil, err
	}
	out := make(map[string]string)
	for _, name := range ad.GetAttributes() {
		if expr, ok := ad.Lookup(name); ok {
			out[strings.ToLower(name)] = expr.String()
		}
	}
	return out, nil
}

// customAttributeNames returns the attribute named by every line of
// submitText that assigns a custom attribute: `+Name = ...` or
// `MY.Name = ...` in any case, the two spellings condor_submit accepts.
// A line continuing the previous one (trailing backslash) is part of a
// value, not an assignment, and is skipped.
func customAttributeNames(submitText string) []string {
	var names []string
	continued := false
	for _, raw := range strings.Split(submitText, "\n") {
		line := strings.TrimSpace(raw)
		wasContinued := continued
		continued = strings.HasSuffix(line, `\`)
		if wasContinued {
			continue
		}
		var rest string
		switch {
		case strings.HasPrefix(line, "+"):
			rest = line[1:]
		case len(line) > 3 && strings.EqualFold(line[:3], "MY."):
			rest = line[3:]
		default:
			continue
		}
		if j := strings.IndexAny(rest, " \t=:"); j >= 0 {
			rest = rest[:j]
		}
		if rest != "" {
			names = append(names, rest)
		}
	}
	return names
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

// insertBeforeQueue splices block in ahead of EVERY queue statement.
// Ahead of the first is where an assignment affects that queue and every
// one after it; repeating it ahead of each later one keeps a command the
// file reassigns between two queue statements (which condor_submit
// honours for the second) from beating it. A submit file with no queue
// statement gets the block appended: the templates path builds its
// `queue ... from (...)` line after this runs, so appending still lands
// ahead of it.
func insertBeforeQueue(submitFile, block string) string {
	lines := strings.Split(submitFile, "\n")
	found := false
	for i, line := range lines {
		if isQueueLine(line) {
			lines[i] = block + line
			found = true
		}
	}
	if !found {
		return ensureTrailingNewline(submitFile) + block
	}
	return strings.Join(lines, "\n")
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
