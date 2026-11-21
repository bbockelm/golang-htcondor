package fuzzconfig

import (
	"fmt"
	"sort"
	"strings"

	"github.com/htcondor/golang-htcondor/fuzz/config/oracle"
)

// Oracle traits: which upstream changes the linked HTCondor carries.
//
// Pull-request CI pins a release and the nightly builds the oracle from
// HTCondor's main branch, so one tree is compared against two parsers. A
// change to the config language shows up as a divergence in the nightly long
// before the pinned oracle has it, and recording it unconditionally would
// fail the pinned build instead -- where the two sides still agree.
//
// A recorded divergence, and a class, can therefore say which side of one
// upstream change it belongs to. One that does not apply to the linked oracle
// is not merely ignored: the seed flips to being expected to AGREE, so both
// oracles are asserted rather than one being skipped.
//
// Traits are decided by PROBING the oracle, never by reading a version
// number: upstream backports across release branches, so a change reaches a
// 25.x patch release and a 26.x release with no version between them that
// separates the two.

// oracleReq is one side of one upstream change: the ticket, and whether the
// thing it qualifies applies when the oracle HAS that change.
type oracleReq struct {
	ticket string
	has    bool
}

// met reports whether the linked oracle satisfies this requirement.
func (r *oracleReq) met() bool {
	if r == nil {
		return true
	}
	return oracleHas[r.ticket] == r.has
}

// oracleTrait is one upstream change the linked HTCondor either has or does
// not.
type oracleTrait struct {
	ticket string
	// what the change does, in one line, for the run's log.
	what string
	// probe reports whether the oracle HAS the change.
	probe func() bool
}

// oracleTraits are the upstream changes the recorded divergences need to
// distinguish.
var oracleTraits = []oracleTrait{
	{
		ticket: "HTCONDOR-3993",
		what:   "three double-quotes switch classic ClassAd parsing to new-ClassAd quoting",
		probe: func() bool {
			// `""""` is a triple-quote marker followed by a quote. An
			// HTCondor that knows the marker lexes the rest as a
			// new-ClassAd string and $INT gets something it can read; one
			// that does not chokes and the macro expands to nothing.
			return cppValueOf(`0=$INT("""">"")`, "0") != ""
		},
	},
}

// cppValueOf runs one config source through the oracle and returns the
// expanded value of a key, or "" when the parse failed or the key is absent.
func cppValueOf(input, key string) string {
	res := oracle.ParseExpand(Prelude(input))
	if !res.Parsed || res.Panic {
		return ""
	}
	for _, line := range strings.Split(res.Table, "\n") {
		k, v, ok := strings.Cut(line, "\x1f")
		if ok && k == key {
			return v
		}
	}
	return ""
}

// oracleHas is the probe result, settled by TestMain: per ticket, whether the
// linked oracle carries that upstream change. Empty when no oracle is linked,
// where nothing is compared anyway.
var oracleHas map[string]bool

// probeOracleTraits asks the oracle, once, about every trait.
func probeOracleTraits() map[string]bool {
	have := make(map[string]bool, len(oracleTraits))
	for _, tr := range oracleTraits {
		have[tr.ticket] = tr.probe()
	}
	return have
}

// describeTraits renders the probe result for the run's log, so a report says
// which HTCondor it faced in terms of behavior and not only a version banner.
func describeTraits(have map[string]bool) string {
	tickets := make([]string, 0, len(have))
	for t := range have {
		tickets = append(tickets, t)
	}
	sort.Strings(tickets)
	var b strings.Builder
	for _, t := range tickets {
		state := "lacks"
		if have[t] {
			state = "has"
		}
		fmt.Fprintf(&b, "\n  %-5s %s", state, t)
	}
	return b.String()
}

// libcCanary is a format whose output separates the two C libraries this
// oracle is built against, without reaching a case either one rejects.
//
// `%A` consumes the double; `%Zz`... is read differently on each side. glibc
// takes Z as a length modifier (a deprecated synonym for z) and the trailing
// Z as an unknown conversion, which printf_unknown writes back as `%Z`.
// macOS libc has no Z modifier: the first Z is itself an unknown conversion,
// printed as a bare character, and the second is literal. So glibc says
// `0X1P+0%Z` and macOS says `0X1P+0ZZ`, and $REAL appends `.0` to both.
const libcCanary = "0=$REAL(1,%A%ZZ)"

// goCanaryValue is what config/printf.go -- the glibc model -- makes of the
// canary. Empty when the Go side could not answer.
func goCanaryValue() string {
	res := GoParseExpand(Prelude(libcCanary))
	if res.Uncomparable != "" {
		return ""
	}
	for _, line := range strings.Split(Canon(res.Table), "\n") {
		if k, v, ok := strings.Cut(line, "\x1f"); ok && k == "0" {
			return v
		}
	}
	return ""
}

// libcWarning is the note a run prints when the linked oracle's C library is
// not the one this parser models. Empty when it is, and empty when either
// side could not answer, since there is then nothing to compare.
//
// config/printf.go is a port of GLIBC's spec parsing, by design: that is the
// C library the pinned and nightly oracles are built against. An oracle built
// against a different one disagrees about printf formats for reasons that
// have nothing to do with this parser, and a local fuzz run then reports
// divergences that do not exist on the platform CI runs on -- which has
// already cost one investigation. See CONFIG_FUZZ_FINDINGS.md, "$REAL(1,%A%Z)
// is a macOS-oracle artifact".
//
// It warns rather than excusing anything. A class that skipped these inputs
// would hide real divergences on the platform that matters.
func libcWarning() string {
	return libcWarningFor(cppValueOf(libcCanary, "0"), goCanaryValue())
}

// libcWarningFor is the decision, separated from the two lookups so it can be
// tested without depending on which C library the test host has.
func libcWarningFor(cppValue, goValue string) string {
	if cppValue == "" || goValue == "" || cppValue == goValue {
		return ""
	}
	return "WARNING: this oracle's C library formats printf specs differently from glibc,\n" +
		"  which config/printf.go models (canary " + libcCanary + ": oracle " + cppValue +
		", model " + goValue + ").\n" +
		"  A $INT/$REAL/$STRING divergence reported here may not exist on the platform CI\n" +
		"  and the nightly run on -- check it against a glibc oracle before chasing it.\n" +
		"  Everything else compares normally.\n"
}
