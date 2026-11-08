package fuzzconfig

import (
	"fmt"
	"sort"
	"strings"

	"github.com/bbockelm/golang-htcondor/fuzz/config/oracle"
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
