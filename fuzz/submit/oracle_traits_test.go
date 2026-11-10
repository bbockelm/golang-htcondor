package fuzzsubmit

import (
	"strings"
	"testing"

	htcondor "github.com/bbockelm/golang-htcondor"
)

// TestEveryTraitIsUsed keeps oracleTraits from accumulating probes nothing
// consults. A trait is a claim about the oracle, and it earns its keep by
// deciding something: whether a recorded divergence applies, which keyword
// rows this parser may be ahead on, which digest keywords it may be behind
// on, or what the Go side produces. A trait deciding none of those is a fix
// that landed and took its entry with it, or a probe
// written ahead of the work it was for.
//
// The second half is checked by running goBehaviorFor rather than by looking
// for the ticket in the source, so a trait that is mentioned there but wired
// to nothing still fails.
func TestEveryTraitIsUsed(t *testing.T) {
	named := map[string]bool{}
	for _, req := range entryTrait {
		named[req.ticket] = true
	}
	// The other places a trait decides something: which keyword rows this
	// parser is allowed to be ahead on, and which digest keywords it is
	// allowed to be behind on.
	for _, ticket := range keywordsAheadOfOracle {
		named[ticket] = true
	}
	for _, ticket := range digestKeywordsBehindOracle {
		named[ticket] = true
	}
	off := goBehaviorFor(map[string]bool{})
	for _, tr := range oracleTraits {
		if named[tr.ticket] || goBehaviorFor(map[string]bool{tr.ticket: true}) != off {
			continue
		}
		t.Errorf("nothing consults %s (%s): nothing names it and it changes no Go behavior -- delete the trait, record what it explains, or wire it",
			tr.ticket, tr.what)
	}
}

// TestImplementedTraitsHaveNoEntry is the rule that keeps the two mechanisms
// from overlapping. Once a trait drives the Go side, the two parsers agree
// against either oracle and the entry that recorded the difference is a stale
// excuse -- one that would hide a real regression in the gate it was replaced
// by.
func TestImplementedTraitsHaveNoEntry(t *testing.T) {
	off := goBehaviorFor(map[string]bool{})
	for _, tr := range oracleTraits {
		if goBehaviorFor(map[string]bool{tr.ticket: true}) == off {
			continue
		}
		for attr, req := range entryTrait {
			if req.ticket == tr.ticket {
				t.Errorf("%s is implemented on the Go side, so %s.md excuses a difference that no longer exists -- delete it",
					tr.ticket, attr)
			}
		}
	}
}

// TestTraitMarkerIsParsed pins the entry-file marker, both spellings and the
// refusals. A marker that silently failed to parse would leave the entry
// applying to every oracle, which is exactly the excuse-everything behavior
// the trait exists to prevent.
func TestTraitMarkerIsParsed(t *testing.T) {
	ok := map[string]traitReq{
		" has HTCONDOR-3998":     {ticket: "HTCONDOR-3998", has: true},
		" lacks HTCONDOR-3998":   {ticket: "HTCONDOR-3998", has: false},
		"   has   HTCONDOR-4020": {ticket: "HTCONDOR-4020", has: true},
	}
	for in, want := range ok {
		got, err := parseTraitReq(in)
		if err != nil {
			t.Errorf("parseTraitReq(%q): %v", in, err)
			continue
		}
		if *got != want {
			t.Errorf("parseTraitReq(%q) = %+v, want %+v", in, *got, want)
		}
	}

	bad := []string{
		" HTCONDOR-3998",              // no side
		" has",                        // no ticket
		" maybe HTCONDOR-3998",        // not a side
		" has HTCONDOR-9999",          // not a trait we probe for
		" has HTCONDOR-3998 and more", // two tickets
		"",
	}
	for _, in := range bad {
		if got, err := parseTraitReq(in); err == nil {
			t.Errorf("parseTraitReq(%q) = %+v, want an error", in, *got)
		}
	}
}

// TestActivateDropsWhatDoesNotApply runs the filter both ways round. The
// failure that matters is an entry surviving against an oracle it is not
// about: it would excuse a divergence that oracle should never produce, and a
// fuzz run reporting nothing looks exactly like a clean one.
func TestActivateDropsWhatDoesNotApply(t *testing.T) {
	withEntries(t, map[string]traitReq{
		"ours":     {},
		"upstream": {ticket: "HTCONDOR-3998", has: true},
		"fixed":    {ticket: "HTCONDOR-3998", has: false},
	}, func() {
		dropped := activateDivergences(map[string]bool{"HTCONDOR-3998": true})
		if strings.Join(dropped, ",") != "fixed" {
			t.Errorf("with the change: dropped %v, want only the `lacks` entry", dropped)
		}
		if _, ok := knownDivergent["ours"]; !ok {
			t.Error("an entry with no trait applies to every oracle and must survive")
		}
		if _, ok := knownDivergent["upstream"]; !ok {
			t.Error("the `has` entry must survive against an oracle that has the change")
		}
	})

	withEntries(t, map[string]traitReq{
		"ours":     {},
		"upstream": {ticket: "HTCONDOR-3998", has: true},
		"fixed":    {ticket: "HTCONDOR-3998", has: false},
	}, func() {
		dropped := activateDivergences(map[string]bool{"HTCONDOR-3998": false})
		if strings.Join(dropped, ",") != "upstream" {
			t.Errorf("without the change: dropped %v, want only the `has` entry", dropped)
		}
		if _, ok := knownDivergent["fixed"]; !ok {
			t.Error("the `lacks` entry must survive against an oracle that lacks the change")
		}
	})
}

// withEntries swaps in a fake ledger for one check and restores the real one,
// so these tests do not depend on which entries happen to be recorded.
func withEntries(t *testing.T, entries map[string]traitReq, body func()) {
	t.Helper()
	savedTrait, savedKnown := entryTrait, knownDivergent
	defer func() { entryTrait, knownDivergent = savedTrait, savedKnown }()

	entryTrait = entries
	knownDivergent = map[string]string{}
	for attr := range entries {
		knownDivergent[attr] = "fake entry for " + attr
	}
	body()
}

// TestDigestAllowanceIsNotDead guards the one thing that cannot be checked
// against a pinned oracle: the allowance names keywords only a newer HTCondor
// has, so no local run ever exercises it.
//
// What a local run CAN prove is that each entry is still about something. An
// entry for a keyword this library has started pruning is dead and hides the
// fact that it was fixed; an entry naming a ticket no trait probes for would
// never be honored at all, and would read as an explanation while explaining
// nothing.
func TestDigestAllowanceIsNotDead(t *testing.T) {
	probed := map[string]bool{}
	for _, tr := range oracleTraits {
		probed[tr.ticket] = true
	}
	for name, ticket := range digestKeywordsBehindOracle {
		if htcondor.DigestKeywordIsPrunable(name) {
			t.Errorf("%s is pruned now, so its allowance explains nothing -- delete the entry", name)
		}
		if !probed[ticket] {
			t.Errorf("%s names %s, which no trait probes for, so the allowance can never apply", name, ticket)
		}
	}

	// The other direction, held to the same standard: an entry here is
	// about a keyword this library prunes, so one that is no longer in the
	// prunable table explains nothing either.
	for name, ticket := range digestKeywordsAheadOfOracle {
		if !htcondor.DigestKeywordIsPrunable(name) {
			t.Errorf("%s is not in the prunable table, so its allowance explains nothing -- delete the entry", name)
		}
		if !probed[ticket] {
			t.Errorf("%s names %s, which no trait probes for, so the allowance can never apply", name, ticket)
		}
		if other, both := digestKeywordsBehindOracle[name]; both {
			t.Errorf("%s is recorded in both directions (%s and %s); one of them is wrong", name, ticket, other)
		}
	}
}

// TestDigestKeywordClassification exercises both allowances without an
// oracle, which is the only place they can be exercised at all: each one is
// about a keyword table only an HTCondor newer than the pinned one has, so
// every run that links an oracle takes the other branch. Left unpinned, an
// allowance that excused too much or nothing would be found by the nightly
// and nowhere else.
func TestDigestKeywordClassification(t *testing.T) {
	// Real entries, so the test moves with the tables rather than with a
	// fixture: one from each allowance, plus a name in neither.
	const (
		behindName = "annex_name"  // the oracle has it, we do not prune it
		aheadName  = "buffer_size" // we prune it, a newer oracle dropped it
		newName    = "not_a_keyword_this_library_knows"
	)
	if _, ok := digestKeywordsBehindOracle[behindName]; !ok {
		t.Fatalf("%s is no longer a recorded allowance; pick another entry", behindName)
	}
	if _, ok := digestKeywordsAheadOfOracle[aheadName]; !ok {
		t.Fatalf("%s is no longer a recorded allowance; pick another entry", aheadName)
	}

	// An oracle that knows behindName and newName, and has dropped
	// aheadName; this library prunes aheadName and not the other two.
	want := map[string]bool{behindName: true, newName: true}
	prunable := []string{aheadName}

	all := map[string]bool{}
	for _, tr := range oracleTraits {
		all[tr.ticket] = true
	}

	withTraits := classifyDigestKeywords(want, prunable, all)
	if len(withTraits.missing) != 1 || withTraits.missing[0] != newName {
		t.Errorf("a keyword nothing accounts for must be reported, got missing=%v", withTraits.missing)
	}
	if len(withTraits.extra) != 0 {
		t.Errorf("the recorded keyword must not be reported, got extra=%v", withTraits.extra)
	}
	if len(withTraits.behind) != 1 || withTraits.behind[0] != behindName {
		t.Errorf("want behind=[%s], got %v", behindName, withTraits.behind)
	}
	if len(withTraits.ahead) != 1 || withTraits.ahead[0] != aheadName {
		t.Errorf("want ahead=[%s], got %v", aheadName, withTraits.ahead)
	}

	// The same two tables against an oracle that carries neither change:
	// both allowances lapse and both differences are findings again. This
	// is the half that keeps an allowance from excusing a difference the
	// pinned oracle should never produce.
	none := classifyDigestKeywords(want, prunable, map[string]bool{})
	if len(none.behind) != 0 || len(none.ahead) != 0 {
		t.Errorf("no trait is present, so neither allowance applies: behind=%v ahead=%v", none.behind, none.ahead)
	}
	if len(none.missing) != 2 {
		t.Errorf("want both unpruned keywords reported, got missing=%v", none.missing)
	}
	if len(none.extra) != 1 || none.extra[0] != aheadName {
		t.Errorf("want extra=[%s], got %v", aheadName, none.extra)
	}
}
