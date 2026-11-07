package fuzzsubmit

import (
	"strings"
	"testing"
)

// TestEveryTraitIsUsed keeps oracleTraits from accumulating probes nothing
// consults. A trait is a claim about the oracle, and it earns its keep one of
// two ways: an entry names it, so it decides whether that divergence applies,
// or goBehaviorFor reads it, so it decides what the Go side produces. A trait
// doing neither is a fix that landed and took its entry with it, or a probe
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
	off := goBehaviorFor(map[string]bool{})
	for _, tr := range oracleTraits {
		if named[tr.ticket] || goBehaviorFor(map[string]bool{tr.ticket: true}) != off {
			continue
		}
		t.Errorf("nothing consults %s (%s): no entry names it and it changes no Go behavior -- delete the trait, write the entry, or wire it",
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
