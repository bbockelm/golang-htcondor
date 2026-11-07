package fuzzsubmit

import (
	"strings"
	"testing"
)

// TestEveryTraitIsNamed keeps oracleTraits from accumulating probes nothing
// uses. A trait is a claim about the oracle that only earns its keep by
// deciding whether some entry applies; one no entry names is either a fix that
// landed and took its entry with it, or a probe written ahead of the entry it
// was for.
func TestEveryTraitIsNamed(t *testing.T) {
	named := map[string]bool{}
	for _, req := range entryTrait {
		named[req.ticket] = true
	}
	for _, tr := range oracleTraits {
		if !named[tr.ticket] {
			t.Errorf("no entry names %s (%s), so nothing decides anything from it -- delete the trait or write the entry",
				tr.ticket, tr.what)
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
