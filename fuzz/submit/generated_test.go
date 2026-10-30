//go:build libcondor_utils

package fuzzsubmit

import (
	"sort"
	"strings"
	"sync"
	"testing"

	"github.com/bbockelm/golang-htcondor/fuzz/submit/oracle"
)

// vocab is built once from the linked HTCondor's own keyword table. Keywords()
// takes the oracle's lock, so it is not something to call per fuzz iteration.
var (
	vocabOnce sync.Once
	vocabVal  *Vocab
)

func genVocab(t testing.TB) *Vocab {
	t.Helper()
	vocabOnce.Do(func() { vocabVal = NewVocab(oracle.Keywords()) })
	if vocabVal == nil {
		t.Fatal("submit keyword table came back empty")
	}
	return vocabVal
}

// genSeeds are byte scripts for the generator, not submit files. They are short
// and varied so the fuzzer starts from inputs that already reach several
// universes; the generator turns any bytes into a syntactically valid file, so
// these only have to be different from each other.
var genSeeds = [][]byte{
	{},
	{0x00},
	{0x01, 0x02, 0x03, 0x04},
	{0xff, 0xfe, 0xfd, 0xfc, 0xfb, 0xfa},
	{0x10, 0x20, 0x30, 0x40, 0x50, 0x60, 0x70, 0x80},
	{0x07, 0x11, 0x2b, 0x3d, 0x41, 0x59, 0x67, 0x71, 0x83, 0x97},
	{0x03, 0x05, 0x07, 0x0b, 0x0d, 0x11, 0x13, 0x17, 0x1d, 0x1f, 0x25, 0x29},
	{0xaa, 0x55, 0xaa, 0x55, 0xaa, 0x55, 0xaa, 0x55, 0xaa, 0x55, 0xaa, 0x55, 0xaa, 0x55},
}

// FuzzSubmitGenerated is FuzzSubmitAds' vocabulary-directed twin: instead of
// mutating submit text, it mutates the script the generator reads, so every
// input is a submit file whose keywords and value shapes come from HTCondor's
// own keyword table. That is what gets the cron_*, grid, vm and container
// families to the comparison at all -- byte mutation never spells a valid cron
// field or grid resource.
//
// Run it with hack/submit-fuzz.sh FuzzSubmitGenerated.
func FuzzSubmitGenerated(f *testing.F) {
	requireOracle(f)
	v := genVocab(f)
	for _, s := range genSeeds {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > 4096 {
			t.Skip("oversized script; the generator caps the file anyway")
		}
		src := v.Generate(data)
		fresh, _, skip := check(t, src)
		if skip {
			return
		}
		for _, d := range fresh {
			t.Errorf("fresh divergence on generated file:\n%s\n  %s", src, d)
		}
	})
}

// TestGeneratedCorpusHasNoFreshDivergence sweeps a fixed, deterministic corpus
// of generated files. It is the regression half of the fuzz target: the inputs
// never change, so a new divergence here is a change in one of the two parsers
// rather than the fuzzer wandering somewhere new.
func TestGeneratedCorpusHasNoFreshDivergence(t *testing.T) {
	requireOracle(t)
	v := genVocab(t)

	// Report each distinct divergence once; a sweep this wide would otherwise
	// print the same finding hundreds of times.
	reported := map[string]bool{}
	for _, data := range generatedCorpus(600) {
		src := v.Generate(data)
		fresh, _, skip := check(t, src)
		if skip {
			continue
		}
		for _, d := range fresh {
			key := d.Attr + " " + d.Kind
			if reported[key] {
				continue
			}
			reported[key] = true
			t.Errorf("fresh divergence on generated file:\n%s\n  %s", src, d)
		}
	}
}

// TestGeneratedCorpusReachesTheOracle guards the generator itself: a change
// that made most files unparseable would hide every divergence while every
// test still passed. Acceptance is not expected to be total -- combinations
// like `should_transfer_files = NO` with a transfer_* keyword are rejected by
// design -- but it must stay well clear of zero.
func TestGeneratedCorpusReachesTheOracle(t *testing.T) {
	requireOracle(t)
	v := genVocab(t)

	corpus := generatedCorpus(400)
	accepted := 0
	for _, data := range corpus {
		if oracle.MakeAds(v.Generate(data), oracle.ModeAds, MaxProcs).OK {
			accepted++
		}
	}
	t.Logf("C++ accepted %d of %d generated files", accepted, len(corpus))
	if accepted*4 < len(corpus) {
		t.Errorf("only %d of %d generated files parse: the generator is emitting values HTCondor rejects",
			accepted, len(corpus))
	}
}

// TestGeneratedFilesAreDeterministic is the property a fuzz reproducer depends
// on: the same script must always produce the same submit file. Without it a
// failing input in testdata/ means nothing.
func TestGeneratedFilesAreDeterministic(t *testing.T) {
	requireOracle(t)
	v := genVocab(t)
	for _, data := range generatedCorpus(64) {
		first := v.Generate(data)
		for i := 0; i < 3; i++ {
			if got := v.Generate(data); got != first {
				t.Fatalf("generation is not deterministic for %x:\n%s\n---\n%s", data, first, got)
			}
		}
		if !strings.Contains(first, "\nqueue") {
			t.Errorf("generated file has no queue statement:\n%s", first)
		}
	}
}

// TestGeneratorSkipsRejectedKeywords pins the exclusions the vocabulary makes,
// so a keyword silently leaving the generator shows up as a test change.
func TestGeneratorSkipsRejectedKeywords(t *testing.T) {
	requireOracle(t)
	v := genVocab(t)
	for _, kw := range oracle.Keywords() {
		// f_error with f_alt_name is f_alt_err -- a usable alternate
		// spelling, not a disabled keyword -- so only the plain f_error ones
		// have to be absent.
		if kw.Opts&oracle.KeyError == 0 || kw.Opts&oracle.KeyAltName != 0 {
			continue
		}
		if _, skipped := v.Skipped[kw.Key]; !skipped {
			t.Errorf("%q is flagged f_error but is still in the generator vocabulary", kw.Key)
		}
	}
	for k, why := range v.Skipped {
		t.Logf("not generated: %s (%s)", k, why)
	}
}

// TestGeneratedDivergencesStillDiverge is knownDivergentGenerated's half of
// what TestKnownDivergencesStillDiverge does for the hand-written table: it
// reports which recorded findings the fixed sweep no longer reproduces, so a
// fix on the Go side shows up as an entry to delete rather than sitting in the
// table forever.
//
// It logs rather than fails. An entry can go quiet because the Go parser was
// fixed (delete it) or because the generator stopped producing the keyword
// that triggers it (a generator change, not a parser change), and only a human
// can tell those apart.
func TestGeneratedDivergencesStillDiverge(t *testing.T) {
	requireOracle(t)
	v := genVocab(t)

	seen := map[string]bool{}
	for _, data := range generatedCorpus(600) {
		_, s, skip := check(t, v.Generate(data))
		if skip {
			continue
		}
		for attr := range s {
			seen[attr] = true
		}
	}
	var quiet []string
	for attr := range knownDivergentGenerated {
		if !seen[attr] {
			quiet = append(quiet, attr)
		}
	}
	sort.Strings(quiet)
	t.Logf("%d of %d recorded divergences reproduced", len(knownDivergentGenerated)-len(quiet), len(knownDivergentGenerated))
	if len(quiet) > 0 {
		t.Logf("not reproduced by this sweep (check whether the Go parser was fixed): %v", quiet)
	}
}
