//go:build libcondor_utils

package fuzzsubmit

import (
	"sort"
	"strings"
	"testing"

	"github.com/bbockelm/golang-htcondor/fuzz/submit/oracle"
)

// TestKeywordCoverage reports how much of HTCondor's own submit vocabulary the
// seed corpus exercises.
//
// The list comes from get_submit_keywords(), so it is the vocabulary of the
// parser actually linked, not a copy that silently falls behind upstream. The
// test reports rather than fails: coverage is a goal to work toward, and a new
// keyword appearing upstream should show up here, not break the build.
func TestKeywordCoverage(t *testing.T) {
	requireOracle(t)

	kws := oracle.Keywords()
	if len(kws) == 0 {
		t.Fatal("submit keyword table came back empty; the struct layout may have changed upstream")
	}

	corpus := strings.ToLower(strings.Join(seedInputs(), "\n"))
	var covered, missing []string
	for _, kw := range kws {
		if kw.Key == "" {
			continue
		}
		if strings.Contains(corpus, strings.ToLower(kw.Key)) {
			covered = append(covered, kw.Key)
		} else {
			missing = append(missing, kw.Key)
		}
	}
	sort.Strings(missing)

	t.Logf("submit keywords in this HTCondor: %d", len(kws))
	t.Logf("exercised by the seed corpus: %d", len(covered))
	t.Logf("not exercised: %d", len(missing))
	const show = 40
	if len(missing) > show {
		t.Logf("first %d unexercised: %v", show, missing[:show])
	} else {
		t.Logf("unexercised: %v", missing)
	}
}

// TestKeywordTypesAreKnown checks that every keyword's value type is one this
// package knows how to generate a value for. A new type bit upstream means the
// generator would emit the wrong shape of value for those keywords, which
// shows up as noise rather than findings.
func TestKeywordTypesAreKnown(t *testing.T) {
	requireOracle(t)

	const knownValueBits = oracle.KeyAsBool | oracle.KeyAsInt | oracle.KeyAsUint |
		oracle.KeyAsString | oracle.KeyAsList

	unknown := make(map[int][]string)
	for _, kw := range oracle.Keywords() {
		// Only the value-type group says what shape a value has; the modifier
		// bits above it (alternate spelling, disabled, file role) do not.
		if v := kw.Opts & oracle.KeyTypeMask; v&^knownValueBits != 0 {
			unknown[v&^knownValueBits] = append(unknown[v&^knownValueBits], kw.Key)
		}
	}
	for bits, keys := range unknown {
		t.Errorf("unknown value-type bits %#x on %d keyword(s), e.g. %v: teach the generator about them", bits, len(keys), keys[:min(3, len(keys))])
	}
}

func seedInputs() []string {
	out := make([]string, 0, len(seeds))
	for _, sc := range seeds {
		out = append(out, sc.input)
	}
	return out
}
