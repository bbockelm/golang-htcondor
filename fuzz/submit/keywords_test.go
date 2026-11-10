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

	seedCorpus := strings.ToLower(strings.Join(seedInputs(), "\n"))

	// The generator's reach is measured over the same fixed corpus the
	// regression sweep uses, so this number is reproducible rather than a
	// function of how long the fuzzer last ran.
	v := genVocab(t)
	var gen strings.Builder
	for _, data := range generatedCorpus(2000) {
		gen.WriteString(strings.ToLower(v.Generate(data)))
		gen.WriteByte('\n')
	}
	genCorpus := gen.String()

	var seedCovered, bothCovered, missing []string
	for _, kw := range kws {
		if kw.Key == "" {
			continue
		}
		k := strings.ToLower(kw.Key)
		inSeed := strings.Contains(seedCorpus, k)
		if inSeed {
			seedCovered = append(seedCovered, kw.Key)
		}
		if inSeed || strings.Contains(genCorpus, k) {
			bothCovered = append(bothCovered, kw.Key)
		} else {
			missing = append(missing, kw.Key)
		}
	}
	sort.Strings(missing)

	t.Logf("submit keywords in this HTCondor: %d", len(kws))
	t.Logf("exercised by the seed corpus: %d", len(seedCovered))
	t.Logf("exercised by seeds + generator: %d", len(bothCovered))
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

// pathKeywords is the f_filemask half of HTCondor's path resolution: the
// keywords whose table entry carries a file role, which do_simple_commands
// runs through full_path so the job ad records an absolute path.
//
// It is a short list because the mask is NOT how most path-valued keywords
// are marked. The cloud credential and data files -- gce_auth_file,
// azure_auth_file, ec2_user_data_file and the rest -- carry no mask at all;
// SetGridParams calls full_path on each of them by hand, and reading the
// mask would say they are ordinary strings. The two mechanisms have to be
// ported separately, so this test can only guard the one that is a table.
//
// The value says what the Go parser does with each, and the test fails when
// a keyword appears upstream that is in neither state. A new f_filemask
// keyword that Go silently stored as written would otherwise only show up
// as a value divergence under an attribute name nobody was looking at.
var pathKeywords = map[string]string{
	"executable":       "resolved by resolveExecutable, against the SUBMITTING directory rather than Iwd: the entry is f_special, so it never reaches do_simple_commands",
	"log":              "resolved against Iwd by setStandardFiles",
	"dagman_log":       "not implemented by the Go parser; see knownDivergentGenerated[dagmannodeslog]",
	"output_directory": "not implemented by the Go parser; see knownDivergentGenerated[outputdirectory]",
	"starter_log":      "resolved against Iwd by the simple-keyword pass, which also derives JobStarterDebug from it",
}

func TestFileRoleKeywordsAreAccountedFor(t *testing.T) {
	requireOracle(t)

	for _, kw := range oracle.Keywords() {
		if kw.Opts&oracle.KeyFileMask == 0 {
			continue
		}
		key := strings.ToLower(kw.Key)
		if _, known := pathKeywords[key]; !known {
			t.Errorf("submit keyword %q (attribute %s) carries a file role (%#x) and nothing here says what the Go parser does with it: SubmitHash resolves it against Iwd, so decide whether the Go parser does too and record it in pathKeywords",
				kw.Key, kw.Attr, kw.Opts&oracle.KeyFileMask)
		}
	}
}
