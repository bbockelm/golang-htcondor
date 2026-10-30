//go:build libcondor_utils

package fuzzsubmit

import (
	"strings"
	"testing"

	"github.com/bbockelm/golang-htcondor/fuzz/submit/oracle"
)

// seedCase is a hand-written submit file. When reason is empty, the Go and C++
// parsers are expected to AGREE on the ads (parity). When reason is non-empty,
// the case is a KNOWN divergence this fuzzer already surfaced: the test asserts
// it still diverges, so a fix flips the case and we get told to promote it to
// parity. See FINDINGS.md.
type seedCase struct {
	input  string
	reason string
}

// seeds double as the fuzz seed corpus. They are submit files, not arbitrary
// bytes: the fuzzer mutates from here, and starting at plausible syntax is what
// gets it past the first parse error into the semantics worth comparing.
var seeds = []seedCase{
	// --- parity ---
	{input: "executable = /bin/sleep\nrequest_cpus = 2\nrequest_memory = 512\narguments = x\nqueue\n"},
	{input: "executable = /bin/sleep\nrequest_cpus = 1\nrequest_memory = 128\narguments = $(Process)\nqueue 3\n"},
	{input: "executable = /bin/sleep\nrequest_cpus = 1\nrequest_memory = 128\narguments = a\nuniverse = vanilla\nqueue 2\n"},

	// --- known divergences (findings) ---
	{input: "executable = /bin/sleep\nqueue\n"},
	{input: "executable = /bin/sleep\narguments = $(Process)\nqueue 3\n"},
	{input: "executable = /bin/sleep\noutput = out.$(Process)\nerror = err.$(Process)\nlog = j.log\nqueue 2\n"},
	{input: "executable = /bin/sleep\nrequest_cpus = 1\nrequest_memory = 128\nqueue\n"},
	{input: "executable = /bin/sleep\nrequest_cpus = 1\nrequest_memory = 128\narguments = a\nqueue 2 in (a b)\n",
		reason: "proc count: `queue 2 in (a b)` is 2 jobs per item over 2 items = 4 procs in C++; Go makes 2."},
	{input: "executable = /bin/sleep\nqueue name in (alice bob)\n",
		reason: "space-separated inline item list: C++ accepts it, Go's parser requires commas and rejects the file."},
	{input: "executable = /bin/sleep\nqueue name from (\n  x\n  y\n)\n",
		reason: "inline `from ( ... )` item list: C++ accepts it, Go's parser rejects the open paren."},

	// --- parity, exercising specific commands ---
	{input: "executable = /bin/sleep\nrequest_cpus = 1\nrequest_memory = 128\narguments = a\nMY.Foo = 1\n+Bar = \"two\"\nqueue\n"},
	{input: "executable = /bin/sleep\nrequest_cpus = 1\nrequest_memory = 128\narguments = $(X)\nX = 7\nqueue\n"},
	{input: "executable = /bin/sleep\nrequest_cpus = 1\nrequest_memory = 128\narguments = a\nrequirements = (Memory > 1024)\nqueue\n"},
	{input: "executable = /bin/sleep\nrequest_cpus = 1\nrequest_memory = 128\narguments = a\nenvironment = \"A=1 B=2\"\nqueue\n"},
	{input: "executable = /bin/sleep\nrequest_cpus = 1\nrequest_memory = 128\narguments = a\ntransfer_input_files = a.txt, b.txt\nqueue\n"},
	{input: "executable = /bin/sleep\nrequest_cpus = 1\nrequest_memory = 128\narguments = a\nshould_transfer_files = YES\nwhen_to_transfer_output = ON_EXIT\nqueue\n"},
	{input: "executable = /bin/sleep\nrequest_cpus = 1\nrequest_memory = 128\narguments = a\npriority = 5\nqueue\n"},
	{input: "executable = /bin/sleep\nrequest_cpus = 1\nrequest_memory = 128\narguments = a\nperiodic_remove = (JobStatus == 5)\nqueue\n"},
	{input: "# just a comment\nexecutable = /bin/sleep\nrequest_cpus = 1\nrequest_memory = 128\narguments = a\nqueue\n"},
	// request_<tag> with no dedicated handling. request_A0 is the input
	// the fuzzer found the generic-request gap from.
	{input: "executable = /bin/sleep\nrequest_A0 = 3\nqueue\n"},
	{input: "executable = /bin/sleep\nrequest_licenses = 4\nrequest_my_thing = 5\nqueue\n"},
	{input: "executable = /bin/sleep\nrequest_slots = 2*2\nrequest_bandwidth = \"high\"\nqueue\n"},
	{input: "executable = /bin/sleep\nRequest_Foo = 5\nrequest_foo = 6\nqueue\n"},
	{input: "executable = /bin/sleep\nrequest_colors = undefined\nqueue\n"},
	{input: "executable = /bin/sleep\nrequest_f = 5\nrequest__foo = 6\nrequest_1 = 7\nqueue\n"},
	{input: "executable = /bin/sleep\nrequest_cpu = 2\nrequest_gpu = 2\nqueue\n"},
	{input: "executable = /bin/sleep\nrequest_gpus = 1\nrequest_gpus_memory = 100\nqueue\n"},
	{input: "executable = /bin/sleep\n+Requestfoo = 9\nrequest_foo = 3\nqueue\n"},
	{input: "executable = /bin/sleep\nrequest_shards = $(Process)+1\nqueue 2\n"},
	{input: "executable = /bin/sleep\nqueue 0\n"},
	{input: ""},
	{input: "queue\n"},
}

func requireOracle(t testing.TB) {
	if !oracle.Available {
		t.Skip("differential submit test needs the C++ oracle: `source hack/submit-fuzz-env.sh` then run with -tags libcondor_utils")
	}
}

// check runs one submit file through both parsers and returns the divergences
// that are neither host-derived nor already known, plus which known ones
// appeared. skip is true when the case is not comparable: the C++ side threw,
// or the two sides disagree about whether the file parses at all.
//
// Parse ACCEPTANCE is deliberately not asserted. The Go parser is stricter in
// places and more lenient in others, and a fuzzer finds those immediately and
// endlessly; what this target is for is the semantics of files both sides
// accept. Acceptance divergence is tracked separately by
// TestSeedParseAcceptance, which reports rather than fails.
func check(t testing.TB, src string) (fresh []Divergence, seenKnown map[string]bool, skip bool) {
	t.Helper()

	cpp := oracle.MakeAds(src, oracle.ModeAds, MaxProcs)
	if cpp.Panic {
		return nil, nil, true // a C++ exception is uncomparable, not a Go bug
	}
	goRes := GoMakeAds(src)
	if goRes.Panic {
		t.Fatalf("Go submit parser panicked on:\n%q", src)
	}
	if !cpp.OK || !goRes.OK {
		return nil, nil, true
	}

	cppAds, err := ParseCanon(cpp.Ads)
	if err != nil {
		t.Fatalf("malformed oracle output for %q: %v", src, err)
	}
	if cppAds.Truncated != goRes.Ads.Truncated {
		return nil, nil, true // one side capped the procs and the other did not
	}

	fresh, seenKnown = Compare(cppAds, goRes.Ads)
	return fresh, seenKnown, false
}

// TestSeedsHaveNoFreshDivergence is the parity assertion. A seed with no
// reason must produce no differences beyond hostDerived and knownDivergent; a
// seed WITH a reason must still differ somehow, so that fixing the Go side
// turns the case red and the finding gets promoted to parity.
func TestSeedsHaveNoFreshDivergence(t *testing.T) {
	requireOracle(t)
	for _, sc := range seeds {
		t.Run(strings.ReplaceAll(firstLine(sc.input), " ", "_"), func(t *testing.T) {
			fresh, _, skip := check(t, sc.input)
			if sc.reason != "" {
				if !skip && len(fresh) == 0 {
					t.Errorf("known divergence no longer reproduces -- promote it to parity and delete the reason:\n  %s", sc.reason)
				}
				for _, d := range fresh {
					t.Logf("known: %s", d)
				}
				return
			}
			if skip {
				t.Skip("not comparable (one side rejected the file)")
			}
			for _, d := range fresh {
				t.Errorf("fresh divergence: %s", d)
			}
		})
	}
}

// TestKnownDivergencesStillDiverge keeps the knownDivergent ATTRIBUTE table
// honest, the way the reason strings keep the seed table honest. Every entry
// listed here must still diverge; when one starts agreeing, the Go side was
// fixed and the entry should be deleted so the fix cannot silently regress.
func TestKnownDivergencesStillDiverge(t *testing.T) {
	requireOracle(t)

	seen := make(map[string]bool)
	for _, sc := range seeds {
		_, s, skip := check(t, sc.input)
		if skip {
			continue
		}
		for attr := range s {
			seen[attr] = true
		}
	}
	// Only attributes a basic submit file always produces are asserted; the
	// rest of the table depends on which commands a seed uses.
	for _, attr := range []string{"shouldtransferfiles", "requirements", "rank", "mytype", "targettype"} {
		if !seen[attr] {
			t.Errorf("%q no longer diverges from the C++ parser: delete it from knownDivergent so the fix is locked in", attr)
		}
	}
}

// TestSeedParseAcceptance reports, without failing, which seeds the two sides
// disagree about accepting. That disagreement is real and worth knowing, but it
// is a different question from whether the ads match, and failing on it would
// bury every semantic finding.
func TestSeedParseAcceptance(t *testing.T) {
	requireOracle(t)
	for _, sc := range seeds {
		cpp := oracle.MakeAds(sc.input, oracle.ModeAds, MaxProcs)
		goRes := GoMakeAds(sc.input)
		if cpp.Panic {
			t.Logf("C++ EXCEPTION on %q: %s", firstLine(sc.input), cpp.Err)
			continue
		}
		if cpp.OK != goRes.OK {
			t.Logf("acceptance differs on %q: cpp.ok=%v (%s) go.ok=%v (%s)",
				firstLine(sc.input), cpp.OK, cpp.Err, goRes.OK, goRes.Err)
		}
	}
}

// FuzzSubmitAds compares the job ads the two parsers build from the same submit
// file. Run it with hack/submit-fuzz.sh, which builds the test binary and runs
// it directly (go test's re-exec loses the oracle's library path on macOS).
func FuzzSubmitAds(f *testing.F) {
	requireOracle(f)
	for _, sc := range seeds {
		f.Add(sc.input)
	}
	f.Fuzz(func(t *testing.T, src string) {
		// The seeds that carry a reason are known divergences, kept in the
		// corpus so the fuzzer explores their syntax. The exact input is
		// skipped -- TestSeedsHaveNoFreshDivergence is what asserts those --
		// while every mutation of it is still compared.
		if knownDivergentSeed(src) {
			t.Skip("known divergent seed; see its reason in the seeds table")
		}
		// A submit file is text. Feeding the oracle arbitrary bytes tests the
		// lexers' handling of garbage, which the ClassAd and config fuzzers
		// already cover, and crowds out the semantic comparison this is for.
		if !isPlausibleSubmit(src) {
			t.Skip("not plausible submit text")
		}
		fresh, _, skip := check(t, src)
		if skip {
			return
		}
		for _, d := range fresh {
			t.Errorf("fresh divergence on:\n%s\n  %s", src, d)
		}
	})
}

// isPlausibleSubmit keeps the fuzzer on inputs that can reach the semantics:
// printable, bounded, and with a queue statement.
func isPlausibleSubmit(src string) bool {
	if len(src) == 0 || len(src) > 4096 {
		return false
	}
	for _, r := range src {
		if r == 0 || (r < 0x20 && r != '\n' && r != '\t' && r != '\r') || r > 0x7e {
			return false
		}
	}
	return strings.Contains(strings.ToLower(src), "queue")
}

func firstLine(s string) string {
	line, _, _ := strings.Cut(s, "\n")
	if line == "" {
		line = "(empty)"
	}
	if len(line) > 40 {
		line = line[:40]
	}
	return line
}

// knownDivergentSeed reports whether src is exactly one of the seeds recorded
// as a known divergence.
func knownDivergentSeed(src string) bool {
	for _, sc := range seeds {
		if sc.reason != "" && sc.input == src {
			return true
		}
	}
	return false
}
