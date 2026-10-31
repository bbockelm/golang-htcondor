//go:build libcondor_utils

package fuzzsubmit

import (
	"strings"
	"testing"

	"github.com/bbockelm/golang-htcondor/fuzz/submit/oracle"
)

// derivedCase is one submit file and the attributes it is about.
type derivedCase struct {
	name  string
	src   string
	attrs []string
}

// TestDerivedAttributesMatchOracle covers the attributes condor_submit
// DERIVES rather than reads from a keyword, where a table-driven keyword
// comparison has nothing to compare.
//
// JobLeaseDuration needs a test of its own for a second reason: the main
// sweep cannot see it. C++ gives every job a JobLeaseDuration from
// JOB_DEFAULT_LEASE_DURATION and this parser does not, so the attribute is in
// knownDivergent and the comparison skips it entirely -- including on the
// files that DO name a lease, where the only difference left is the floor.
func TestDerivedAttributesMatchOracle(t *testing.T) {
	requireOracle(t)

	starter := []string{"JobStarterLog", "JobStarterDebug"}
	lease := []string{"JobLeaseDuration"}
	parallel := []string{"WantIOProxy", "JobRequiresSandbox"}
	nice := []string{"NiceUser", "AccountingGroup", "AcctGroup", "MaxJobRetirementTime"}

	for _, c := range []derivedCase{
		// starter_log with no starter_debug defaults the flags to the
		// pool's STARTER_DEBUG, which is what gets the file written.
		{"starter_log alone", "executable = /bin/sleep\nstarter_log = s.log\nqueue\n", starter},
		{"starter_log with starter_debug", "executable = /bin/sleep\nstarter_log = s.log\nstarter_debug = D_FULLDEBUG\nqueue\n", starter},
		// An empty starter_debug is "not set" to the keyword pass, so the
		// default still applies; an empty starter_log sets nothing at all.
		{"starter_debug empty", "executable = /bin/sleep\nstarter_log = s.log\nstarter_debug =\nqueue\n", starter},
		{"starter_log empty", "executable = /bin/sleep\nstarter_log =\nqueue\n", starter},
		{"starter_debug alone", "executable = /bin/sleep\nstarter_debug = D_ALWAYS\nqueue\n", starter},
		// The attribute's own name is the keyword's second spelling.
		{"JobStarterLog spelling", "executable = /bin/sleep\nJobStarterLog = s.log\nqueue\n", starter},
		// SetAutoAttributes runs BEFORE the +Attr pass, so a log that
		// arrived as +JobStarterLog derives nothing.
		{"plus JobStarterLog", "executable = /bin/sleep\n+JobStarterLog = \"s.log\"\nqueue\n", starter},

		// The 20-second floor, and the shapes that do not reach it.
		{"lease 5", "executable = /bin/sleep\njob_lease_duration = 5\nqueue\n", lease},
		{"lease 19", "executable = /bin/sleep\njob_lease_duration = 19\nqueue\n", lease},
		{"lease 20", "executable = /bin/sleep\njob_lease_duration = 20\nqueue\n", lease},
		{"lease 3600", "executable = /bin/sleep\njob_lease_duration = 3600\nqueue\n", lease},
		{"lease 0", "executable = /bin/sleep\njob_lease_duration = 0\nqueue\n", lease},
		{"lease negative", "executable = /bin/sleep\njob_lease_duration = -3\nqueue\n", lease},
		// A real is truncated toward zero before the range test: 19.9 is
		// 19 and is raised, 0.5 is 0 and is not.
		{"lease 19.9", "executable = /bin/sleep\njob_lease_duration = 19.9\nqueue\n", lease},
		{"lease 0.5", "executable = /bin/sleep\njob_lease_duration = 0.5\nqueue\n", lease},
		{"lease exponent", "executable = /bin/sleep\njob_lease_duration = 1e1\nqueue\n", lease},
		// A boolean counts as a number; a string does not, and neither
		// does anything built with an operator.
		{"lease true", "executable = /bin/sleep\njob_lease_duration = true\nqueue\n", lease},
		{"lease string", "executable = /bin/sleep\njob_lease_duration = \"5\"\nqueue\n", lease},
		{"lease expression", "executable = /bin/sleep\njob_lease_duration = 4 + 5\nqueue\n", lease},
		// Same ordering rule as JobStarterDebug: the check runs before
		// the +Attr pass.
		{"plus JobLeaseDuration", "executable = /bin/sleep\n+JobLeaseDuration = 5\nqueue\n", lease},

		// The parallel universe implies both; the `want_io_proxy` keyword
		// still overrides, and the MPI universe gets neither.
		{"parallel", "universe = parallel\nexecutable = /bin/sleep\nmachine_count = 2\nqueue\n", parallel},
		{"parallel no io proxy", "universe = parallel\nexecutable = /bin/sleep\nmachine_count = 2\nwant_io_proxy = false\nqueue\n", parallel},
		{"vanilla", "executable = /bin/sleep\nqueue\n", parallel},
		// The MPI universe is a universe of its own in condor_submit and
		// gets neither, although this parser maps the spelling onto
		// UniverseParallel. (The two sides do disagree about JobUniverse
		// itself for `universe = mpi`; that is a separate divergence and
		// is not what this case is about.)
		{"mpi", "universe = mpi\nexecutable = /bin/sleep\nmachine_count = 2\nqueue\n", parallel},

		// nice_user is a shorthand for an accounting group and nothing
		// else: no NiceUser attribute is written either way.
		{"nice_user true", "executable = /bin/sleep\nnice_user = true\nqueue\n", nice},
		{"nice_user false", "executable = /bin/sleep\nnice_user = false\nqueue\n", nice},
		{"nice_user with group", "executable = /bin/sleep\nnice_user = true\naccounting_group = Proj\nqueue\n", nice},
	} {
		t.Run(strings.ReplaceAll(c.name, " ", "_"), func(t *testing.T) {
			cpp := oracle.MakeAds(c.src, oracle.ModeAds, MaxProcs)
			if !cpp.OK {
				t.Fatalf("oracle rejected the file: %s", cpp.Err)
			}
			cppAds, err := ParseCanon(cpp.Ads)
			if err != nil {
				t.Fatalf("malformed oracle output: %v", err)
			}
			goRes := GoMakeAds(c.src)
			if !goRes.OK {
				t.Fatalf("Go parser rejected the file: %s", goRes.Err)
			}
			for _, key := range cppAds.Keys() {
				goAttrs, ok := goRes.Ads.ByKey[key]
				if !ok {
					t.Fatalf("Go produced no ad %s", key)
				}
				for _, attr := range c.attrs {
					cppVal, cppHas := lookupFold(cppAds.ByKey[key], attr)
					goVal, goHas := lookupFold(goAttrs, attr)
					switch {
					case cppHas != goHas:
						t.Errorf("%s %s: cpp present=%v (%s), go present=%v (%s)", key, attr, cppHas, cppVal, goHas, goVal)
					case cppHas && !sameValue(cppVal, goVal):
						t.Errorf("%s %s: cpp=%s go=%s", key, attr, cppVal, goVal)
					}
				}
			}
		})
	}
}

// TestScheddIntervalIsNotDerived pins the one entry in this slice that was
// deliberately left alone. condor_submit writes ScheddInterval only to feed
// the deferral clause of the Requirements it generates, which this parser
// does not generate, so the attribute stays absent on the Go side on
// purpose. If the Requirements work later adds that clause, this test is
// what says the attribute has to come with it.
func TestScheddIntervalIsNotDerived(t *testing.T) {
	requireOracle(t)

	for _, src := range []string{
		"executable = /bin/sleep\ncron_minute = 5\nqueue\n",
		"executable = /bin/sleep\ndeferral_time = 1700000000\nqueue\n",
	} {
		cpp := oracle.MakeAds(src, oracle.ModeAds, MaxProcs)
		if !cpp.OK {
			t.Fatalf("oracle rejected the file: %s", cpp.Err)
		}
		cppAds, err := ParseCanon(cpp.Ads)
		if err != nil {
			t.Fatalf("malformed oracle output: %v", err)
		}
		key := cppAds.Keys()[0]
		if _, has := lookupFold(cppAds.ByKey[key], "ScheddInterval"); !has {
			t.Errorf("%q: C++ no longer writes ScheddInterval; the reason recorded in knownDivergentGenerated is stale", firstLine(src))
		}
		goRes := GoMakeAds(src)
		if !goRes.OK {
			t.Fatalf("Go parser rejected the file: %s", goRes.Err)
		}
		if v, has := lookupFold(goRes.Ads.ByKey[key], "ScheddInterval"); has {
			t.Errorf("%q: Go now writes ScheddInterval=%s; it is only useful with the deferral clause of Requirements, so add that clause and promote this to a comparison", firstLine(src), v)
		}
	}
}
