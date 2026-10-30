//go:build libcondor_utils

package fuzzsubmit

import (
	"slices"
	"sort"
	"strings"
	"testing"

	htcondor "github.com/bbockelm/golang-htcondor"
	"github.com/bbockelm/golang-htcondor/fuzz/submit/oracle"
)

// factorySeeds are submit files that make condor_submit use late
// materialization. Each of the three spellings that trigger it is covered,
// because want_factory_submit checks them in order and an implementation that
// handles only max_materialize would still pass on the first.
var factorySeeds = []struct {
	name  string
	input string
}{
	{"max_materialize", "executable = /bin/sleep\nmax_materialize = 2\nqueue 5\n"},
	{"max_idle", "executable = /bin/sleep\nmax_idle = 5\nqueue 5\n"},
	{"materialize_max_idle", "executable = /bin/sleep\nmaterialize_max_idle = 3\nqueue 5\n"},
	{"max_idle with items", "executable = /bin/sleep\narguments = $(item)\nmax_idle = 5\nqueue item in (a b c)\n"},

	// Everything below exercises make_digest rather than the decision: what
	// it prunes, what it expands now and what it leaves for the schedd.
	{"pruning and expansion", "executable = /bin/sleep\n" +
		"arguments = $(item) $(Process)\n" +
		"output = out.$(item).$(ClusterId).$(Process)\n" +
		"request_memory = 128\n" +
		"getenv = true\n" +
		"requirements = (Memory > 32)\n" +
		"my.Thing = $(item)\n" +
		"max_idle = 5\n" +
		"queue item in (a b c)\n"},
	// A my. key with nothing pending is pruned; one with a reference is not.
	{"my keys", "executable = /bin/sleep\nmy.Fixed = 5\nmy.Varies = $(Process)\nmax_idle = 2\nqueue 4\n"},
	// +Attr is the same macro under its canonical spelling.
	{"plus attribute", "executable = /bin/sleep\n+Note = \"p$(Process)\"\n+Fixed = 3\nmax_idle = 2\nqueue 4\n"},
	// Keys are written out in the macro table's order, which is the sorted
	// one -- not the order the file wrote them, and not case-sensitive.
	{"key order", "executable = /bin/sleep\nZebra = $(Process)\nalpha = $(Process)\nBETA = $(Process)\nmax_idle = 2\nqueue 3\n"},
	// initialdir is resolved against the submitting directory before it goes
	// in the digest; the schedd's working directory is not the submitter's.
	{"initialdir", "executable = /bin/sleep\ninitialdir = somewhere\narguments = $(Process)\nmax_idle = 2\nqueue 3\n"},
	{"absolute initialdir", "executable = /bin/sleep\ninitialdir = /tmp/sub\narguments = $(Process)\nmax_idle = 2\nqueue 3\n"},
	// A reference to a knob the submit file defines is expanded now; one to
	// a per-proc knob through it is not.
	{"indirect reference", "executable = /bin/sleep\nbase = /data\narguments = $(base)/$(Process)\nmax_idle = 2\nqueue 3\n"},
	// Macro functions: $BASENAME over a settled knob is evaluated, over a
	// per-proc one it cannot be.
	{"macro functions", "executable = /bin/sleep\npath = /a/b/c.txt\nargs_a = $BASENAME(path)\nargs_b = $BASENAME(Item)\nmax_idle = 2\nqueue item in (x y)\n"},
	// $(DOLLAR) is always left for the schedd.
	{"dollar", "executable = /bin/sleep\narguments = $(DOLLAR)(Process)\nmax_idle = 2\nqueue 3\n"},
	// $$(...) is a machine-ad reference the starter expands, not a macro.
	{"double dollar", "executable = /bin/sleep\narguments = $$(OpSys) $(Process)\nmax_idle = 2\nqueue 3\n"},
	// Two loop variables: the rows go on the wire with their fields joined
	// by the unit separator.
	{"two vars", "executable = /bin/sleep\narguments = $(a) $(b)\nmax_idle = 2\nqueue a,b from (1 2\n3 4\n)\n"},
	// A multi-line value is written back in the @=end block form.
	{"multiline value", "executable = /bin/sleep\nmy.Block @=end\n1 +\n$(Process)\n@end\nmax_idle = 2\nqueue 3\n"},
	// A universe the file names stays; the keyword is not prunable.
	{"universe", "universe = vanilla\nexecutable = /bin/sleep\narguments = $(Process)\nmax_idle = 2\nqueue 3\n"},
	// max_materialize wins over max_idle, and both reach the digest.
	{"both limits", "executable = /bin/sleep\nmax_materialize = 3\nmax_idle = 2\narguments = $(Process)\nqueue 10\n"},
	// The limit is clamped down to the job count.
	{"limit above job count", "executable = /bin/sleep\nmax_materialize = 100\nqueue 4\n"},
	// queue N over a list makes N jobs per row.
	{"count over items", "executable = /bin/sleep\narguments = $(item) $(Step)\nmax_idle = 2\nqueue 2 item in (a b)\n"},
	// A limit of zero or below is not a limit of zero: it reads as "no
	// limit named", and the clamp turns it into the job count.
	{"zero limit", "executable = /bin/sleep\nmax_materialize = 0\nqueue 5\n"},
	{"negative limit", "executable = /bin/sleep\nmax_materialize = -3\nqueue 5\n"},
	// The inline item list splits on whitespace as well as commas, so this
	// is four rows of one field, not two rows of two.
	{"inline list with two vars", "executable = /bin/sleep\narguments = $(a) $(b)\nmax_idle = 2\nqueue a,b in (1 2, 3 4)\n"},
	// $(ItemIndex) is not a macro either side defines while the digest is
	// being built, so both expand it to nothing. It is here because the Go
	// side DOES define it once a job ad is built, which makes this the seed
	// that fails if the digest is ever built after the first row goes live.
	{"itemindex", "executable = /bin/sleep\noutput = o.$(ItemIndex).$(Process)\nmax_idle = 2\nqueue item in (alpha beta)\n"},
	// on_evict_checks and the transform bodies its tags name are left out
	// of the digest; a transform body no tag names is not.
	{"on_evict_checks", "executable = /bin/sleep\non_evict_checks = chk\ntransform_body_chk = SET Foo $(Process)\nmax_idle = 2\nqueue 3\n"},
	{"unreferenced transform body", "executable = /bin/sleep\ntransform_body_other = SET Foo $(Process)\nmax_idle = 2\nqueue 3\n"},
}

// TestFactoryOracleReportsLateMaterialization pins what the C++ side decides,
// so the Go comparison below has something to be measured against.
func TestFactoryOracleReportsLateMaterialization(t *testing.T) {
	requireOracle(t)

	for _, fs := range factorySeeds {
		t.Run(fs.name, func(t *testing.T) {
			fi := oracle.Factory(fs.input, MaxProcs, "items.txt")
			if !fi.OK {
				t.Fatalf("oracle rejected %q: %s", fs.input, fi.Err)
			}
			if !fi.Factory {
				t.Errorf("want_factory_submit said no for a file setting %s", fs.name)
			}
			if fi.MaxMaterialize <= 0 {
				t.Errorf("max_materialize = %d, want a positive limit", fi.MaxMaterialize)
			}
			if fi.Digest == "" {
				t.Error("empty submit digest: the schedd would have nothing to expand")
			}
			// The digest must keep macro references unexpanded, or the schedd
			// cannot vary them per proc.
			if strings.Contains(fs.input, "$(item)") && !strings.Contains(fi.Digest, "$(item)") {
				t.Errorf("digest expanded $(item) instead of leaving it for the schedd:\n%s", fi.Digest)
			}
			t.Logf("factory=%v max_materialize=%d vars=%v items=%v",
				fi.Factory, fi.MaxMaterialize, fi.Vars, fi.Items)
		})
	}
}

// spooledItems stands in for the path the schedd reports after it spools the
// itemdata. Both sides are told the same one, so the queue statement at the
// end of the digest is comparable without a schedd.
const spooledItems = "/var/lib/condor/spool/1/condor_submit.1.items"

// TestGoLateMaterializationMatchesCondorSubmit compares what the Go submit
// path sends for a factory submission against what condor_submit sends: the
// decision, the materialize limit, the loop variables, the itemdata rows and
// the submit digest, byte for byte.
//
// The digest is the part that has to be exact. The schedd parses it with the
// same submit parser it would use on the file, and every proc the factory
// materializes comes out of it -- so a digest that differs is not a cosmetic
// difference, it is every job in the cluster being a different job.
func TestGoLateMaterializationMatchesCondorSubmit(t *testing.T) {
	requireOracle(t)

	for _, fs := range factorySeeds {
		t.Run(fs.name, func(t *testing.T) {
			fi := oracle.Factory(fs.input, MaxProcs, spooledItems)
			if !fi.OK {
				t.Fatalf("oracle rejected %q: %s", fs.input, fi.Err)
			}

			sf, err := htcondor.ParseSubmitFile(strings.NewReader(fs.input))
			if err != nil {
				t.Fatalf("Go parser rejected the file: %v", err)
			}
			res, err := sf.SubmitLate(ClusterID)
			if err != nil {
				t.Fatalf("SubmitLate failed: %v", err)
			}

			if (res.Factory != nil) != fi.Factory {
				t.Fatalf("factory decision: go=%v cpp=%v", res.Factory != nil, fi.Factory)
			}
			if res.Factory == nil {
				return
			}
			// A factory submission sends no proc ads at all.
			if len(res.ProcAds) != 0 {
				t.Errorf("Go materialized %d proc ads; a factory submission sends none", len(res.ProcAds))
			}
			if res.ClusterAd == nil {
				t.Error("no cluster ad: the schedd chains every materialized proc to it")
			}

			f := res.Factory
			if int64(f.MaxMaterialize) != fi.MaxMaterialize {
				t.Errorf("max_materialize: go=%d cpp=%d", f.MaxMaterialize, fi.MaxMaterialize)
			}
			if int64(f.TotalProcs) != fi.TotalProcs {
				t.Errorf("total procs: go=%d cpp=%d", f.TotalProcs, fi.TotalProcs)
			}
			if strings.Join(f.Vars, ",") != strings.Join(fi.Vars, ",") {
				t.Errorf("loop variables: go=%v cpp=%v", f.Vars, fi.Vars)
			}

			// The oracle reports each row without its newline, which every
			// row carries on the wire.
			gotRows := make([]string, 0, len(f.Items))
			for _, row := range f.Items {
				if !strings.HasSuffix(row, "\n") {
					t.Errorf("itemdata row %q is not newline terminated", row)
				}
				gotRows = append(gotRows, strings.TrimSuffix(row, "\n"))
			}
			if !slices.Equal(gotRows, fi.Items) {
				t.Errorf("itemdata rows:\n go=%q\ncpp=%q", gotRows, fi.Items)
			}

			itemsFile := ""
			if len(f.Items) > 0 {
				itemsFile = spooledItems
			}
			if got := f.Digest(itemsFile); got != fi.Digest {
				t.Errorf("submit digest differs\n--- go ---\n%s\n--- cpp ---\n%s", got, fi.Digest)
			}
		})
	}
}

// TestNonFactorySubmitLateStillMaterializes checks the other half of
// SubmitLate's contract: a file that never asked for late materialization is
// submitted the way it always was, with one proc ad per job. Making the
// factory path unconditional would silently change every existing caller.
func TestNonFactorySubmitLateStillMaterializes(t *testing.T) {
	sf, err := htcondor.ParseSubmitFile(strings.NewReader("executable = /bin/sleep\nqueue 3\n"))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	res, err := sf.SubmitLate(ClusterID)
	if err != nil {
		t.Fatalf("SubmitLate failed: %v", err)
	}
	if res.Factory != nil {
		t.Error("a file with no materialize keyword was submitted as a factory")
	}
	if len(res.ProcAds) != 3 {
		t.Errorf("got %d proc ads, want 3", len(res.ProcAds))
	}
}

// TestDigestKeywordsMatchOracle guards the generated prunable-keyword table
// in the root package against drift: an upstream keyword this does not know
// about would be left in the digest where condor_submit prunes it, or pruned
// where condor_submit keeps it.
func TestDigestKeywordsMatchOracle(t *testing.T) {
	requireOracle(t)

	want := map[string]bool{}
	for _, kw := range oracle.Keywords() {
		if kw.Key != "" {
			want[strings.ToLower(kw.Key)] = true
		}
		if kw.Attr != "" {
			want[strings.ToLower(kw.Attr)] = true
		}
	}
	if len(want) == 0 {
		t.Fatal("the oracle returned no keywords")
	}

	var missing, extra []string
	for name := range want {
		if !htcondor.DigestKeywordIsPrunable(name) {
			missing = append(missing, name)
		}
	}
	for _, name := range htcondor.DigestPrunableKeywordNames() {
		if !want[name] {
			extra = append(extra, name)
		}
	}
	sort.Strings(missing)
	sort.Strings(extra)
	if len(missing) > 0 {
		t.Errorf("%d keywords HTCondor prunes that Go does not: %v", len(missing), missing)
	}
	if len(extra) > 0 {
		t.Errorf("%d keywords Go prunes that HTCondor does not: %v", len(extra), extra)
	}
}

// TestFactoryAttributesReachTheClusterAd checks the part of late
// materialization that does not need the factory path at all: max_idle and
// max_materialize are ordinary submit keywords that set JobMaterializeMaxIdle
// and JobMaterializeLimit on the cluster ad. Whether or not Go implements
// factories, it should carry these through.
func TestFactoryAttributesReachTheClusterAd(t *testing.T) {
	requireOracle(t)

	// max_materialize is deliberately absent: it never becomes an ad
	// attribute. want_factory_submit reads it and condor_submit passes it to
	// set_Factory(), so there is nothing on the ad to compare. Verified
	// against the oracle, which emits no JobMaterialize* for it.
	cases := []struct {
		input string
		attr  string
	}{
		{"executable = /bin/sleep\nmax_idle = 5\nqueue\n", "JobMaterializeMaxIdle"},
		{"executable = /bin/sleep\nmaterialize_max_idle = 3\nqueue\n", "JobMaterializeMaxIdle"},
	}
	for _, c := range cases {
		t.Run(strings.ReplaceAll(firstLine(c.input), " ", "_")+"_"+c.attr, func(t *testing.T) {
			cpp := oracle.MakeAds(c.input, oracle.ModeAds, MaxProcs)
			if !cpp.OK {
				t.Fatalf("oracle rejected the file: %s", cpp.Err)
			}
			cppAds, err := ParseCanon(cpp.Ads)
			if err != nil {
				t.Fatalf("malformed oracle output: %v", err)
			}
			if _, ok := lookupFold(cppAds.ByKey[AdKey{Cluster: ClusterID, Proc: 0}], c.attr); !ok {
				t.Fatalf("the C++ parser does not set %s either, so there is nothing to compare", c.attr)
			}

			goRes := GoMakeAds(c.input)
			if !goRes.OK {
				t.Fatalf("Go parser rejected the file: %s", goRes.Err)
			}
			attrs, ok := goRes.Ads.ByKey[AdKey{Cluster: ClusterID, Proc: 0}]
			if !ok {
				t.Fatal("Go produced no proc 0 ad")
			}
			cppVal, _ := lookupFold(cppAds.ByKey[AdKey{Cluster: ClusterID, Proc: 0}], c.attr)
			goVal, present := lookupFold(attrs, c.attr)
			if !present {
				t.Fatalf("Go drops %s, so nothing records that the file asked to be throttled", c.attr)
			}
			if !sameValue(cppVal, goVal) {
				t.Errorf("%s: cpp=%s go=%s", c.attr, cppVal, goVal)
			}
		})
	}
}
