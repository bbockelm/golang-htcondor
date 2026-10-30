package htcondor

import (
	"slices"
	"strings"
	"testing"

	"github.com/PelicanPlatform/classad/classad"
)

// These pin the client half of late materialization without the C++ oracle or
// a schedd, so CI sees a regression even where neither is available. The
// values they expect were taken from libcondor_utils 26.2.0 through
// fuzz/submit's oracle, which is where they are re-derived on every run that
// has it.

// parseFactory builds the factory for text as cluster 1, which is the
// cluster the oracle in fuzz/submit uses too, so a digest here and a digest
// there are comparable.
func parseFactory(t *testing.T, text string) *JobFactory {
	t.Helper()
	sf, err := ParseSubmitFile(strings.NewReader(text))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	f, err := sf.Factory(1)
	if err != nil {
		t.Fatalf("Factory: %v", err)
	}
	return f
}

// TestWantFactoryReadsEverySpelling checks the decision itself. All three
// keywords ask for a factory, and want_factory_submit reads them in this
// order, so an implementation that handled only the first would still pass a
// test that used only max_materialize.
func TestWantFactoryReadsEverySpelling(t *testing.T) {
	cases := []struct {
		keyword   string
		wantLimit int64
	}{
		// max_materialize names the limit outright.
		{"max_materialize", 7},
		// The max_idle spellings ask for a factory with no limit of their
		// own, which the clamp later turns into the job count.
		{"max_idle", 0},
		{"materialize_max_idle", 0},
		// The attribute spellings of the same two keywords.
		{"JobMaterializeLimit", 7},
		{"JobMaterializeMaxIdle", 0},
	}
	for _, c := range cases {
		t.Run(c.keyword, func(t *testing.T) {
			sf, err := ParseSubmitFile(strings.NewReader(
				"executable = /bin/sleep\n" + c.keyword + " = 7\nqueue 10\n"))
			if err != nil {
				t.Fatalf("parse: %v", err)
			}
			limit, want, err := sf.WantFactory()
			if err != nil {
				t.Fatalf("WantFactory: %v", err)
			}
			if !want {
				t.Fatalf("%s = 7 did not ask for a factory", c.keyword)
			}
			if limit != c.wantLimit {
				t.Errorf("limit = %d, want %d", limit, c.wantLimit)
			}
		})
	}
}

// TestNoMaterializeKeywordIsNotAFactory is the negative half: nothing else in
// a submit file turns it into a factory.
func TestNoMaterializeKeywordIsNotAFactory(t *testing.T) {
	sf, err := ParseSubmitFile(strings.NewReader("executable = /bin/sleep\nqueue 1000\n"))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if _, want, err := sf.WantFactory(); err != nil || want {
		t.Errorf("WantFactory = (%v, %v), want (false, nil)", want, err)
	}
	f, err := sf.Factory(1)
	if err != nil {
		t.Fatalf("Factory: %v", err)
	}
	if f != nil {
		t.Error("a file with no materialize keyword produced a factory")
	}
}

// TestFactoryLimitIsClamped pins condor_submit's clamp. An unspecified limit
// is not sent as INT_MAX; it is sent as the job count, so the schedd's view of
// the cluster matches the submitter's.
func TestFactoryLimitIsClamped(t *testing.T) {
	cases := []struct {
		name  string
		input string
		want  int
	}{
		{"unspecified becomes the job count", "executable = /bin/sleep\nmax_idle = 2\nqueue 5\n", 5},
		{"a limit above the job count comes down", "executable = /bin/sleep\nmax_materialize = 100\nqueue 4\n", 4},
		{"a limit below it is kept", "executable = /bin/sleep\nmax_materialize = 2\nqueue 5\n", 2},
		// Zero and below are not limits of zero: the clamp reads them as
		// "no limit named" before it sees the job count, exactly as a
		// missing max_materialize is read. Verified against the oracle --
		// a clamp that produced 1 here would materialize one job of five
		// and leave the rest waiting on a limit nobody asked for.
		{"zero means no limit named", "executable = /bin/sleep\nmax_materialize = 0\nqueue 5\n", 5},
		{"a negative limit means the same", "executable = /bin/sleep\nmax_materialize = -3\nqueue 5\n", 5},
		{"max_materialize wins over max_idle", "executable = /bin/sleep\nmax_materialize = 3\nmax_idle = 9\nqueue 10\n", 3},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			f := parseFactory(t, c.input)
			if f == nil {
				t.Fatal("no factory")
			}
			if f.MaxMaterialize != c.want {
				t.Errorf("MaxMaterialize = %d, want %d", f.MaxMaterialize, c.want)
			}
		})
	}
}

// TestFactoryRejectsAnUnparsableLimit checks that a value which is not an
// integer fails the submission rather than being read as "no factory".
// Silently ignoring it would submit a million jobs eagerly against a pool the
// submitter meant to throttle.
func TestFactoryRejectsAnUnparsableLimit(t *testing.T) {
	sf, err := ParseSubmitFile(strings.NewReader("executable = /bin/sleep\nmax_materialize = banana\nqueue 5\n"))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if _, _, err := sf.WantFactory(); err == nil {
		t.Error("max_materialize = banana was accepted")
	}
}

// TestDigestKeepsPerProcReferences is the property the whole feature rests
// on: the digest must not expand anything that varies per proc, because the
// schedd expands it once per job it materializes. A digest with the values
// baked in makes every job in the cluster a copy of the first.
func TestDigestKeepsPerProcReferences(t *testing.T) {
	f := parseFactory(t, "executable = /bin/sleep\n"+
		"arguments = $(item) $(Process)\n"+
		"output = out.$(item).$(ClusterId).$(Process)\n"+
		"request_memory = 128\n"+
		"getenv = true\n"+
		"requirements = (Memory > 32)\n"+
		"my.Thing = $(item)\n"+
		"max_idle = 5\n"+
		"queue item in (a b c)\n")
	if f == nil {
		t.Fatal("no factory")
	}

	// The body, before the queue statement is appended. Every line of it is
	// here on purpose: a key kept, a key pruned, a key omitted outright and
	// a reference left standing.
	const wantBody = "FACTORY.Requirements=MY.Requirements\n" +
		"arguments=$(item) $(Process)\n" +
		"my.Thing=$(item)\n" +
		"output=out.$(item).1.$(Process)\n"
	if got := f.body; got != wantBody {
		t.Errorf("digest body:\n got %q\nwant %q", got, wantBody)
	}

	digest, err := f.Digest("/spool/1/items")
	if err != nil {
		t.Fatalf("Digest: %v", err)
	}
	if !strings.HasSuffix(digest, "\nQueue 1 item from /spool/1/items\n") {
		t.Errorf("digest does not end with the queue statement the schedd iterates:\n%s", digest)
	}
}

// TestDigestPrunesWhatTheClusterAdAlreadyCarries pins the two halves of the
// pruning rule, which is what keeps a digest small.
func TestDigestPrunesWhatTheClusterAdAlreadyCarries(t *testing.T) {
	f := parseFactory(t, "executable = /bin/sleep\n"+
		"request_memory = 128\n"+ // prunable, nothing pending: dropped
		"my.Fixed = 5\n"+ // my. key, nothing pending: dropped
		"my.Varies = $(Process)\n"+ // my. key with a reference: kept
		"notification = never\n"+ // prunable: dropped
		"max_idle = 2\n"+
		"queue 4\n")
	if f == nil {
		t.Fatal("no factory")
	}
	for _, gone := range []string{"executable", "request_memory", "my.Fixed", "notification", "max_idle"} {
		if strings.Contains(f.body, gone+"=") {
			t.Errorf("digest keeps %s, whose effect the cluster ad already carries:\n%s", gone, f.body)
		}
	}
	if !strings.Contains(f.body, "my.Varies=$(Process)") {
		t.Errorf("digest dropped my.Varies, which varies per proc:\n%s", f.body)
	}
}

// TestDigestOmitsGetenvAndRequirements checks the keys that never appear
// whatever their value. getenv reads the submitting host's environment, which
// the schedd is not; requirements is replaced by the FACTORY.Requirements
// line because a Requirements rebuilt from a pruned digest would constrain
// the job differently from the one the submitter saw.
func TestDigestOmitsGetenvAndRequirements(t *testing.T) {
	f := parseFactory(t, "executable = /bin/sleep\n"+
		"getenv = $(Process)\n"+
		"requirements = (Memory > $(Process))\n"+
		"max_idle = 2\n"+
		"queue 4\n")
	if f == nil {
		t.Fatal("no factory")
	}
	// Both carry a pending expansion, so nothing but the omit list keeps
	// them out. The match is on a whole line: FACTORY.Requirements is in
	// the digest on purpose and a substring test would find it there.
	for _, gone := range []string{"getenv", "requirements"} {
		for _, line := range strings.Split(f.body, "\n") {
			if name, _, found := strings.Cut(line, "="); found && strings.EqualFold(name, gone) {
				t.Errorf("digest keeps %s:\n%s", gone, f.body)
			}
		}
	}
	if !strings.Contains(f.body, "FACTORY.Requirements=MY.Requirements") {
		t.Errorf("digest has no FACTORY.Requirements line:\n%s", f.body)
	}
}

// TestDigestOmitsOnlyTheNamedTransformBodies pins the narrow half of the
// on_evict_checks rule. Its transform bodies are left out of the digest
// because expanding the tag list and the bodies in step is not something the
// digest format supports -- but only the bodies whose tag the list names. A
// transform body nothing names is an ordinary key and belongs in the digest;
// dropping it would silently lose a transform the job asked for.
func TestDigestOmitsOnlyTheNamedTransformBodies(t *testing.T) {
	f := parseFactory(t, "executable = /bin/sleep\n"+
		"on_evict_checks = chk\n"+
		"transform_body_chk = SET Foo $(Process)\n"+
		"transform_body_other = SET Bar $(Process)\n"+
		"max_idle = 2\nqueue 3\n")
	if strings.Contains(f.body, "transform_body_chk") {
		t.Errorf("digest keeps the transform body on_evict_checks names:\n%s", f.body)
	}
	if strings.Contains(strings.ToLower(f.body), "on_evict_checks") {
		t.Errorf("digest keeps on_evict_checks:\n%s", f.body)
	}
	if !strings.Contains(f.body, "transform_body_other=SET Bar $(Process)") {
		t.Errorf("digest dropped a transform body no tag names:\n%s", f.body)
	}
}

// TestDigestDefinesItemWhenThereAreNoRows pins a detail that is easy to miss
// and impossible to guess: condor_submit reads the first row before it builds
// the digest, and reading from an empty list defines the macro Item as empty.
// Item is not a prunable keyword, so that empty definition lands in the
// digest. A digest without it is a different digest.
func TestDigestDefinesItemWhenThereAreNoRows(t *testing.T) {
	withRows := parseFactory(t, "executable = /bin/sleep\nmax_idle = 2\nqueue item in (a b)\n")
	withoutRows := parseFactory(t, "executable = /bin/sleep\nmax_idle = 2\nqueue 4\n")
	if strings.Contains(withRows.body, "Item=") {
		t.Errorf("a queue statement with rows should not define Item:\n%s", withRows.body)
	}
	if !strings.Contains(withoutRows.body, "Item=\n") {
		t.Errorf("a queue statement with no rows should define Item as empty:\n%s", withoutRows.body)
	}

	// The definition is an assignment, so it replaces a value the file gave
	// Item rather than deferring to it. Keeping "mine" here would hand the
	// schedd a macro the submitter's own jobs never saw.
	fileAssigned := parseFactory(t, "executable = /bin/sleep\nItem = mine\nmax_idle = 2\nqueue 3\n")
	if !strings.Contains(fileAssigned.body, "Item=\n") {
		t.Errorf("a file-assigned Item should be replaced by the empty definition:\n%s", fileAssigned.body)
	}
}

// TestItemdataRowEncoding pins the wire form of the itemdata.
func TestItemdataRowEncoding(t *testing.T) {
	t.Run("one variable passes the row through", func(t *testing.T) {
		f := parseFactory(t, "executable = /bin/sleep\nmax_idle = 2\nqueue item in (a, b, c)\n")
		want := []string{"a\n", "b\n", "c\n"}
		if got := f.Items; !slices.Equal(got, want) {
			t.Errorf("Items = %q, want %q", got, want)
		}
	})
	t.Run("two variables are joined with the unit separator", func(t *testing.T) {
		// The rows come from a file rather than an inline list because the
		// inline list splits on whitespace as well as commas, so
		// `in (1 2, 3 4)` is four rows of one field, not two rows of two.
		// That is HTCondor's own reading of it, checked against the oracle.
		f := parseFactory(t, "executable = /bin/sleep\nmax_idle = 2\nqueue a,b from (1 2\n3 4\n)\n")
		want := []string{"1\x1f2\n", "3\x1f4\n"}
		if got := f.Items; !slices.Equal(got, want) {
			t.Errorf("Items = %q, want %q", got, want)
		}
	})
	t.Run("an inline list splits on whitespace too", func(t *testing.T) {
		f := parseFactory(t, "executable = /bin/sleep\nmax_idle = 2\nqueue a,b in (1 2, 3 4)\n")
		want := []string{"1\x1f\n", "2\x1f\n", "3\x1f\n", "4\x1f\n"}
		if got := f.Items; !slices.Equal(got, want) {
			t.Errorf("Items = %q, want %q", got, want)
		}
	})
	t.Run("a row that already uses the separator is left alone", func(t *testing.T) {
		f := parseFactory(t, "executable = /bin/sleep\nmax_idle = 2\nqueue a,b in (1\x1f2)\n")
		want := []string{"1\x1f2\n"}
		if got := f.Items; !slices.Equal(got, want) {
			t.Errorf("Items = %q, want %q", got, want)
		}
	})
	t.Run("a count has no rows", func(t *testing.T) {
		f := parseFactory(t, "executable = /bin/sleep\nmax_idle = 2\nqueue 5\n")
		if len(f.Items) != 0 {
			t.Errorf("Items = %q, want none", f.Items)
		}
	})
}

// TestFactoryQueueStatement pins the statement the schedd iterates, which is
// what tells it how many jobs to make and where the rows are.
func TestFactoryQueueStatement(t *testing.T) {
	cases := []struct {
		name      string
		input     string
		itemsFile string
		want      string
	}{
		{"a bare count", "executable = /bin/sleep\nmax_idle = 2\nqueue 5\n", "", "\nQueue 5 \n"},
		{"one loop variable", "executable = /bin/sleep\nmax_idle = 2\nqueue item in (a b)\n", "/s/items", "\nQueue 1 item from /s/items\n"},
		{"two loop variables", "executable = /bin/sleep\nmax_idle = 2\nqueue a,b in (1 2)\n", "/s/items", "\nQueue 1 a,b from /s/items\n"},
		{"a count over rows", "executable = /bin/sleep\nmax_idle = 2\nqueue 2 item in (a b)\n", "/s/items", "\nQueue 2 item from /s/items\n"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			f := parseFactory(t, c.input)
			digest, err := f.Digest(c.itemsFile)
			if err != nil {
				t.Fatalf("Digest: %v", err)
			}
			if !strings.HasSuffix(digest, c.want) {
				t.Errorf("digest ends %q, want it to end %q", lastLines(digest, 2), c.want)
			}
		})
	}
}

// TestDigestRejectsAnItemsFilenameMismatch pins the guard. A digest built for
// rows but naming no file says "Queue 1 item", which the schedd reads as one
// job with no row rather than one job per row -- the whole cluster quietly
// wrong. The caller has to be told instead.
func TestDigestRejectsAnItemsFilenameMismatch(t *testing.T) {
	withRows := parseFactory(t, "executable = /bin/sleep\nmax_idle = 2\nqueue item in (a b)\n")
	if _, err := withRows.Digest(""); err == nil {
		t.Error("a factory with rows accepted an empty itemdata filename")
	}
	withoutRows := parseFactory(t, "executable = /bin/sleep\nmax_idle = 2\nqueue 3\n")
	if _, err := withoutRows.Digest("/spool/1/items"); err == nil {
		t.Error("a factory with no rows accepted an itemdata filename")
	}
}

// TestSubmitLateSendsNoProcAds is the behavioral difference the feature is
// for: a factory submission sends a cluster ad and a digest, not one ad per
// job. Materializing them here would be the old behavior under a new name.
func TestSubmitLateSendsNoProcAds(t *testing.T) {
	sf, err := ParseSubmitFile(strings.NewReader("executable = /bin/sleep\nmax_idle = 2\nqueue 1000\n"))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	res, err := sf.SubmitLate(1)
	if err != nil {
		t.Fatalf("SubmitLate: %v", err)
	}
	if res.Factory == nil {
		t.Fatal("max_idle did not produce a factory")
	}
	if len(res.ProcAds) != 0 {
		t.Errorf("SubmitLate built %d proc ads; a factory submission sends none", len(res.ProcAds))
	}
	if res.ClusterAd == nil {
		t.Error("no cluster ad: the schedd chains every proc it materializes to it")
	}
	if res.NumProcs != 1000 {
		t.Errorf("NumProcs = %d, want 1000", res.NumProcs)
	}
}

// TestReadCapabilitiesLateMaterialize pins how the schedd's capability ad is
// read, including the case a boolean alone cannot express: a schedd too old
// to mention late materialization at all.
func TestReadCapabilitiesLateMaterialize(t *testing.T) {
	cases := []struct {
		name      string
		ad        string
		wantAllow bool
		wantVer   int
		wantKnown bool
	}{
		{"a modern schedd", `[LateMaterialize = true; LateMaterializeVersion = 2]`, true, 2, true},
		{"late materialization switched off", `[LateMaterialize = false; LateMaterializeVersion = 2]`, false, 2, true},
		{"known but no version", `[LateMaterialize = true]`, true, 1, true},
		{"a version too high to mean anything", `[LateMaterialize = true; LateMaterializeVersion = 999]`, true, 1, true},
		{"a schedd too old to know the feature", `[UseJobsets = false]`, false, 0, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			ad, err := classad.Parse(c.ad)
			if err != nil {
				t.Fatalf("parse capability ad: %v", err)
			}
			q := &QmgmtConnection{}
			q.readCapabilities(ad)
			if got := q.AllowsLateMaterialize(); got != c.wantAllow {
				t.Errorf("AllowsLateMaterialize = %v, want %v", got, c.wantAllow)
			}
			ver, known := q.LateMaterializeVersion()
			if ver != c.wantVer || known != c.wantKnown {
				t.Errorf("LateMaterializeVersion = (%d, %v), want (%d, %v)", ver, known, c.wantVer, c.wantKnown)
			}
		})
	}
}

func lastLines(s string, n int) string {
	lines := strings.Split(strings.TrimSuffix(s, "\n"), "\n")
	if len(lines) > n {
		lines = lines[len(lines)-n:]
	}
	return strings.Join(lines, "\n") + "\n"
}
