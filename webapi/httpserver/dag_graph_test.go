package httpserver

import (
	"archive/tar"
	"bytes"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/PelicanPlatform/classad/classad"
	"github.com/bbockelm/golang-htcondor/webapi/dagman"
)

// adFrom builds a job ad from old-format text, which is how the schedd
// hands one over and the shortest way to write one here.
func adFrom(t *testing.T, text string) *classad.ClassAd {
	t.Helper()
	ad, err := classad.ParseOld(text)
	if err != nil {
		t.Fatalf("parse ad: %v", err)
	}
	return ad
}

// --- the -Dag argument ------------------------------------------------

func TestSplitArgsV2(t *testing.T) {
	cases := []struct {
		name string
		raw  string
		want []string
	}{
		{"plain", "-f -l . -Dag workflow.dag", []string{"-f", "-l", ".", "-Dag", "workflow.dag"}},
		{"quoted run", "-Dag 'my workflow.dag' -MaxIdle 5",
			[]string{"-Dag", "my workflow.dag", "-MaxIdle", "5"}},
		{"doubled quote", "-Dag 'it''s.dag'", []string{"-Dag", "it's.dag"}},
		{"extra spaces", "  -f   -Dag  a.dag ", []string{"-f", "-Dag", "a.dag"}},
		{"empty", "", nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := splitArgsV2(tc.raw)
			if strings.Join(got, "|") != strings.Join(tc.want, "|") {
				t.Errorf("splitArgsV2(%q) = %v, want %v", tc.raw, got, tc.want)
			}
		})
	}
}

func TestDagFileFromAd(t *testing.T) {
	cases := []struct {
		name string
		ad   string
		want string
	}{
		{
			name: "Arguments V2",
			ad:   `Arguments = "-f -l . -Lockfile workflow.dag.lock -Dag workflow.dag -MaxIdle 10"`,
			want: "workflow.dag",
		},
		{
			name: "Arguments V2 with a quoted name",
			ad:   `Arguments = "-f -Dag 'my workflow.dag'"`,
			want: "my workflow.dag",
		},
		{
			name: "Args V1 fallback",
			ad:   `Args = "-f -l . -Lockfile old.dag.lock -Dag old.dag"`,
			want: "old.dag",
		},
		{
			name: "lower case spelling",
			ad:   `Arguments = "-f -dag lower.dag"`,
			want: "lower.dag",
		},
		{
			name: "a path is reduced to its basename, because a spool is flat",
			ad:   `Arguments = "-f -Dag /home/alice/work/deep.dag"`,
			want: "deep.dag",
		},
		{
			name: "both present, V2 wins",
			ad:   "Arguments = \"-Dag new.dag\"\nArgs = \"-Dag old.dag\"",
			want: "new.dag",
		},
		{
			name: "no -Dag at all",
			ad:   `Arguments = "-f -l ."`,
			want: "",
		},
		{
			name: "-Dag with nothing after it",
			ad:   `Arguments = "-f -Dag"`,
			want: "",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := dagFileFromAd(adFrom(t, tc.ad)); got != tc.want {
				t.Errorf("dagFileFromAd = %q, want %q", got, tc.want)
			}
		})
	}
}

// --- preconditions ----------------------------------------------------

func TestDagPreconditionNotASchedulerUniverseJob(t *testing.T) {
	ad := adFrom(t, "JobUniverse = 5\nIwd = \"/home/alice\"\n")
	dagFile, status, msg := dagPrecondition(ad, 42, 0)
	if status != http.StatusNotFound {
		t.Fatalf("status = %d, want %d", status, http.StatusNotFound)
	}
	if dagFile != "" {
		t.Errorf("dagFile = %q, want empty", dagFile)
	}
	if !strings.Contains(msg, "not a DAGMan workflow") || !strings.Contains(msg, "42.0") {
		t.Errorf("message does not explain what is wrong: %q", msg)
	}
	if strings.Contains(msg, "submitted from a shell") {
		t.Errorf("a universe-5 job got the shell-submission message: %q", msg)
	}
}

// TestDagPreconditionShellSubmittedWorkflow is the SUBMIT_Iwd check. A
// manager submitted with plain condor_submit_dag has its .dag in the
// user's home directory, which this server cannot read -- and saying
// "not found" for it would send the user looking for the wrong problem.
func TestDagPreconditionShellSubmittedWorkflow(t *testing.T) {
	ad := adFrom(t, `JobUniverse = 7
Iwd = "/home/alice/workflows"
Arguments = "-f -l . -Dag workflow.dag"
`)
	dagFile, status, msg := dagPrecondition(ad, 7, 0)
	if status != http.StatusConflict {
		t.Fatalf("status = %d, want %d (%q)", status, http.StatusConflict, msg)
	}
	if dagFile != "" {
		t.Errorf("dagFile = %q, want empty", dagFile)
	}
	if !strings.Contains(msg, "submitted from a shell on the access point") {
		t.Errorf("message does not explain the problem: %q", msg)
	}
	// The Iwd is another user's home directory, and this handler is
	// reachable against another user's job by a token caller, so the
	// path must not be echoed back. handleJobOutputFile draws the same
	// line.
	if strings.Contains(msg, "/home/alice") {
		t.Errorf("the 409 echoes the job's Iwd: %q", msg)
	}
}

func TestDagPreconditionEmptySubmitIwdIsAlsoUnspooled(t *testing.T) {
	ad := adFrom(t, `JobUniverse = 7
SUBMIT_Iwd = "   "
Iwd = "/home/bob"
Arguments = "-Dag w.dag"
`)
	_, status, msg := dagPrecondition(ad, 9, 0)
	if status != http.StatusConflict {
		t.Fatalf("a blank SUBMIT_Iwd must not count as spooled: status %d, %q", status, msg)
	}
}

func TestDagPreconditionSchedulerJobWithNoDagArgument(t *testing.T) {
	ad := adFrom(t, `JobUniverse = 7
SUBMIT_Iwd = "/home/alice/workflows"
Iwd = "/var/lib/condor/spool/42/0/cluster42.proc0.subproc0"
Arguments = "--serve /etc/thing.conf"
`)
	_, status, msg := dagPrecondition(ad, 42, 0)
	if status != http.StatusNotFound {
		t.Fatalf("status = %d, want %d", status, http.StatusNotFound)
	}
	if !strings.Contains(msg, "-Dag") {
		t.Errorf("message should name the missing argument: %q", msg)
	}
}

func TestDagPreconditionAccepts(t *testing.T) {
	ad := adFrom(t, `JobUniverse = 7
SUBMIT_Iwd = "/home/alice/workflows"
Iwd = "/var/lib/condor/spool/42/0/cluster42.proc0.subproc0"
Arguments = "-f -l . -Lockfile workflow.dag.lock -Dag workflow.dag"
`)
	dagFile, status, msg := dagPrecondition(ad, 42, 0)
	if status != 0 {
		t.Fatalf("a spooled DAGMan manager was refused: %d %q", status, msg)
	}
	if dagFile != "workflow.dag" {
		t.Errorf("dagFile = %q, want workflow.dag", dagFile)
	}
}

// --- the structure cache ----------------------------------------------

func testStructure(name string) *dagStructure {
	return &dagStructure{dagFile: name, dotFile: name, grouping: &dagman.Grouping{}, fetchedAt: time.Now()}
}

// testOwner is whose workflow the cache cases are about. Cases that
// need a second OWNER (rather than a second caller) build the value
// themselves, so the difference is visible where it matters.
const testOwner = "alice"

// ownedBy is a cache entry for a structure belonging to testOwner.
func ownedBy(key, name string) dagCacheEntry {
	return dagCacheEntry{key: key, owner: testOwner, value: testStructure(name)}
}

// accessAs is caller asking about testOwner's workflow.
func accessAs(caller string) dagCacheAccess {
	return dagCacheAccess{owner: testOwner, caller: caller}
}

func TestDagStructureCacheHit(t *testing.T) {
	c := newDagStructureCache(4, time.Hour)
	e := ownedBy("k", "a.dag")
	c.put(e)
	got, ok := c.get("k")
	if !ok || got.value != e.value {
		t.Fatalf("get after put = %v, %v", got, ok)
	}
	if _, ok := c.get("other"); ok {
		t.Errorf("an unrelated key hit the cache")
	}
}

// TestDagCacheEntryIsRefusedToAnotherUser is the authorization
// regression at the unit level, and it is about what a HIT skips.
//
// A miss ends in a whole-sandbox transfer, and the schedd is what
// refuses a transfer to a non-owner (UserCheck2, per job, on a
// WRITE-registered command). The ad read in front of it is not
// owner-checked for a token caller, because bulkOwnerScope only scopes a
// browser session. So a hit does not save work, it removes the check.
func TestDagCacheEntryIsRefusedToAnotherUser(t *testing.T) {
	entry := ownedBy("1234.0|w.dot", "w.dag")

	if !accessAs(testOwner).mayUse(entry) {
		t.Errorf("the owner may not read her own cached workflow")
	}
	if accessAs("bob").mayUse(entry) {
		t.Errorf("bob was served alice's cached workflow structure")
	}
	// A bearer token whose actor could not be resolved is nobody, and
	// nobody is not the owner.
	if accessAs("").mayUse(entry) {
		t.Errorf("an unidentified caller was served a cached workflow")
	}
	// An admin reads any user's job through the neighbouring handlers,
	// so the cache must not be the one place that breaks the admin view.
	admin := dagCacheAccess{owner: "alice", caller: "carol", admin: true}
	if !admin.mayUse(entry) {
		t.Errorf("a Web UI admin was refused a cached workflow")
	}
	// ...but not an entry that describes a DIFFERENT workflow, which is
	// what a recycled cluster id under the same key looks like.
	if (dagCacheAccess{owner: "dave", caller: "dave"}).mayUse(entry) {
		t.Errorf("an entry belonging to another owner was served under a recycled cluster id")
	}
	if (dagCacheAccess{owner: "dave", caller: "carol", admin: true}).mayUse(entry) {
		t.Errorf("an admin was served a recycled cluster id's stale entry")
	}
	// An entry with no owner recorded is usable by nobody: it predates
	// knowing, and guessing is what this test exists to prevent.
	if accessAs(testOwner).mayUse(dagCacheEntry{key: "k", value: testStructure("w.dag")}) {
		t.Errorf("an entry with no owner was served")
	}
}

// TestCachedDagStructureRefusesAnotherUsersHit is the same rule at the
// level that decides whether the transfer happens.
func TestCachedDagStructureRefusesAnotherUsersHit(t *testing.T) {
	c := newDagStructureCache(4, time.Hour)
	builds := 0
	build := func() (*dagStructure, error) {
		builds++
		st := testStructure("alice.dag")
		return st, nil
	}
	if _, err := cachedDagStructure(c, "k", accessAs(testOwner), false, build); err != nil {
		t.Fatalf("alice's own load: %v", err)
	}
	if builds != 1 {
		t.Fatalf("builds = %d, want 1", builds)
	}
	// Alice again: a hit, no transfer.
	if _, err := cachedDagStructure(c, "k", accessAs(testOwner), false, build); err != nil {
		t.Fatalf("alice's cached load: %v", err)
	}
	if builds != 1 {
		t.Fatalf("alice's second load re-fetched the sandbox (%d builds)", builds)
	}

	// Bob asks for the same workflow. He must NOT be served the cached
	// copy; he must fall through to a real transfer, which is where the
	// schedd refuses him.
	bobBuilt := false
	_, err := cachedDagStructure(c, "k", accessAs("bob"), false,
		func() (*dagStructure, error) {
			bobBuilt = true
			return nil, errors.New("SCHEDD: permission denied")
		})
	if err == nil {
		t.Fatalf("bob was served alice's workflow out of the cache")
	}
	if !bobBuilt {
		t.Errorf("bob never reached the transfer the schedd would have refused")
	}
	// ...and his refusal did not evict or poison alice's entry.
	if _, err := cachedDagStructure(c, "k", accessAs(testOwner), false, build); err != nil ||
		builds != 1 {
		t.Errorf("alice's entry did not survive bob's attempt: %v, %d builds", err, builds)
	}
}

// TestCachedDagStructureDoesNotShareAFlightWithAnotherUser: collapsing
// concurrent builds is a second way to be handed someone else's result,
// so it obeys the same rule.
func TestCachedDagStructureDoesNotShareAFlightWithAnotherUser(t *testing.T) {
	c := newDagStructureCache(4, time.Hour)
	release := make(chan struct{})
	started := make(chan struct{})
	var mu sync.Mutex
	builds := 0

	done := make(chan error, 1)
	go func() {
		_, err := cachedDagStructure(c, "k", accessAs(testOwner), false,
			func() (*dagStructure, error) {
				mu.Lock()
				builds++
				mu.Unlock()
				close(started)
				<-release
				return testStructure("alice.dag"), nil
			})
		done <- err
	}()
	<-started

	// Bob arrives while alice's transfer is in flight.
	bobBuilt := make(chan struct{})
	bobDone := make(chan error, 1)
	go func() {
		_, err := cachedDagStructure(c, "k", accessAs("bob"), false,
			func() (*dagStructure, error) {
				close(bobBuilt)
				return nil, errors.New("SCHEDD: permission denied")
			})
		bobDone <- err
	}()
	select {
	case <-bobBuilt:
	case <-time.After(5 * time.Second):
		t.Fatal("bob was attached to alice's in-flight transfer instead of making his own")
	}
	if err := <-bobDone; err == nil {
		t.Errorf("bob's attempt succeeded")
	}

	close(release)
	if err := <-done; err != nil {
		t.Fatalf("alice's build: %v", err)
	}
	mu.Lock()
	defer mu.Unlock()
	if builds != 1 {
		t.Errorf("alice built %d times", builds)
	}
}

// TestCachedDagStructureCollapsesConcurrentBuilds is the DoS half: one
// whole-sandbox transfer buffers tens of megabytes for up to two
// minutes, so N simultaneous loads of one workflow must not be N of
// them.
func TestCachedDagStructureCollapsesConcurrentBuilds(t *testing.T) {
	c := newDagStructureCache(4, time.Hour)
	release := make(chan struct{})
	var mu sync.Mutex
	builds := 0
	var wg sync.WaitGroup
	for i := 0; i < 25; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			// Half of them ask for a refresh, which must not be a way
			// around the collapse.
			_, err := cachedDagStructure(c, "k", accessAs(testOwner), i%2 == 0,
				func() (*dagStructure, error) {
					mu.Lock()
					builds++
					mu.Unlock()
					<-release
					return testStructure("alice.dag"), nil
				})
			if err != nil {
				t.Errorf("load %d: %v", i, err)
			}
		}(i)
	}
	// Give them all a chance to pile up before any can finish.
	time.Sleep(100 * time.Millisecond)
	close(release)
	wg.Wait()

	mu.Lock()
	defer mu.Unlock()
	if builds > 3 {
		t.Errorf("25 concurrent loads started %d whole-sandbox transfers; they must collapse", builds)
	}
}

// TestDagStructureCacheUnderRace exercises the cache the way the server
// does, from many goroutines at once, for the race detector.
func TestDagStructureCacheUnderRace(t *testing.T) {
	c := newDagStructureCache(dagCacheMaxEntries, time.Hour)
	var wg sync.WaitGroup
	for i := 0; i < 32; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			key := fmt.Sprintf("k%d", i%8)
			for j := 0; j < 50; j++ {
				c.put(ownedBy(key, "a.dag"))
				if e, ok := c.get(key); ok && e.value.dagFile != "a.dag" {
					t.Errorf("get returned %q", e.value.dagFile)
				}
				st, err := cachedDagStructure(c, key, accessAs(testOwner), j%5 == 0,
					func() (*dagStructure, error) { return testStructure("a.dag"), nil })
				if err != nil || st == nil {
					t.Errorf("concurrent load: %v", err)
				}
			}
		}(i)
	}
	wg.Wait()
}

// TestDagStructureCacheEvictsOldest fills the real 16-entry cache and
// puts a 17th, which must push the first one out.
func TestDagStructureCacheEvictsOldest(t *testing.T) {
	c := newDagStructureCache(dagCacheMaxEntries, time.Hour)
	for i := 0; i < dagCacheMaxEntries; i++ {
		c.put(ownedBy(fmt.Sprintf("k%d", i), fmt.Sprintf("d%d.dag", i)))
	}
	if _, ok := c.get("k0"); !ok {
		t.Fatalf("the oldest entry was evicted before the cache was full")
	}
	c.put(ownedBy("k16", "d16.dag"))
	if _, ok := c.get("k0"); ok {
		t.Errorf("the 17th entry did not evict the oldest")
	}
	for i := 1; i <= dagCacheMaxEntries; i++ {
		if _, ok := c.get(fmt.Sprintf("k%d", i)); !ok {
			t.Errorf("entry k%d should still be cached", i)
		}
	}
}

func TestDagStructureCacheRePutRefreshesPosition(t *testing.T) {
	c := newDagStructureCache(2, time.Hour)
	c.put(ownedBy("a", "a.dag"))
	c.put(ownedBy("b", "b.dag"))
	c.put(ownedBy("a", "a2.dag")) // a is now the newest
	c.put(ownedBy("c", "c.dag"))  // evicts b, not a
	if _, ok := c.get("b"); ok {
		t.Errorf("b should have been evicted")
	}
	got, ok := c.get("a")
	if !ok || got.value.dagFile != "a2.dag" {
		t.Errorf("a = %v, %v; want the replacement", got, ok)
	}
}

func TestDagStructureCacheTTLExpiry(t *testing.T) {
	now := time.Now()
	const ttl = 30 * time.Minute
	c := newDagStructureCache(4, ttl)
	c.now = func() time.Time { return now }
	c.put(ownedBy("k", "a.dag"))

	now = now.Add(ttl - time.Minute)
	if _, ok := c.get("k"); !ok {
		t.Fatalf("the entry expired before its TTL")
	}
	now = now.Add(2 * time.Minute) // now past the TTL
	if _, ok := c.get("k"); ok {
		t.Errorf("the entry outlived its TTL")
	}
	if dagCacheTTL != time.Hour {
		t.Errorf("the production TTL is %v; the comment on it says an hour", dagCacheTTL)
	}
	// An expired entry is dropped, not merely hidden.
	c.mu.Lock()
	n := len(c.entries)
	c.mu.Unlock()
	if n != 0 {
		t.Errorf("the expired entry is still held: %d entries", n)
	}
}

// TestDagNegativeCacheExpiresSooner: a refusal is remembered, because a
// UI polls precisely because it got one -- but only for seconds, because
// DAGMan may be about to write the file that makes it untrue.
func TestDagNegativeCacheExpiresSooner(t *testing.T) {
	now := time.Now()
	c := newDagStructureCache(4, time.Hour)
	c.now = func() time.Time { return now }
	c.put(dagCacheEntry{key: "k", owner: "alice", err: errDagNoStructure})

	now = now.Add(dagNegativeCacheTTL / 2)
	if _, ok := c.get("k"); !ok {
		t.Fatalf("the negative entry expired immediately")
	}
	now = now.Add(dagNegativeCacheTTL)
	if _, ok := c.get("k"); ok {
		t.Errorf("a negative entry lived for the full structure TTL")
	}
	if dagNegativeCacheTTL >= dagCacheTTL {
		t.Errorf("a refusal is cached for as long as an answer (%v vs %v)", dagNegativeCacheTTL, dagCacheTTL)
	}
}

// TestCachedDagStructureRefreshBypass is the ?refresh=1 contract: an
// ordinary load must be served from the cache (no whole-sandbox
// transfer), and refresh must rebuild AND repopulate.
func TestCachedDagStructureRefreshBypass(t *testing.T) {
	c := newDagStructureCache(4, time.Hour)
	builds := 0
	build := func() (*dagStructure, error) {
		builds++
		return testStructure(fmt.Sprintf("build%d.dag", builds)), nil
	}
	alice := accessAs(testOwner)

	if _, err := cachedDagStructure(c, "k", alice, false, build); err != nil {
		t.Fatalf("first build: %v", err)
	}
	if builds != 1 {
		t.Fatalf("first call built %d times, want 1", builds)
	}

	got, err := cachedDagStructure(c, "k", alice, false, build)
	if err != nil {
		t.Fatalf("cached load: %v", err)
	}
	if builds != 1 {
		t.Errorf("an ordinary load re-fetched the sandbox (%d builds)", builds)
	}
	if got.dagFile != "build1.dag" {
		t.Errorf("cached load returned %q", got.dagFile)
	}

	got, err = cachedDagStructure(c, "k", alice, true, build)
	if err != nil {
		t.Fatalf("refresh: %v", err)
	}
	if builds != 2 {
		t.Fatalf("refresh=1 did not bypass the cache (%d builds)", builds)
	}
	if got.dagFile != "build2.dag" {
		t.Errorf("refresh returned the stale %q", got.dagFile)
	}

	// ...and the refreshed value is what the next ordinary load sees.
	got, err = cachedDagStructure(c, "k", alice, false, build)
	if err != nil {
		t.Fatalf("load after refresh: %v", err)
	}
	if builds != 2 || got.dagFile != "build2.dag" {
		t.Errorf("refresh did not repopulate the cache: %d builds, %q", builds, got.dagFile)
	}
}

func TestCachedDagStructureDoesNotCacheFailures(t *testing.T) {
	c := newDagStructureCache(4, time.Hour)
	want := errors.New("boom")
	if _, err := cachedDagStructure(c, "k", accessAs(testOwner), false,
		func() (*dagStructure, error) {
			return nil, want
		}); !errors.Is(err, want) {
		t.Fatalf("err = %v, want %v", err, want)
	}
	if _, ok := c.get("k"); ok {
		t.Errorf("a transfer failure was cached")
	}
}

// TestCachedDagStructureCachesARefusal: the two failures that are a
// PROPERTY OF THE WORKFLOW are remembered briefly, because each retry
// otherwise re-pays a whole-sandbox transfer that cannot say anything
// new -- and the "not yet"/"never" distinction survives the cache.
func TestCachedDagStructureCachesARefusal(t *testing.T) {
	for _, tc := range []struct {
		name string
		err  error
	}{
		{"no dot file", &dagNoStructureError{started: true}},
		{"unparsable dot file", fmt.Errorf("read w.dot: %w: %w", errDagUnparsableDot, errors.New("line 3"))},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := newDagStructureCache(4, time.Hour)
			builds := 0
			build := func() (*dagStructure, error) {
				builds++
				return nil, tc.err
			}
			alice := accessAs(testOwner)
			if _, err := cachedDagStructure(c, "k", alice, false, build); err == nil {
				t.Fatalf("the refusal was swallowed")
			}
			got, err := cachedDagStructure(c, "k", alice, false, build)
			if err == nil || got != nil {
				t.Fatalf("the cached refusal did not come back: %v, %v", got, err)
			}
			if builds != 1 {
				t.Errorf("a retry re-paid the whole-sandbox transfer (%d builds)", builds)
			}
			var noStructure *dagNoStructureError
			if errors.As(tc.err, &noStructure) {
				var cached *dagNoStructureError
				if !errors.As(err, &cached) || !cached.started {
					t.Errorf("the cached refusal lost the started flag, so the 409 would tell the "+
						"caller to retry forever: %v", err)
				}
			}
			// A refusal is not usable by another user either.
			bobBuilt := false
			_, _ = cachedDagStructure(c, "k", accessAs("bob"), false,
				func() (*dagStructure, error) {
					bobBuilt = true
					return nil, errors.New("denied")
				})
			if !bobBuilt {
				t.Errorf("bob was served alice's cached refusal")
			}
		})
	}
}

func TestDagCacheKeyIncludesDotFile(t *testing.T) {
	// A recycled cluster id that names a different workflow must not hit.
	if dagCacheKey(1, 0, "a.dag") == dagCacheKey(1, 0, "b.dag") {
		t.Errorf("the cache key ignores the dag file name")
	}
	if dagCacheKey(1, 0, "a.dag") == dagCacheKey(1, 1, "a.dag") {
		t.Errorf("the cache key ignores the proc id")
	}
}

// --- the node status file ---------------------------------------------

// sampleNodeStatusFile is the ClassAd format, which is what a DAG whose
// author declared their own NODE_STATUS_FILE most likely writes.
const sampleNodeStatusFile = `
[
  MyType = "DagStatus";
  DagFiles = { "diamond.dag" };
  Timestamp = 1399674138;
  DagStatus = 3;
  DagStatusDetails = "";
  NodesTotal = 4;
]
[
  MyType = "NodeStatus";
  Node = "A";
  NodeStatus = 5;
  StatusDetails = "";
]
[
  MyType = "NodeStatus";
  Node = "B";
  NodeStatus = 3;
  StatusDetails = "idle";
]
[
  MyType = "NodeStatus";
  Node = "C";
  NodeStatus = 2;
  StatusDetails = "";
]
[
  MyType = "NodeStatus";
  Node = "D";
  NodeStatus = 7;
  StatusDetails = "Had an ancestor node fail";
]
[
  MyType = "StatusEnd";
  EndTime = 1399674140;
  Timestamp = 1399674140;
  NextUpdate = 1399674141;
]
`

// sampleNodeStatusJSON is `JSON COMPACT`: one object per line, which is
// the format this server asks for and therefore the one that has to be
// right. The attribute ORDER is deliberately different on every line --
// DAGMan does not promise one, and reading by position would break
// silently the day it changes.
const sampleNodeStatusJSON = `{"MyType":"DagStatus","DagFiles":["diamond.dag"],"Timestamp":1399674138,"DagStatus":3,"NodesTotal":4}
{"Node":"A","MyType":"NodeStatus","NodeStatus":5,"StatusDetails":""}
{"MyType":"NodeStatus","NodeStatus":3,"StatusDetails":"idle: 1 held","Node":"B"}
{"StatusDetails":"","MyType":"NodeStatus","Node":"C","NodeStatus":2}
{"MyType":"NodeStatus","Node":"D","NodeStatus":7,"StatusDetails":"Had an ancestor node fail"}
{"MyType":"StatusEnd","EndTime":1399674140,"Timestamp":1399674140,"NextUpdate":1399674141}
`

func wantSampleStates(t *testing.T, states map[string]dagStatusEntry) {
	t.Helper()
	want := map[string]string{
		"a": dagStateDone,
		"b": dagStateSubmitted,
		"c": dagStatePreRun,
		"d": dagStateFutile,
	}
	if len(states) != len(want) {
		t.Fatalf("parsed %d node states, want %d: %v", len(states), len(want), states)
	}
	for name, state := range want {
		if states[name].state != state {
			t.Errorf("node %s = %q, want %q", name, states[name].state, state)
		}
	}
}

// TestParseNodeStatusFileTypeSpelling: DAGMan's source writes this
// attribute as ATTR_MY_TYPE ("MyType"), and a 25.8 access point writes
// "Type". Both have to be read, or the endpoint loses every node state
// against whichever half of the field it did not expect.
func TestParseNodeStatusFileTypeSpelling(t *testing.T) {
	body := `[
  Type = "DagStatus";
  DagFiles = {
    "fanout.dag"
  };
  Timestamp = 1790295242; /* "Thu Sep 24 19:14:02 2026" */
  DagStatus = 5; /* "STATUS_DONE (success)" */
]
[
  Type = "NodeStatus";
  Node = "produce_1";
  NodeStatus = 5; /* "STATUS_DONE" */
  StatusDetails = "";
]
[
  Type = "StatusEnd";
  Timestamp = 1790295242;
  NextUpdate = 0;
]
`
	states, at, next, sawEnd := parseNodeStatusFile(body)
	if len(states) != 1 || states["produce_1"].state != dagStateDone {
		t.Fatalf("states = %v", states)
	}
	if at != 1790295242 || next != 0 {
		t.Errorf("timestamp/next = %d/%d", at, next)
	}
	if !sawEnd {
		t.Errorf("the StatusEnd ad was read but not reported; NextUpdate 0 means nothing without it")
	}

	// The same file in JSON, since the spelling travels with the ad and
	// not with the format.
	states, _, _, _ = parseNodeStatusFile(
		`{"Type":"NodeStatus","Node":"produce_1","NodeStatus":5}` + "\n")
	if len(states) != 1 || states["produce_1"].state != dagStateDone {
		t.Fatalf("json states = %v", states)
	}
}

func TestParseNodeStatusFileClassAd(t *testing.T) {
	states, at, next, _ := parseNodeStatusFile(sampleNodeStatusFile)
	wantSampleStates(t, states)
	if at != 1399674140 {
		t.Errorf("timestamp = %d, want the latest one in the file (1399674140)", at)
	}
	if next != 1399674141 {
		t.Errorf("NextUpdate = %d, want 1399674141", next)
	}
	if states["d"].detail != "Had an ancestor node fail" {
		t.Errorf("detail = %q; DAGMan's own note about the node is the useful half", states["d"].detail)
	}
}

func TestParseNodeStatusFileJSON(t *testing.T) {
	states, at, next, _ := parseNodeStatusFile(sampleNodeStatusJSON)
	wantSampleStates(t, states)
	if at != 1399674140 {
		t.Errorf("timestamp = %d, want 1399674140", at)
	}
	if next != 1399674141 {
		t.Errorf("NextUpdate = %d, want 1399674141", next)
	}
	if states["b"].detail != "idle: 1 held" {
		t.Errorf("detail = %q", states["b"].detail)
	}
}

// TestParseNodeStatusFileJSONPretty: `JSON` without COMPACT is the same
// ads pretty-printed across many lines, so nothing may assume one object
// per line.
func TestParseNodeStatusFileJSONPretty(t *testing.T) {
	states, at, _, _ := parseNodeStatusFile(`{
    "MyType": "DagStatus",
    "Timestamp": 1700000000
}
{
    "MyType": "NodeStatus",
    "Node": "only",
    "NodeStatus": 4
}
`)
	if len(states) != 1 || states["only"].state != dagStatePostRun {
		t.Fatalf("states = %v", states)
	}
	if at != 1700000000 {
		t.Errorf("timestamp = %d", at)
	}
}

// TestParseNodeStatusFileFinalFile: a DAG that has ended writes
// NextUpdate 0, which is how this endpoint knows the state will never
// change again and stops re-fetching the sandbox for it.
func TestParseNodeStatusFileFinalFile(t *testing.T) {
	_, _, next, sawEnd := parseNodeStatusFile(
		`{"MyType":"NodeStatus","Node":"a","NodeStatus":5}` + "\n" +
			`{"MyType":"StatusEnd","Timestamp":1700000000,"NextUpdate":0}` + "\n")
	if next != 0 {
		t.Errorf("NextUpdate = %d, want 0", next)
	}
	if !sawEnd {
		t.Errorf("the closing StatusEnd ad was not reported")
	}
}

// TestStateIsFinalNeedsAStatusEnd is C2: NextUpdate is inserted only on
// the StatusEnd ad (condor_dagman/dag.cpp:2703), so an ABSENT one leaves
// it zero -- and zero is also how DAGMan says "written for the last
// time". Inferring finality from the number alone declares a file
// truncated mid rewrite to be final and freezes a RUNNING workflow's
// state for the whole cache TTL, while still reporting status-file as
// its source.
func TestStateIsFinalNeedsAStatusEnd(t *testing.T) {
	// The case parseNodeStatusFile deliberately tolerates: the last ad
	// was cut off, so there is no StatusEnd and no NextUpdate.
	truncated := `{"MyType":"DagStatus","Timestamp":1700000000}` + "\n" +
		`{"MyType":"NodeStatus","Node":"a","NodeStatus":3}` + "\n" +
		`{"MyType":"NodeStatus","Node":"b","NodeStat`
	states, _, next, sawEnd := parseNodeStatusFile(truncated)
	if len(states) != 1 {
		t.Fatalf("states = %v", states)
	}
	if next != 0 || sawEnd {
		t.Fatalf("next/sawEnd = %d/%v; a truncated file has neither", next, sawEnd)
	}
	running := &dagStructure{statusFileName: "w.status", statusNextUpdate: next, sawStatusEnd: sawEnd}
	if running.stateIsFinal() {
		t.Errorf("a workflow whose status file was truncated mid rewrite was declared final")
	}

	final := &dagStructure{statusFileName: "w.status", statusNextUpdate: 0, sawStatusEnd: true}
	if !final.stateIsFinal() {
		t.Errorf("a file DAGMan closed with NextUpdate 0 is final and must not be re-fetched")
	}
}

// TestParseNodeStatusFileTruncated: DAGMan rewrites this file while we
// may be reading it, so a half-written last ad must not throw away the
// nodes that did parse.
func TestParseNodeStatusFileTruncated(t *testing.T) {
	cut := func(t *testing.T, body, at string) string {
		t.Helper()
		i := strings.Index(body, at)
		if i < 0 {
			t.Fatalf("the sample file no longer contains %s", at)
		}
		return body[:i]
	}
	for _, tc := range []struct{ name, body string }{
		{"classad", cut(t, sampleNodeStatusFile, `Node = "D"`)},
		{"json", cut(t, sampleNodeStatusJSON, `"Node":"D"`)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			states, _, _, _ := parseNodeStatusFile(tc.body)
			if len(states) != 3 {
				t.Fatalf("got %d states from a truncated file, want the 3 complete ads: %v",
					len(states), states)
			}
			if states["a"].state != dagStateDone {
				t.Errorf("node A = %q", states["a"].state)
			}
		})
	}
}

func TestParseNodeStatusFileEmpty(t *testing.T) {
	states, at, next, _ := parseNodeStatusFile("")
	if len(states) != 0 || at != 0 || next != 0 {
		t.Errorf("empty file gave %v, %d, %d", states, at, next)
	}
}

func TestNodeStatusStateCoversTheEnum(t *testing.T) {
	want := []string{
		dagStateUnready, dagStateReady, dagStatePreRun, dagStateSubmitted,
		dagStatePostRun, dagStateDone, dagStateFailed, dagStateFutile,
	}
	for i, w := range want {
		if got := nodeStatusState(int64(i)); got != w {
			t.Errorf("nodeStatusState(%d) = %q, want %q", i, got, w)
		}
	}
	if got := nodeStatusState(99); got != dagStateUnready {
		t.Errorf("an unknown status should read as unready, got %q", got)
	}
}

func TestDotNodeState(t *testing.T) {
	for letter, want := range map[string]string{
		dagman.DotStateDone:    dagStateDone,
		dagman.DotStateRunning: dagStateSubmitted,
		dagman.DotStatePre:     dagStatePreRun,
		dagman.DotStatePost:    dagStatePostRun,
		dagman.DotStateError:   dagStateFailed,
		dagman.DotStateIdle:    dagStateReady,
		"":                     dagStateReady,
	} {
		if got := dotNodeState(letter); got != want {
			t.Errorf("dotNodeState(%q) = %q, want %q", letter, got, want)
		}
	}
}

// --- state mapping ----------------------------------------------------

func TestQueueJobState(t *testing.T) {
	for status, want := range map[int64]string{
		1: dagStateIdle, 2: dagStateRunning, 3: dagStateRemoved, 4: dagStateDone,
		5: dagStateHeld, 6: dagStateTransferring, 7: dagStateSuspended,
	} {
		if got := queueJobState(status); got != want {
			t.Errorf("queueJobState(%d) = %q, want %q", status, got, want)
		}
	}
}

// TestArchiveJobState is the distinction the queue's vocabulary loses: a
// node whose job exited 1 is "Completed" to the schedd and a failure to
// the workflow.
func TestArchiveJobState(t *testing.T) {
	cases := []struct{ ad, want string }{
		{"JobStatus = 4\nExitCode = 0\nExitBySignal = false", dagStateDone},
		{"JobStatus = 4\nExitCode = 1\nExitBySignal = false", dagStateFailed},
		{"JobStatus = 4\nExitBySignal = true\nExitSignal = 9", dagStateFailed},
		{"JobStatus = 3", dagStateRemoved},
		{"JobStatus = 4", dagStateDone},
	}
	for _, tc := range cases {
		if got := archiveJobState(adFrom(t, tc.ad)); got != tc.want {
			t.Errorf("archiveJobState(%q) = %q, want %q", tc.ad, got, tc.want)
		}
	}
}

func TestDagStateRankPrefersWhatNeedsAttention(t *testing.T) {
	if dagStateRank(dagStateHeld) <= dagStateRank(dagStateRunning) {
		t.Errorf("held must outrank running")
	}
	if dagStateRank(dagStateRunning) <= dagStateRank(dagStateIdle) {
		t.Errorf("running must outrank idle")
	}
	if dagStateRank(dagStateIdle) <= dagStateRank(dagStateDone) {
		t.Errorf("idle must outrank done")
	}
}

// --- the group roll-up ------------------------------------------------

func TestRollUpDagGroups(t *testing.T) {
	d := dagman.ParseWithFiles(`
JOB setup setup.sub
JOB work_0 work.sub
JOB work_1 work.sub
JOB work_2 work.sub
JOB gather gather.sub
PARENT setup CHILD work_0 work_1 work_2
PARENT work_0 work_1 work_2 CHILD gather
`, nil)
	g := dagman.Collapse(d)

	states := map[string]dagNodeState{
		"setup":  {state: dagStateDone, jobID: "10.0", source: dagSourceArchive},
		"work_0": {state: dagStateDone, jobID: "11.0", source: dagSourceArchive},
		"work_1": {state: dagStateRunning, jobID: "12.0", source: dagSourceQueue},
		"work_2": {state: dagStateHeld, jobID: "13.0", holdReason: "no disk", source: dagSourceQueue},
		// gather is deliberately absent: it has not been submitted.
	}

	groups, nodes := rollUpDagGroups(g, states)
	if len(groups) != 3 {
		t.Fatalf("got %d groups, want 3", len(groups))
	}
	byLabel := map[string]DagGraphGroup{}
	for _, grp := range groups {
		byLabel[grp.Label] = grp
	}
	work := byLabel["work"]
	if work.Status[dagStateDone] != 1 || work.Status[dagStateRunning] != 1 || work.Status[dagStateHeld] != 1 {
		t.Errorf("fan-out histogram = %v", work.Status)
	}
	if len(work.Status) != 3 {
		t.Errorf("fan-out histogram has extra buckets: %v", work.Status)
	}
	if got := byLabel["gather"].Status[dagStateUnready]; got != 1 {
		t.Errorf("a node no source knows about should read as unready, got %v", byLabel["gather"].Status)
	}
	if byLabel["setup"].ParentIDs == nil {
		t.Errorf("ParentIDs must serialize as [] rather than null")
	}

	if len(nodes) != 5 {
		t.Fatalf("got %d nodes, want 5", len(nodes))
	}
	byName := map[string]DagGraphNode{}
	for _, n := range nodes {
		byName[n.Name] = n
	}
	if byName["work_2"].HoldReason != "no disk" || byName["work_2"].JobID != "13.0" {
		t.Errorf("held node lost its detail: %+v", byName["work_2"])
	}
	if byName["gather"].Source != dagSourceInferred {
		t.Errorf("gather source = %q, want %q", byName["gather"].Source, dagSourceInferred)
	}
	if byName["work_1"].GroupID != work.ID {
		t.Errorf("node/group linkage is wrong: %+v", byName["work_1"])
	}
}

// --- reading the spool tar --------------------------------------------

type tarEntry struct {
	name string
	body []byte
	typ  byte
	size int64 // when non-zero, overrides len(body) in the header
}

func buildTar(t *testing.T, entries []tarEntry) *bytes.Buffer {
	t.Helper()
	buf := &bytes.Buffer{}
	tw := tar.NewWriter(buf)
	for _, e := range entries {
		typ := e.typ
		if typ == 0 {
			typ = tar.TypeReg
		}
		size := int64(len(e.body))
		if e.size != 0 {
			size = e.size
		}
		if err := tw.WriteHeader(&tar.Header{
			Name: e.name, Mode: 0o644, Size: size, Typeflag: typ,
		}); err != nil {
			t.Fatalf("tar header: %v", err)
		}
		if size == int64(len(e.body)) {
			if _, err := tw.Write(e.body); err != nil {
				t.Fatalf("tar write: %v", err)
			}
		}
	}
	// A header that lied about its size leaves the archive unclosable;
	// tests that do that ignore the error.
	_ = tw.Close()
	return buf
}

func TestCollectTarTextFiles(t *testing.T) {
	buf := buildTar(t, []tarEntry{
		{name: "./workflow.dag", body: []byte("JOB a a.sub\n")},
		{name: "./a.sub", body: []byte("executable = /bin/true\nqueue\n")},
		{name: "./subdir/", typ: tar.TypeDir},
		{name: "./payload.bin", body: []byte{0x7f, 'E', 'L', 'F', 0x00, 0x01}},
		{name: "./workflow.dag.status", body: []byte("[ MyType = \"StatusEnd\" ]\n")},
	})
	files, err := collectTarTextFilesDefault(tar.NewReader(buf), dagBigFilePredicate("workflow.dag"))
	if err != nil {
		t.Fatalf("collect: %v", err)
	}
	if len(files) != 3 {
		t.Fatalf("kept %d files, want 3 (the directory and the binary are not text): %v",
			len(files), keysOf(files))
	}
	if files["workflow.dag"] != "JOB a a.sub\n" {
		t.Errorf("the dag file came back as %q", files["workflow.dag"])
	}
	if _, ok := files["payload.bin"]; ok {
		t.Errorf("a binary entry was kept")
	}
}

func TestCollectTarTextFilesRefusesAnOversizeStructure(t *testing.T) {
	// Only the header has to claim the size; nothing reads the body.
	buf := buildTar(t, []tarEntry{{name: "big.dot", size: dagBigFileMaxBytes + 1}})
	_, err := collectTarTextFilesDefault(tar.NewReader(buf), dagBigFilePredicate("big.dag"))
	if err == nil {
		t.Fatalf("an oversize dot file was accepted")
	}
	if !strings.Contains(err.Error(), "big.dot") {
		t.Errorf("the refusal does not name the file: %v", err)
	}
}

func TestCollectTarTextFilesSkipsAnOversizeLog(t *testing.T) {
	// A workflow's own .dagman.out routinely runs to hundreds of
	// megabytes. Skipping it is right; refusing the whole graph over it
	// would make the endpoint useless on exactly the long-running
	// workflows people want to look at.
	buf := buildTar(t, []tarEntry{
		{name: "workflow.dagman.out", body: bytes.Repeat([]byte("x"), dagAuxFileMaxBytes+1)},
		{name: "workflow.dot", body: []byte("digraph DAG {\n}\n")},
	})
	files, err := collectTarTextFilesDefault(tar.NewReader(buf), dagBigFilePredicate("workflow.dag"))
	if err != nil {
		t.Fatalf("an oversize log should be skipped, not refused: %v", err)
	}
	if _, ok := files["workflow.dot"]; !ok {
		t.Errorf("the dot file was lost: %v", keysOf(files))
	}
	if _, ok := files["workflow.dagman.out"]; ok {
		t.Errorf("the oversize log was kept")
	}
}

// collectTarTextFilesDefault is the production size discipline, which is
// what every case that is not ABOUT the ceilings should be reading.
func collectTarTextFilesDefault(tr *tar.Reader, big func(string) bool) (map[string]string, error) {
	return collectTarTextFiles(tr, big, defaultDagFileLimits())
}

func keysOf(m map[string]string) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}

// --- finding the files in the tar -------------------------------------

// sampleDotFile is what DAGMan writes for a fan-out workflow. The states
// are the ones a run in flight would have.
const sampleDotFile = `digraph DAG {
    label="DAGMan Job status at Mon Sep 22 10:11:12 2025";

    "setup" [shape=ellipse label="setup (Done)" style=bold];
    "work_0" [shape=ellipse label="work_0 (R)" peripheries=2];
    "work_1" [shape=ellipse label="work_1 (I)"];
    "gather" [shape=ellipse label="gather (I)"];

    "setup" -> "work_0";
    "setup" -> "work_1";
    "work_0" -> "gather";
    "work_1" -> "gather";
}
`

func TestFindDotFile(t *testing.T) {
	files := map[string]string{
		"workflow.dot":        sampleDotFile,
		"workflow.dagman.out": "Dag contains 4 total nodes\n",
		"notes.txt":           "nothing to see",
	}
	name, body, ok := findDotFile(files, "workflow.dot")
	if !ok || name != "workflow.dot" || body != sampleDotFile {
		t.Fatalf("findDotFile = %q, %v", name, ok)
	}

	// A DAG whose author named their own dot file, or asked for
	// DONT-OVERWRITE (which has DAGMan writing name.0, name.1 ...), is
	// still readable: the file is found by what it is.
	for _, spelling := range []string{"mygraph.dot", "workflow.dot.3", "graph"} {
		t.Run(spelling, func(t *testing.T) {
			name, _, ok := findDotFile(map[string]string{
				spelling:    sampleDotFile,
				"notes.txt": "nothing to see",
			}, "workflow.dot")
			if !ok || name != spelling {
				t.Errorf("findDotFile = %q, %v; want %q", name, ok, spelling)
			}
		})
	}

	if _, _, ok := findDotFile(map[string]string{"notes.txt": "hello"}, "workflow.dot"); ok {
		t.Errorf("a sandbox with no graph in it reported one")
	}
}

func TestFindStatusFile(t *testing.T) {
	files := map[string]string{
		"workflow.status": sampleNodeStatusJSON,
		"notes.txt":       "nothing to see",
	}
	name, body, ok := findStatusFile(files, "workflow.status")
	if !ok || name != "workflow.status" || body != sampleNodeStatusJSON {
		t.Fatalf("findStatusFile = %q, %v", name, ok)
	}
	name, _, ok = findStatusFile(map[string]string{"mine.txt": sampleNodeStatusFile}, "workflow.status")
	if !ok || name != "mine.txt" {
		t.Errorf("an author-named status file was not found: %q %v", name, ok)
	}
	if _, _, ok := findStatusFile(map[string]string{"notes.txt": "hello"}, "workflow.status"); ok {
		t.Errorf("a sandbox with no status file reported one")
	}
}

// --- the structure, end to end from a tar -----------------------------

// TestBuildDagStructureFromTar exercises everything between the tar and
// the structure: the DOT file is found and collapsed, and the node status
// file is read out of the same transfer.
func TestBuildDagStructureFromTar(t *testing.T) {
	buf := buildTar(t, []tarEntry{
		{name: "./fanout.dot", body: []byte(sampleDotFile)},
		{name: "./fanout.status", body: []byte(sampleNodeStatusJSON)},
		{name: "./fanout.dagman.out", body: []byte("Dag contains 4 total nodes\n")},
		{name: "./combine.sub", body: []byte("executable = /bin/true\nqueue\n")},
	})
	files, err := collectTarTextFilesDefault(tar.NewReader(buf), dagBigFilePredicate("fanout.dag"))
	if err != nil {
		t.Fatalf("collect: %v", err)
	}

	name, body, ok := findDotFile(files, dagman.DotFileName("fanout.dag"))
	if !ok {
		t.Fatalf("the dot file was not found in %v", keysOf(files))
	}
	if name != "fanout.dot" {
		t.Errorf("found %q", name)
	}
	graph, err := dagman.ParseDot(strings.NewReader(body))
	if err != nil {
		t.Fatalf("ParseDot: %v", err)
	}
	g := dagman.CollapseGraph(graph)
	if g.NodeCount != 4 || g.EdgeCount != 4 {
		t.Fatalf("NodeCount/EdgeCount = %d/%d, want 4/4", g.NodeCount, g.EdgeCount)
	}
	if len(g.Groups) != 3 {
		t.Fatalf("got %d groups, want 3 (setup, the pair, gather): %+v", len(g.Groups), g.Groups)
	}

	statusName, statusBody, ok := findStatusFile(files, dagman.StatusFileName("fanout.dag"))
	if !ok || statusName != "fanout.status" {
		t.Fatalf("the status file was not found: %q %v", statusName, ok)
	}
	states, at, _, _ := parseNodeStatusFile(statusBody)
	if at != 1399674140 {
		t.Errorf("status file timestamp = %d", at)
	}
	if states["a"].state != dagStateDone {
		t.Errorf("the status file was not read: %v", states)
	}
}

// --- state precedence -------------------------------------------------

// fanStructure is a two-node structure to overlay states on.
func fanStructure(t *testing.T, statusStates map[string]dagStatusEntry, dotStates map[string]string) *dagStructure {
	t.Helper()
	graph, err := dagman.ParseDot(strings.NewReader(sampleDotFile))
	if err != nil {
		t.Fatalf("ParseDot: %v", err)
	}
	return &dagStructure{
		dagFile:      "fanout.dag",
		dotFile:      "fanout.dot",
		grouping:     dagman.CollapseGraph(graph),
		dotStates:    dotStates,
		statusStates: statusStates,
	}
}

// TestMergeDagStatesStatusFileOutranksTheQueue is the precedence rule.
//
// DAGMan says work_0 is in its POST script; the queue says the job is
// gone and the archive says it completed. Both are true, and only the
// first answers the question being asked -- "what is this NODE doing" --
// because a POST script is not a job and has no ad anywhere. If the queue
// won here, every node with a POST script would read as done while its
// script was still running, and a workflow would look finished while it
// was not.
func TestMergeDagStatesStatusFileOutranksTheQueue(t *testing.T) {
	st := fanStructure(t, map[string]dagStatusEntry{
		"work_0": {state: dagStatePostRun, detail: "running"},
		"work_1": {state: dagStateFailed, detail: "Job proc (7.0) failed with status 1"},
	}, nil)
	live := map[string]dagNodeState{
		"work_0": {state: dagStateDone, jobID: "6.0", source: dagSourceArchive},
		"work_1": {state: dagStateDone, jobID: "7.0", exitCode: intPtr(1), source: dagSourceArchive},
	}

	states, used := mergeDagStates(st, live)
	if got := states["work_0"]; got.state != dagStatePostRun || got.source != dagSourceStatusFile {
		t.Errorf("work_0 = %+v; the queue's view of the job overrode DAGMan's view of the node", got)
	}
	// ...and the job's identity survives, because "postrun" alone does
	// not tell anyone which job to go and look at.
	if states["work_0"].jobID != "6.0" {
		t.Errorf("work_0 lost its job id: %+v", states["work_0"])
	}
	failed := states["work_1"]
	if failed.state != dagStateFailed {
		t.Errorf("work_1 = %q, want %q", failed.state, dagStateFailed)
	}
	if failed.exitCode == nil || *failed.exitCode != 1 || failed.jobID != "7.0" {
		t.Errorf("a failed node lost the why: %+v", failed)
	}
	if failed.detail == "" {
		t.Errorf("a failed node lost DAGMan's own note")
	}
	if !used[dagSourceStatusFile] || !used[dagSourceArchive] {
		t.Errorf("sources used = %v", used)
	}
}

// TestMergeDagStatesFallsBackDownThePrecedence: with no status file, the
// DOT label is better than nothing; with a live job, the job is better
// than the label, because the label was written once at startup and the
// job is now.
func TestMergeDagStatesFallsBackDownThePrecedence(t *testing.T) {
	st := fanStructure(t, nil, map[string]string{
		"setup":  dagStateDone,
		"work_0": dagStateReady,
	})
	live := map[string]dagNodeState{
		"work_0": {state: dagStateRunning, jobID: "6.0", source: dagSourceQueue},
	}
	states, used := mergeDagStates(st, live)
	if got := states["setup"]; got.state != dagStateDone || got.source != dagSourceDot {
		t.Errorf("setup = %+v, want the dot file's own state", got)
	}
	if got := states["work_0"]; got.state != dagStateRunning || got.source != dagSourceQueue {
		t.Errorf("work_0 = %+v, want the live queue state", got)
	}
	if got := states["gather"]; got.state != dagStateUnready || got.source != dagSourceInferred {
		t.Errorf("a node nothing knows about = %+v", got)
	}
	if !used[dagSourceDot] || !used[dagSourceQueue] || !used[dagSourceInferred] {
		t.Errorf("sources used = %v", used)
	}
}

func intPtr(v int) *int { return &v }

// --- the missing-structure message ------------------------------------

// TestDagNoStructureMessage: "not yet" and "never" call for opposite
// reactions -- retry, or stop waiting -- so one message for both would be
// useless to whichever caller guessed wrong.
func TestDagNoStructureMessage(t *testing.T) {
	justStarted := adFrom(t, fmt.Sprintf("JobStatus = 2\nJobCurrentStartDate = %d\n", time.Now().Unix()))
	if msg := dagNoStructureMessage(justStarted, "workflow.dot", false); !strings.Contains(msg, "Retry") {
		t.Errorf("a workflow that just started should be retried: %q", msg)
	}

	// DAGMan's own log says it got past the point where it writes the
	// file, so waiting is pointless however young the job is.
	if msg := dagNoStructureMessage(justStarted, "workflow.dot", true); !strings.Contains(msg, "declares no DOT") {
		t.Errorf("a started DAGMan with no dot file declares none: %q", msg)
	}

	old := adFrom(t, fmt.Sprintf("JobStatus = 2\nJobCurrentStartDate = %d\n",
		time.Now().Add(-time.Hour).Unix()))
	msg := dagNoStructureMessage(old, "workflow.dot", false)
	if !strings.Contains(msg, "declares no DOT") {
		t.Errorf("a long-running workflow with no dot file declares none: %q", msg)
	}
	// The remaining instruction is to the workflow's AUTHOR -- a line
	// they add to their own DAG file -- not a description of what this
	// server does with the spool.
	if !strings.Contains(msg, "DOT workflow.dot") {
		t.Errorf("the message does not say what to add to the DAG file: %q", msg)
	}
	for _, banned := range []string{"spool", "DAGMan writes", "instrumented for this"} {
		if strings.Contains(msg, banned) {
			t.Errorf("the message explains the server rather than the workflow (%q): %q", banned, msg)
		}
	}

	done := adFrom(t, fmt.Sprintf("JobStatus = 4\nJobCurrentStartDate = %d\n", time.Now().Unix()))
	if msg := dagNoStructureMessage(done, "workflow.dot", false); !strings.Contains(msg, "declares no DOT") {
		t.Errorf("a finished workflow with no dot file declares none: %q", msg)
	}
}

// --- an ordinary load never transfers a sandbox ----------------------

// TestOrdinaryLoadNeverRefetchesHoweverOldTheEntryIs pins the fix to the
// first of the two reported defects.
//
// There used to be a dagStatusMaxAge of 45 seconds: a cached entry whose
// node status half was older than that was discarded and the ordinary
// page load behind it re-paid a whole-sandbox transfer. Almost every
// real page view is more than 45 seconds after the last one, so the
// "cheap cached load" the panel advertised was a fiction and nearly
// every load paid a spool transfer -- which is what made a 20-node
// workflow take seconds to open.
//
// Restoring that auto-refetch makes this test fail: the build function
// counts, and an ordinary load must never call it.
func TestOrdinaryLoadNeverRefetchesHoweverOldTheEntryIs(t *testing.T) {
	c := newDagStructureCache(4, time.Hour)
	builds := 0
	// A RUNNING workflow -- NextUpdate in the future, so DAGMan will
	// write its status file again -- fetched an hour ago. This is
	// exactly the entry the old rule threw away.
	aged := &dagStructure{
		dotFile:          "w.dot",
		grouping:         &dagman.Grouping{},
		statusFileName:   "w.status",
		statusNextUpdate: time.Now().Add(30 * time.Second).Unix(),
		sawStatusEnd:     true,
		fetchedAt:        time.Now().Add(-time.Hour),
	}
	build := func() (*dagStructure, error) {
		builds++
		return aged, nil
	}
	if _, err := cachedDagStructure(c, "k", accessAs(testOwner), false, build); err != nil {
		t.Fatalf("seed: %v", err)
	}
	if builds != 1 {
		t.Fatalf("the first load must build: builds = %d", builds)
	}

	for i := 0; i < 5; i++ {
		got, err := cachedDagStructure(c, "k", accessAs(testOwner), false, build)
		if err != nil || got != aged {
			t.Fatalf("ordinary load %d: %v / %p", i, err, got)
		}
	}
	if builds != 1 {
		t.Errorf("an ordinary load transferred a sandbox %d time(s); it must never do that",
			builds-1)
	}

	// A workflow that has NOT written a status file yet is the same
	// rule. The old code re-fetched this one on a timer too.
	c2 := newDagStructureCache(4, time.Hour)
	stateless := &dagStructure{dotFile: "w.dot", grouping: &dagman.Grouping{},
		fetchedAt: time.Now().Add(-time.Hour)}
	n := 0
	build2 := func() (*dagStructure, error) { n++; return stateless, nil }
	for i := 0; i < 3; i++ {
		if _, err := cachedDagStructure(c2, "k", accessAs(testOwner), false, build2); err != nil {
			t.Fatalf("stateless load %d: %v", i, err)
		}
	}
	if n != 1 {
		t.Errorf("a workflow with no status file was re-fetched %d times", n-1)
	}

	// ...and ?refresh=1 is still the thing that fetches, or the panel
	// has no way to get a newer answer at all.
	if _, err := cachedDagStructure(c, "k", accessAs(testOwner), true, build); err != nil {
		t.Fatalf("refresh: %v", err)
	}
	if builds != 2 {
		t.Errorf("?refresh=1 did not fetch: builds = %d", builds)
	}
}

// --- the archive query is sized to the workflow ----------------------

// TestDagArchiveBoundsAreSizedToTheWorkflow pins the fix to the second
// reported defect.
//
// The schedd walks the history file backwards and stops at the first of
// the match limit and the scan limit. The old bounds were flat -- 20,000
// matches, 200,000 records -- so a 20-node workflow, which can never
// produce 20,000 matches, never hit the match limit and scanned the full
// 200,000 records on EVERY page load, cached or not. Measured against a
// 200,000-record history file that was ~0.9s per load with nothing else
// in the request costing more than 50ms.
//
// Restoring either flat bound makes this test fail.
func TestDagArchiveBoundsAreSizedToTheWorkflow(t *testing.T) {
	// The size the report is about. The match limit has to be small
	// enough that finding the workflow's own nodes ENDS the scan.
	limit, scan := dagArchiveBounds(20)
	if limit > 200 {
		t.Errorf("a 20-node workflow asks the history for %d matches; the scan then cannot stop "+
			"until it has read the whole file", limit)
	}
	if limit < 20 {
		t.Errorf("a 20-node workflow asks for %d matches, fewer than it has nodes", limit)
	}
	if scan >= dagArchiveScanLimit {
		t.Errorf("a 20-node workflow scans %d records; that is the flat ceiling this exists to "+
			"get away from", scan)
	}

	// A one-node workflow still gets slack: DAGMan retries submit the
	// node again under the same name, and a node may have several procs.
	if l, _ := dagArchiveBounds(1); l <= 1 {
		t.Errorf("a one-node workflow asks for %d records, leaving no room for a retry", l)
	}

	// Bigger workflows ask for more, up to the ceilings and never past
	// them -- the ceilings are what keeps a 100,000-node workflow from
	// asking the schedd for an unbounded read.
	prevLimit, prevScan := 0, 0
	for _, n := range []int{1, 20, 500, 5000, 100000, 1 << 20} {
		l, sc := dagArchiveBounds(n)
		if l > dagArchiveLimit || sc > dagArchiveScanLimit {
			t.Errorf("bounds(%d) = %d/%d, past the ceilings %d/%d",
				n, l, sc, dagArchiveLimit, dagArchiveScanLimit)
		}
		if l <= 0 || sc <= 0 {
			// Zero or negative is "unlimited" to the history client, so
			// an overflow here would remove the bound entirely.
			t.Fatalf("bounds(%d) = %d/%d; a non-positive bound means UNLIMITED", n, l, sc)
		}
		if l < prevLimit || sc < prevScan {
			t.Errorf("bounds are not monotonic at %d: %d/%d after %d/%d", n, l, sc, prevLimit, prevScan)
		}
		prevLimit, prevScan = l, sc
	}
}

// TestDagArchiveTruncationWarningFollowsTheBound: the warning exists
// because a cut-off archive answer and a complete one are
// indistinguishable in the ads, and it has to compare against the bound
// THIS workflow asked for -- sizing the query to the workflow moved the
// cut, and a warning still checking the flat 20,000 would never fire.
func TestDagArchiveTruncationWarningFollowsTheBound(t *testing.T) {
	limit, _ := dagArchiveBounds(20)
	if w := dagArchiveTruncationWarning(limit-1, 20); w != "" {
		t.Errorf("a complete answer warned: %q", w)
	}
	w := dagArchiveTruncationWarning(limit, 20)
	if w == "" {
		t.Fatalf("an answer that hit this workflow's own %d-record bound did not warn", limit)
	}
	// ...and it says it in words that do not describe the server.
	for _, banned := range []string{"inferred", "record limit", "looked up", "archive answered"} {
		if strings.Contains(w, banned) {
			t.Errorf("the warning explains the server rather than the workflow: %q", w)
		}
	}
}

// TestClampDagNodeTextBoundsTheOnlyUnboundedFields: a node entry is
// otherwise a name, a state word and a job id -- 23 real nodes measured
// 2.8 KB of response in total. StatusDetails and HoldReason come from
// outside this server and have no length of their own; a hold reason
// from a failed transfer carries the plugin's output and runs to
// kilobytes.
func TestClampDagNodeTextBoundsTheOnlyUnboundedFields(t *testing.T) {
	if got := clampDagNodeText("short"); got != "short" {
		t.Errorf("an ordinary detail was altered: %q", got)
	}
	long := strings.Repeat("x", 64<<10)
	got := clampDagNodeText(long)
	if len(got) > dagNodeTextMaxBytes+8 {
		t.Errorf("a %d-byte hold reason came back as %d bytes", len(long), len(got))
	}
	if !strings.HasSuffix(got, "\u2026") {
		t.Errorf("a truncated value does not say it was truncated: %q", got[len(got)-8:])
	}
	// Cut on a rune boundary: the result is JSON, and half a rune is not
	// text. A string of 3-byte runes cannot be cut at any multiple of
	// 1024 without landing inside one.
	multibyte := strings.Repeat("\u4e16", 4096)
	if cut := clampDagNodeText(multibyte); !utf8.ValidString(cut) {
		t.Errorf("clamping produced invalid UTF-8")
	}
}

// --- the spool tar, bounded -------------------------------------------

// TestCollectTarTextFilesCapsTheEntryCount is R2: the byte ceilings say
// nothing about the NUMBER of files, and a fan-out workflow whose nodes
// write their output into the DAG's own Iwd -- the normal shape -- puts
// one tiny file per node in the spool. A million map entries exhaust
// memory long before a million small files add up to a byte limit.
func TestCollectTarTextFilesCapsTheEntryCount(t *testing.T) {
	lim := dagFileLimits{big: 1 << 20, aux: 1 << 20, auxTotal: 1 << 20, entries: 8}
	entries := []tarEntry{{name: "workflow.dot", body: []byte("digraph DAG {\n}\n")}}
	for i := 0; i < lim.entries; i++ {
		entries = append(entries, tarEntry{name: fmt.Sprintf("out_%d.txt", i), body: []byte("x")})
	}
	_, err := collectTarTextFiles(tar.NewReader(buildTar(t, entries)),
		dagBigFilePredicate("workflow.dag"), lim)
	if err == nil {
		t.Fatalf("a spool of %d files was accepted against a cap of %d", len(entries), lim.entries)
	}
	if !strings.Contains(err.Error(), "files") || !strings.Contains(err.Error(), "8") {
		t.Errorf("the refusal does not say what was wrong or name the cap: %v", err)
	}

	// The cap is a cap, not a ceiling on ordinary workflows: one entry
	// under it is fine.
	files, err := collectTarTextFiles(tar.NewReader(buildTar(t, entries[:lim.entries])),
		dagBigFilePredicate("workflow.dag"), lim)
	if err != nil {
		t.Fatalf("a spool inside the cap was refused: %v", err)
	}
	if _, ok := files["workflow.dot"]; !ok {
		t.Errorf("the dot file was lost: %v", keysOf(files))
	}

	// And the production cap is a real number, in the region the finding
	// asked for rather than whatever the last edit left behind.
	if dagMaxSpoolEntries < 10000 || dagMaxSpoolEntries > 100000 {
		t.Errorf("dagMaxSpoolEntries = %d", dagMaxSpoolEntries)
	}
	if defaultDagFileLimits().entries != dagMaxSpoolEntries {
		t.Errorf("the production limits do not carry the entry cap")
	}
}

// TestCollectTarTextFilesKeepsBothBigFiles is R3.
//
// dagBigFileMaxBytes is generous because the 100,000-node workflows that
// most need drawing have a huge dot file AND a huge status file. A total
// that governed both and sat below twice the per-file ceiling
// hard-refused exactly those workflows: 50 MiB + 50 MiB cleared both
// per-file ceilings and blew a 96 MiB shared total.
func TestCollectTarTextFilesKeepsBothBigFiles(t *testing.T) {
	// Two target files that each clear the per-file ceiling and together
	// blow the aux budget several times over.
	lim := dagFileLimits{big: 1000, aux: 100, auxTotal: 150, entries: 100}
	dot := strings.Repeat("d", 900) + "\ndigraph DAG {\n}\n"
	status := strings.Repeat("s", 900) + "\n[ MyType = \"DagStatus\" ]\n"
	files, err := collectTarTextFiles(tar.NewReader(buildTar(t, []tarEntry{
		{name: "workflow.dot", body: []byte(dot)},
		{name: "workflow.status", body: []byte(status)},
	})), dagBigFilePredicate("workflow.dag"), lim)
	if err != nil {
		t.Fatalf("two target files that each fit the per-file ceiling were refused: %v", err)
	}
	if files["workflow.dot"] != dot || files["workflow.status"] != status {
		t.Fatalf("a target file was dropped: %v", keysOf(files))
	}

	// The production numbers must not reintroduce the same trap: either
	// the total is above two big files, or the big files are exempt from
	// it -- and the exemption is what is implemented.
	p := defaultDagFileLimits()
	if 2*p.big > p.auxTotal && !bigFilesAreExemptFromTheTotal(t) {
		t.Errorf("the total (%d) is below two big files (%d) and still governs them",
			p.auxTotal, 2*p.big)
	}
}

// bigFilesAreExemptFromTheTotal proves the exemption directly: with an
// aux budget of nothing at all, a target file is still kept.
func bigFilesAreExemptFromTheTotal(t *testing.T) bool {
	t.Helper()
	body := "digraph DAG {\n}\n"
	files, err := collectTarTextFiles(
		tar.NewReader(buildTar(t, []tarEntry{{name: "workflow.dot", body: []byte(body)}})),
		dagBigFilePredicate("workflow.dag"),
		dagFileLimits{big: 1 << 20, aux: 1 << 20, auxTotal: 0, entries: 10})
	return err == nil && files["workflow.dot"] == body
}

// TestCollectTarTextFilesAuxBudgetSkipsAndCountsWhatItKeeps: the aux
// budget behaves like the per-file aux ceiling -- past it a file is
// skipped and the graph is still read -- and it is measured against the
// same number the accumulator keeps, bytes actually KEPT. The check used
// to run before the text sniff, so a spool full of binaries could refuse
// a graph whose bytes it never held.
func TestCollectTarTextFilesAuxBudgetSkipsAndCountsWhatItKeeps(t *testing.T) {
	lim := dagFileLimits{big: 1 << 20, aux: 1 << 20, auxTotal: 40, entries: 100}
	binary := append([]byte("binary"), 0x00)
	binary = append(binary, bytes.Repeat([]byte{0x7f}, 60)...)

	files, err := collectTarTextFiles(tar.NewReader(buildTar(t, []tarEntry{
		{name: "blob.bin", body: binary},                      // 67 bytes, never kept
		{name: "workflow.dot", body: []byte("digraph DAG{}")}, // target file, exempt
		{name: "notes.txt", body: []byte(strings.Repeat("n", 30))},
		{name: "more.txt", body: []byte(strings.Repeat("m", 30))}, // 60 > 40: skipped
	})), dagBigFilePredicate("workflow.dag"), lim)
	if err != nil {
		t.Fatalf("the aux budget refused the whole graph instead of skipping: %v", err)
	}
	if _, ok := files["workflow.dot"]; !ok {
		t.Errorf("the dot file was lost: %v", keysOf(files))
	}
	if _, ok := files["blob.bin"]; ok {
		t.Errorf("a binary was kept")
	}
	// The binary's 67 bytes must not have been charged to the budget:
	// if they had been, notes.txt (30) would have been skipped too.
	if _, ok := files["notes.txt"]; !ok {
		t.Errorf("a text file was skipped because a BINARY had already spent the budget: %v",
			keysOf(files))
	}
	if _, ok := files["more.txt"]; ok {
		t.Errorf("the aux budget was not enforced: %v", keysOf(files))
	}
}

// --- what the caller actually sees ------------------------------------

// fakeSandbox writes a tar into the transfer's writer and reports done.
func fakeSandbox(body []byte, err error) func(io.Writer) <-chan error {
	return func(w io.Writer) <-chan error {
		ch := make(chan error, 1)
		go func() {
			_, werr := w.Write(body)
			if err != nil {
				ch <- err
				return
			}
			ch <- werr
		}()
		return ch
	}
}

// TestSandboxTextFilesReportsTheRefusalNotThePipe is R4.
//
// collectTarTextFiles stopping early closes the reader, which makes the
// still-running transfer fail with io.ErrClosedPipe -- OUR doing. This
// used to be checked FIRST, so every carefully worded refusal reached
// the caller as "download sandbox: io: read/write on closed pipe". The
// inner function's own test passed throughout, which is why this one is
// at the level the handler calls.
func TestSandboxTextFilesReportsTheRefusalNotThePipe(t *testing.T) {
	lim := dagFileLimits{big: 1 << 20, aux: 1 << 20, auxTotal: 1 << 20, entries: 4}
	var entries []tarEntry
	// Far more than the cap, so the transfer is still writing when the
	// reader is closed under it -- which is what made the pipe's error
	// available to win.
	for i := 0; i < 2000; i++ {
		entries = append(entries, tarEntry{name: fmt.Sprintf("out_%d.txt", i), body: []byte("x")})
	}
	tarBytes := buildTar(t, entries).Bytes()

	_, err := sandboxTextFiles(dagBigFilePredicate("workflow.dag"), lim, fakeSandbox(tarBytes, nil))
	if err == nil {
		t.Fatalf("an oversize spool was accepted")
	}
	if strings.Contains(err.Error(), "closed pipe") {
		t.Fatalf("the caller was told about our own pipe instead of why we refused: %v", err)
	}
	if !strings.Contains(err.Error(), "more than 4 files") {
		t.Errorf("the refusal the caller sees is not the one collectTarTextFiles wrote: %v", err)
	}
}

// TestSandboxTextFilesReportsATransferFailure is the other half: when
// the TRANSFER is what failed, its error is still what the caller gets.
// Preferring readErr unconditionally would report "read tar: unexpected
// EOF" for a schedd that hung up.
func TestSandboxTextFilesReportsATransferFailure(t *testing.T) {
	want := errors.New("SCHEDD: permission denied")
	body := buildTar(t, []tarEntry{{name: "workflow.dot", body: []byte("digraph DAG {\n}\n")}}).Bytes()
	_, err := sandboxTextFiles(dagBigFilePredicate("workflow.dag"), defaultDagFileLimits(),
		fakeSandbox(body[:len(body)/2], want))
	if err == nil {
		t.Fatalf("a failed transfer was accepted")
	}
	if !errors.Is(err, want) {
		t.Fatalf("the transfer's own error was lost: %v", err)
	}
	if !strings.Contains(err.Error(), "download sandbox") {
		t.Errorf("the failure does not say the download was what failed: %v", err)
	}
}

// TestSandboxTextFilesSucceeds pins the ordinary path, so the error
// precedence above cannot be satisfied by refusing everything.
func TestSandboxTextFilesSucceeds(t *testing.T) {
	body := buildTar(t, []tarEntry{
		{name: "./workflow.dot", body: []byte(sampleDotFile)},
		{name: "./notes.txt", body: []byte("hello")},
	}).Bytes()
	files, err := sandboxTextFiles(dagBigFilePredicate("workflow.dag"), defaultDagFileLimits(),
		fakeSandbox(body, nil))
	if err != nil {
		t.Fatalf("a good transfer failed: %v", err)
	}
	if files["workflow.dot"] != sampleDotFile {
		t.Errorf("the dot file did not come back: %v", keysOf(files))
	}
}

// --- finding the files, deterministically -----------------------------

// TestFindDotFileBreaksTiesOnTheName is C3. Equal-ranking candidates
// used to resolve by Go's randomised map order, so the graph could
// change shape between two loads of the same workflow with nothing
// having changed.
func TestFindDotFileBreaksTiesOnTheName(t *testing.T) {
	// Two candidates that rank the same (neither is the expected name,
	// neither is a prefix of it, both end in .dot).
	files := map[string]string{
		"zeta.dot":  sampleDotFile,
		"alpha.dot": sampleDotFile,
	}
	for i := 0; i < 50; i++ {
		name, _, ok := findDotFile(files, "workflow.dot")
		if !ok || name != "alpha.dot" {
			t.Fatalf("findDotFile = %q, %v; want the sorted-first candidate every time", name, ok)
		}
	}
	// Ranking still beats sorting: the expected stem wins over a name
	// that sorts earlier.
	ranked := map[string]string{
		"aaa.dot":        sampleDotFile,
		"workflow.dot.3": sampleDotFile,
	}
	if name, _, _ := findDotFile(ranked, "workflow.dot"); name != "workflow.dot.3" {
		t.Errorf("findDotFile = %q; the expected stem must outrank the alphabet", name)
	}
}

// TestFindStatusFileRanksItsCandidates is the other half of C3:
// findStatusFile had no ranking at all and took the first sniff match.
// A spooled DAG's node outputs land in the DAG's own spool, so a node
// whose stdout mentions NodeStatus is a plausible false candidate that
// won or lost by map order.
func TestFindStatusFileRanksItsCandidates(t *testing.T) {
	realOne := sampleNodeStatusJSON
	decoy := "NodeStatus of the thing I was asked to report\n"
	files := map[string]string{
		"produce_1.out":   decoy,
		"produce_2.out":   decoy,
		"workflow.status": realOne,
	}
	for i := 0; i < 50; i++ {
		name, body, ok := findStatusFile(files, "workflow.status")
		if !ok || name != "workflow.status" || body != realOne {
			t.Fatalf("findStatusFile = %q, %v; the node output won the coin toss", name, ok)
		}
	}
	// With no expected name present, the ranking still prefers a
	// .status file, and ties break on the sorted name.
	tie := map[string]string{"b.out": decoy, "a.out": decoy, "other.status": decoy}
	if name, _, _ := findStatusFile(tie, "workflow.status"); name != "other.status" {
		t.Errorf("findStatusFile = %q; a .status file must outrank a node's stdout", name)
	}
	for i := 0; i < 50; i++ {
		if name, _, _ := findStatusFile(map[string]string{"b.out": decoy, "a.out": decoy},
			"workflow.status"); name != "a.out" {
			t.Fatalf("findStatusFile = %q; equal candidates must resolve the same way twice", name)
		}
	}
}

// TestDagArchiveTruncationStillSaysSomethingWasMissed is R5, kept. The
// archive query stops at its match bound and the nodes past the cut read
// as "unready" -- indistinguishable from a node that never started. A
// finished 100,000-node workflow would report 80% of itself as never
// having run, silently. What the warning must NOT do any more is
// explain the server: see
// TestDagArchiveTruncationWarningFollowsTheBound.
func TestDagArchiveTruncationStillSaysSomethingWasMissed(t *testing.T) {
	big, _ := dagArchiveBounds(1 << 20)
	if w := dagArchiveTruncationWarning(0, 1<<20); w != "" {
		t.Errorf("an empty answer produced a warning: %q", w)
	}
	w := dagArchiveTruncationWarning(big, 1<<20)
	if w == "" {
		t.Fatalf("an answer that hit the limit was reported as complete")
	}
	// A reader has to be able to tell this apart from "nothing ran",
	// which is the whole point of saying anything.
	if !strings.Contains(w, "cut short") || !strings.Contains(w, dagStateUnready) {
		t.Errorf("the warning does not say what the missing nodes may NOT mean: %s", w)
	}
}
