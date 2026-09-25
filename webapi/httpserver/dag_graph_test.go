package httpserver

import (
	"archive/tar"
	"bytes"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"

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
	want := "This workflow was submitted from a shell on the access point, so its files are in " +
		"/home/alice/workflows and are not readable through this server."
	if msg != want {
		t.Errorf("message =\n%q\nwant\n%q", msg, want)
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

func TestDagStructureCacheHit(t *testing.T) {
	c := newDagStructureCache(4, time.Hour)
	want := testStructure("a.dag")
	c.put("k", want)
	got, ok := c.get("k")
	if !ok || got != want {
		t.Fatalf("get after put = %v, %v", got, ok)
	}
	if _, ok := c.get("other"); ok {
		t.Errorf("an unrelated key hit the cache")
	}
}

// TestDagStructureCacheEvictsOldest fills the real 16-entry cache and
// puts a 17th, which must push the first one out.
func TestDagStructureCacheEvictsOldest(t *testing.T) {
	c := newDagStructureCache(dagCacheMaxEntries, time.Hour)
	for i := 0; i < dagCacheMaxEntries; i++ {
		c.put(fmt.Sprintf("k%d", i), testStructure(fmt.Sprintf("d%d.dag", i)))
	}
	if _, ok := c.get("k0"); !ok {
		t.Fatalf("the oldest entry was evicted before the cache was full")
	}
	c.put("k16", testStructure("d16.dag"))
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
	c.put("a", testStructure("a.dag"))
	c.put("b", testStructure("b.dag"))
	c.put("a", testStructure("a2.dag")) // a is now the newest
	c.put("c", testStructure("c.dag"))  // evicts b, not a
	if _, ok := c.get("b"); ok {
		t.Errorf("b should have been evicted")
	}
	got, ok := c.get("a")
	if !ok || got.dagFile != "a2.dag" {
		t.Errorf("a = %v, %v; want the replacement", got, ok)
	}
}

func TestDagStructureCacheTTLExpiry(t *testing.T) {
	now := time.Now()
	const ttl = 30 * time.Minute
	c := newDagStructureCache(4, ttl)
	c.now = func() time.Time { return now }
	c.put("k", testStructure("a.dag"))

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

	if _, err := cachedDagStructure(c, "k", false, build); err != nil {
		t.Fatalf("first build: %v", err)
	}
	if builds != 1 {
		t.Fatalf("first call built %d times, want 1", builds)
	}

	got, err := cachedDagStructure(c, "k", false, build)
	if err != nil {
		t.Fatalf("cached load: %v", err)
	}
	if builds != 1 {
		t.Errorf("an ordinary load re-fetched the sandbox (%d builds)", builds)
	}
	if got.dagFile != "build1.dag" {
		t.Errorf("cached load returned %q", got.dagFile)
	}

	got, err = cachedDagStructure(c, "k", true, build)
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
	got, err = cachedDagStructure(c, "k", false, build)
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
	if _, err := cachedDagStructure(c, "k", false, func() (*dagStructure, error) {
		return nil, want
	}); !errors.Is(err, want) {
		t.Fatalf("err = %v, want %v", err, want)
	}
	if _, ok := c.get("k"); ok {
		t.Errorf("a failed build was cached")
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
	states, at, next := parseNodeStatusFile(body)
	if len(states) != 1 || states["produce_1"].state != dagStateDone {
		t.Fatalf("states = %v", states)
	}
	if at != 1790295242 || next != 0 {
		t.Errorf("timestamp/next = %d/%d", at, next)
	}

	// The same file in JSON, since the spelling travels with the ad and
	// not with the format.
	states, _, _ = parseNodeStatusFile(
		`{"Type":"NodeStatus","Node":"produce_1","NodeStatus":5}` + "\n")
	if len(states) != 1 || states["produce_1"].state != dagStateDone {
		t.Fatalf("json states = %v", states)
	}
}

func TestParseNodeStatusFileClassAd(t *testing.T) {
	states, at, next := parseNodeStatusFile(sampleNodeStatusFile)
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
	states, at, next := parseNodeStatusFile(sampleNodeStatusJSON)
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
	states, at, _ := parseNodeStatusFile(`{
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
	_, _, next := parseNodeStatusFile(
		`{"MyType":"NodeStatus","Node":"a","NodeStatus":5}` + "\n" +
			`{"MyType":"StatusEnd","Timestamp":1700000000,"NextUpdate":0}` + "\n")
	if next != 0 {
		t.Errorf("NextUpdate = %d, want 0", next)
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
			states, _, _ := parseNodeStatusFile(tc.body)
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
	states, at, next := parseNodeStatusFile("")
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
	files, err := collectTarTextFiles(tar.NewReader(buf), dagBigFilePredicate("workflow.dag"))
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
	_, err := collectTarTextFiles(tar.NewReader(buf), dagBigFilePredicate("big.dag"))
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
	files, err := collectTarTextFiles(tar.NewReader(buf), dagBigFilePredicate("workflow.dag"))
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
	files, err := collectTarTextFiles(tar.NewReader(buf), dagBigFilePredicate("fanout.dag"))
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
	states, at, _ := parseNodeStatusFile(statusBody)
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
	if !strings.Contains(msg, "instrumented") {
		t.Errorf("the message should say workflows submitted here are instrumented: %q", msg)
	}

	done := adFrom(t, fmt.Sprintf("JobStatus = 4\nJobCurrentStartDate = %d\n", time.Now().Unix()))
	if msg := dagNoStructureMessage(done, "workflow.dot", false); !strings.Contains(msg, "declares no DOT") {
		t.Errorf("a finished workflow with no dot file declares none: %q", msg)
	}
}

// --- state freshness --------------------------------------------------

// TestDagStateStale: the structure may be cached for an hour, but the
// node states sharing its cache entry are live data and may not.
func TestDagStateStale(t *testing.T) {
	now := time.Now()
	fresh := &dagStructure{statusFileName: "w.status", statusNextUpdate: now.Unix() + 30, fetchedAt: now}
	if dagStateStale(fresh, now.Add(dagStatusMaxAge/2)) {
		t.Errorf("a status file read seconds ago is not stale")
	}
	if !dagStateStale(fresh, now.Add(dagStatusMaxAge+time.Second)) {
		t.Errorf("an old status file must be re-read: the state half of this endpoint is live")
	}

	// A workflow DAGMan has finished with wrote NextUpdate 0. Its states
	// will never change again, so re-fetching its whole sandbox for them
	// would be pure waste.
	final := &dagStructure{statusFileName: "w.status", statusNextUpdate: 0, fetchedAt: now}
	if dagStateStale(final, now.Add(24*time.Hour)) {
		t.Errorf("a finished workflow's final status file never goes stale")
	}

	// And a workflow with no status file at all has no live half.
	none := &dagStructure{fetchedAt: now}
	if dagStateStale(none, now.Add(24*time.Hour)) {
		t.Errorf("a workflow with no status file has nothing to go stale")
	}
}
