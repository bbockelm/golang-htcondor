//go:build integration

package httpserver

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/bbockelm/golang-htcondor/webapi/mcpserver"
	"github.com/bbockelm/golang-htcondor/webapi/multiap"
	"github.com/bbockelm/golang-htcondor/webapi/watchpoll"
)

// Watches, the dashboard and run-attempt history in multi-AP mode, end
// to end, on the same stack TestMultiAPEndToEnd builds -- two schedds,
// a spoke each, a hub federating epoch_history too -- with the schedds
// writing epoch history.
//
// While spoke 2 is stopped, ap2's 1.0 is removed on schedd 2, and the
// watch over it fires from the job's history record once spoke 2 is
// back. The absence rule itself cannot be exercised here (see
// e2eStaleAPRemoval); its unit tests hold it.
//
// The job that runs is ap1's: epoch history is written by the shadow,
// which reads JOB_EPOCH_HISTORY without the second schedd's local name,
// so in this one-pool harness only the first schedd's file is its own.
func TestMultiAPWatchesEndToEnd(t *testing.T) {
	if testing.Short() {
		t.Skip("integration test (runs two schedds, three htcondordb daemons and an API server)")
	}
	bin := htcondordbBinary(t)
	if os.Geteuid() == 0 {
		t.Skip("schedd sync refuses to run as root; run this test as an ordinary user")
	}
	started := time.Now()
	s := startMultiAPStackWith(t, bin, multiAPStackOptions{
		// Run-attempt history, through each spoke to the hub. (Only ap1
		// runs a job; see above.)
		pool: "\nJOB_EPOCH_HISTORY = $(SPOOL)/epoch_history\n",
		spoke: func(history string) string {
			return "HTCONDORDB_JOB_EPOCH_HISTORY = " + filepath.Join(filepath.Dir(history), "epoch_history") + "\n"
		},
		hub: "HTCONDORDB_FEDERATE_TABLES = jobs history syncstatus epoch_history\n",
	})
	s.waitList(t, "both APs' jobs to reach the API through the hub, with both APs fresh", 90*time.Second,
		s.me, func(l e2eList) bool {
			for _, k := range e2eMine {
				if !containsJob(l.keys(), k) {
					return false
				}
			}
			return l.Sources.APs == 2 && l.Sources.Fresh == 2
		})
	t.Logf("stack up in %s", time.Since(started).Round(time.Second))

	w := &e2eWatches{s: s, token: s.mintToken(t, s.me)}
	for _, phase := range []struct {
		name string
		run  func(*testing.T, *e2eWatches)
	}{
		{"the hub reports each AP's jobs stream caught up", e2eHubPublishesJobsSynced},
		{"watches register over both APs' 1.0", e2eRegisterWatches},
		{"ap1's 1.0 completes and fires the watch for ap1 only", e2eAP1Completes},
		{"the completed job's run attempts come from the hub", e2eEpochsFromHub},
		{"the dashboard counts per AP", e2eDashboardPerAP},
		{"a removal on a stale AP fires nothing until the AP is back", e2eStaleAPRemoval},
	} {
		t.Run(phase.name, func(t *testing.T) { phase.run(t, w) })
	}
	if n := s.srv.multi.scheddCalls.Load(); n != 0 {
		t.Errorf("the single-schedd accessor was called %d times in multi-AP mode", n)
	}
	t.Logf("total %s", time.Since(started).Round(time.Second))
}

type e2eWatches struct {
	s     *multiAPStack
	token string
	// any fires when either 1.0 is done; all when both are. Their URLs
	// report them.
	anyURL, allURL string
}

// call runs an MCP tool and returns its structured content.
func (w *e2eWatches) call(t *testing.T, name string, args map[string]any) map[string]any {
	t.Helper()
	params, _ := json.Marshal(map[string]any{"name": name, "arguments": args})
	resp := sendMCPRequest(t, w.s.client, w.s.baseURL, w.token, mcpserver.MCPMessage{
		JSONRPC: "2.0", ID: 1, Method: "tools/call", Params: params,
	})
	if msg, failed := mcpToolFailure(t, resp); failed {
		t.Fatalf("%s failed: %s", name, msg)
	}
	b, _ := json.Marshal(resp.Result)
	var r struct {
		StructuredContent map[string]any `json:"structuredContent"`
	}
	if err := json.Unmarshal(b, &r); err != nil || r.StructuredContent == nil {
		t.Fatalf("%s: no structured content in %s", name, b)
	}
	return r.StructuredContent
}

// poll redeems a watch URL, blocking up to wait.
func (w *e2eWatches) poll(t *testing.T, watchURL string, wait time.Duration) watchpoll.Answer {
	t.Helper()
	u, err := url.Parse(watchURL)
	if err != nil {
		t.Fatal(err)
	}
	q := u.Query()
	q.Set("wait", fmt.Sprint(int(wait.Seconds())))
	req, _ := http.NewRequest(http.MethodGet, w.s.baseURL+u.Path+"?"+q.Encode(), nil) //nolint:noctx // test
	client := &http.Client{Timeout: wait + 30*time.Second}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("polling the watch URL: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	var a watchpoll.Answer
	if resp.StatusCode != http.StatusOK || json.NewDecoder(resp.Body).Decode(&a) != nil {
		t.Fatalf("watch URL = %d", resp.StatusCode)
	}
	return a
}

func (w *e2eWatches) register(t *testing.T, label, mode string) string {
	t.Helper()
	sc := w.call(t, "watch_jobs", map[string]any{"constraint": "ClusterId == 1", "event": "done", "mode": mode, "label": label})
	id, _ := sc["watch_id"].(string)
	if id == "" || sc["fired"] == true {
		t.Fatalf("watch_jobs %s: %v", label, sc)
	}
	u, _ := w.call(t, "create_watch_url", map[string]any{"watch_id": id})["url"].(string)
	if u == "" {
		t.Fatalf("create_watch_url for %s returned no URL", id)
	}
	return u
}

func matchedIDs(a watchpoll.Answer) []string {
	var out []string
	for _, m := range a.Matched {
		out = append(out, fmt.Sprintf("%d.%d@%s", m.Cluster, m.Proc, m.Schedd))
	}
	return out
}

// e2eHubPublishesJobsSynced: the pinned hub publishes JobsSynced and
// JobsSyncedAt for both APs, so the absence rule runs on the catch-up
// state rather than the older-hub LastReset fallback. A renamed or missing
// attribute would otherwise go unnoticed: the fallback still passes the
// rest of this test.
func e2eHubPublishesJobsSynced(t *testing.T, w *e2eWatches) {
	srcs := w.s.srv.multi.svc.Hub.Sources()
	if len(srcs) != 2 {
		t.Fatalf("the hub lists %d sources, want 2", len(srcs))
	}
	for _, src := range srcs {
		ts := src.TableStatus[multiap.TableJobs]
		if !ts.SyncedKnown || !ts.Synced || ts.SyncedAt.IsZero() {
			t.Errorf("hub source %s jobs stream = %+v, want JobsSynced true with a JobsSyncedAt", src.Schedd, ts)
		}
	}
}

// e2eRegisterWatches: two watches over ClusterId == 1, which is a job on
// each AP; each tracks both, as two jobs.
func e2eRegisterWatches(t *testing.T, w *e2eWatches) {
	w.anyURL = w.register(t, "any", "any")
	w.allURL = w.register(t, "all", "all")
	for _, u := range []string{w.anyURL, w.allURL} {
		if a := w.poll(t, u, 0); a.State != watchpoll.StateWaiting || a.Selected != 2 {
			t.Errorf("a fresh watch = %+v, want waiting on 1.0 on both APs", a)
		}
	}
}

// e2eAP1Completes: ap1's 1.0 runs (the startd takes only E2ERun jobs)
// and finishes; the "any" watch fires naming it and nothing on ap2.
func e2eAP1Completes(t *testing.T, w *e2eWatches) {
	s := w.s
	s.condor(t, "condor_qedit", "-name", e2eAP1, "1.0", "Args", `"2"`)
	s.condor(t, "condor_qedit", "-name", e2eAP1, "1.0", "E2ERun", "true")
	var a watchpoll.Answer
	deadline := time.Now().Add(4 * time.Minute)
	for a.State != watchpoll.StateFired && time.Now().Before(deadline) {
		a = w.poll(t, w.anyURL, 60*time.Second)
	}
	if a.State != watchpoll.StateFired {
		t.Fatalf("the any-watch did not fire after %s completed: %+v", e2eAP1Job1, a)
	}
	if got := matchedIDs(a); len(got) != 1 || got[0] != e2eAP1Job1.String() || a.MatchedTotal != 1 {
		t.Fatalf("fired for %v (total %d), want %s alone", got, a.MatchedTotal, e2eAP1Job1)
	}
	if a.Matched[0].Attrs["JobStatus"] != "4" {
		t.Errorf("%s matched with %v, want its completed record", e2eAP1Job1, a.Matched[0].Attrs)
	}
	if b := w.poll(t, w.allURL, 0); b.State != watchpoll.StateWaiting {
		t.Errorf("the all-watch = %+v with %s still queued", b, e2eAP2Job1)
	}
}

// e2eEpochsFromHub: the completed job's run attempt reaches the hub's
// epoch_history and is served from there, for that AP's 1.0 only; ap2's
// 1.0 never ran.
func e2eEpochsFromHub(t *testing.T, w *e2eWatches) {
	s := w.s
	path := "/api/v1/jobs/epochs?job_id=" + url.QueryEscape(e2eAP1Job1.String())
	var l e2eList
	var lastErr error
	t.Cleanup(func() {
		if t.Failed() {
			t.Logf("last epochs read: %+v, %v", l, lastErr)
			for _, src := range s.srv.multi.svc.Hub.Sources() {
				t.Logf("hub source %s: %s tables %v", src.Schedd, src.State, src.Tables)
			}
		}
	})
	waitFor(t, "the run attempt of "+e2eAP1Job1.String()+" to reach the hub", 90*time.Second, func() bool {
		l, lastErr = s.tryList(t, s.me, path)
		return lastErr == nil && len(l.Ads) > 0
	})
	for _, r := range l.Ads {
		if r.key() != e2eAP1Job1 {
			t.Errorf("epochs for %s returned %s", e2eAP1Job1, r.key())
		}
	}
	all := s.list(t, s.me, "/api/v1/jobs/epochs")
	for _, r := range all.Ads {
		if r.key() == e2eAP2Job1 {
			t.Errorf("%s never ran, but has a run attempt", e2eAP2Job1)
		}
	}
}

// e2eDashboardPerAP: the dashboard counts the caller's jobs per AP.
func e2eDashboardPerAP(t *testing.T, w *e2eWatches) {
	s := w.s
	// ap1: 2.0 once the finished 1.0 has left the queue (3.0 is another
	// user's); ap2: 1.0 and 2.0.
	var d DashboardResponse
	per := map[string]int{}
	waitFor(t, "the dashboard to count "+e2eAP1Job1.String()+" gone", 60*time.Second, func() bool {
		code, body := s.get(t, s.me, "/api/v1/dashboard")
		d = DashboardResponse{}
		if code != http.StatusOK || json.Unmarshal([]byte(body), &d) != nil {
			t.Fatalf("dashboard = %d %s", code, body)
		}
		per = map[string]int{}
		for _, ap := range d.APs {
			per[ap.Schedd] = ap.JobsTotal
		}
		return per[e2eAP1] == 1
	})
	if per[e2eAP2] != 2 || d.JobsTotal != 3 || d.Sources == nil || d.Sources.APs != 2 {
		t.Errorf("dashboard per AP %v total %d sources %+v, want %s:1 %s:2", per, d.JobsTotal, d.Sources, e2eAP1, e2eAP2)
	}
	code, body := s.get(t, s.me, "/api/v1/dashboard/activity")
	var a DashboardActivityResponse
	if code != http.StatusOK || json.Unmarshal([]byte(body), &a) != nil {
		t.Fatalf("dashboard activity = %d %s", code, body)
	}
	found := false
	for _, ap := range a.APs {
		if ap.Schedd == e2eAP1 {
			found = true
			if ap.FinishedRecently < 1 {
				t.Errorf("%s finished_recently %d, want %s counted", e2eAP1, ap.FinishedRecently, e2eAP1Job1)
			}
		}
	}
	if !found {
		t.Errorf("dashboard activity aps %+v lacks %s", a.APs, e2eAP1)
	}
}

// e2eStaleAPRemoval: with spoke 2 stopped, ap2's 1.0 is removed on its
// schedd; the watch is still waiting and the dashboard calls ap2 not
// current. Once spoke 2 is back, the job's history record fires the
// all-watch.
//
// This does not test the absence rule: the hub keeps a stopped spoke's
// rows (until HTCONDORDB_FEDERATE_RETIRE_AFTER), so ap2's 1.0 is never
// missing from the hub's queue while ap2 is stale, and an evaluator that
// ignored coverage would wait here too. The rule -- stale, absent,
// untrusted, disconnected, erroring, replaying or catching-up sources,
// an unreachable hub, the horizon -- is held by the unit tests in
// webapi/multiap (watch_test.go) and webapi/jobwatch
// (multiap_absence_test.go).
func e2eStaleAPRemoval(t *testing.T, w *e2eWatches) {
	s := w.s
	s.spoke2.Stop()
	s.waitList(t, e2eAP2+" to go stale", 60*time.Second, s.me, func(l e2eList) bool {
		return l.degraded(e2eAP2) != nil
	})
	s.condorRm(t, e2eAP2Job1)

	if a := w.poll(t, w.allURL, 0); a.State != watchpoll.StateWaiting {
		t.Fatalf("the all-watch = %+v while %s is stale; its removal cannot have been seen", a, e2eAP2)
	}
	code, body := s.get(t, s.me, "/api/v1/dashboard")
	var d DashboardResponse
	if code != http.StatusOK || json.Unmarshal([]byte(body), &d) != nil {
		t.Fatalf("dashboard = %d %s", code, body)
	}
	found := false
	for _, ap := range d.APs {
		if ap.Schedd == e2eAP2 {
			found = true
			if ap.State == multiap.StateFresh {
				t.Errorf("dashboard reports %s fresh with its spoke stopped", e2eAP2)
			}
		}
	}
	if !found {
		t.Errorf("dashboard aps %+v lacks %s", d.APs, e2eAP2)
	}

	s.spoke2.Start()
	var a watchpoll.Answer
	deadline := time.Now().Add(3 * time.Minute)
	for a.State != watchpoll.StateFired && time.Now().Before(deadline) {
		a = w.poll(t, w.allURL, 60*time.Second)
	}
	if a.State != watchpoll.StateFired {
		t.Fatalf("the all-watch did not fire after spoke 2 came back: %+v", a)
	}
	got := map[string]string{}
	for _, m := range a.Matched {
		got[fmt.Sprintf("%d.%d@%s", m.Cluster, m.Proc, m.Schedd)] = m.Attrs["JobStatus"]
	}
	// Removed (3) from its history record, completed (4) from its own.
	if len(got) != 2 || got[e2eAP2Job1.String()] != "3" || got[e2eAP1Job1.String()] != "4" {
		t.Errorf("all-watch fired with %v, want %s from its history record (JobStatus 3) and %s (4)",
			got, e2eAP2Job1, e2eAP1Job1)
	}
}
