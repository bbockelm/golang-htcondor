//go:build integration

package httpserver

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/PelicanPlatform/classad/classad"
	"github.com/bbockelm/cedar/security"

	htcondor "github.com/bbockelm/golang-htcondor"
	"github.com/bbockelm/golang-htcondor/webapi/mcpserver"
	"github.com/bbockelm/golang-htcondor/webapi/multiap"
)

// Multi-AP mode, end to end: two real schedds, a real htcondordb spoke
// syncing each one's job_queue.log and history, a real federation hub
// discovering both spokes through the collector, and the API server in
// multi-AP mode discovering the hub through the collector.
//
// Every other multi-AP test reads hub-shaped tables built by hand in an
// in-process database, and the hub's own tests feed its spokes
// synthetic logs. So nothing else checks that the hub's contract (table
// names, ScheddName on every row, federation_sources states) is what
// the API reads, that collector discovery pairs real spokes with real
// schedds, or that a change on a schedd reaches the API through the
// whole chain. A drift between htcondordb and the API passes every other
// test and fails here.
//
// The stack is built once and the phases run in order, because each one
// starts from the state the previous one left (a removed job, a stopped
// spoke).

// The two access points. The host part of each name is what the hub's
// spoke validation compares with the host of the spoke's address: a
// spoke is paired with a schedd only when its primary address is the
// schedd's host. Everything here listens on 127.0.0.1, so the schedds
// are named for it -- a name ending in this machine's hostname would
// resolve to some other interface and the hub would rightly refuse the
// pairing.
const (
	e2eAP1 = "ap1@127.0.0.1"
	e2eAP2 = "ap2@127.0.0.1"
	// e2eAPConstraint selects both, and nothing else, for the API
	// server and the hub alike.
	e2eAPConstraint = `regexp("^ap[12]@", Name)`
	// e2eOther is the second identity, whose job must never appear in
	// the test user's listings.
	e2eOther = "bob"
)

// multiAPStack is the running system under test.
type multiAPStack struct {
	harness *htcondor.CondorTestHarness
	cfgFile string
	dir     string
	spoke1  *htcondordbProc
	spoke2  *htcondordbProc
	hub     *htcondordbProc
	baseURL string
	client  *http.Client
	me      string // the test user's OS name, which is the jobs' Owner
	srv     *Server
}

// apJob names a job across APs.
type apJob struct {
	schedd        string
	cluster, proc int64
}

func (k apJob) String() string { return fmt.Sprintf("%d.%d@%s", k.cluster, k.proc, k.schedd) }

// The jobs startMultiAPStack submits. Each schedd is fresh, so its first
// cluster is 1: 1.0 exists on both APs.
var (
	e2eAP1Job1  = apJob{e2eAP1, 1, 0}
	e2eAP1Job2  = apJob{e2eAP1, 2, 0}
	e2eAP1Other = apJob{e2eAP1, 3, 0} // e2eOther's
	e2eAP2Job1  = apJob{e2eAP2, 1, 0}
	e2eAP2Job2  = apJob{e2eAP2, 2, 0}
	// e2eMine is the test user's.
	e2eMine = []apJob{e2eAP1Job1, e2eAP1Job2, e2eAP2Job1, e2eAP2Job2}
)

func TestMultiAPEndToEnd(t *testing.T) {
	if testing.Short() {
		t.Skip("integration test (runs two schedds, three htcondordb daemons and an API server)")
	}
	// Look for the daemon before paying for a pool.
	bin := htcondordbBinary(t)
	if os.Geteuid() == 0 {
		// htcondordb refuses schedd sync as root (it would follow the
		// schedd's files with root's privileges), so the spokes cannot
		// run. Every CI job that runs this tag runs as a normal user.
		t.Skip("schedd sync refuses to run as root; run this test as an ordinary user")
	}
	s := startMultiAPStack(t, bin)

	// Convergence: both spokes have synced, the hub has both, and both
	// are fresh. Everything after this asserts on a settled system. Only
	// presence is waited for: anything extra is for the phases to name.
	s.waitList(t, "both APs' jobs to reach the API through the hub, with both APs fresh", 90*time.Second,
		s.me, func(l e2eList) bool {
			for _, k := range e2eMine {
				if !containsJob(l.keys(), k) {
					return false
				}
			}
			return l.Sources.APs == 2 && l.Sources.Fresh == 2
		})

	// In order: each phase starts from the state the last one left.
	for _, phase := range []struct {
		name string
		run  func(*testing.T, *multiAPStack)
	}{
		{"spokes and hub advertise what discovery pairs on", e2eAdvertisements},
		{"jobs from both APs, with identities", e2eListsBothAPs},
		{"another user's jobs never appear", e2eScopesToTheCaller},
		{"aps lists both with hub state", e2eListsAPs},
		{"single job by complete id and by an ambiguous one", e2eGetsSingleJobs},
		{"mutating routes are refused", e2eRefusesMutations},
		{"MCP query_jobs and get_job", e2eMCPReads},
		{"a job removed on its schedd leaves the list and enters history", e2eRemovalReachesTheAPI},
		{"a stopped spoke degrades its AP and a restarted one recovers", e2eSpokeOutage},
		{"a stopped hub is an error, not an empty queue, and single-job reads use the spoke", e2eHubOutage},
	} {
		t.Run(phase.name, func(t *testing.T) { phase.run(t, s) })
	}

	// Nothing above may have reached the single-schedd accessor.
	if n := s.srv.multi.scheddCalls.Load(); n != 0 {
		t.Errorf("the single-schedd accessor was called %d times in multi-AP mode", n)
	}
}

// e2eAdvertisements: each spoke names the schedd it mirrors as the
// schedd names itself (read from the schedd's address file -- the
// derived fallback would name this host, not 127.0.0.1), and the hub
// advertises the AP set it was configured with and both sources fresh.
// Discovery on both sides pairs on these.
func e2eAdvertisements(t *testing.T, s *multiAPStack) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	coll := htcondor.NewCollector(s.harness.GetCollectorAddr())
	ads, _, err := coll.QueryAdsWithOptions(ctx, "HTCondorDB", "true", &htcondor.QueryOptions{
		Limit: -1, Projection: []string{"Name", "MirroredScheddName", "FederationConstraint", "SourcesFresh", "SourcesTotal"},
	})
	if err != nil {
		t.Fatalf("querying HTCondorDB ads: %v", err)
	}
	byName := map[string]*classad.ClassAd{}
	for _, ad := range ads {
		if n, ok := ad.EvaluateAttrString("Name"); ok {
			byName[n] = ad
		}
	}
	for spoke, schedd := range map[string]string{"spoke1@127.0.0.1": e2eAP1, "spoke2@127.0.0.1": e2eAP2} {
		ad := byName[spoke]
		if ad == nil {
			t.Errorf("no ad for %s among %d HTCondorDB ads", spoke, len(ads))
			continue
		}
		if got, _ := ad.EvaluateAttrString("MirroredScheddName"); got != schedd {
			t.Errorf("%s advertises MirroredScheddName %q, want %q", spoke, got, schedd)
		}
	}
	hub := byName["hub@127.0.0.1"]
	if hub == nil {
		t.Fatalf("no hub ad among %d HTCondorDB ads", len(ads))
	}
	if got, _ := hub.EvaluateAttrString("FederationConstraint"); !strings.Contains(got, e2eAPConstraint) {
		t.Errorf("hub FederationConstraint = %q, want it to carry %s", got, e2eAPConstraint)
	}
	if _, ok := hub.EvaluateAttrString("MirroredScheddName"); ok {
		t.Error("the hub claims to mirror a schedd")
	}
	// The ad lags the hub's state by up to an update interval.
	waitFor(t, "the hub's ad to report both sources fresh", 30*time.Second, func() bool {
		ads, _, err := coll.QueryAdsWithOptions(ctx, "HTCondorDB", `Name == "hub@127.0.0.1"`, &htcondor.QueryOptions{
			Limit: -1, Projection: []string{"SourcesFresh", "SourcesTotal"},
		})
		if err != nil || len(ads) != 1 {
			return false
		}
		fresh, _ := ads[0].EvaluateAttrInt("SourcesFresh")
		total, _ := ads[0].EvaluateAttrInt("SourcesTotal")
		return fresh == 2 && total == 2
	})
}

// e2eListsBothAPs: both APs' jobs, each with its identity, and the
// same cluster.proc on two APs as two jobs.
func e2eListsBothAPs(t *testing.T, s *multiAPStack) {
	l := s.list(t, s.me, "/api/v1/jobs")
	if !sameJobs(l.keys(), e2eMine) {
		t.Fatalf("jobs = %v, want %v", l.keys(), e2eMine)
	}
	// The same cluster.proc on two APs is two jobs.
	seen := map[string]bool{}
	for _, j := range l.Jobs {
		k := j.key()
		if want := k.cluster; mustInt(t, j.raw["ClusterId"]) != want {
			t.Errorf("%s: ClusterId %v disagrees with cluster %d", k, j.raw["ClusterId"], want)
		}
		if want := fmt.Sprintf("%d.%d@%s", k.cluster, k.proc, k.schedd); j.JobID != want {
			t.Errorf("%s: job_id = %q, want %q", k, j.JobID, want)
		}
		if seen[j.JobID] {
			t.Errorf("job_id %q listed twice", j.JobID)
		}
		seen[j.JobID] = true
		if got, want := j.raw["ScheddName"], k.schedd; got != want {
			t.Errorf("%s: ScheddName = %v, want %q (the hub stamps it from the source)", k, got, want)
		}
		if got, want := j.raw["Owner"], s.me; got != want {
			t.Errorf("%s: Owner = %v, want %q", k, got, want)
		}
	}
	if !seen[e2eAP1Job1.String()] || !seen[e2eAP2Job1.String()] {
		t.Errorf("1.0 is not listed on both APs: %v", l.keys())
	}

	// The per-AP filter, both ways.
	for _, c := range []struct {
		schedd string
		want   []apJob
	}{{e2eAP1, []apJob{e2eAP1Job1, e2eAP1Job2}}, {e2eAP2, []apJob{e2eAP2Job1, e2eAP2Job2}}} {
		l := s.list(t, s.me, "/api/v1/jobs?schedd="+url.QueryEscape(c.schedd))
		if !sameJobs(l.keys(), c.want) {
			t.Errorf("?schedd=%s: jobs = %v, want %v", c.schedd, l.keys(), c.want)
		}
	}
}

// e2eScopesToTheCaller: another user's job is never listed or resolved.
func e2eScopesToTheCaller(t *testing.T, s *multiAPStack) {
	// Guard the setup: the other job really is someone else's on the
	// schedd, so its absence below means the scope held rather than
	// that the job never existed.
	if got := s.scheddAttr(t, e2eAP1, e2eAP1Other, "User"); got != e2eOther+"@"+s.harness.GetTrustDomain() {
		t.Fatalf("setup: %s has User %q on its schedd, want %s@%s", e2eAP1Other, got, e2eOther, s.harness.GetTrustDomain())
	}
	for _, path := range []string{"/api/v1/jobs", "/api/v1/jobs?constraint=true", "/api/v1/jobs?constraint=" + url.QueryEscape(`Owner == "`+e2eOther+`"`)} {
		for _, k := range s.list(t, s.me, path).keys() {
			if k == e2eAP1Other {
				t.Errorf("GET %s as %s returned %s's job %s", path, s.me, e2eOther, k)
			}
		}
	}
	// And the other user sees exactly theirs.
	if got := s.list(t, e2eOther, "/api/v1/jobs").keys(); !sameJobs(got, []apJob{e2eAP1Other}) {
		t.Errorf("%s's jobs = %v, want [%s]", e2eOther, got, e2eAP1Other)
	}
	// Resolving a bare id runs over the hub too, and must not find it.
	if code, body := s.get(t, s.me, "/api/v1/jobs/3.0"); code != http.StatusNotFound {
		t.Errorf("GET /api/v1/jobs/3.0 as %s = %d %s, want 404 (it is %s's)", s.me, code, body, e2eOther)
	}
}

// e2eListsAPs: GET /api/v1/aps names both APs with the hub's state.
func e2eListsAPs(t *testing.T, s *multiAPStack) {
	aps := s.aps(t)
	if !aps.Hub.Reachable {
		t.Errorf("hub not reachable: %+v", aps.Hub)
	}
	if aps.Constraint != e2eAPConstraint {
		t.Errorf("constraint = %q", aps.Constraint)
	}
	got := map[string]multiap.APInfo{}
	for _, a := range aps.APs {
		got[a.Schedd] = a
	}
	for _, name := range []string{e2eAP1, e2eAP2} {
		a, ok := got[name]
		switch {
		case !ok:
			t.Errorf("%s missing from %+v", name, aps.APs)
		case !a.InCollector || a.Address == "":
			t.Errorf("%s: in_collector=%v address=%q", name, a.InCollector, a.Address)
		case a.Hub.State != multiap.StateFresh:
			t.Errorf("%s: hub state %q (%s), want fresh", name, a.Hub.State, a.Hub.Reason)
		}
	}
	if len(aps.APs) != 2 {
		t.Errorf("%d APs listed: %+v", len(aps.APs), aps.APs)
	}
}

// e2eGetsSingleJobs: a complete id is served from the hub; a bare one
// on both APs is a 409 naming both.
func e2eGetsSingleJobs(t *testing.T, s *multiAPStack) {
	j := s.getJob(t, s.me, e2eAP1Job1.String())
	if j.key() != e2eAP1Job1 || j.Source != multiap.SourceHub {
		t.Errorf("GET %s = %s from %q, want it from the hub", e2eAP1Job1, j.key(), j.Source)
	}
	// 1.0 is on both APs: name one.
	code, body := s.get(t, s.me, "/api/v1/jobs/1.0")
	if code != http.StatusConflict {
		t.Fatalf("GET /api/v1/jobs/1.0 = %d %s, want 409", code, body)
	}
	var conflict struct {
		Candidates []multiap.JobRef `json:"candidates"`
	}
	if err := json.Unmarshal([]byte(body), &conflict); err != nil {
		t.Fatalf("decoding the 409: %v: %s", err, body)
	}
	var cands []apJob
	for _, c := range conflict.Candidates {
		cands = append(cands, apJob{c.Schedd, c.Cluster, c.Proc})
		if c.JobID != (apJob{c.Schedd, c.Cluster, c.Proc}).String() {
			t.Errorf("candidate job_id %q does not name %s", c.JobID, c.Schedd)
		}
	}
	if !sameJobs(cands, []apJob{e2eAP1Job1, e2eAP2Job1}) {
		t.Errorf("409 candidates = %v, want both 1.0s", cands)
	}
	// A bare id that matches one of the caller's jobs is resolved to
	// it: 3.0 is only on ap1, and it is the other user's.
	if j := s.getJob(t, e2eOther, "3.0"); j.key() != e2eAP1Other {
		t.Errorf("GET 3.0 as %s = %s, want %s", e2eOther, j.key(), e2eAP1Other)
	}
}

// e2eRefusesMutations: multi-AP mode is read-only.
func e2eRefusesMutations(t *testing.T, s *multiAPStack) {
	code, body := s.do(t, s.me, http.MethodPost, "/api/v1/jobs", `{"submit_file":"executable=/bin/true\nqueue\n"}`)
	if code != http.StatusNotImplemented {
		t.Errorf("POST /api/v1/jobs = %d %s, want 501", code, body)
	}
	code, body = s.do(t, s.me, http.MethodDelete, "/api/v1/jobs/"+url.PathEscape(e2eAP1Job1.String()), "")
	if code != http.StatusNotImplemented {
		t.Errorf("DELETE /api/v1/jobs/%s = %d %s, want 501", e2eAP1Job1, code, body)
	}
	// Refused, so the job is still there.
	if got := s.scheddAttr(t, e2eAP1, e2eAP1Job1, "JobStatus"); got != "1" {
		t.Errorf("%s has JobStatus %q after a refused DELETE", e2eAP1Job1, got)
	}
}

// e2eMCPReads: the MCP read tools over the same hub.
func e2eMCPReads(t *testing.T, s *multiAPStack) {
	// A bearer the API must identify by asking a member schedd, so
	// this also runs the multi-AP identity ping against a real one.
	token := s.mintToken(t, s.me)
	text := s.mcpTool(t, token, "query_jobs", map[string]any{"constraint": "true", "limit": 50})
	var got []apJob
	for _, j := range decodeToolRows(t, text) {
		got = append(got, j.key())
	}
	if !sameJobs(got, e2eMine) {
		t.Errorf("query_jobs = %v, want %v\n%s", got, e2eMine, text)
	}
	text = s.mcpTool(t, token, "get_job", map[string]any{"job_id": e2eAP2Job1.String()})
	// "Job <id>:\n{...}\n".
	_, rest, _ := strings.Cut(text, "\n")
	var raw json.RawMessage
	if err := json.NewDecoder(strings.NewReader(rest)).Decode(&raw); err != nil {
		t.Fatalf("decoding get_job: %v\n%s", err, text)
	}
	if j := decodeRow(t, raw); j.key() != e2eAP2Job1 {
		t.Errorf("get_job %s returned %s", e2eAP2Job1, j.key())
	}
}

// e2eRemovalReachesTheAPI: a job removed on its schedd leaves the list
// and appears in history, through spoke and hub.
func e2eRemovalReachesTheAPI(t *testing.T, s *multiAPStack) {
	s.condorRm(t, e2eAP1Job2)
	s.waitList(t, e2eAP1Job2.String()+" to leave the list", 60*time.Second, s.me, func(l e2eList) bool {
		return sameJobs(l.keys(), []apJob{e2eAP1Job1, e2eAP2Job1, e2eAP2Job2})
	})
	s.waitArchive(t, e2eAP1Job2)
}

// e2eSpokeOutage: a stopped spoke degrades its AP without dropping its
// rows, and a restarted one catches up what it missed.
func e2eSpokeOutage(t *testing.T, s *multiAPStack) {
	s.spoke2.Stop()

	l := s.waitList(t, e2eAP2+" to be reported degraded", 60*time.Second, s.me, func(l e2eList) bool {
		return l.Sources.Fresh == 1 && l.degraded(e2eAP2) != nil
	})
	if d := l.degraded(e2eAP2); d.State != multiap.StateStale {
		t.Errorf("%s degraded as %q (%s), want stale", e2eAP2, d.State, d.Reason)
	}
	if l.degraded(e2eAP1) != nil {
		t.Errorf("%s reported degraded too: %+v", e2eAP1, l.Sources.Degraded)
	}
	// A stale AP's rows are still served, flagged.
	if !sameJobs(l.keys(), []apJob{e2eAP1Job1, e2eAP2Job1, e2eAP2Job2}) {
		t.Errorf("jobs with %s stale = %v; its rows should remain", e2eAP2, l.keys())
	}
	for _, a := range s.aps(t).APs {
		if a.Schedd == e2eAP2 && a.Hub.State != multiap.StateStale {
			t.Errorf("/api/v1/aps: %s hub state %q, want stale", e2eAP2, a.Hub.State)
		}
	}

	// With the hub's copy stale and the spoke gone, a single-job read
	// goes to the schedd itself.
	j := s.getJob(t, s.me, e2eAP2Job1.String())
	if j.key() != e2eAP2Job1 {
		t.Errorf("GET %s returned %s", e2eAP2Job1, j.key())
	}
	if j.Source != multiap.SourceSchedd {
		t.Errorf("GET %s with its spoke stopped came from %q, want %q", e2eAP2Job1, j.Source, multiap.SourceSchedd)
	}
	if j.Degraded == nil || j.Degraded.Schedd != e2eAP2 {
		t.Errorf("GET %s does not say its AP is degraded: %+v", e2eAP2Job1, j.Degraded)
	}

	// A change the hub cannot see yet: the stale row stays until the
	// spoke is back.
	s.condorRm(t, e2eAP2Job2)
	if !containsJob(s.list(t, s.me, "/api/v1/jobs").keys(), e2eAP2Job2) {
		t.Errorf("%s vanished while its AP's spoke was down; nothing could have reported it", e2eAP2Job2)
	}

	s.spoke2.Start()
	s.waitList(t, e2eAP2+" to be fresh again, with the removal caught up", 90*time.Second, s.me, func(l e2eList) bool {
		return l.Sources.Fresh == 2 && sameJobs(l.keys(), []apJob{e2eAP1Job1, e2eAP2Job1})
	})
	s.waitArchive(t, e2eAP2Job2)
	if j := s.getJob(t, s.me, e2eAP2Job1.String()); j.Source != multiap.SourceHub || j.Degraded != nil {
		t.Errorf("GET %s after recovery: source %q degraded %+v, want the hub and no degradation", e2eAP2Job1, j.Source, j.Degraded)
	}
}

// e2eHubOutage: a stopped hub is an error, not an empty queue; a
// single-job read uses the spoke; a restarted hub serves again.
func e2eHubOutage(t *testing.T, s *multiAPStack) {
	s.hub.Stop()

	// The hub not answering must not read as "you have no jobs".
	code, body := s.get(t, s.me, "/api/v1/jobs")
	if code != http.StatusServiceUnavailable {
		t.Errorf("GET /api/v1/jobs with the hub stopped = %d %s, want 503", code, body)
	}
	// A single-job read falls through to the AP's own spoke.
	if j := s.getJob(t, s.me, e2eAP1Job1.String()); j.key() != e2eAP1Job1 || j.Source != multiap.SourceSpoke {
		t.Errorf("GET %s with the hub stopped = %s from %q, want it from the spoke", e2eAP1Job1, j.key(), j.Source)
	}

	started := time.Now()
	s.hub.Start()
	s.waitList(t, "the restarted hub to serve both APs fresh", 90*time.Second, s.me, func(l e2eList) bool {
		return l.Sources.Fresh == 2 && sameJobs(l.keys(), []apJob{e2eAP1Job1, e2eAP2Job1})
	})
	t.Logf("reads recovered %s after the hub restarted", time.Since(started).Round(100*time.Millisecond))
}

// startMultiAPStack builds the pool, submits the jobs, and starts the
// spokes, the hub and the API server.
func startMultiAPStack(t *testing.T, bin string) *multiAPStack {
	t.Helper()
	me, err := user.Current()
	if err != nil {
		t.Fatal(err)
	}
	s := &multiAPStack{dir: t.TempDir(), me: me.Username, client: &http.Client{Timeout: 30 * time.Second}}

	// The second schedd's own state, outside the harness tree (which does
	// not exist until the harness creates it).
	ap2Dir := filepath.Join(s.dir, "schedd2")
	ap2Spool := filepath.Join(ap2Dir, "spool")
	if err := os.MkdirAll(ap2Spool, 0o750); err != nil {
		t.Fatal(err)
	}

	// Two schedds in one pool: the harness's own, renamed, and a second
	// under the local name SCHEDD2 with its own spool, queue log, history
	// and address file. No startd or negotiator: the jobs stay idle,
	// which keeps every state the test asserts on one it caused.
	poolCfg := fmt.Sprintf(`
DAEMON_LIST = MASTER, COLLECTOR, SCHEDD, SCHEDD2
DC_DAEMON_LIST = + SCHEDD2
UID_DOMAIN = %[1]s
SCHEDD_NAME = %[2]s
SCHEDD_INTERVAL = 2
SCHEDD2 = $(SCHEDD)
SCHEDD2_ARGS = -local-name SCHEDD2
SCHEDD2.SCHEDD_NAME = %[3]s
SCHEDD2.SPOOL = %[4]s
SCHEDD2.JOB_QUEUE_LOG = %[4]s/job_queue.log
SCHEDD2.HISTORY = %[4]s/history
SCHEDD2.SCHEDD_ADDRESS_FILE = %[5]s/.schedd_address
SCHEDD2.SCHEDD_DAEMON_AD_FILE = %[5]s/.schedd_classad
SCHEDD2.SCHEDD_LOG = $(LOG)/SchedLog2
# Lets a job be queued for another owner (+Owner), as a submit portal
# does; the test user is not root.
QUEUE_ALL_USERS_TRUSTED = True
`, htcondor.HarnessTrustDomain, e2eAP1, e2eAP2, ap2Spool, ap2Dir)
	s.harness = htcondor.SetupCondorHarnessWithConfig(t, poolCfg)
	s.cfgFile = s.harness.GetConfigFile()
	t.Cleanup(func() {
		if t.Failed() {
			for _, f := range []string{"ScheddLog", "SchedLog2", "MasterLog", "CollectorLog"} {
				if b, err := os.ReadFile(filepath.Join(s.harness.GetLogDir(), f)); err == nil { //nolint:gosec // test log
					t.Logf("=== %s ===\n%s", f, tail(b, 32*1024))
				}
			}
		}
	})
	s.waitSchedds(t)

	// The jobs: e2eAP1Job1 and on, in submission order.
	s.submit(t, e2eAP1, "")                             // 1.0
	s.submit(t, e2eAP1, "")                             // 2.0
	s.submit(t, e2eAP1, `+Owner = "`+e2eOther+`"`+"\n") // 3.0, another user's
	s.submit(t, e2eAP2, "")                             // 1.0
	s.submit(t, e2eAP2, "")                             // 2.0

	// Every database takes IDTOKENS as well as FS: the API server
	// authenticates to the hub, and to a spoke for a single-job read,
	// with the token it mints from the signing key, as in production.
	// The hub reaches the spokes over FS.
	const dbAuth = "SEC_DEFAULT_AUTHENTICATION_METHODS = FS, IDTOKENS\n"

	// The spokes: schedd sync against each schedd's files, naming the
	// mirrored schedd from its address file (the schedd writes its own
	// Name there), heartbeating every second.
	spokeCfg := func(name, queueLog, history, addrFile string) string {
		return dbAuth + fmt.Sprintf(`
HTCONDORDB_NAME = %s
HTCONDORDB_SYNC_SCHEDD = true
HTCONDORDB_JOB_QUEUE_LOG = %s
HTCONDORDB_HISTORY = %s
HTCONDORDB_MIRRORED_SCHEDD_ADDRESS_FILE = %s
HTCONDORDB_SYNCSTATUS_INTERVAL = 1
UPDATE_INTERVAL = 2
`, name, queueLog, history, addrFile)
	}
	spool1 := s.harness.GetSpoolDir()
	s.spoke1 = startHTCondorDB(t, s.harness, bin, filepath.Join(s.dir, "spoke1"), spokeCfg("spoke1@127.0.0.1",
		filepath.Join(spool1, "job_queue.log"), filepath.Join(spool1, "history"),
		filepath.Join(spool1, ".schedd_address")))
	s.spoke2 = startHTCondorDB(t, s.harness, bin, filepath.Join(s.dir, "spoke2"), spokeCfg("spoke2@127.0.0.1",
		filepath.Join(ap2Spool, "job_queue.log"), filepath.Join(ap2Spool, "history"),
		filepath.Join(ap2Dir, ".schedd_address")))

	// The hub: discovers the AP set and its spokes from the collector.
	// Freshness at 5 s against a 1 s heartbeat, so a stopped spoke goes
	// stale within seconds; nothing retires during the test.
	s.hub = startHTCondorDB(t, s.harness, bin, filepath.Join(s.dir, "hub"), dbAuth+fmt.Sprintf(`
HTCONDORDB_NAME = hub@127.0.0.1
HTCONDORDB_FEDERATE_SCHEDD_CONSTRAINT = %s
HTCONDORDB_FEDERATE_FRESH_SECONDS = 5
HTCONDORDB_FEDERATE_DISCOVER_INTERVAL = 1
HTCONDORDB_FEDERATE_STATE_INTERVAL = 1
HTCONDORDB_FEDERATE_RETIRE_AFTER = 1h
UPDATE_INTERVAL = 2
`, e2eAPConstraint))

	s.startServer(t)
	return s
}

// waitSchedds waits for both schedds to advertise: the API server's AP
// registry polls the collector once at startup and then once a minute.
func (s *multiAPStack) waitSchedds(t *testing.T) {
	t.Helper()
	coll := htcondor.NewCollector(s.harness.GetCollectorAddr())
	waitFor(t, "both schedds to advertise", 60*time.Second, func() bool {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		ads, _, err := coll.QueryAdsWithOptions(ctx, "Schedd", e2eAPConstraint, &htcondor.QueryOptions{Limit: -1, Projection: []string{"Name"}})
		return err == nil && len(ads) == 2
	})
}

func (s *multiAPStack) startServer(t *testing.T) {
	t.Helper()
	htcCfg, err := s.harness.GetConfig()
	if err != nil {
		t.Fatal(err)
	}
	listener, baseURL := listenLocal(t)
	srv, err := NewServer(Config{
		ClientConfig:   htcCfg,
		HTCondorConfig: htcCfg,
		ListenAddr:     listener.Addr().String(),
		MultiAP:        MultiAPConfig{ScheddConstraint: e2eAPConstraint},
		Collector:      htcondor.NewCollector(s.harness.GetCollectorAddr()).WithConfig(htcCfg),
		// The test plays a trusted proxy naming the caller.
		UserHeader:               "X-Test-User",
		UserHeaderTrustAnyUnsafe: true,
		SigningKeyPath:           s.harness.GetSigningKeyPath(),
		TrustDomain:              s.harness.GetTrustDomain(),
		UIDDomain:                s.harness.GetTrustDomain(),
		EnableMCP:                true,
		OAuth2DBPath:             filepath.Join(s.dir, "oauth2.db"),
	})
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	go func() { _ = srv.ServeListener(listener, "http") }()
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		_ = srv.Shutdown(ctx)
	})
	if err := waitForServer(baseURL, 15*time.Second); err != nil {
		t.Fatal(err)
	}
	s.srv, s.baseURL = srv, baseURL
}

// submit queues one idle job on schedd and returns nothing: the test
// knows the ids a fresh schedd assigns, and asserts them.
func (s *multiAPStack) submit(t *testing.T, schedd, extra string) {
	t.Helper()
	sub := filepath.Join(s.dir, fmt.Sprintf("job-%d.sub", time.Now().UnixNano()))
	body := "executable = /bin/sleep\narguments = 600\ntransfer_executable = False\n" + extra + "queue\n"
	if err := os.WriteFile(sub, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	out := s.condor(t, "condor_submit", "-terse", "-name", schedd, sub)
	t.Logf("submitted %s to %s", strings.TrimSpace(out), schedd)
}

func (s *multiAPStack) condorRm(t *testing.T, k apJob) {
	t.Helper()
	s.condor(t, "condor_rm", "-name", k.schedd, fmt.Sprintf("%d.%d", k.cluster, k.proc))
}

// scheddAttr reads one attribute of a job from its schedd directly.
func (s *multiAPStack) scheddAttr(t *testing.T, schedd string, k apJob, attr string) string {
	t.Helper()
	out := s.condor(t, "condor_q", "-name", schedd, "-allusers", fmt.Sprintf("%d.%d", k.cluster, k.proc), "-af", attr)
	return strings.Trim(strings.TrimSpace(out), `"`)
}

func (s *multiAPStack) condor(t *testing.T, tool string, args ...string) string {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	cmd := exec.CommandContext(ctx, tool, args...) //nolint:gosec // HTCondor tools with test-built arguments
	cmd.Env = append(os.Environ(), "CONDOR_CONFIG="+s.cfgFile)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("%s %v: %v\n%s", tool, args, err, out)
	}
	return string(out)
}

// --- the API ----------------------------------------------------------------

func (s *multiAPStack) do(t *testing.T, as, method, path, body string) (int, string) {
	t.Helper()
	var rd io.Reader
	if body != "" {
		rd = strings.NewReader(body)
	}
	req, err := http.NewRequestWithContext(context.Background(), method, s.baseURL+path, rd)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("X-Test-User", as)
	if body != "" {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := s.client.Do(req)
	if err != nil {
		t.Fatalf("%s %s: %v", method, path, err)
	}
	defer func() { _ = resp.Body.Close() }()
	b, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(b)
}

func (s *multiAPStack) get(t *testing.T, as, path string) (int, string) {
	t.Helper()
	return s.do(t, as, http.MethodGet, path, "")
}

// e2eRow is one job as a multi-AP read renders it.
type e2eRow struct {
	Schedd   string            `json:"schedd"`
	Cluster  int64             `json:"cluster"`
	Proc     int64             `json:"proc"`
	JobID    string            `json:"job_id"`
	Archived bool              `json:"archived"`
	Source   string            `json:"source"`
	Degraded *multiap.Degraded `json:"degraded"`
	// raw is the whole object, ad attributes included.
	raw map[string]any
}

func (r e2eRow) key() apJob { return apJob{r.Schedd, r.Cluster, r.Proc} }

func decodeRow(t *testing.T, b []byte) e2eRow {
	t.Helper()
	var r e2eRow
	if err := json.Unmarshal(b, &r); err != nil {
		t.Fatalf("decoding a job: %v: %s", err, b)
	}
	if err := json.Unmarshal(b, &r.raw); err != nil {
		t.Fatalf("decoding a job: %v: %s", err, b)
	}
	return r
}

// e2eList is a list response.
type e2eList struct {
	Jobs    []e2eRow
	Ads     []e2eRow
	Sources multiap.Sources
	Error   string
}

func (l e2eList) keys() []apJob {
	var out []apJob
	for _, j := range append(append([]e2eRow(nil), l.Jobs...), l.Ads...) {
		out = append(out, j.key())
	}
	return out
}

func (l e2eList) degraded(schedd string) *multiap.Degraded {
	for i := range l.Sources.Degraded {
		if l.Sources.Degraded[i].Schedd == schedd {
			return &l.Sources.Degraded[i]
		}
	}
	return nil
}

// tryList reads a list endpoint, reporting rather than failing on an
// error, for polling.
func (s *multiAPStack) tryList(t *testing.T, as, path string) (e2eList, error) {
	t.Helper()
	code, body := s.get(t, as, path)
	if code != http.StatusOK {
		return e2eList{}, fmt.Errorf("GET %s = %d %s", path, code, body)
	}
	var raw struct {
		Jobs    []json.RawMessage `json:"jobs"`
		Ads     []json.RawMessage `json:"ads"`
		Sources multiap.Sources   `json:"sources"`
		Error   string            `json:"error"`
	}
	if err := json.Unmarshal([]byte(body), &raw); err != nil {
		return e2eList{}, fmt.Errorf("decoding GET %s: %w: %s", path, err, body)
	}
	if raw.Error != "" {
		return e2eList{}, fmt.Errorf("GET %s reported an error: %s", path, raw.Error)
	}
	l := e2eList{Sources: raw.Sources}
	for _, j := range raw.Jobs {
		l.Jobs = append(l.Jobs, decodeRow(t, j))
	}
	for _, j := range raw.Ads {
		l.Ads = append(l.Ads, decodeRow(t, j))
	}
	return l, nil
}

func (s *multiAPStack) list(t *testing.T, as, path string) e2eList {
	t.Helper()
	l, err := s.tryList(t, as, path)
	if err != nil {
		t.Fatal(err)
	}
	return l
}

// waitList polls GET /api/v1/jobs until ok, and returns the response
// that satisfied it. On timeout it reports the last response.
func (s *multiAPStack) waitList(t *testing.T, what string, limit time.Duration, as string, ok func(e2eList) bool) e2eList {
	t.Helper()
	var last e2eList
	var lastErr error
	deadline := time.Now().Add(limit)
	for time.Now().Before(deadline) {
		last, lastErr = s.tryList(t, as, "/api/v1/jobs")
		if lastErr == nil && ok(last) {
			return last
		}
		time.Sleep(250 * time.Millisecond)
	}
	t.Fatalf("timed out after %s waiting for %s; last: jobs=%v sources=%+v err=%v", limit, what, last.keys(), last.Sources, lastErr)
	return last
}

// waitArchive polls GET /api/v1/jobs/archive until k appears, then
// checks how it is rendered.
func (s *multiAPStack) waitArchive(t *testing.T, k apJob) {
	t.Helper()
	var last e2eList
	var lastErr error
	deadline := time.Now().Add(60 * time.Second)
	for time.Now().Before(deadline) {
		last, lastErr = s.tryList(t, s.me, "/api/v1/jobs/archive?limit=50")
		if lastErr == nil {
			for _, r := range last.Ads {
				if r.key() == k {
					if r.JobID != k.String() || !r.Archived {
						t.Errorf("archived %s rendered as job_id %q archived=%v", k, r.JobID, r.Archived)
					}
					if got := r.raw["ScheddName"]; got != k.schedd {
						t.Errorf("archived %s has ScheddName %v", k, got)
					}
					if st, _ := r.raw["JobStatus"].(float64); st != 3 {
						t.Errorf("archived %s has JobStatus %v, want 3 (removed)", k, r.raw["JobStatus"])
					}
					return
				}
			}
		}
		time.Sleep(250 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %s in /api/v1/jobs/archive; last: %v err=%v", k, last.keys(), lastErr)
}

func (s *multiAPStack) getJob(t *testing.T, as, id string) e2eRow {
	t.Helper()
	code, body := s.get(t, as, "/api/v1/jobs/"+url.PathEscape(id))
	if code != http.StatusOK {
		t.Fatalf("GET /api/v1/jobs/%s = %d %s", id, code, body)
	}
	return decodeRow(t, []byte(body))
}

func (s *multiAPStack) aps(t *testing.T) APsResponse {
	t.Helper()
	code, body := s.get(t, s.me, "/api/v1/aps")
	if code != http.StatusOK {
		t.Fatalf("GET /api/v1/aps = %d %s", code, body)
	}
	var out APsResponse
	if err := json.Unmarshal([]byte(body), &out); err != nil {
		t.Fatalf("decoding /api/v1/aps: %v: %s", err, body)
	}
	return out
}

// mintToken signs an IDTOKEN for user with the harness's pool key, the
// credential an HTCondor user would present.
func (s *multiAPStack) mintToken(t *testing.T, user string) string {
	t.Helper()
	now := time.Now().Unix()
	tok, err := security.GenerateJWT(s.harness.GetPasswordDir(), "POOL", user+"@"+s.harness.GetTrustDomain(),
		s.harness.GetTrustDomain(), now-60, now+900, []string{"READ"})
	if err != nil {
		t.Fatalf("GenerateJWT: %v", err)
	}
	return tok
}

func (s *multiAPStack) mcpTool(t *testing.T, token, name string, args map[string]any) string {
	t.Helper()
	params, _ := json.Marshal(map[string]any{"name": name, "arguments": args})
	resp := sendMCPRequest(t, s.client, s.baseURL, token, mcpserver.MCPMessage{
		JSONRPC: "2.0", ID: 1, Method: "tools/call", Params: params,
	})
	if msg, failed := mcpToolFailure(t, resp); failed {
		t.Fatalf("%s failed: %s", name, msg)
	}
	return toolText(t, resp.Result)
}

// decodeToolRows reads the JSON array a multi-AP list tool prints after
// its first line.
func decodeToolRows(t *testing.T, text string) []e2eRow {
	t.Helper()
	// "Found N job(s):\n[...]\n" and then notes; decode the one array.
	_, rest, _ := strings.Cut(text, "\n")
	var raws []json.RawMessage
	if err := json.NewDecoder(strings.NewReader(rest)).Decode(&raws); err != nil {
		t.Fatalf("decoding tool rows: %v\n%s", err, text)
	}
	out := make([]e2eRow, 0, len(raws))
	for _, r := range raws {
		out = append(out, decodeRow(t, r))
	}
	return out
}

// --- small helpers ------------------------------------------------------------

func sameJobs(got, want []apJob) bool {
	if len(got) != len(want) {
		return false
	}
	g := append([]apJob(nil), got...)
	w := append([]apJob(nil), want...)
	less := func(a []apJob) func(i, j int) bool {
		return func(i, j int) bool { return a[i].String() < a[j].String() }
	}
	sort.Slice(g, less(g))
	sort.Slice(w, less(w))
	for i := range g {
		if g[i] != w[i] {
			return false
		}
	}
	return true
}

func containsJob(keys []apJob, k apJob) bool {
	for _, x := range keys {
		if x == k {
			return true
		}
	}
	return false
}

func mustInt(t *testing.T, v any) int64 {
	t.Helper()
	switch n := v.(type) {
	case float64:
		return int64(n)
	case string:
		i, err := strconv.ParseInt(n, 10, 64)
		if err == nil {
			return i
		}
	}
	t.Fatalf("not an integer: %#v", v)
	return 0
}
