package httpserver

import (
	"encoding/json"
	"fmt"
	"net/http"
	"slices"
	"testing"
	"time"

	"github.com/PelicanPlatform/classad/classad"

	"github.com/bbockelm/golang-htcondor/webapi/runtimeest"
)

// groupAd is a job ad, finished (status 4, with a runtime and completion)
// or queued.
func groupAd(t *testing.T, cluster int, owner, cmd, args, batch string, status int, runtime int, completedAgo time.Duration) *classad.ClassAd {
	t.Helper()
	now := time.Now()
	text := fmt.Sprintf(`ClusterId = %d
ProcId = 0
Owner = %q
Cmd = %q
Arguments = %q
JobUniverse = 5
JobStatus = %d
QDate = %d`, cluster, owner, cmd, args, status, now.Add(-24*time.Hour).Unix())
	if batch != "" {
		text += fmt.Sprintf("\nJobBatchName = %q", batch)
	}
	if status == 4 {
		done := now.Add(-completedAgo).Unix()
		text += fmt.Sprintf("\nExitCode = 0\nCommittedTime = %d\nRemoteWallClockTime = %d.0\nCompletionDate = %d\nEnteredHistoryTime = %d",
			runtime, runtime, done, done)
	}
	ad, err := classad.ParseOld(text)
	if err != nil {
		t.Fatal(err)
	}
	return ad
}

// groupsFixture: alice's five finished "sim --seed N" jobs of the "sweep"
// batch and one of another program; bob's five of the same command line;
// thirty of carol's, which never answer for anyone else. Queued: alice's sim job 400 (a new seed, a new sweep run),
// alice's job 401 of a program with no history, bob's job 500. The
// estimator has read all the history.
func groupsFixture(t *testing.T) *twoOwnerFixture {
	t.Helper()
	f := twoOwnerScheddServer(t)
	var history []*classad.ClassAd
	for i := 1; i <= 5; i++ {
		history = append(history, groupAd(t, 300+i, "alice", "/home/alice/sim", fmt.Sprintf("--seed %d", i), "sweep+300", 4, 100*i, time.Duration(i)*time.Hour))
		history = append(history, groupAd(t, 600+i, "bob", "/home/alice/sim", fmt.Sprintf("--seed %d", i), "sweep+600", 4, 50*i, time.Duration(i)*time.Hour))
	}
	history = append(history, groupAd(t, 310, "alice", "/home/alice/other", "", "", 4, 999, time.Hour))
	for i := range 30 {
		history = append(history, groupAd(t, 700+i, "carol", "/home/carol/x", "", "", 4, 1000, time.Hour))
	}
	f.schedd.AddHistory(history...)
	f.schedd.AddJobs(
		groupAd(t, 400, "alice", "/home/alice/sim", "--seed 99", "sweep+400", 1, 0, 0),
		groupAd(t, 401, "alice", "/home/alice/brand-new", "", "", 1, 0, 0),
		groupAd(t, 500, "bob", "/home/alice/sim", "--seed 99", "sweep+500", 1, 0, 0),
	)
	f.s.runtimeEst = runtimeest.New(runtimeest.Config{})
	b := runtimeest.NewBatch()
	for _, ad := range history {
		b.AddAd(ad)
	}
	f.s.runtimeEst.Ingest(b)
	return f
}

func (f *twoOwnerFixture) similar(t *testing.T, path string, auth func(*http.Request)) (int, SimilarJobsResponse) {
	t.Helper()
	w := f.do(t, http.MethodGet, path, "", auth)
	var resp SimilarJobsResponse
	if w.Code == http.StatusOK {
		if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
			t.Fatalf("decoding %s: %v", w.Body.String(), err)
		}
	}
	return w.Code, resp
}

func similarIDs(r SimilarJobsResponse) []string {
	var out []string
	for _, j := range r.Jobs {
		out = append(out, j.ID)
	}
	return out
}

// The jobs behind job 400's estimate: alice's five sim runs, newest
// first, whatever their seed (template ignores numbers) -- never bob's
// identical command lines, nor her other program.
func TestJobSimilar(t *testing.T) {
	f := groupsFixture(t)
	alice := f.bearer(t, "alice")
	code, resp := f.similar(t, "/api/v1/jobs/400.0/similar", alice)
	if code != http.StatusOK {
		t.Fatalf("similar: %d", code)
	}
	if resp.EstimateLevel == nil || *resp.EstimateLevel != "template" || resp.Level != "template" || resp.Description != "same command, numbers ignored" {
		t.Errorf("level = %q (estimate %v) %q", resp.Level, resp.EstimateLevel, resp.Description)
	}
	if want := []string{"301.0", "302.0", "303.0", "304.0", "305.0"}; !slices.Equal(similarIDs(resp), want) || resp.Total != 5 {
		t.Errorf("jobs = %v (total %d), want %v newest first", similarIDs(resp), resp.Total, want)
	}
	// R-7 over 100..500: the median is the estimate, 300.
	if resp.Runtimes == nil || resp.Runtimes.Count != 5 || resp.Runtimes.P50 != 300 || resp.Runtimes.P10 != 140 {
		t.Errorf("runtimes = %+v", resp.Runtimes)
	}
	if resp.Jobs[0].Runtime != 100 || resp.Jobs[0].ExitCode != 0 || resp.Window.Days != 7 || resp.Window.MaxJobs != runtimeest.DefaultWindow {
		t.Errorf("row/window = %+v %+v", resp.Jobs[0], resp.Window)
	}

	// The batch level ignores the run suffix: sweep+300 and sweep+400.
	if _, resp := f.similar(t, "/api/v1/jobs/400.0/similar?level=batch", alice); len(resp.Jobs) != 5 || resp.Description != "same batch name, run number ignored" {
		t.Errorf("batch level: %v", similarIDs(resp))
	}
	// The owner level: all six of alice's jobs, none of bob's or carol's.
	if _, resp := f.similar(t, "/api/v1/jobs/400.0/similar?level=owner", alice); len(resp.Jobs) != 6 {
		t.Errorf("owner level: %v", similarIDs(resp))
	}
	// Paging.
	_, page := f.similar(t, "/api/v1/jobs/400.0/similar?page_size=2&offset=2", alice)
	if !slices.Equal(similarIDs(page), []string{"303.0", "304.0"}) || page.NextOffset == nil || *page.NextOffset != 4 {
		t.Errorf("page = %v next %v", similarIDs(page), page.NextOffset)
	}
}

// Each level's sample count, for the picker; iwd does not apply, and
// asking for it is a 400.
func TestJobSimilarLevels(t *testing.T) {
	f := groupsFixture(t)
	alice := f.bearer(t, "alice")
	_, resp := f.similar(t, "/api/v1/jobs/400.0/similar", alice)
	counts := map[string]*int{}
	for _, l := range resp.Levels {
		counts[l.Level] = l.Count
		if l.Level == "iwd" && l.Applies {
			t.Error("iwd applies to a job with no Iwd")
		}
	}
	if counts["template"] == nil || *counts["template"] != 5 || counts["owner"] == nil || *counts["owner"] != 6 || counts["iwd"] != nil {
		t.Errorf("level counts = template %v owner %v iwd %v", counts["template"], counts["owner"], counts["iwd"])
	}
	if code, _ := f.similar(t, "/api/v1/jobs/400.0/similar?level=iwd", alice); code != http.StatusBadRequest {
		t.Errorf("a level that does not apply: %d", code)
	}
}

// No group spans other users: there is no access-point-wide level to
// list, and a job whose owner has nothing of its kind -- alice's brand-new
// program aside from her other jobs -- is grouped with her jobs alone.
func TestJobSimilarHasNoAccessPointLevel(t *testing.T) {
	f := groupsFixture(t)
	alice := f.bearer(t, "alice")
	if code, _ := f.similar(t, "/api/v1/jobs/400.0/similar?level=global", alice); code != http.StatusBadRequest {
		t.Errorf("level=global: %d, want 400", code)
	}
	_, resp := f.similar(t, "/api/v1/jobs/401.0/similar", alice)
	for _, l := range resp.Levels {
		if l.Level == "global" {
			t.Errorf("levels offer %q", l.Level)
		}
	}
	if resp.EstimateLevel == nil || *resp.EstimateLevel != "owner" || resp.Level != "owner" || resp.Total != 6 {
		t.Errorf("brand-new program: level %q (estimate %v), %v", resp.Level, resp.EstimateLevel, similarIDs(resp))
	}
	for _, j := range resp.Jobs {
		if j.Cluster >= 600 {
			t.Errorf("alice's group holds another user's %s", j.ID)
		}
	}
}

// Someone else's job is not found, and a group's list never holds
// another user's jobs -- even for an administrator, the group is its
// owner's.
func TestJobSimilarScoping(t *testing.T) {
	f := groupsFixture(t)
	bob := f.bearer(t, "bob")
	if code, _ := f.similar(t, "/api/v1/jobs/400.0/similar", bob); code != http.StatusNotFound {
		t.Errorf("bob reading alice's job: %d, want 404", code)
	}
	_, resp := f.similar(t, "/api/v1/jobs/500.0/similar?level=template", bob)
	if want := []string{"601.0", "602.0", "603.0", "604.0", "605.0"}; !slices.Equal(similarIDs(resp), want) {
		t.Errorf("bob's own group = %v, want only his", similarIDs(resp))
	}
	_, resp = f.similar(t, "/api/v1/jobs/400.0/similar?level=template", f.bearer(t, "root"))
	for _, j := range resp.Jobs {
		if j.Cluster >= 600 {
			t.Errorf("admin listing alice's group got bob's %s", j.ID)
		}
	}
}

func (f *twoOwnerFixture) forJob(t *testing.T, id string, auth func(*http.Request)) (int, UtilizationForJob) {
	t.Helper()
	w := f.do(t, http.MethodGet, "/api/v1/utilization/for-job/"+id, "", auth)
	var resp UtilizationForJob
	if w.Code == http.StatusOK {
		if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
			t.Fatalf("decoding %s: %v", w.Body.String(), err)
		}
	}
	return w.Code, resp
}

// A queued job links to the workflow its finished siblings were analysed
// under -- the same key the Utilization page uses -- and a job of a
// program with no history says so.
func TestUtilizationForJob(t *testing.T) {
	f := groupsFixture(t)
	alice := f.bearer(t, "alice")
	code, link := f.forJob(t, "400.0", alice)
	if code != http.StatusOK || link.Name != "sweep" || link.Executable != "sim" || link.Owner != "alice" {
		t.Fatalf("for-job: %d %+v", code, link)
	}
	if link.HasHistory == nil || !*link.HasHistory {
		t.Errorf("has_history = %v, want true", link.HasHistory)
	}
	summary := f.utilization(t, "/api/v1/utilization?days=30", alice)
	var keys []string
	for _, w := range summary.Workflows {
		keys = append(keys, w.Executable+"="+w.Key)
	}
	if !slices.Contains(keys, "sim="+link.Key) {
		t.Errorf("key %s is not the analysis's (%v)", link.Key, keys)
	}
	if _, fresh := f.forJob(t, "401.0", alice); fresh.HasHistory == nil || *fresh.HasHistory {
		t.Errorf("a program with no history: has_history = %v, want false", fresh.HasHistory)
	}
	// A finished job resolves too.
	if code, done := f.forJob(t, "303.0", alice); code != http.StatusOK || done.Key != link.Key {
		t.Errorf("finished job: %d %+v", code, done)
	}
	if code, _ := f.forJob(t, "400.0", f.bearer(t, "bob")); code != http.StatusNotFound {
		t.Errorf("bob: %d, want 404", code)
	}
	if code, _ := f.forJob(t, "nope", alice); code != http.StatusBadRequest {
		t.Errorf("bad id: %d", code)
	}
}

// A project lead can open a member's job in the project, but its group
// lists only the member's jobs the lead may read: those in the project.
func TestJobSimilarProjectLead(t *testing.T) {
	f := twoOwnerScheddServer(t)
	inProject := func(ad *classad.ClassAd) *classad.ClassAd {
		ad.InsertAttrString("ProjectName", "physics")
		return ad
	}
	f.schedd.AddHistory(
		inProject(groupAd(t, 301, "alice", "/home/alice/sim", "--seed 1", "", 4, 100, time.Hour)),
		inProject(groupAd(t, 302, "alice", "/home/alice/sim", "--seed 2", "", 4, 200, 2*time.Hour)),
		groupAd(t, 303, "alice", "/home/alice/sim", "--seed 3", "", 4, 300, 3*time.Hour),
	)
	f.schedd.AddJobs(inProject(groupAd(t, 400, "alice", "/home/alice/sim", "--seed 99", "", 1, 0, 0)))
	f.s.projectLeads = newProjectLeads("", "{project}-leads", "", nil)
	code, resp := f.similar(t, "/api/v1/jobs/400.0/similar?level=template", f.session(t, "dave", "physics-leads"))
	if code != http.StatusOK || !slices.Equal(similarIDs(resp), []string{"301.0", "302.0"}) {
		t.Errorf("lead: %d %v, want only the project's 301.0 and 302.0", code, similarIDs(resp))
	}
}
