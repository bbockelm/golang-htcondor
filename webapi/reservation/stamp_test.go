package reservation

import (
	"context"
	"errors"
	"testing"
)

func TestPlanStampsTakesTheLargestEstimateInACluster(t *testing.T) {
	// A cluster whose procs differ is described by its longest. The
	// other way round admits a job onto a machine that needs the core
	// back before it ends.
	jobs := []JobView{
		{Owner: testOwner, Cluster: 7, Want: 1800},
		{Owner: testOwner, Cluster: 7, Want: 5400},
		{Owner: testOwner, Cluster: 7, Want: 3600},
	}
	got := PlanStamps(jobs, nil, 0)
	if len(got) != 1 {
		t.Fatalf("planned %d writes for one cluster: %+v", len(got), got)
	}
	if got[0].Bucket != 5400 {
		t.Errorf("bucket = %d, want the largest (5400)", got[0].Bucket)
	}
	if got[0].Jobs != 3 {
		t.Errorf("Jobs = %d, want 3", got[0].Jobs)
	}
}

func TestPlanStampsSkipsClustersAlreadyCorrect(t *testing.T) {
	jobs := []JobView{{Owner: testOwner, Cluster: 1, Want: 1800}, {Owner: testOwner, Cluster: 2, Want: 3600}}
	clusters := []ClusterView{{Cluster: 1, Have: 1800}, {Cluster: 2, Have: 1800}}
	got := PlanStamps(jobs, clusters, 0)
	if len(got) != 1 || got[0].Cluster != 2 {
		t.Fatalf("planned %+v, want only cluster 2 rewritten", got)
	}
	if got[0].New {
		t.Errorf("cluster 2 was already stamped, so the write is not new")
	}
}

// TestPlanStampsPrefersUnstampedClusters: the sieve refuses an
// unstamped job outright and accepts a stale stamp, so a budget spent
// on a cluster that has no stamp buys admissions and one spent
// correcting a stale stamp buys accuracy.
func TestPlanStampsPrefersUnstampedClusters(t *testing.T) {
	jobs := []JobView{
		{Owner: testOwner, Cluster: 1, Want: 1800}, {Owner: testOwner, Cluster: 1, Want: 1800}, {Owner: testOwner, Cluster: 1, Want: 1800},
		{Owner: testOwner, Cluster: 2, Want: 3600},
	}
	clusters := []ClusterView{{Cluster: 1, Have: 900}} // stale, and bigger
	got := PlanStamps(jobs, clusters, 1)
	if len(got) != 1 {
		t.Fatalf("budget of 1 planned %d writes", len(got))
	}
	if got[0].Cluster != 2 {
		t.Errorf("spent the budget on cluster %d; the unstamped cluster 2 is refused by the sieve", got[0].Cluster)
	}
}

// TestPlanStampsPrefersBiggerClusters: among equals, the write that
// stamps the most idle jobs.
func TestPlanStampsPrefersBiggerClusters(t *testing.T) {
	var jobs []JobView
	for range 5 {
		jobs = append(jobs, JobView{Owner: testOwner, Cluster: 10, Want: 1800})
	}
	jobs = append(jobs, JobView{Owner: testOwner, Cluster: 11, Want: 1800})
	got := PlanStamps(jobs, nil, 1)
	if len(got) != 1 || got[0].Cluster != 10 {
		t.Errorf("planned %+v, want the five-job cluster first", got)
	}
}

// TestPlanStampsIgnoresJobsWithNoEstimate. Writing zero would be worse
// than writing nothing: the sieve refuses a non-positive bucket either
// way, and a cluster stamped zero looks stamped to the next pass.
func TestPlanStampsIgnoresJobsWithNoEstimate(t *testing.T) {
	got := PlanStamps([]JobView{{Owner: testOwner, Cluster: 1, Want: 0}, {Owner: testOwner, Cluster: 1, Want: -5}}, nil, 0)
	if len(got) != 0 {
		t.Errorf("planned %+v for a cluster with no estimate", got)
	}
}

// TestPlanStampsIsStable: two passes over the same queue plan the same
// thing, so a budget that cannot cover the queue makes progress instead
// of rewriting a different arbitrary subset each time.
func TestPlanStampsIsStable(t *testing.T) {
	jobs := []JobView{
		{Owner: testOwner, Cluster: 3, Want: 1800}, {Owner: testOwner, Cluster: 1, Want: 1800},
		{Owner: testOwner, Cluster: 2, Want: 1800}, {Owner: testOwner, Cluster: 4, Want: 1800},
	}
	a := PlanStamps(jobs, nil, 2)
	b := PlanStamps(jobs, nil, 2)
	if len(a) != 2 || len(b) != 2 {
		t.Fatalf("budget not honoured: %d, %d", len(a), len(b))
	}
	for i := range a {
		if a[i] != b[i] {
			t.Fatalf("two passes planned differently: %+v vs %+v", a, b)
		}
	}
}

type fakeQueue struct {
	jobs     []JobView
	clusters []ClusterView
	err      error
}

func (q fakeQueue) IdleJobs(context.Context) ([]JobView, error) { return q.jobs, q.err }
func (q fakeQueue) Clusters(context.Context) ([]ClusterView, error) {
	return q.clusters, q.err
}

type fakeStampWriter struct {
	wrote []Stamp
	err   error
	// partial, when positive, writes only that many stamps and reports
	// the rest as failed: one owner's clusters landing and another's
	// not is the shape a real pass fails in.
	partial int
}

func (w *fakeStampWriter) Write(_ context.Context, s []Stamp) (int, error) {
	if w.partial > 0 {
		n := min(w.partial, len(s))
		w.wrote = append(w.wrote, s[:n]...)
		return n, errors.New("one owner's writes were refused")
	}
	if w.err != nil {
		return 0, w.err
	}
	w.wrote = append(w.wrote, s...)
	return len(s), nil
}

func TestStamperPassReportsWhatItDid(t *testing.T) {
	jobs := []JobView{
		{Owner: testOwner, Cluster: 1, Want: 1800}, {Owner: testOwner, Cluster: 1, Want: 1800},
		{Owner: testOwner, Cluster: 2, Want: 3600},
		{Owner: testOwner, Cluster: 3, Want: 0}, // no estimate
	}
	w := &fakeStampWriter{}
	s := &Stamper{Queue: fakeQueue{jobs: jobs}, Writer: w}

	res, err := s.Pass(context.Background())
	if err != nil {
		t.Fatalf("Pass: %v", err)
	}
	if res.Idle != 4 {
		t.Errorf("Idle = %d, want 4", res.Idle)
	}
	if res.Clusters != 3 {
		t.Errorf("Clusters = %d, want 3", res.Clusters)
	}
	if res.Written != 2 {
		t.Errorf("Written = %d, want 2 (cluster 3 has no estimate)", res.Written)
	}
	if res.Covered != 3 {
		t.Errorf("Covered = %d, want 3 idle jobs stamped by 2 writes", res.Covered)
	}
	if res.Unestimated != 1 {
		t.Errorf("Unestimated = %d, want 1", res.Unestimated)
	}
	if len(w.wrote) != 2 {
		t.Errorf("wrote %d cluster ads, want 2", len(w.wrote))
	}
	if s.Last().Written != 2 {
		t.Errorf("Last() does not report the pass")
	}
}

// TestStamperReportsDeferredWork: a budget too small for the queue has
// to be visible, or an operator sees a subsystem that works and a pool
// that is never fully usable.
func TestStamperReportsDeferredWork(t *testing.T) {
	var jobs []JobView
	for i := range 10 {
		jobs = append(jobs, JobView{Owner: testOwner, Cluster: i, Want: 1800})
	}
	s := &Stamper{Queue: fakeQueue{jobs: jobs}, Writer: &fakeStampWriter{}, Budget: 3}
	res, err := s.Pass(context.Background())
	if err != nil {
		t.Fatalf("Pass: %v", err)
	}
	if res.Written != 3 {
		t.Errorf("Written = %d, want the budget of 3", res.Written)
	}
	if res.Deferred != 7 {
		t.Errorf("Deferred = %d, want 7", res.Deferred)
	}
}

// TestStamperDoesNotClaimWritesItCouldNotMake: a failed write must not
// report Covered jobs. Otherwise the admin page says the queue is
// stamped while the sieve refuses all of it.
func TestStamperDoesNotClaimWritesItCouldNotMake(t *testing.T) {
	boom := errors.New("schedd refused the transaction")
	s := &Stamper{
		Queue:  fakeQueue{jobs: []JobView{{Owner: testOwner, Cluster: 1, Want: 1800}}},
		Writer: &fakeStampWriter{err: boom},
	}
	res, err := s.Pass(context.Background())
	if !errors.Is(err, boom) {
		t.Fatalf("Pass error = %v, want the writer's", err)
	}
	if res.Written != 0 || res.Covered != 0 {
		t.Errorf("reported %d writes covering %d jobs after a failed write", res.Written, res.Covered)
	}
	if res.Err == nil {
		t.Errorf("the result does not carry the error")
	}
}

func TestStamperReportsAnUnreadableQueue(t *testing.T) {
	boom := errors.New("schedd down")
	s := &Stamper{Queue: fakeQueue{err: boom}, Writer: &fakeStampWriter{}}
	if _, err := s.Pass(context.Background()); !errors.Is(err, boom) {
		t.Errorf("Pass error = %v, want the queue's", err)
	}
}

// testOwner is the identity the fixtures' jobs belong to. Stamping acts
// as the owner of the job it edits, so a job without one is not stamped
// at all -- see TestPlanStampsLeavesJobsWithNoOwnerAlone.
const testOwner = "alice@example.org"

func TestPlanStampsLeavesJobsWithNoOwnerAlone(t *testing.T) {
	// Non-vacuous: the same job with an owner is planned.
	owned := PlanStamps([]JobView{{Owner: testOwner, Cluster: 1, Want: 1800}}, nil, 0)
	if len(owned) != 1 {
		t.Fatalf("planned %d writes for an owned cluster, want 1", len(owned))
	}
	if owned[0].Owner != testOwner {
		t.Fatalf("planned a write as %q, want %q", owned[0].Owner, testOwner)
	}

	got := PlanStamps([]JobView{{Cluster: 1, Want: 1800}}, nil, 0)
	if len(got) != 0 {
		t.Fatalf("planned %d writes for a job with no owner: %+v", len(got), got)
	}
}

func TestPassCountsTheJobsItCannotWriteAs(t *testing.T) {
	jobs := []JobView{
		{Owner: testOwner, Cluster: 1, Want: 1800},
		{Cluster: 2, Want: 1800},
		{Cluster: 3, Want: 1800},
	}
	w := &fakeStampWriter{}
	s := &Stamper{Queue: fakeQueue{jobs: jobs}, Writer: w}
	res, err := s.Pass(context.Background())
	if err != nil {
		t.Fatalf("Pass: %v", err)
	}
	if res.Unowned != 2 {
		t.Fatalf("Unowned = %d, want 2", res.Unowned)
	}
	if len(w.wrote) != 1 {
		t.Fatalf("wrote %d cluster ads, want only the owned one", len(w.wrote))
	}
	if w.wrote[0].Cluster != 1 {
		t.Fatalf("wrote cluster %d, want 1", w.wrote[0].Cluster)
	}
}

func TestByOwnerGroupsAPlanInAFixedOrder(t *testing.T) {
	stamps := []Stamp{
		{Cluster: 3, Owner: "carol@example.org"},
		{Cluster: 1, Owner: "bob@example.org"},
		{Cluster: 2, Owner: "alice@example.org"},
		{Cluster: 4, Owner: "bob@example.org"},
	}
	owners, byOwner := ByOwner(stamps)
	want := []string{"alice@example.org", "bob@example.org", "carol@example.org"}
	if len(owners) != len(want) {
		t.Fatalf("grouped into %v, want %v", owners, want)
	}
	for i := range want {
		if owners[i] != want[i] {
			t.Fatalf("owners = %v, want %v", owners, want)
		}
	}
	if n := len(byOwner["bob@example.org"]); n != 2 {
		t.Fatalf("bob has %d clusters, want 2", n)
	}
	if byOwner["bob@example.org"][0].Cluster != 1 || byOwner["bob@example.org"][1].Cluster != 4 {
		t.Fatalf("bob's clusters are not in plan order: %+v", byOwner["bob@example.org"])
	}
}

func TestEveryClusterIsStampedAsItsOwnOwner(t *testing.T) {
	jobs := []JobView{
		{Owner: "alice@example.org", Cluster: 1, Want: 1800},
		{Owner: "bob@example.org", Cluster: 2, Want: 3600},
	}
	w := &fakeStampWriter{}
	s := &Stamper{Queue: fakeQueue{jobs: jobs}, Writer: w}
	if _, err := s.Pass(context.Background()); err != nil {
		t.Fatalf("Pass: %v", err)
	}
	by := map[int]string{}
	for _, st := range w.wrote {
		by[st.Cluster] = st.Owner
	}
	if by[1] != "alice@example.org" {
		t.Fatalf("cluster 1 stamped as %q, want alice", by[1])
	}
	if by[2] != "bob@example.org" {
		t.Fatalf("cluster 2 stamped as %q, want bob", by[2])
	}
}

// A pass can now partly succeed: writes are made as each owner, so one
// user the schedd will not let this process edit for costs that user
// their stamps and nobody else theirs.
func TestPassClaimsOnlyTheStampsThatLanded(t *testing.T) {
	var jobs []JobView
	for cluster := 1; cluster <= 4; cluster++ {
		// Descending job counts, so the plan's order is known and
		// Covered cannot come out right by averaging.
		for range 5 - cluster {
			jobs = append(jobs, JobView{Owner: testOwner, Cluster: cluster, Want: 1800})
		}
	}
	w := &fakeStampWriter{partial: 2}
	s := &Stamper{Queue: fakeQueue{jobs: jobs}, Writer: w}

	res, err := s.Pass(context.Background())
	if err == nil {
		t.Fatal("Pass reported no error for a partly refused write")
	}
	if res.Written != 2 {
		t.Fatalf("Written = %d, want the 2 that landed", res.Written)
	}
	// The plan is ordered by coverage, so the two that landed are the
	// four-job and three-job clusters.
	if res.Covered != 7 {
		t.Fatalf("Covered = %d, want 7 jobs under the 2 writes that landed", res.Covered)
	}
	if len(w.wrote) != 2 {
		t.Fatalf("the writer took %d stamps, want 2", len(w.wrote))
	}
}
