//go:build integration

package httpserver

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/PelicanPlatform/classad/classad"

	htcondor "github.com/bbockelm/golang-htcondor"
	"github.com/bbockelm/golang-htcondor/webapi/runtimeest"
)

// scheddRunningJobs is drainJobSource straight from a schedd.
type scheddRunningJobs struct{ s *htcondor.Schedd }

func (r scheddRunningJobs) RunningJobs(ctx context.Context, attrs []string, limit int, yield func(*classad.ClassAd)) (bool, error) {
	ads, _, err := r.s.QueryWithOptions(ctx, "JobStatus == 2", &htcondor.QueryOptions{Limit: limit + 1, Projection: attrs})
	if err != nil {
		return false, err
	}
	for i, ad := range ads {
		if i >= limit {
			return true, nil
		}
		yield(ad)
	}
	return len(ads) > limit, nil
}

// TestPoolDrainAgainstARealPool reads a real startd's claimed slot and a
// real schedd's running job: the slot attributes drainest projects are
// the ones a startd publishes, the job's GlobalJobId matches its slot's,
// and its schedd name is the one the schedd advertises.
func TestPoolDrainAgainstARealPool(t *testing.T) {
	t.Parallel()
	if testing.Short() {
		t.Skip("integration test (starts a real pool)")
	}
	harness := htcondor.SetupCondorHarness(t)
	if err := harness.WaitForDaemons(); err != nil {
		t.Fatalf("daemons failed to start: %v", err)
	}
	if err := harness.WaitForStartd(45 * time.Second); err != nil {
		t.Fatalf("startd never reported in: %v", err)
	}
	cfg, err := harness.GetConfig()
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(htcondor.WithDaemonCredential(context.Background(), "test"), 3*time.Minute)
	defer cancel()
	coll := htcondor.NewCollector(harness.GetCollectorAddr()).WithConfig(cfg)
	loc, err := coll.LocateDaemon(ctx, "Schedd", "")
	if err != nil {
		t.Fatalf("locate schedd: %v", err)
	}
	schedd := htcondor.NewSchedd(loc.Name, loc.Address).WithConfig(cfg)
	cluster, _, err := schedd.SubmitRemote(ctx, "executable = /bin/sleep\narguments = 600\ntransfer_executable = false\n"+
		"request_cpus = 1\nrequest_memory = 64\nrequest_disk = 64\nqueue\n")
	if err != nil {
		t.Fatalf("submit: %v", err)
	}
	waitFor(t, "the job to run", 2*time.Minute, func() bool {
		ads, _, qerr := schedd.QueryWithOptions(ctx, fmt.Sprintf("ClusterId == %d && JobStatus == 2", cluster), nil)
		return qerr == nil && len(ads) == 1
	})
	// The startd's ad for the claim lags the schedd's view by up to an
	// update interval.
	slots := collectorDrainSlots{c: coll}
	waitFor(t, "the claimed slot to reach the collector", 2*time.Minute, func() bool {
		found := false
		_ = slots.Slots(ctx, func(ad *classad.ClassAd) {
			if g, _ := ad.EvaluateAttrString("GlobalJobId"); g != "" {
				found = true
			}
		})
		return found
	})

	// An estimator that knows /bin/sleep 600 takes 600 seconds.
	jobAds, _, err := schedd.QueryWithOptions(ctx, fmt.Sprintf("ClusterId == %d", cluster),
		&htcondor.QueryOptions{Projection: []string{"Owner"}})
	if err != nil || len(jobAds) != 1 {
		t.Fatalf("reading the job: %v", err)
	}
	owner, _ := jobAds[0].EvaluateAttrString("Owner")
	est := runtimeest.New(runtimeest.Config{})
	b := runtimeest.NewBatch()
	for i := range 3 {
		b.Add(runtimeest.Completion{
			Features:  runtimeest.Features{Owner: owner, ClusterID: int64(9000 + i), Cmd: "/bin/sleep", Args: []string{"600"}},
			Runtime:   600,
			Submitted: time.Now().Add(-time.Hour),
			Started:   time.Now().Add(-time.Hour),
			Completed: time.Now().Add(-50 * time.Minute),
		})
	}
	est.Ingest(b)

	p := newPoolDrain(slots, scheddRunningJobs{s: schedd}, est, "", testLogger(t))
	resp, err := p.get(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if resp.AccessPoint != loc.Name {
		t.Errorf("access point learned as %q, schedd advertises %q", resp.AccessPoint, loc.Name)
	}
	jobs := 0
	for _, m := range resp.Machines {
		for _, s := range m.Slots {
			t.Logf("slot %s: %+v", s.Name, s)
			if !s.FromThisAP {
				t.Errorf("slot %s: not matched to this access point (submitted from %q)", s.Name, s.SubmittedFrom)
			}
			if s.RunningSeconds == nil {
				t.Errorf("slot %s: no JobStart", s.Name)
			}
			if s.RetirementDeadline == nil {
				t.Errorf("slot %s: no RetirementTimeRemaining", s.Name)
			}
			if s.ExpectedEnd == nil {
				t.Errorf("slot %s: no estimate for a job the estimator knows", s.Name)
			}
			jobs++
		}
	}
	if jobs != 1 {
		t.Fatalf("%d running jobs in %+v, want 1", jobs, resp.Machines)
	}
	if resp.Summary.JobsRunning != 1 || resp.Summary.JobsEstimated != 1 {
		t.Errorf("summary %+v", resp.Summary)
	}
}
