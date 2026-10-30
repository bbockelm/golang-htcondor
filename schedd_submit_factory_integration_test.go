package htcondor

import (
	"context"
	"os/exec"
	"strconv"
	"strings"
	"testing"
	"time"
)

// allowLateMaterialize and refuseLateMaterialize pin the schedd capability a
// factory submission needs, in both directions.
//
// Neither is redundant. The knob's built-in default is on, but it is read
// through param_info rather than written into the generated config, so a
// release that changed it would silently turn one of these two tests into a
// copy of the other. A schedd with it off advertises LateMaterialize = false
// and refuses SendMaterializeData with EPERM.
const (
	allowLateMaterialize  = "SCHEDD_ALLOW_LATE_MATERIALIZE = True\n"
	refuseLateMaterialize = "SCHEDD_ALLOW_LATE_MATERIALIZE = False\n"
)

// factoryClusterAttrs reads the attributes the schedd stored on a cluster ad
// out of its job_queue.log, which is where a factory's bookkeeping shows up.
func factoryClusterAttrs(t *testing.T, spoolDir string, cluster int) (clusterAttrs map[string]string, procs []int) {
	t.Helper()
	for key, attrs := range setAttrsByKey(t, spoolDir) {
		c, p, ok := jobQueueKey(key)
		if !ok || c != cluster {
			continue
		}
		if p == clusterAdProcID {
			clusterAttrs = attrs
		} else {
			procs = append(procs, p)
		}
	}
	return clusterAttrs, procs
}

// TestSubmitLateMaterializesThroughTheSchedd is the end-to-end claim: a
// submit file asking for late materialization is submitted as a job factory
// and the schedd, not this library, creates the procs.
//
// The evidence is in the queue rather than in what was sent. A factory
// submission writes one cluster ad and no proc ads, so every proc that turns
// up afterwards was materialized by the schedd out of the digest -- which
// also means the digest parsed, which is the part no client-side test can
// establish.
func TestSubmitLateMaterializesThroughTheSchedd(t *testing.T) {
	if _, err := exec.LookPath("condor_master"); err != nil {
		t.Skip("condor_master not found in PATH - skipping integration test")
	}

	harness := SetupCondorHarnessWithConfig(t, allowLateMaterialize)
	if err := harness.WaitForSchedd(60 * time.Second); err != nil {
		t.Fatalf("schedd failed to start: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	collector := NewCollector(harness.GetCollectorAddr())
	location, err := collector.LocateDaemon(ctx, "Schedd", "")
	if err != nil {
		t.Fatalf("failed to locate schedd: %v", err)
	}
	schedd := NewSchedd(location.Name, location.Address)

	// requirements = false keeps every materialized proc idle, so the only
	// writes to these ads are the submission and the materialization.
	// arguments carries both a loop variable and $(Process), so a digest
	// with the first row baked into it would show up as three identical
	// jobs rather than three different ones.
	submitFile := `
executable = /bin/sleep
arguments = $(item) $(Process)
universe = vanilla
request_cpus = 1
request_memory = 128
requirements = false
max_idle = 5
queue item in (alpha beta gamma)
`
	clusterIDStr, err := schedd.Submit(ctx, submitFile)
	if err != nil {
		harness.PrintScheddLog()
		t.Fatalf("failed to submit: %v", err)
	}
	cluster, err := strconv.Atoi(clusterIDStr)
	if err != nil {
		t.Fatalf("submit returned a non-numeric cluster id %q: %v", clusterIDStr, err)
	}

	clusterAttrs, _ := factoryClusterAttrs(t, harness.GetSpoolDir(), cluster)
	if clusterAttrs == nil {
		t.Fatalf("cluster %d has no cluster ad in job_queue.log", cluster)
	}
	t.Logf("cluster %d attributes: %v", cluster, attrNames(clusterAttrs))

	// The schedd records a factory on the cluster ad. Without these the
	// submission went through as an ordinary one and the rest of this test
	// would pass for the wrong reason.
	for _, attr := range []string{"JobMaterializeLimit", "JobMaterializeNextProcId", "JobMaterializeMaxIdle"} {
		if _, ok := clusterAttrs[attr]; !ok {
			harness.PrintScheddLog()
			t.Fatalf("cluster ad has no %s: the schedd did not make this cluster a factory", attr)
		}
	}
	if got := clusterAttrs["JobMaterializeLimit"]; got != "3" {
		t.Errorf("JobMaterializeLimit = %s, want 3 (the job count, which clamps the unspecified limit)", got)
	}

	// Now wait for the schedd to materialize the procs out of the digest.
	var ads []map[string]string
	deadline := time.Now().Add(60 * time.Second)
	for {
		found, err := queryFactoryProcs(ctx, schedd, cluster)
		if err != nil {
			t.Fatalf("failed to query cluster %d: %v", cluster, err)
		}
		if len(found) >= 3 || time.Now().After(deadline) {
			ads = found
			break
		}
		time.Sleep(time.Second)
	}
	if len(ads) != 3 {
		harness.PrintScheddLog()
		t.Fatalf("the schedd materialized %d procs of cluster %d, want 3", len(ads), cluster)
	}

	// Each proc has to have got its own row and its own proc id, which is
	// the whole point of leaving $(item) and $(Process) in the digest.
	want := map[string]bool{"alpha 0": true, "beta 1": true, "gamma 2": true}
	for _, ad := range ads {
		t.Logf("materialized proc: %v", ad)
		args := strings.Trim(ad["Arguments"], `"`)
		if args == "" {
			args = strings.Trim(ad["Args"], `"`)
		}
		if !want[args] {
			t.Errorf("materialized proc has Arguments %q, which is not one of the three expected rows", args)
			continue
		}
		delete(want, args)
	}
	for args := range want {
		t.Errorf("no materialized proc has Arguments %q", args)
	}
}

// queryFactoryProcs returns one map of attributes per proc of cluster.
func queryFactoryProcs(ctx context.Context, schedd *Schedd, cluster int) ([]map[string]string, error) {
	ads, err := schedd.Query(ctx, "ClusterId == "+strconv.Itoa(cluster), []string{"ClusterId", "ProcId", "Arguments", "Args"})
	if err != nil {
		return nil, err
	}
	out := make([]map[string]string, 0, len(ads))
	for _, ad := range ads {
		attrs := map[string]string{}
		for _, name := range ad.GetAttributes() {
			if expr, ok := ad.Lookup(name); ok && expr != nil {
				attrs[name] = expr.String()
			}
		}
		out = append(out, attrs)
	}
	return out, nil
}

// TestSubmitFallsBackWhenTheScheddRefusesFactories checks the other path: a
// schedd with SCHEDD_ALLOW_LATE_MATERIALIZE off still accepts a submit file
// that asks for a factory, by materializing the procs here instead.
//
// condor_submit does the same, and silently: max_materialize and max_idle ask
// for late materialization, they do not insist on it. Failing the submission
// would make a submit file that runs against one pool fail against another
// for a reason the submitter cannot see.
func TestSubmitFallsBackWhenTheScheddRefusesFactories(t *testing.T) {
	if _, err := exec.LookPath("condor_master"); err != nil {
		t.Skip("condor_master not found in PATH - skipping integration test")
	}

	harness := SetupCondorHarnessWithConfig(t, refuseLateMaterialize)
	if err := harness.WaitForSchedd(60 * time.Second); err != nil {
		t.Fatalf("schedd failed to start: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	collector := NewCollector(harness.GetCollectorAddr())
	location, err := collector.LocateDaemon(ctx, "Schedd", "")
	if err != nil {
		t.Fatalf("failed to locate schedd: %v", err)
	}
	schedd := NewSchedd(location.Name, location.Address)

	submitFile := `
executable = /bin/sleep
arguments = $(item) $(Process)
universe = vanilla
request_cpus = 1
request_memory = 128
requirements = false
max_idle = 5
queue item in (alpha beta gamma)
`
	clusterIDStr, err := schedd.Submit(ctx, submitFile)
	if err != nil {
		harness.PrintScheddLog()
		t.Fatalf("failed to submit against a schedd that refuses factories: %v", err)
	}
	cluster, err := strconv.Atoi(clusterIDStr)
	if err != nil {
		t.Fatalf("submit returned a non-numeric cluster id %q: %v", clusterIDStr, err)
	}

	clusterAttrs, procs := factoryClusterAttrs(t, harness.GetSpoolDir(), cluster)
	if clusterAttrs == nil {
		t.Fatalf("cluster %d has no cluster ad in job_queue.log", cluster)
	}
	if _, ok := clusterAttrs["JobMaterializeLimit"]; ok {
		t.Error("the schedd recorded a materialize limit although it advertises LateMaterialize = false")
	}
	if len(procs) != 3 {
		t.Fatalf("got %d proc ads for cluster %d, want 3 materialized by the client", len(procs), cluster)
	}
}
