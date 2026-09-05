//go:build integration

//nolint:errcheck,noctx,gosec // Integration test file with acceptable test patterns
package httpserver

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	htcondor "github.com/bbockelm/golang-htcondor"
)

// The aggregate path had no test at all, which is why a report of
// "constraints are ignored" could not be checked without a live pool.
// This runs the real thing against a real schedd: the constraint is
// asserted to agree with a plain query over the same jobs, so a
// constraint that stopped being applied -- or was applied to a projected
// ad that no longer carries the attribute -- fails here.
func TestAggregateJobsAgainstARealSchedd(t *testing.T) {
	if _, err := exec.LookPath("condor_master"); err != nil {
		t.Skip("condor_master not found in PATH, skipping integration test")
	}

	tempDir, err := os.MkdirTemp("", "htcondor-agg-*")
	if err != nil {
		t.Fatalf("temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)
	socketDir, err := os.MkdirTemp("/tmp", "htc_agg_sock_*")
	if err != nil {
		t.Fatalf("socket dir: %v", err)
	}
	defer os.RemoveAll(socketDir)
	defer func() {
		if t.Failed() {
			printHTCondorLogs(tempDir, t)
		}
	}()

	passwordsDir := filepath.Join(tempDir, "passwords.d")
	if err := os.MkdirAll(passwordsDir, 0700); err != nil {
		t.Fatalf("passwords.d: %v", err)
	}
	if err := os.WriteFile(filepath.Join(passwordsDir, "POOL"), make([]byte, 32), 0600); err != nil {
		t.Fatalf("signing key: %v", err)
	}

	configFile := filepath.Join(tempDir, "condor_config")
	if err := writeMiniCondorConfig(configFile, tempDir, socketDir, passwordsDir, "test.htcondor.org", t); err != nil {
		t.Fatalf("config: %v", err)
	}
	os.Setenv("CONDOR_CONFIG", configFile)
	defer os.Unsetenv("CONDOR_CONFIG")

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	condorMaster, err := startCondorMaster(ctx, configFile, tempDir)
	if err != nil {
		t.Fatalf("start condor_master: %v", err)
	}
	defer stopCondorMaster(condorMaster, t)
	if err := waitForCondor(tempDir, 60*time.Second, t); err != nil {
		t.Fatalf("condor did not start: %v", err)
	}
	scheddAddr, err := getScheddAddress(tempDir, 10*time.Second)
	if err != nil {
		t.Fatalf("schedd address: %v", err)
	}
	schedd := htcondor.NewSchedd("local", scheddAddr)

	const submitted = 4
	for i := 0; i < submitted; i++ {
		sf := fmt.Sprintf("executable = /bin/true\ntransfer_executable = False\nlog = agg%d.log\nqueue\n", i)
		if _, _, err := schedd.SubmitRemote(ctx, sf); err != nil {
			t.Fatalf("submit %d: %v", i, err)
		}
	}

	// The status the jobs actually settled in, read from a plain query.
	// Asserting against a hardcoded status would make this test a
	// statement about HTCondor's scheduling rather than about the
	// aggregate path.
	ads, _, err := schedd.QueryWithOptions(ctx, "true", &htcondor.QueryOptions{
		Projection: []string{"ClusterId", "JobStatus", "Owner"}, Limit: 100,
	})
	if err != nil {
		t.Fatalf("plain query: %v", err)
	}
	if len(ads) != submitted {
		t.Fatalf("plain query saw %d jobs, submitted %d", len(ads), submitted)
	}
	byStatus := map[int64]int64{}
	for _, ad := range ads {
		st, ok := ad.EvaluateAttrInt("JobStatus")
		if !ok {
			t.Fatalf("job ad has no JobStatus: %v", ad)
		}
		byStatus[st]++
	}
	var presentStatus, absentStatus int64 = -1, 99
	for st := range byStatus {
		presentStatus = st
		break
	}
	if presentStatus < 0 {
		t.Fatal("no jobs to aggregate over")
	}
	t.Logf("submitted %d jobs; observed JobStatus distribution %v", submitted, byStatus)

	total := func(rows []htcondor.AggregateRow) int64 {
		var n int64
		for _, r := range rows {
			n += r.Count
		}
		return n
	}


	t.Run("an unconstrained aggregate counts every job", func(t *testing.T) {
		rows, err := schedd.AggregateJobs(ctx, "true", []string{"Owner"}, nil)
		if err != nil {
			t.Fatalf("aggregate: %v", err)
		}
		if got := total(rows); got != submitted {
			t.Errorf("counted %d, want %d (rows: %v)", got, submitted, rows)
		}
	})

	t.Run("a matching constraint is applied, not ignored", func(t *testing.T) {
		c := fmt.Sprintf("JobStatus == %d", presentStatus)
		rows, err := schedd.AggregateJobs(ctx, c, []string{"Owner"}, nil)
		if err != nil {
			t.Fatalf("aggregate: %v", err)
		}
		if got, want := total(rows), byStatus[presentStatus]; got != want {
			t.Errorf("%q counted %d, want %d -- the constraint disagrees with a plain query "+
				"over the same jobs (rows: %v)", c, got, want, rows)
		}
	})

	t.Run("a non-matching constraint excludes everything", func(t *testing.T) {
		// The other half of the previous case: a constraint that is
		// merely ignored would return every job here.
		c := fmt.Sprintf("JobStatus == %d", absentStatus)
		rows, err := schedd.AggregateJobs(ctx, c, []string{"Owner"}, nil)
		if err != nil {
			t.Fatalf("aggregate: %v", err)
		}
		if got := total(rows); got != 0 {
			t.Errorf("%q counted %d, want 0 -- the constraint is not being applied (rows: %v)",
				c, got, rows)
		}
	})

	t.Run("grouping by an attribute splits the counts", func(t *testing.T) {
		rows, err := schedd.AggregateJobs(ctx, "true", []string{"JobStatus"}, nil)
		if err != nil {
			t.Fatalf("aggregate: %v", err)
		}
		if len(rows) != len(byStatus) {
			t.Errorf("got %d group(s), want %d (one per observed status): %v", len(rows), len(byStatus), rows)
		}
		if got := total(rows); got != submitted {
			t.Errorf("grouped counts sum to %d, want %d", got, submitted)
		}
	})

	// The limit is what silently dropped groups. Prove it truncates, so
	// the +1 probe the MCP tool uses to DETECT truncation is resting on
	// real behaviour rather than an assumption about the schedd.
	t.Run("LimitResults truncates the group list", func(t *testing.T) {
		rows, err := schedd.AggregateJobs(ctx, "true", []string{"ClusterId"},
			&htcondor.QueryOptions{Limit: 1})
		if err != nil {
			t.Fatalf("aggregate: %v", err)
		}
		if len(rows) != 1 {
			t.Fatalf("limit 1 returned %d group(s), want 1: %v", len(rows), rows)
		}
		all, err := schedd.AggregateJobs(ctx, "true", []string{"ClusterId"},
			&htcondor.QueryOptions{Limit: 100})
		if err != nil {
			t.Fatalf("aggregate: %v", err)
		}
		if len(all) <= 1 {
			t.Fatalf("expected more than one cluster to group by, got %v", all)
		}
		// And nothing in the truncated answer says it was truncated,
		// which is exactly why the caller has to ask for limit+1.
		if total(rows) >= total(all) {
			t.Errorf("truncated total %d is not less than the full total %d",
				total(rows), total(all))
		}
	})
}
