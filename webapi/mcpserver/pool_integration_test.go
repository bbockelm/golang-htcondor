//go:build integration

package mcpserver

import (
	"context"
	"encoding/json"
	"os/exec"
	"strings"
	"testing"
	"time"

	htcondor "github.com/bbockelm/golang-htcondor"
)

// TestQueryPoolAgainstARealCollector runs query_pool against a mini
// HTCondor's collector. What the unit tests cannot show is that the
// projections reach a real collector intact: a summary whose projection
// were dropped would come back with every slot's Cpus and Memory missing,
// which this checks for directly.
func TestQueryPoolAgainstARealCollector(t *testing.T) {
	t.Parallel()
	if testing.Short() {
		t.Skip("integration test (forks a real HTCondor)")
	}
	if _, err := exec.LookPath("condor_master"); err != nil {
		t.Skip("condor_master not in PATH")
	}

	harness := htcondor.SetupCondorHarness(t)
	if err := harness.WaitForDaemons(); err != nil {
		t.Fatalf("daemons failed to start: %v", err)
	}
	if err := harness.WaitForStartd(60 * time.Second); err != nil {
		t.Fatalf("startd: %v", err)
	}

	s := contractServer(t)
	s.collector = htcondor.NewCollector(harness.GetCollectorAddr())

	t.Run("slot summary", func(t *testing.T) {
		sc, text := callPool(t, s, nil)
		t.Logf("\n%s", text)
		if n, _ := sc["count"].(float64); n < 1 {
			t.Fatalf("no slots counted: %v", sc)
		}
		if m, _ := sc["machines"].(float64); m < 1 {
			t.Errorf("no machines counted: %v", sc["machines"])
		}
		missing, _ := sc["missing"].(map[string]interface{})
		if missing["Cpus"] != 0.0 || missing["Memory"] != 0.0 {
			t.Errorf("slots came back without Cpus/Memory, so the projection did not reach the collector: %v", missing)
		}
		res, _ := sc["resources"].(map[string]interface{})
		cpus, _ := res["Cpus"].(map[string]interface{})
		if total, _ := cpus["total"].(float64); total <= 0 {
			t.Errorf("Cpus total = %v, want > 0", cpus)
		}
	})

	t.Run("slot listing", func(t *testing.T) {
		sc, _ := callPool(t, s, map[string]interface{}{"mode": "list", "projection": []interface{}{"*"}})
		ads, _ := sc["ads"].([]interface{})
		if len(ads) == 0 {
			t.Fatalf("no slot ads listed: %v", sc)
		}
		first, _ := ads[0].(map[string]interface{})
		if first["Name"] == nil || first["Cpus"] == nil {
			t.Errorf("listed slot lacks Name or Cpus: %v", first)
		}
		raw, _ := json.Marshal(sc)
		if strings.Contains(strings.ToLower(string(raw)), `"claimid"`) {
			t.Errorf("a claim id reached the answer: %s", raw)
		}
	})

	// The assumption the slot totals rest on, checked against a real
	// startd: once a job claims part of the partitionable slot, the
	// partitionable slot advertises less and a dynamic slot advertises
	// the claimed part, so the summed capacity does not change.
	t.Run("claimed resources are counted once", func(t *testing.T) {
		before, _ := callPool(t, s, nil)
		total := func(sc map[string]interface{}, attr, key string) float64 {
			res, _ := sc["resources"].(map[string]interface{})
			r, _ := res[attr].(map[string]interface{})
			v, _ := r[key].(float64)
			return v
		}

		schedd := locateSchedd(t, harness)
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
		defer cancel()
		cluster, err := schedd.Submit(ctx, "universe = vanilla\nexecutable = /bin/sleep\narguments = 300\n"+
			"request_cpus = 1\nrequest_memory = 128\nqueue\n")
		if err != nil {
			t.Fatalf("submit: %v", err)
		}
		jobID := cluster + ".0"
		defer func() {
			cctx, ccancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer ccancel()
			_, _ = schedd.RemoveJobsByID(cctx, []string{jobID}, "test cleanup")
		}()

		var after map[string]interface{}
		deadline := time.Now().Add(90 * time.Second)
		for {
			after, _ = callPool(t, s, nil)
			if total(after, "Cpus", "claimed") > 0 {
				break
			}
			if time.Now().After(deadline) {
				harness.PrintStartdLog()
				t.Fatalf("job %s never claimed a slot; last summary: %v", jobID, after)
			}
			time.Sleep(time.Second)
		}

		types, _ := after["slot_types"].(map[string]interface{})
		if types["Dynamic"] == nil {
			t.Errorf("no dynamic slot after the job matched: %v", types)
		}
		for _, attr := range []string{"Cpus", "Memory"} {
			if b, a := total(before, attr, "total"), total(after, attr, "total"); a != b {
				t.Errorf("%s total changed from %v to %v when a job claimed part of the pool: "+
					"claimed resources are being counted twice or not at all", attr, b, a)
			}
		}
		if got := total(after, "Memory", "claimed"); got < 128 {
			t.Errorf("Memory claimed = %v, want at least the job's 128", got)
		}
		t.Logf("before: %v\nafter: %v", before["resources"], after["resources"])
	})

	t.Run("schedd summary", func(t *testing.T) {
		sc, text := callPool(t, s, map[string]interface{}{"ad_type": "schedd"})
		if n, _ := sc["count"].(float64); n < 1 {
			t.Fatalf("no schedd counted:\n%s", text)
		}
		if missing, _ := sc["missing"].(map[string]interface{}); missing["TotalRunningJobs"] != 0.0 {
			t.Errorf("schedd ad without TotalRunningJobs: %v", missing)
		}
	})
}
