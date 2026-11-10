package htcondor

import (
	"context"
	"errors"
	"io"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/bbockelm/golang-htcondor/classadlog"
)

// setAttrsByKey reads the schedd's job_queue.log and returns, for every ad the
// log mentions, the set of attributes that were set on that ad.
//
// The log is the ground truth for attribute placement. It cannot be observed
// over the wire: QUERY_JOB_ADS merges a proc ad with its chained cluster ad
// before returning it, so a query cannot tell an attribute stored on the proc
// from one inherited from the cluster.
func setAttrsByKey(t *testing.T, spoolDir string) map[string]map[string]string {
	t.Helper()

	parser := classadlog.NewParser(filepath.Join(spoolDir, "job_queue.log"))
	if err := parser.Open(); err != nil {
		t.Fatalf("failed to open job_queue.log: %v", err)
	}
	defer func() {
		if err := parser.Close(); err != nil {
			t.Logf("warning: failed to close job_queue.log: %v", err)
		}
	}()

	byKey := make(map[string]map[string]string)
	for {
		entry, err := parser.ReadEntry()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			t.Fatalf("failed to read job_queue.log: %v", err)
		}
		if entry == nil || entry.OpType != classadlog.OpSetAttribute {
			continue
		}
		if byKey[entry.Key] == nil {
			byKey[entry.Key] = make(map[string]string)
		}
		byKey[entry.Key][entry.Name] = entry.Value
	}
	return byKey
}

// jobQueueKey parses a job_queue.log key into its cluster and proc ids.
// Cluster ads are keyed with a leading zero ("042.-1" for cluster 42), which
// strconv.Atoi accepts.
func jobQueueKey(key string) (cluster, proc int, ok bool) {
	dot := strings.LastIndex(key, ".")
	if dot < 0 {
		return 0, 0, false
	}
	cluster, err := strconv.Atoi(key[:dot])
	if err != nil {
		return 0, 0, false
	}
	proc, err = strconv.Atoi(key[dot+1:])
	if err != nil {
		return 0, 0, false
	}
	return cluster, proc, true
}

// attrNames returns the sorted attribute names of one ad's recorded writes.
func attrNames(attrs map[string]string) []string {
	names := make([]string, 0, len(attrs))
	for name := range attrs {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

// TestSubmitPlacesSharedAttributesOnClusterAd checks where a multi-proc
// submission's attributes land in the queue.
//
// Everything shared across the procs belongs on the cluster ad, and the first
// proc's ad should hold nothing but ProcId and JobStatus -- see issue #746.
// Before that change every proc carried its own copy of all ~30 attributes
// and the cluster ad was left empty.
func TestSubmitPlacesSharedAttributesOnClusterAd(t *testing.T) {
	if _, err := exec.LookPath("condor_master"); err != nil {
		t.Skip("condor_master not found in PATH - skipping integration test")
	}

	harness := SetupCondorHarness(t)
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

	// requirements = false keeps every proc idle, so nothing but the
	// submission itself writes to these ads. arguments = $(Process) gives
	// each proc exactly one attribute of its own.
	submitFile := `
executable = /bin/sleep
arguments = $(Process)
universe = vanilla
request_cpus = 1
request_memory = 128
requirements = false
queue 3
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

	var clusterAttrs map[string]string
	procAttrs := make(map[int]map[string]string)
	for key, attrs := range setAttrsByKey(t, harness.GetSpoolDir()) {
		c, p, ok := jobQueueKey(key)
		if !ok || c != cluster {
			continue
		}
		t.Logf("%s (cluster %d proc %d): %v", key, c, p, attrNames(attrs))
		if p == clusterAdProcID {
			clusterAttrs = attrs
		} else {
			procAttrs[p] = attrs
		}
	}

	if clusterAttrs == nil {
		t.Fatalf("cluster %d has no cluster ad in job_queue.log", cluster)
	}
	if len(procAttrs) != 3 {
		t.Fatalf("got %d proc ads for cluster %d, want 3", len(procAttrs), cluster)
	}

	// The attributes the submit file shares across all three procs belong on
	// the cluster ad and on no proc ad.
	for _, attr := range []string{"Cmd", "Owner", "JobUniverse", "Requirements", "RequestCpus", "RequestMemory", "Iwd", "QDate"} {
		if _, ok := clusterAttrs[attr]; !ok {
			t.Errorf("cluster ad is missing shared attribute %s", attr)
		}
		for proc := range procAttrs {
			if _, ok := procAttrs[proc][attr]; ok {
				t.Errorf("proc %d stores shared attribute %s, which belongs on the cluster ad", proc, attr)
			}
		}
	}

	// Every proc ad identifies itself and carries its own status, because the
	// schedd's totals by state are computed from the proc ads.
	for proc, attrs := range procAttrs {
		if got, want := attrs["ProcId"], strconv.Itoa(proc); got != want {
			t.Errorf("proc %d has ProcId %q, want %q", proc, got, want)
		}
		if _, ok := attrs["JobStatus"]; !ok {
			t.Errorf("proc %d has no JobStatus of its own", proc)
		}
	}

	// Proc 0's ad *is* the cluster ad, so it holds nothing of its own beyond
	// ProcId and JobStatus. GlobalJobId and anything else the schedd writes at
	// commit time is not in the cluster ad, so the general invariant below
	// covers it without this test having to name it.
	if args, ok := procAttrs[0]["Args"]; ok {
		t.Errorf("proc 0 stores Args = %s; it should be inherited from the cluster ad", args)
	}

	// The one attribute that does differ per proc is sent per proc.
	if got, want := clusterAttrs["Args"], `"0"`; got != want {
		t.Errorf("cluster ad has Args %s, want %s (proc 0's value)", got, want)
	}
	for _, proc := range []int{1, 2} {
		if got, want := procAttrs[proc]["Args"], `"`+strconv.Itoa(proc)+`"`; got != want {
			t.Errorf("proc %d has Args %s, want %s", proc, got, want)
		}
	}

	// The invariant the whole change rests on: a proc ad never stores a value
	// its cluster ad already holds, because it inherits that value through the
	// chain. JobStatus is the documented exception.
	for proc, attrs := range procAttrs {
		for name, value := range attrs {
			if strings.EqualFold(name, "JobStatus") {
				continue
			}
			if clusterValue, ok := clusterAttrs[name]; ok && clusterValue == value {
				t.Errorf("proc %d stores %s = %s, a duplicate of the cluster ad's value", proc, name, value)
			}
		}
	}
}
