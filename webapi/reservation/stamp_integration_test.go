//go:build integration

package reservation_test

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/PelicanPlatform/classad/classad"

	htcondor "github.com/bbockelm/golang-htcondor"
	"github.com/bbockelm/golang-htcondor/webapi/reservation"
)

// TestClusterAdStampGovernsEveryProc is the claim the stamping design
// rests on: a proc inherits RuntimeP90Bucket from its cluster ad, and
// the startd's START sees the inherited value.
//
// It matters because of the ratio. On the access point this was
// measured against, the idle queue holds a median of 43,567 jobs in 371
// distinct clusters. If this were false, stamping would cost one write
// per job and the whole subsystem would be gated on schedd write
// throughput; because it is true, it costs one write per cluster.
//
// The negative half is what makes the test mean anything: the same
// procs are watched first with no stamp anywhere, and must NOT run.
// Without that, a pool that would have run them regardless looks like
// an inheritance that works.
func TestClusterAdStampGovernsEveryProc(t *testing.T) {
	cfg := "NUM_CPUS = 4\nMEMORY = 4096\n" +
		"SEC_ENABLE_REMOTE_ADMINISTRATION = True\n" +
		reservation.StartStanza + "\n" +
		"NEGOTIATOR_INTERVAL = 3\nNEGOTIATOR_CYCLE_DELAY = 3\nSCHEDD_INTERVAL = 3\nUPDATE_INTERVAL = 3\n"
	h, coll := harness(t, cfg)
	machines := waitForSlots(t, coll)
	if len(machines) == 0 {
		t.Fatal("no machines")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	act := &reservation.PoolActuator{Query: coll, RequireCapability: true}
	bell := time.Now().Add(time.Hour)
	if err := act.Hold(ctx, reservation.HoldRequest{
		Machine:  machines[0].Name,
		Deadline: bell,
		Until:    bell.Add(time.Hour),
		Project:  "cs301",
	}); err != nil {
		t.Fatalf("Hold: %v", err)
	}

	const procs = 3
	cluster := submitCluster(t, h, procs)

	status := func() string {
		//nolint:gosec,noctx // G204: fixed command in a test
		c := exec.Command("condor_q", strconv.Itoa(cluster), "-af", "ProcId", "JobStatus", reservation.AttrBucket)
		c.Env = append(os.Environ(), "CONDOR_CONFIG="+h.GetConfigFile())
		o, _ := c.CombinedOutput()
		return strings.TrimSpace(string(o))
	}
	anyRunning := func() bool {
		for _, line := range strings.Split(status(), "\n") {
			if f := strings.Fields(line); len(f) >= 2 && f[1] == "2" {
				return true
			}
		}
		return false
	}

	// Unstamped: nothing may run. Held open long enough for several
	// negotiation cycles, so "did not run" is not "has not run yet".
	deadline := time.Now().Add(40 * time.Second)
	for time.Now().Before(deadline) {
		if anyRunning() {
			t.Fatalf("an unstamped job ran on a held machine:\n%s", status())
		}
		time.Sleep(4 * time.Second)
	}

	// One write, to the cluster ad.
	conn, err := htcondor.NewQmgmtConnection(ctx, scheddAddress(t, h))
	if err != nil {
		t.Fatalf("qmgmt connect: %v", err)
	}
	defer func() { _ = conn.Close() }()
	// NewQmgmtConnection's capability exchange already opened a
	// transaction, so there is nothing to begin.
	if err := conn.SetAttribute(ctx, cluster, -1, reservation.AttrBucket, "1800", 0); err != nil {
		t.Fatalf("stamping the cluster ad: %v", err)
	}
	if err := conn.CommitTransaction(ctx); err != nil {
		t.Fatalf("commit: %v", err)
	}

	deadline = time.Now().Add(150 * time.Second)
	for {
		running := 0
		stamped := 0
		for _, line := range strings.Split(status(), "\n") {
			f := strings.Fields(line)
			if len(f) < 3 {
				continue
			}
			if f[1] == "2" {
				running++
			}
			if f[2] == "1800" {
				stamped++
			}
		}
		if stamped == procs && running > 0 {
			// Every proc reports the inherited value, and the sieve
			// admitted at least one of them on it.
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("after stamping only the cluster ad, %d/%d procs report the value and %d run:\n%s",
				stamped, procs, running, status())
		}
		time.Sleep(4 * time.Second)
	}
}

func submitCluster(t *testing.T, h *htcondor.CondorTestHarness, n int) int {
	t.Helper()
	dir := t.TempDir()
	body := "executable = /bin/sleep\narguments = 300\nuniverse = vanilla\n" +
		"request_cpus = 1\nrequest_memory = 128\nshould_transfer_files = no\n" +
		"log = " + filepath.Join(dir, "log") + "\nqueue " + strconv.Itoa(n) + "\n"
	path := filepath.Join(dir, "j.sub")
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatalf("writing the submit file: %v", err)
	}
	//nolint:gosec,noctx // G204: fixed command in a test
	cmd := exec.Command("condor_submit", "-terse", path)
	cmd.Env = append(os.Environ(), "CONDOR_CONFIG="+h.GetConfigFile())
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("condor_submit: %v\n%s", err, out)
	}
	id := strings.TrimSpace(string(out))
	if i := strings.IndexByte(id, '.'); i > 0 {
		id = id[:i]
	}
	cluster, err := strconv.Atoi(id)
	if err != nil {
		t.Fatalf("parsing the cluster id from %q: %v", out, err)
	}
	return cluster
}

func scheddAddress(t *testing.T, h *htcondor.CondorTestHarness) string {
	t.Helper()
	//nolint:gosec,noctx // G204: fixed command in a test
	cmd := exec.Command("condor_status", "-schedd", "-af", "MyAddress")
	cmd.Env = append(os.Environ(), "CONDOR_CONFIG="+h.GetConfigFile())
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("condor_status -schedd: %v\n%s", err, out)
	}
	addr := strings.TrimSpace(string(out))
	if i := strings.IndexByte(addr, '\n'); i > 0 {
		addr = addr[:i]
	}
	if addr == "" {
		t.Fatal("the collector reported no schedd address")
	}
	return addr
}

// TestClusterAdsAreQueryableSeparately is the other half of the
// stamping adapter: deciding what to write needs the value on the
// CLUSTER ad, and a proc ad reports the value it inherits. If the two
// could not be told apart, an unstamped cluster whose submitter set
// their own attribute would look already written and never converge --
// or worse, a cluster the pass just wrote would look unwritten forever.
func TestClusterAdsAreQueryableSeparately(t *testing.T) {
	h, _ := harness(t, "NUM_CPUS = 1\nSCHEDD_INTERVAL = 3\n")
	cluster := submitCluster(t, h, 2)

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	schedd := htcondor.NewSchedd("", scheddAddress(t, h))

	clusterAds := func() []*classad.ClassAd {
		ads, _, err := schedd.QueryWithOptions(ctx, "", &htcondor.QueryOptions{
			Projection: []string{"ClusterId", "ProcId", reservation.AttrBucket},
			Limit:      1000,
			FetchOpts:  htcondor.FetchNoProcAds | htcondor.FetchIncludeClusterAd,
		})
		if err != nil {
			t.Fatalf("querying cluster ads: %v", err)
		}
		return ads
	}

	// Before the write: the cluster ad exists and carries no bucket.
	var found bool
	for _, ad := range clusterAds() {
		id, ok := ad.EvaluateAttrInt("ClusterId")
		if !ok || int(id) != cluster {
			continue
		}
		found = true
		if _, has := ad.Lookup(reservation.AttrBucket); has {
			t.Errorf("a fresh cluster ad already carries %s", reservation.AttrBucket)
		}
	}
	if !found {
		t.Fatalf("no cluster ad for cluster %d came back; FetchNoProcAds does not return what this expects", cluster)
	}

	conn, err := htcondor.NewQmgmtConnection(ctx, scheddAddress(t, h))
	if err != nil {
		t.Fatalf("qmgmt connect: %v", err)
	}
	defer func() { _ = conn.Close() }()
	if err := conn.SetAttribute(ctx, cluster, -1, reservation.AttrBucket, "3600", 0); err != nil {
		t.Fatalf("stamping: %v", err)
	}
	if err := conn.CommitTransaction(ctx); err != nil {
		t.Fatalf("commit: %v", err)
	}

	deadline := time.Now().Add(60 * time.Second)
	for {
		for _, ad := range clusterAds() {
			id, ok := ad.EvaluateAttrInt("ClusterId")
			if !ok || int(id) != cluster {
				continue
			}
			if v, has := ad.EvaluateAttrInt(reservation.AttrBucket); has && v == 3600 {
				return
			}
		}
		if time.Now().After(deadline) {
			t.Fatalf("the cluster ad never reported the value that was written to it")
		}
		time.Sleep(3 * time.Second)
	}
}
