//go:build integration

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

// TestScheddAggregateCounts checks the schedd's native grouping against
// a real queue.
//
// This is the path a pool with no htcondordb mirror takes when asked to
// count jobs. Before it existed, aggregate_jobs simply failed there --
// while the guidance on every other tool said to prefer counting over
// listing, which is advice that only worked for pools that had a
// mirror.
//
// Setting ProjectionIsGroupBy routes the request to the schedd's
// aggregating handler, which walks the queue once and returns one row
// per group carrying JobCount. The assertion that matters is that those
// counts are right; that no ads crossed the wire is the reason to care.
func TestScheddAggregateCounts(t *testing.T) {
	if _, err := exec.LookPath("condor_master"); err != nil {
		t.Skip("condor_master not found in PATH")
	}
	tempDir, _ := os.MkdirTemp("", "htcondor-agg-*")
	defer os.RemoveAll(tempDir)
	socketDir, _ := os.MkdirTemp("/tmp", "htc_agg_sock_*")
	defer os.RemoveAll(socketDir)
	defer func() {
		if t.Failed() {
			printHTCondorLogs(tempDir, t)
		}
	}()

	passwordsDir := filepath.Join(tempDir, "passwords.d")
	os.MkdirAll(passwordsDir, 0700)
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i)
	}
	os.WriteFile(filepath.Join(passwordsDir, "POOL"), key, 0600)

	const trustDomain = "test.htcondor.org"
	configFile := filepath.Join(tempDir, "condor_config")
	if err := writeMiniCondorConfig(configFile, tempDir, socketDir, passwordsDir, trustDomain, t); err != nil {
		t.Fatal(err)
	}
	cf, _ := os.OpenFile(configFile, os.O_APPEND|os.O_WRONLY, 0600)
	fmt.Fprintf(cf, "\nUID_DOMAIN = %s\nTRUST_DOMAIN = %s\nQUEUE_ALL_USERS_TRUSTED = True\n", trustDomain, trustDomain)
	cf.Close()

	os.Setenv("CONDOR_CONFIG", configFile)
	defer htcondor.ReloadDefaultConfig()
	defer os.Unsetenv("CONDOR_CONFIG")
	htcondor.ReloadDefaultConfig()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	m, err := startCondorMaster(ctx, configFile, tempDir)
	if err != nil {
		t.Fatal(err)
	}
	defer stopCondorMaster(m, t)
	if err := waitForCondor(tempDir, 60*time.Second, t); err != nil {
		t.Fatal(err)
	}
	scheddAddr, _ := getScheddAddress(tempDir, 10*time.Second)

	owner := currentOSUser(t)
	const nAlice, nBob = 3, 2
	for i := 0; i < nAlice; i++ {
		submitJobOwnedBy(t, tempDir, configFile, "alice")
	}
	for i := 0; i < nBob; i++ {
		submitJobOwnedBy(t, tempDir, configFile, "bob")
	}
	_ = owner

	schedd := htcondor.NewSchedd("local", scheddAddr)

	// Ungrouped: one total.
	rows, err := schedd.AggregateJobs(ctx, "true", nil, nil)
	if err != nil {
		t.Fatalf("AggregateJobs (total): %v", err)
	}
	total := int64(0)
	for _, r := range rows {
		total += r.Count
	}
	t.Logf("TOTAL rows=%d count=%d (want %d)", len(rows), total, nAlice+nBob)
	if total != nAlice+nBob {
		t.Errorf("total = %d, want %d", total, nAlice+nBob)
	}

	// Grouped by Owner.
	rows, err = schedd.AggregateJobs(ctx, "true", []string{"Owner"}, nil)
	if err != nil {
		t.Fatalf("AggregateJobs (by Owner): %v", err)
	}
	got := map[string]int64{}
	for _, r := range rows {
		if len(r.Group) == 1 {
			got[r.Group[0]] = r.Count
		}
	}
	t.Logf("BY OWNER: %v", got)
	if got["alice"] != nAlice || got["bob"] != nBob {
		t.Errorf("by Owner = %v, want alice=%d bob=%d", got, nAlice, nBob)
	}
}
