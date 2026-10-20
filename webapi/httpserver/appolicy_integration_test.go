//go:build integration

package httpserver

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	htcondor "github.com/bbockelm/golang-htcondor"
)

// TestRESTSubmitTakesTheAccessPointsRequestDefaults submits through
// POST /api/v1/jobs a job that omits request_memory and request_cpus,
// to a schedd configured with its own JOB_DEFAULT_REQUEST* values, and
// reads the queue: the job must carry the access point's defaults, which
// this server learns by asking the schedd, not HTCondor's built-in ones.
func TestRESTSubmitTakesTheAccessPointsRequestDefaults(t *testing.T) {
	t.Parallel()
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}
	if _, err := exec.LookPath("condor_master"); err != nil {
		t.Skip("condor_master not found in PATH - skipping integration test")
	}

	harness := htcondor.SetupCondorHarnessWithConfig(t, "JOB_DEFAULT_REQUESTMEMORY = 777\nJOB_DEFAULT_REQUESTCPUS = 3\n")
	if err := harness.WaitForDaemons(); err != nil {
		t.Fatalf("Daemons failed to start: %v", err)
	}
	location, err := htcondor.NewCollector(harness.GetCollectorAddr()).LocateDaemon(context.Background(), "Schedd", "")
	if err != nil {
		t.Fatalf("Failed to locate schedd: %v", err)
	}
	schedd := htcondor.NewSchedd(location.Name, location.Address)

	passwordsDir := filepath.Join(harness.GetSpoolDir(), "passwords.d")
	if err := os.MkdirAll(passwordsDir, 0700); err != nil {
		t.Fatal(err)
	}
	signingKeyPath := filepath.Join(passwordsDir, "POOL")
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i)
	}
	if err := os.WriteFile(signingKeyPath, key, 0600); err != nil {
		t.Fatal(err)
	}

	server, err := NewServer(Config{
		ListenAddr:               "127.0.0.1:0",
		ScheddName:               location.Name,
		ScheddAddr:               location.Address,
		UserHeader:               "X-Test-User",
		UserHeaderTrustAnyUnsafe: true, // demo opt-in: tests run on a single host with no proxy
		SigningKeyPath:           signingKeyPath,
		TrustDomain:              "test.htcondor.org",
		UIDDomain:                "test.htcondor.org",
		OAuth2DBPath:             filepath.Join(harness.GetSpoolDir(), "oauth2.db"),
	})
	if err != nil {
		t.Fatalf("Failed to create server: %v", err)
	}
	go func() { _ = server.Start() }()
	defer func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = server.Shutdown(ctx)
	}()
	baseURL := ""
	for deadline := time.Now().Add(10 * time.Second); time.Now().Before(deadline); time.Sleep(50 * time.Millisecond) {
		if addr := server.GetAddr(); addr != "" {
			baseURL = "http://" + addr
			break
		}
	}
	if baseURL == "" {
		t.Fatal("the server never started listening")
	}
	if err := waitForServer(baseURL, 10*time.Second); err != nil {
		t.Fatal(err)
	}

	client := &http.Client{Timeout: 30 * time.Second}
	cluster, jobID := submitJob(t, client, baseURL, localOwner(t),
		"executable = /bin/sleep\narguments = 1\ntransfer_executable = false\nqueue\n")
	defer func() {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		_, _ = schedd.RemoveJobsByID(ctx, []string{jobID}, "test cleanup")
	}()

	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	ads, _, err := schedd.QueryWithOptions(ctx, fmt.Sprintf("ClusterId == %d", cluster),
		&htcondor.QueryOptions{Projection: []string{"RequestMemory", "RequestCpus"}})
	if err != nil || len(ads) != 1 {
		t.Fatalf("query: %d ads, %v", len(ads), err)
	}
	if v, _ := ads[0].EvaluateAttrInt("RequestMemory"); v != 777 {
		t.Errorf("RequestMemory = %d, want the access point's 777", v)
	}
	if v, _ := ads[0].EvaluateAttrInt("RequestCpus"); v != 3 {
		t.Errorf("RequestCpus = %d, want the access point's 3", v)
	}
}
