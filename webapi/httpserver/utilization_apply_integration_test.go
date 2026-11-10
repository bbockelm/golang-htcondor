//go:build integration

package httpserver

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	htcondor "github.com/bbockelm/golang-htcondor"
	"github.com/bbockelm/golang-htcondor/webapi/utilization"
)

// TestUtilizationApplyIntegration runs the Utilization round trip on a
// real pool: a finished batch of twenty short jobs over-requesting
// memory and disk, then a waiting batch of the same program that cannot
// match. The analysis must find the finished batch, the detail must
// count the waiting jobs, and apply must change their requests to the
// advised values.
//
//nolint:gocyclo // one end-to-end scenario, read top to bottom
func TestUtilizationApplyIntegration(t *testing.T) {
	t.Parallel()
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}
	if _, err := exec.LookPath("condor_master"); err != nil {
		t.Skip("condor_master not found in PATH - skipping integration test")
	}
	harness := htcondor.SetupCondorHarnessWithConfig(t, "NUM_CPUS = 10\nMEMORY = 20480\nSTARTER_UPDATE_INTERVAL = 2\n")
	if err := harness.WaitForDaemons(); err != nil {
		t.Fatalf("Daemons failed to start: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Minute)
	defer cancel()
	location, err := htcondor.NewCollector(harness.GetCollectorAddr()).LocateDaemon(ctx, "Schedd", "")
	if err != nil {
		t.Fatalf("Failed to locate schedd: %v", err)
	}
	schedd := htcondor.NewSchedd(location.Name, location.Address)
	testUser := localOwner(t)

	passwordsDir := filepath.Join(harness.GetSpoolDir(), "passwords.d")
	if err := os.MkdirAll(passwordsDir, 0o700); err != nil {
		t.Fatal(err)
	}
	signingKeyPath := filepath.Join(passwordsDir, "POOL")
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i)
	}
	if err := os.WriteFile(signingKeyPath, key, 0o600); err != nil {
		t.Fatal(err)
	}
	server, err := NewServer(Config{
		ListenAddr:               "127.0.0.1:0",
		ScheddName:               location.Name,
		ScheddAddr:               location.Address,
		UserHeader:               "X-Test-User",
		UserHeaderTrustAnyUnsafe: true,
		SigningKeyPath:           signingKeyPath,
		TrustDomain:              "test.htcondor.org",
		UIDDomain:                "test.htcondor.org",
		OAuth2DBPath:             filepath.Join(harness.GetSpoolDir(), "oauth2.db"),
	})
	if err != nil {
		t.Fatal(err)
	}
	go func() { _ = server.Start() }()
	defer func() {
		shutdownCtx, c := context.WithTimeout(context.Background(), 5*time.Second)
		defer c()
		_ = server.Shutdown(shutdownCtx)
	}()
	time.Sleep(500 * time.Millisecond)
	base := "http://" + server.GetAddr()
	client := &http.Client{Timeout: time.Minute}
	call := func(method, path string, body any, out any) int {
		t.Helper()
		var rdr *bytes.Reader
		if body != nil {
			b, _ := json.Marshal(body)
			rdr = bytes.NewReader(b)
		} else {
			rdr = bytes.NewReader(nil)
		}
		req, _ := http.NewRequestWithContext(ctx, method, base+path, rdr)
		req.Header.Set("X-Test-User", testUser)
		req.Header.Set("Content-Type", "application/json")
		resp, err := client.Do(req)
		if err != nil {
			t.Fatalf("%s %s: %v", method, path, err)
		}
		defer func() { _ = resp.Body.Close() }()
		if out != nil && resp.StatusCode == http.StatusOK {
			if err := json.NewDecoder(resp.Body).Decode(out); err != nil {
				t.Fatalf("%s %s: decoding: %v", method, path, err)
			}
		}
		return resp.StatusCode
	}

	work := t.TempDir()
	finished, err := schedd.Submit(ctx, fmt.Sprintf(`
universe = vanilla
executable = /bin/sleep
arguments = 2
initialdir = %s
request_memory = 1024
request_disk = 2GB
queue 20
`, work))
	if err != nil {
		t.Fatalf("submitting the finished batch: %v", err)
	}
	t.Logf("finished batch %s", finished)
	deadline := time.Now().Add(150 * time.Second)
	for {
		ads, _, err := schedd.QueryWithOptions(ctx, "ClusterId == "+finished, &htcondor.QueryOptions{Projection: []string{"JobStatus"}})
		if err == nil && len(ads) == 0 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("the finished batch did not finish in time (%d still queued)", len(ads))
		}
		time.Sleep(2 * time.Second)
	}

	// The same program, waiting: it can never match.
	waiting, err := schedd.Submit(ctx, fmt.Sprintf(`
universe = vanilla
executable = /bin/sleep
arguments = 2
initialdir = %s
request_memory = 1024
request_disk = 2GB
requirements = false
queue 3
`, work))
	if err != nil {
		t.Fatalf("submitting the waiting batch: %v", err)
	}
	defer func() {
		cleanup, c := context.WithTimeout(context.Background(), 10*time.Second)
		defer c()
		_, _ = schedd.RemoveJobs(cleanup, "ClusterId == "+waiting, "test cleanup")
	}()

	var summary utilization.Summary
	if code := call(http.MethodGet, "/api/v1/utilization?days=1", nil, &summary); code != http.StatusOK {
		t.Fatalf("GET /utilization: %d", code)
	}
	var wfKey string
	for _, w := range summary.Workflows {
		if w.Executable == "sleep" && w.Jobs == 20 {
			wfKey = w.Key
		}
	}
	if wfKey == "" {
		t.Fatalf("no 20-job sleep workflow in %+v", summary.Workflows)
	}
	var detail struct {
		Workflow    utilization.Workflow `json:"workflow"`
		WaitingJobs *int                 `json:"waiting_jobs"`
	}
	if code := call(http.MethodGet, "/api/v1/utilization/workflow?days=1&w="+wfKey, nil, &detail); code != http.StatusOK {
		t.Fatalf("GET /utilization/workflow: %d", code)
	}
	if detail.WaitingJobs == nil || *detail.WaitingJobs != 3 {
		t.Fatalf("waiting_jobs = %v, want 3", detail.WaitingJobs)
	}
	var ids []string
	want := map[string]float64{}
	for _, a := range detail.Workflow.Advice {
		if a.Applies {
			ids = append(ids, a.ID)
			want[a.Change.Attribute] = a.Change.Value
		}
	}
	if len(ids) == 0 {
		t.Fatalf("no applicable advice: %+v", detail.Workflow.Advice)
	}
	t.Logf("applying %v: %v", ids, want)

	var applied UtilizationApplyResponse
	if code := call(http.MethodPost, "/api/v1/utilization/apply", map[string]any{"w": wfKey, "days": 1, "advice": ids}, &applied); code != http.StatusOK {
		t.Fatalf("POST /utilization/apply: %d", code)
	}
	if applied.Edited != 3 || len(applied.Failed) != 0 {
		t.Errorf("apply = %+v", applied)
	}
	attrs := make([]string, 0, len(want))
	for a := range want {
		attrs = append(attrs, a)
	}
	ads, _, err := schedd.QueryWithOptions(ctx, "ClusterId == "+waiting, &htcondor.QueryOptions{Projection: attrs})
	if err != nil || len(ads) != 3 {
		t.Fatalf("reading the waiting jobs: %d ads, %v", len(ads), err)
	}
	for _, ad := range ads {
		for a, v := range want {
			if got, ok := ad.EvaluateAttrNumber(a); !ok || got != v {
				t.Errorf("%s = %v, want %v", a, got, v)
			}
		}
	}
}
