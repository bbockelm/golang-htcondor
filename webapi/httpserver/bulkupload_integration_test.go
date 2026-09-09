//go:build integration

package httpserver

import (
	"archive/tar"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"testing"
	"time"

	htcondor "github.com/bbockelm/golang-htcondor"
)

// The REST half of the cluster-wide upload, over real HTTP against a real
// schedd.
//
// This path differs from the MCP one in the way that matters: the upload
// arrives as a stream and these endpoints accept up to a gigabyte, so a
// fan-out cannot replay it from memory. It is buffered to a file in
// SpoolBufferDir and each proc reads its own copy. The MCP integration
// test cannot cover that -- its tar is already in memory.

// restUploadEnv is one harness plus one server, shared by the subtests
// below. Both entry points spool through the same fan-out, so standing
// up a second HTCondor for the second one would double the wall clock
// and cover nothing new.
type restUploadEnv struct {
	schedd  *htcondor.Schedd
	base    string
	bufDir  string
	harness *htcondor.CondorTestHarness
}

func setupRESTUpload(t *testing.T) *restUploadEnv {
	t.Helper()
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
	collector := htcondor.NewCollector(harness.GetCollectorAddr())
	loc, err := collector.LocateDaemon(context.Background(), "Schedd", "")
	if err != nil {
		t.Fatalf("locating the schedd: %v", err)
	}
	schedd := htcondor.NewSchedd(loc.Name, loc.Address)

	// A buffer directory of our own, so the test can assert the fan-out
	// leaves nothing behind. A server that leaks a gigabyte per call
	// fills the directory and then the disk.
	bufDir := t.TempDir()

	server, err := NewServer(Config{
		ListenAddr:               "127.0.0.1:0",
		ScheddName:               loc.Name,
		ScheddAddr:               loc.Address,
		UserHeader:               "X-Test-User",
		UserHeaderTrustAnyUnsafe: true, // single-host test, no proxy in front
		SigningKeyPath:           harness.GetSigningKeyPath(),
		TrustDomain:              harness.GetTrustDomain(),
		UIDDomain:                harness.GetTrustDomain(),
		SpoolBufferDir:           bufDir,
		OAuth2DBPath:             filepath.Join(harness.GetSpoolDir(), "oauth2.db"),
	})
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	go func() { _ = server.Start() }()
	time.Sleep(500 * time.Millisecond)

	return &restUploadEnv{
		schedd:  schedd,
		base:    "http://" + server.GetAddr(),
		bufDir:  bufDir,
		harness: harness,
	}
}

func TestRESTClusterUpload(t *testing.T) {
	env := setupRESTUpload(t)

	// POST multipart/form-data, the browser and SPA path.
	t.Run("multipart", func(t *testing.T) {
		body, contentType := multipartBody(t, "executable", "restbulk.sh", "#!/bin/sh\nexit 0\n")
		env.uploadCluster(t, "restbulk.sh", http.MethodPost, "/input/multipart", contentType, body)
	})

	// PUT a raw tar, the CLI path. Same fan-out, different framing --
	// and it was the entry point that still only understood a single
	// proc.
	t.Run("put_raw_tar", func(t *testing.T) {
		env.uploadCluster(t, "restput.sh", http.MethodPut, "/input", "application/x-tar",
			tarBody(t, "restput.sh", "#!/bin/sh\nexit 0\n"))
	})
}

// uploadCluster submits a multi-proc cluster, uploads its input in one
// call addressed to the bare cluster id, and holds the result to the
// standard every-proc-ran-and-nothing-leaked bar.
func (env *restUploadEnv) uploadCluster(
	t *testing.T,
	executable string,
	method string,
	suffix string,
	contentType string,
	body io.Reader,
) {
	t.Helper()
	schedd := env.schedd

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	const procs = 12 // above the fan-out's concurrency, so it runs in waves
	cluster, _, err := schedd.SubmitRemote(ctx, fmt.Sprintf(`
universe = vanilla
executable = %s
transfer_executable = true
log = %s.log
request_memory = 64
queue %d
`, executable, executable, procs))
	if err != nil {
		t.Fatalf("submit: %v", err)
	}
	t.Logf("cluster %d, %d procs", cluster, procs)
	waitHeld(t, ctx, schedd, cluster, procs)

	// Addressed to the CLUSTER, not a proc.
	req, err := http.NewRequestWithContext(ctx, method,
		fmt.Sprintf("%s/api/v1/jobs/%d%s", env.base, cluster, suffix), body)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", contentType)
	req.Header.Set("X-Test-User", currentUser(t))

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("upload: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	raw, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("upload returned %d: %s", resp.StatusCode, raw)
	}

	var got struct {
		ClusterID      int      `json:"cluster_id"`
		ProcsSpooled   int      `json:"procs_spooled"`
		ProcsRemaining int      `json:"procs_remaining"`
		Spooled        []string `json:"spooled"`
	}
	if err := json.Unmarshal(raw, &got); err != nil {
		t.Fatalf("response is not the fan-out shape: %v (%s)", err, raw)
	}
	if got.ProcsSpooled != procs {
		t.Errorf("procs_spooled = %d, want %d (%s)", got.ProcsSpooled, procs, raw)
	}
	if got.ProcsRemaining != 0 {
		t.Errorf("procs_remaining = %d, want 0 (%s)", got.ProcsRemaining, raw)
	}

	waitNoneHeld(t, ctx, schedd, cluster)

	// The upload actually arrived. Leaving the hold is a weaker claim:
	// the schedd drops tar entries outside its allow-set silently and
	// clears the hold anyway, so an empty allow-set looks identical at
	// the queue level and then fails at execute time on a missing file.
	// This submission transfers only the executable, so the allow-set
	// depends on Cmd and TransferExecutable surviving the fan-out's
	// projection -- dropping them from jobInputSpoolProjection fails
	// here with "(errno 2) No such file or directory".
	waitAnySucceeded(t, ctx, schedd, cluster)

	// And the buffer file is gone.
	entries, err := os.ReadDir(env.bufDir)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 0 {
		t.Errorf("the fan-out left %d file(s) in the buffer directory", len(entries))
	}
}

func multipartBody(t *testing.T, field, filename, content string) (io.Reader, string) {
	t.Helper()
	var buf bytes.Buffer
	w := multipart.NewWriter(&buf)
	fw, err := w.CreateFormFile(field, filename)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := fw.Write([]byte(content)); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	return &buf, w.FormDataContentType()
}

func tarBody(t *testing.T, name, content string) io.Reader {
	t.Helper()
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	if err := tw.WriteHeader(&tar.Header{
		Name: name,
		Mode: 0o755,
		Size: int64(len(content)),
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := tw.Write([]byte(content)); err != nil {
		t.Fatal(err)
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	return &buf
}

func heldCount(t *testing.T, ctx context.Context, schedd *htcondor.Schedd, cluster int) int {
	t.Helper()
	ads, _, err := schedd.QueryWithOptions(ctx,
		fmt.Sprintf("ClusterId == %d && JobStatus == 5 && HoldReasonCode == 16", cluster),
		&htcondor.QueryOptions{Projection: []string{"ProcId"}, Limit: -1})
	if err != nil {
		t.Fatalf("query: %v", err)
	}
	return len(ads)
}

func waitHeld(t *testing.T, ctx context.Context, schedd *htcondor.Schedd, cluster, want int) {
	t.Helper()
	for deadline := time.Now().Add(60 * time.Second); time.Now().Before(deadline); {
		if heldCount(t, ctx, schedd, cluster) == want {
			return
		}
		time.Sleep(time.Second)
	}
	t.Fatalf("cluster %d never had %d procs held for spooling", cluster, want)
}

func waitNoneHeld(t *testing.T, ctx context.Context, schedd *htcondor.Schedd, cluster int) {
	t.Helper()
	for deadline := time.Now().Add(90 * time.Second); time.Now().Before(deadline); {
		if heldCount(t, ctx, schedd, cluster) == 0 {
			return
		}
		time.Sleep(time.Second)
	}
	t.Fatalf("cluster %d still has %d procs held after a cluster-wide upload",
		cluster, heldCount(t, ctx, schedd, cluster))
}

func waitAnySucceeded(t *testing.T, ctx context.Context, schedd *htcondor.Schedd, cluster int) {
	t.Helper()
	for deadline := time.Now().Add(150 * time.Second); time.Now().Before(deadline); {
		ads, _, err := schedd.QueryWithOptions(ctx, fmt.Sprintf("ClusterId == %d", cluster),
			&htcondor.QueryOptions{
				Projection: []string{"ProcId", "JobStatus", "ExitCode", "HoldReason", "HoldReasonCode"},
				Limit:      -1,
			})
		if err != nil {
			t.Fatalf("query: %v", err)
		}
		for _, ad := range ads {
			st, _ := ad.EvaluateAttrInt("JobStatus")
			code, has := ad.EvaluateAttrInt("ExitCode")
			if st == 4 && has && code == 0 {
				return
			}
			if st == 5 {
				hc, _ := ad.EvaluateAttrInt("HoldReasonCode")
				reason, _ := ad.EvaluateAttrString("HoldReason")
				p, _ := ad.EvaluateAttrInt("ProcId")
				// A hold after spooling will not clear on its own; the
				// usual cause is that the uploaded file never landed.
				t.Fatalf("%d.%d went on hold after the upload (%d): %s", cluster, p, hc, reason)
			}
		}
		time.Sleep(3 * time.Second)
	}
	t.Fatalf("no proc of cluster %d reached ExitCode 0", cluster)
}

// currentUser is the identity the header auth stands in for. It must
// match the owner of the jobs the harness submits, which is whoever is
// running the test.
//
// Deliberately a Fatal and not a Skip: $USER is unset in the CI
// container, and the first version of this read the environment and
// skipped -- so both subtests skipped in "Integration Test in Docker"
// while the job reported green.
func currentUser(t *testing.T) string {
	t.Helper()
	u, err := user.Current()
	if err != nil {
		t.Fatalf("looking up the current user: %v", err)
	}
	return u.Username
}
