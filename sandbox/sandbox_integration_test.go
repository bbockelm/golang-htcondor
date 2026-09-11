//go:build integration

package sandbox

import (
	"archive/tar"
	"bytes"
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/PelicanPlatform/classad/classad"
	htcondor "github.com/bbockelm/golang-htcondor"
)

// TestInputSandboxRoundtrip tests that input sandbox tarball matches running job's filesystem
//
// Test strategy:
// 1. Create input files with specific directory structure
// 2. Submit a job that lists its directory contents
// 3. Create input sandbox tarball from job ad
// 4. Compare job's actual filesystem with tarball contents
func TestInputSandboxRoundtrip(t *testing.T) {
	// Setup HTCondor test harness
	harness := htcondor.SetupCondorHarness(t)

	// Wait for daemons to start
	if err := harness.WaitForDaemons(); err != nil {
		t.Fatalf("Daemons failed to start: %v", err)
	}

	// Get schedd connection info
	scheddLocation := getScheddAddress(t, harness)
	t.Logf("Schedd discovered at: %s", scheddLocation.Address)

	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()

	// Create schedd client
	schedd := htcondor.NewSchedd(scheddLocation.Name, scheddLocation.Address)

	// Create test input files in a temporary directory
	tempDir := t.TempDir()
	inputDir := filepath.Join(tempDir, "input")
	if err := os.Mkdir(inputDir, 0755); err != nil {
		t.Fatalf("Failed to create input dir: %v", err)
	}

	// Create files with directory structure
	createFile(t, filepath.Join(inputDir, "input.txt"), "input data")
	createFile(t, filepath.Join(inputDir, "script.sh"), "#!/bin/bash\nls -laR > listing.txt")

	dataDir := filepath.Join(inputDir, "data")
	if err := os.Mkdir(dataDir, 0755); err != nil {
		t.Fatalf("Failed to create data dir: %v", err)
	}
	createFile(t, filepath.Join(dataDir, "params.json"), `{"key":"value"}`)

	// Submit job that lists directory contents
	submitFile := fmt.Sprintf(`
universe = vanilla
executable = %s/script.sh
transfer_input_files = %s/input.txt, %s/data/params.json
transfer_output_files = listing.txt
initialdir = %s
output = job.out
error = job.err
log = job.log
should_transfer_files = YES
when_to_transfer_output = ON_EXIT
queue
`, inputDir, inputDir, inputDir, inputDir)

	t.Logf("Submitting job...")
	clusterID, err := schedd.Submit(ctx, submitFile)
	if err != nil {
		harness.PrintScheddLog()
		t.Fatalf("Failed to submit job: %v", err)
	}

	jobID := fmt.Sprintf("%s.0", clusterID)
	t.Logf("Job submitted: %s", jobID)

	// Wait for job to complete
	t.Logf("Waiting for job to complete...")
	if err := waitForJobCompletion(ctx, schedd, clusterID); err != nil {
		harness.PrintScheddLog()
		t.Fatalf("Job did not complete: %v", err)
	}

	// Query job ad from history (job is removed from queue after
	// completion).
	//
	// Owner is not optional: CreateInputSandboxTar resolves the user
	// whose files it reads from OsUser or Owner, and fails outright
	// without one. This projection omitted both, so the test failed on
	// every run with "job ad missing both OsUser and Owner attributes".
	projection := []string{"Iwd", "TransferInput", "TransferExecutable", "Cmd", "Owner", "OsUser"}
	jobs, err := schedd.QueryHistory(ctx, fmt.Sprintf("ClusterId == %s && ProcId == 0", clusterID), projection)
	if err != nil {
		t.Fatalf("Failed to query job history: %v", err)
	}
	if len(jobs) == 0 {
		t.Fatalf("Job not found in history")
	}
	jobAd := jobs[0]

	// Create input sandbox tarball from job ad
	var tarBuf bytes.Buffer
	if err := CreateInputSandboxTar(ctx, jobAd, &tarBuf); err != nil {
		t.Fatalf("Failed to create input sandbox: %v", err)
	}

	// Read tarball contents
	tarFiles := readTarFiles(t, &tarBuf)

	// Verify expected files are in tarball
	expectedFiles := []string{"script.sh", "input.txt", "data/params.json"}
	for _, expectedFile := range expectedFiles {
		if _, ok := tarFiles[expectedFile]; !ok {
			t.Errorf("Expected file %s not found in tarball", expectedFile)
		}
	}

	t.Logf("Input sandbox roundtrip test passed")
}

// TestOutputSandboxRoundtrip runs a job, retrieves its output from the
// schedd, and extracts it.
//
// This test was skipped for "a bug in schedd.ReceiveJobSandbox() --
// files transfer but tarball is empty". There is no such bug. The test
// submitted LOCALLY, and a locally submitted job writes its output into
// the submit directory; nothing is staged in the schedd's spool, which
// is what TRANSFER_DATA_WITH_PERMS serves. The empty 1024-byte tar was
// the correct answer to the question the test was asking.
//
// Submitted with spooling, the same call returns the output files. The
// wrong diagnosis mattered because ReceiveJobSandbox is what four
// webapi handlers use to serve job output and logs, so a comment
// blaming it sends anyone auditing those paths after a bug that is not
// there.
func TestOutputSandboxRoundtrip(t *testing.T) {
	harness := htcondor.SetupCondorHarness(t)
	if err := harness.WaitForDaemons(); err != nil {
		t.Fatalf("Daemons failed to start: %v", err)
	}
	scheddLocation := getScheddAddress(t, harness)
	schedd := htcondor.NewSchedd(scheddLocation.Name, scheddLocation.Address)

	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Minute)
	defer cancel()

	tempDir := t.TempDir()

	// A spooled job runs in the spool directory the schedd makes for
	// it, so there is no initialdir and no file on disk to point at --
	// the executable goes up with the input sandbox.
	cluster := submitSpooledJob(t, ctx, schedd, `
universe = vanilla
executable = job.sh
transfer_executable = true
transfer_output_files = output.txt, results/data.json
output = job.out
error = job.err
log = job.log
should_transfer_files = YES
when_to_transfer_output = ON_EXIT
request_memory = 64
queue
`, map[string]string{
		"job.sh": "#!/bin/sh\necho result > output.txt\nmkdir -p results\necho '{\"result\":42}' > results/data.json\n",
	})
	t.Logf("Submitted spooled job %d.0", cluster)

	jobAd := waitForSpooledCompletion(t, ctx, schedd, cluster)

	var outputTarBuf bytes.Buffer
	constraint := fmt.Sprintf("ClusterId == %d && ProcId == 0", cluster)
	if err := <-schedd.ReceiveJobSandbox(ctx, constraint, &outputTarBuf); err != nil {
		harness.PrintScheddLog()
		t.Fatalf("Failed to receive output sandbox: %v", err)
	}

	tarFiles := readTarFiles(t, bytes.NewReader(outputTarBuf.Bytes()))
	t.Logf("Files in the retrieved sandbox: %v", sortedKeys(tarFiles))
	// The empty tarball this test was skipped for fails here, and so
	// does one carrying only the job's stdout.
	//
	// data.json, not results/data.json: HTCondor flattens output file
	// names on transfer, so a file the job listed with a directory
	// component arrives under its basename and sits that way in the
	// spool. Filtering the incoming names against the listed ones used
	// to drop it silently -- see the basename handling in
	// processJobSandbox.
	for _, want := range []string{"output.txt", "data.json"} {
		if _, ok := tarFiles[want]; !ok {
			t.Errorf("%s is missing from the retrieved sandbox: %v", want, sortedKeys(tarFiles))
		}
	}
	if got, ok := tarFiles["output.txt"]; ok && strings.TrimSpace(got) != "result" {
		t.Errorf("output.txt = %q, want \"result\"", got)
	}

	extractDir := filepath.Join(tempDir, "extracted")
	if err := os.Mkdir(extractDir, 0755); err != nil {
		t.Fatalf("Failed to create extraction dir: %v", err)
	}
	// Iwd is where a relative output path lands on extraction.
	_ = jobAd.Set("Iwd", extractDir)
	if err := ExtractOutputSandbox(ctx, jobAd, &outputTarBuf); err != nil {
		t.Fatalf("Failed to extract output sandbox: %v", err)
	}
	for _, want := range []string{"output.txt", "data.json"} {
		if _, err := os.Stat(filepath.Join(extractDir, want)); err != nil {
			t.Errorf("%s was not extracted into %s: %v", want, extractDir, err)
		}
	}
}

// TestOutputSandboxWithRemaps checks that extraction honors
// transfer_output_remaps: an absolute remap target is written where it
// points, a relative one lands under Iwd.
//
// Skipped alongside the test above for the same wrong reason. The
// remaps are applied by ExtractOutputSandbox on this side, so what the
// test needs from the schedd is only that the files come back at all.
func TestOutputSandboxWithRemaps(t *testing.T) {
	harness := htcondor.SetupCondorHarness(t)
	if err := harness.WaitForDaemons(); err != nil {
		t.Fatalf("Daemons failed to start: %v", err)
	}
	scheddLocation := getScheddAddress(t, harness)
	schedd := htcondor.NewSchedd(scheddLocation.Name, scheddLocation.Address)

	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Minute)
	defer cancel()

	tempDir := t.TempDir()
	finalDir := filepath.Join(tempDir, "final")
	if err := os.Mkdir(finalDir, 0755); err != nil {
		t.Fatalf("Failed to create final dir: %v", err)
	}

	cluster := submitSpooledJob(t, ctx, schedd, fmt.Sprintf(`
universe = vanilla
executable = job.sh
transfer_executable = true
transfer_output_files = out1.txt, out2.txt
transfer_output_remaps = "out1.txt=%s/remapped1.txt;out2.txt=subdir/remapped2.txt"
output = job.out
error = job.err
log = job.log
should_transfer_files = YES
when_to_transfer_output = ON_EXIT
request_memory = 64
queue
`, finalDir), map[string]string{
		"job.sh": "#!/bin/sh\necho output1 > out1.txt\necho output2 > out2.txt\n",
	})
	t.Logf("Submitted spooled job %d.0", cluster)

	jobAd := waitForSpooledCompletion(t, ctx, schedd, cluster)

	var outputTarBuf bytes.Buffer
	constraint := fmt.Sprintf("ClusterId == %d && ProcId == 0", cluster)
	if err := <-schedd.ReceiveJobSandbox(ctx, constraint, &outputTarBuf); err != nil {
		harness.PrintScheddLog()
		t.Fatalf("Failed to receive output sandbox: %v", err)
	}
	t.Logf("Files in the retrieved sandbox: %v",
		sortedKeys(readTarFiles(t, bytes.NewReader(outputTarBuf.Bytes()))))
	extractDir := filepath.Join(tempDir, "extracted")
	if err := os.Mkdir(extractDir, 0755); err != nil {
		t.Fatalf("Failed to create extraction dir: %v", err)
	}
	_ = jobAd.Set("Iwd", extractDir)
	if err := ExtractOutputSandbox(ctx, jobAd, &outputTarBuf); err != nil {
		t.Fatalf("Failed to extract output sandbox: %v", err)
	}

	// An absolute remap goes where it points, outside Iwd.
	if _, err := os.Stat(filepath.Join(finalDir, "remapped1.txt")); err != nil {
		t.Errorf("remapped1.txt is not in %s: %v", finalDir, err)
	}
	// A relative one is resolved against Iwd.
	if _, err := os.Stat(filepath.Join(extractDir, "subdir", "remapped2.txt")); err != nil {
		t.Errorf("subdir/remapped2.txt is not under %s: %v", extractDir, err)
	}
}

// Helper functions

func getScheddAddress(t *testing.T, harness *htcondor.CondorTestHarness) *htcondor.DaemonLocation {
	t.Helper()

	t.Logf("Querying collector for schedd location")

	collector := htcondor.NewCollector(harness.GetCollectorAddr())
	ctx := context.Background()
	location, err := collector.LocateDaemon(ctx, "Schedd", "")
	if err != nil {
		t.Fatalf("Failed to locate schedd: %v", err)
	}

	return location
}

// submitSpooledJob submits with input spooling and sends files into the
// spool, returning the cluster id.
//
// The distinction matters for anything that reads output back from the
// schedd: TRANSFER_DATA_WITH_PERMS -- what ReceiveJobSandbox speaks --
// serves the job's SPOOL directory. A locally submitted job writes its
// output straight into the submit directory and leaves the spool empty,
// so the schedd correctly has nothing to hand back. Only a spooled
// submission stages output where transfer_data can reach it.
func submitSpooledJob(
	t *testing.T,
	ctx context.Context,
	schedd *htcondor.Schedd,
	submitFile string,
	files map[string]string,
) int {
	t.Helper()

	cluster, _, err := schedd.SubmitRemote(ctx, submitFile)
	if err != nil {
		t.Fatalf("Failed to submit: %v", err)
	}

	var tarBuf bytes.Buffer
	tw := tar.NewWriter(&tarBuf)
	for name, content := range files {
		if err := tw.WriteHeader(&tar.Header{
			Name: name,
			Mode: 0o755,
			Size: int64(len(content)),
		}); err != nil {
			t.Fatalf("Failed to write tar header for %s: %v", name, err)
		}
		if _, err := tw.Write([]byte(content)); err != nil {
			t.Fatalf("Failed to write %s into the tar: %v", name, err)
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatalf("Failed to close the tar: %v", err)
	}

	// The schedd accepts only the filenames in an allow-set it computes
	// from the job ad, and silently drops the rest, so the projection
	// has to carry Cmd and TransferExecutable -- without them the
	// executable is dropped and the job fails at execute time with
	// "No such file or directory".
	ads, _, err := schedd.QueryWithOptions(ctx, fmt.Sprintf("ClusterId == %d", cluster),
		&htcondor.QueryOptions{
			Projection: []string{"ClusterId", "ProcId", "TransferInput", "Cmd", "TransferExecutable"},
			Limit:      -1,
		})
	if err != nil {
		t.Fatalf("Failed to query the submitted job: %v", err)
	}
	if len(ads) == 0 {
		t.Fatalf("Cluster %d has no procs", cluster)
	}
	if err := schedd.SpoolJobFilesFromTar(ctx, ads, bytes.NewReader(tarBuf.Bytes())); err != nil {
		t.Fatalf("Failed to spool input files: %v", err)
	}
	return cluster
}

// waitForSpooledCompletion waits for a spooled job to finish and returns
// its ad from the queue. A spooled job stays in the queue after it
// completes -- its output is still in the spool, waiting to be
// retrieved -- so there is no history lookup here.
func waitForSpooledCompletion(
	t *testing.T,
	ctx context.Context,
	schedd *htcondor.Schedd,
	cluster int,
) *classad.ClassAd {
	t.Helper()

	deadline := time.Now().Add(150 * time.Second)
	for time.Now().Before(deadline) {
		ads, _, err := schedd.QueryWithOptions(ctx,
			fmt.Sprintf("ClusterId == %d && ProcId == 0", cluster),
			&htcondor.QueryOptions{Limit: 1})
		if err != nil {
			t.Fatalf("Failed to query job %d.0: %v", cluster, err)
		}
		if len(ads) > 0 {
			status, _ := ads[0].EvaluateAttrInt("JobStatus")
			switch status {
			case 4:
				return ads[0]
			case 5:
				// Code 16 is the spooling hold every remote submission
				// passes through; anything else will not clear itself.
				if code, _ := ads[0].EvaluateAttrInt("HoldReasonCode"); code != 16 {
					reason, _ := ads[0].EvaluateAttrString("HoldReason")
					t.Fatalf("job %d.0 went on hold (%d): %s", cluster, code, reason)
				}
			}
		}
		time.Sleep(2 * time.Second)
	}
	t.Fatalf("job %d.0 did not complete", cluster)
	return nil
}

func waitForJobCompletion(ctx context.Context, schedd *htcondor.Schedd, clusterID string) error {
	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()

	timeout := time.After(45 * time.Second)

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-timeout:
			return fmt.Errorf("timeout waiting for job to complete")
		case <-ticker.C:
			// Query job status from queue
			jobs, _, err := schedd.QueryWithOptions(ctx, fmt.Sprintf("ClusterId == %s", clusterID), nil)
			if err != nil {
				return fmt.Errorf("failed to query job: %w", err)
			}

			if len(jobs) == 0 {
				// Job not in queue - check history to see if it completed
				histJobs, err := schedd.QueryHistory(ctx, fmt.Sprintf("ClusterId == %s", clusterID), nil)
				if err != nil {
					return fmt.Errorf("failed to query history: %w", err)
				}

				if len(histJobs) > 0 {
					// Job found in history - check if it completed successfully
					jobAd := histJobs[0]
					statusExpr, ok := jobAd.Lookup("JobStatus")
					if !ok {
						return fmt.Errorf("job in history but no status")
					}

					statusVal := statusExpr.Eval(nil)
					status, err := statusVal.IntValue()
					if err != nil {
						return fmt.Errorf("invalid job status: %w", err)
					}

					// JobStatus: 1=Idle, 2=Running, 3=Removed, 4=Completed, 5=Held
					if status == 4 { // Completed
						return nil
					}
					return fmt.Errorf("job ended with status %d", status)
				}

				// Not in queue or history yet - continue waiting
				continue
			}

			jobAd := jobs[0]
			statusExpr, ok := jobAd.Lookup("JobStatus")
			if !ok {
				continue
			}

			statusVal := statusExpr.Eval(nil)
			status, err := statusVal.IntValue()
			if err != nil {
				continue
			}

			// JobStatus: 1=Idle, 2=Running, 3=Removed, 4=Completed, 5=Held
			if status == 4 { // Completed
				return nil
			}
			if status == 3 { // Removed
				return fmt.Errorf("job was removed")
			}
			if status == 5 { // Held
				return fmt.Errorf("job was held")
			}
		}
	}
}

func createFile(t *testing.T, path, content string) {
	t.Helper()

	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatalf("Failed to create file %s: %v", path, err)
	}
}

func readTarFiles(t *testing.T, r io.Reader) map[string]string {
	t.Helper()

	files := make(map[string]string)
	tr := tar.NewReader(r)

	for {
		header, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatalf("Failed to read tar: %v", err)
		}

		if header.Typeflag == tar.TypeReg {
			content, err := io.ReadAll(tr)
			if err != nil {
				t.Fatalf("Failed to read file %s: %v", header.Name, err)
			}
			files[header.Name] = string(content)
		}
	}

	return files
}

// sortedKeys names what a tarball holds, in a stable order.
func sortedKeys(files map[string]string) []string {
	names := make([]string, 0, len(files))
	for name := range files {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}
