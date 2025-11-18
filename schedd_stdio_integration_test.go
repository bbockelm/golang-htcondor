package htcondor

import (
	"archive/tar"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"testing/fstest"
	"time"
)

// TestStdioFilesIntegration tests job submission with stdin, stdout, and stderr handling
// This verifies the complete workflow of:
// 1. Creating a job that reads from stdin and writes to stdout/stderr
// 2. Spooling input files including stdin
// 3. Waiting for the job to complete
// 4. Downloading the sandbox and verifying stdout and stderr contents
//
//nolint:gocyclo // Integration test requires complex setup and verification logic
func TestStdioFilesIntegration(t *testing.T) {
	// Setup HTCondor test harness
	harness := setupCondorHarness(t)

	// Wait for daemons to start
	if err := harness.waitForDaemons(); err != nil {
		t.Fatalf("Daemons failed to start: %v", err)
	}

	// Get schedd connection info
	scheddAddr := getScheddAddress(t, harness)
	t.Logf("Schedd discovered at: %s", scheddAddr)

	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()

	// Create schedd client
	schedd := NewSchedd(harness.scheddName, scheddAddr)

	// Create a job that reads from stdin and writes to stdout/stderr
	// The job script will:
	// 1. Read from stdin (input.txt)
	// 2. Echo stdin content to stdout (job.out)
	// 3. Write custom content to stderr (job.err)
	submitFile := `
universe = vanilla
executable = /bin/sh
arguments = job_script.sh
transfer_executable = false
transfer_input_files = input.txt,job_script.sh
should_transfer_files = YES
when_to_transfer_output = ON_EXIT
request_cpus = 1
request_memory = 128
request_disk = 1024
input = input.txt
output = job.out
error = job.err
log = job.log
queue
`

	// Submit the job remotely
	t.Logf("Submitting job remotely...")
	clusterID, procAds, err := schedd.SubmitRemote(ctx, submitFile)
	if err != nil {
		harness.printScheddLog()
		t.Fatalf("Failed to submit job: %v", err)
	}

	t.Logf("Job submitted successfully: cluster=%d, num_procs=%d", clusterID, len(procAds))

	// Create input files
	// The job script will read from stdin and process it
	testFS := fstest.MapFS{
		"input.txt": &fstest.MapFile{
			Data: []byte("This is stdin content\nLine 2 from stdin\nLine 3 from stdin\n"),
			Mode: 0644,
		},
		"job_script.sh": &fstest.MapFile{
			Data: []byte("#!/bin/sh\n# Read from stdin (which is input.txt due to 'input = input.txt')\necho 'Job started' >&2\ncat\necho 'Processing complete' >&2\necho 'Job finished' >&2\n"),
			Mode: 0755,
		},
	}

	// Spool the input files
	t.Logf("Spooling input files for job %d.0", clusterID)
	spoolCtx, spoolCancel := context.WithTimeout(ctx, 30*time.Second)
	defer spoolCancel()

	if err := schedd.SpoolJobFilesFromFS(spoolCtx, procAds, testFS); err != nil {
		harness.printScheddLog()
		t.Fatalf("Failed to spool files: %v", err)
	}

	t.Logf("Successfully spooled input files")

	// Wait for job to complete (with timeout)
	t.Logf("Waiting for job to complete...")
	jobCompleted := false
	startTime := time.Now()
	maxWait := 30 * time.Second
	var lastStatus int64 = -1

	for time.Since(startTime) < maxWait {
		queryResult, err := schedd.Query(ctx, fmt.Sprintf("ClusterId == %d", clusterID), []string{"JobStatus"})
		if err != nil {
			t.Logf("Warning: Failed to query job status: %v", err)
		} else if len(queryResult) > 0 {
			jobAd := queryResult[0]
			if statusExpr, ok := jobAd.Lookup("JobStatus"); ok {
				statusVal := statusExpr.Eval(nil)
				if statusInt, err := statusVal.IntValue(); err == nil {
					t.Logf("Job status: %d (1=IDLE, 2=RUNNING, 4=COMPLETED, 5=HELD)", statusInt)

					// If status changed, extend timeout
					if lastStatus != -1 && statusInt != lastStatus {
						maxWait += 10 * time.Second
						t.Logf("Job status changed from %d to %d - extending timeout by 10 seconds",
							lastStatus, statusInt)
					}
					lastStatus = statusInt

					if statusInt == 4 {
						t.Logf("Job completed!")
						jobCompleted = true
						break
					}
				}
			}
		}
		time.Sleep(1 * time.Second)
	}

	if !jobCompleted {
		harness.printScheddLog()
		t.Fatalf("Job did not complete within %v", maxWait)
	}

	// Download the job sandbox
	t.Logf("Downloading job sandbox...")
	var sandboxBuf bytes.Buffer
	constraint := fmt.Sprintf("ClusterId == %d", clusterID)

	downloadCtx, downloadCancel := context.WithTimeout(ctx, 30*time.Second)
	defer downloadCancel()

	errChan := schedd.ReceiveJobSandbox(downloadCtx, constraint, &sandboxBuf)

	// Wait for download to complete
	if err := <-errChan; err != nil {
		harness.printScheddLog()
		t.Fatalf("Failed to download job sandbox: %v", err)
	}

	t.Logf("Successfully downloaded job sandbox (%d bytes)", sandboxBuf.Len())

	// Extract and verify the tar archive
	t.Logf("Extracting and verifying sandbox contents...")
	tarReader := tar.NewReader(&sandboxBuf)

	filesFound := make(map[string]string) // filename -> content
	expectedFiles := []string{"job.out", "job.err"}

	for {
		header, err := tarReader.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			t.Fatalf("Failed to read tar entry: %v", err)
		}

		t.Logf("Found file in sandbox: %s (size: %d bytes)", header.Name, header.Size)

		// Read file content
		content, err := io.ReadAll(tarReader)
		if err != nil {
			t.Fatalf("Failed to read file content: %v", err)
		}

		baseName := filepath.Base(header.Name)
		filesFound[baseName] = string(content)
	}

	// Verify we got the expected files
	for _, expectedFile := range expectedFiles {
		if _, ok := filesFound[expectedFile]; !ok {
			t.Errorf("Expected file %s not found in sandbox", expectedFile)
		}
	}

	// Verify stdout (job.out) contains stdin content
	stdout, ok := filesFound["job.out"]
	if !ok {
		t.Fatal("job.out not found in sandbox")
	}
	t.Logf("stdout (job.out) content:\n%s", stdout)

	if !strings.Contains(stdout, "This is stdin content") {
		t.Errorf("stdout does not contain expected stdin content")
	}
	if !strings.Contains(stdout, "Line 2 from stdin") {
		t.Errorf("stdout does not contain Line 2 from stdin")
	}
	if !strings.Contains(stdout, "Line 3 from stdin") {
		t.Errorf("stdout does not contain Line 3 from stdin")
	}

	// Verify stderr (job.err) contains expected messages
	stderr, ok := filesFound["job.err"]
	if !ok {
		t.Fatal("job.err not found in sandbox")
	}
	t.Logf("stderr (job.err) content:\n%s", stderr)

	if !strings.Contains(stderr, "Job started") {
		t.Errorf("stderr does not contain 'Job started' message")
	}
	if !strings.Contains(stderr, "Processing complete") {
		t.Errorf("stderr does not contain 'Processing complete' message")
	}
	if !strings.Contains(stderr, "Job finished") {
		t.Errorf("stderr does not contain 'Job finished' message")
	}

	t.Logf("Successfully verified stdin/stdout/stderr handling")
}

// TestStdioFilesFromTarIntegration tests job submission with stdin using tar archive
// This verifies spooling input files including stdin from a tar archive
//
//nolint:gocyclo // Integration test requires complex setup and verification logic
func TestStdioFilesFromTarIntegration(t *testing.T) {
	// Setup HTCondor test harness
	harness := setupCondorHarness(t)

	// Wait for daemons to start
	if err := harness.waitForDaemons(); err != nil {
		t.Fatalf("Daemons failed to start: %v", err)
	}

	// Get schedd connection info
	scheddAddr := getScheddAddress(t, harness)
	t.Logf("Schedd discovered at: %s", scheddAddr)

	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()

	// Create schedd client
	schedd := NewSchedd(harness.scheddName, scheddAddr)

	// Create a job that reads from stdin
	submitFile := `
universe = vanilla
executable = /bin/sh
arguments = -c "cat > output.txt && echo 'stderr message' >&2"
transfer_executable = false
transfer_input_files = stdin.txt
should_transfer_files = YES
when_to_transfer_output = ON_EXIT
transfer_output_files = output.txt
request_cpus = 1
request_memory = 128
request_disk = 1024
input = stdin.txt
output = job.out
error = job.err
log = job.log
queue
`

	// Submit the job remotely
	t.Logf("Submitting job remotely...")
	clusterID, procAds, err := schedd.SubmitRemote(ctx, submitFile)
	if err != nil {
		harness.printScheddLog()
		t.Fatalf("Failed to submit job: %v", err)
	}

	t.Logf("Job submitted successfully: cluster=%d, num_procs=%d", clusterID, len(procAds))

	// Create a tar archive with stdin file
	var tarBuf bytes.Buffer
	tarWriter := tar.NewWriter(&tarBuf)

	stdinContent := []byte("Content from stdin via tar\nSecond line via tar\n")
	header := &tar.Header{
		Name:    "stdin.txt",
		Size:    int64(len(stdinContent)),
		Mode:    0644,
		ModTime: time.Now(),
	}
	if err := tarWriter.WriteHeader(header); err != nil {
		t.Fatalf("Failed to write tar header: %v", err)
	}
	if _, err := tarWriter.Write(stdinContent); err != nil {
		t.Fatalf("Failed to write tar data: %v", err)
	}

	if err := tarWriter.Close(); err != nil {
		t.Fatalf("Failed to close tar writer: %v", err)
	}

	// Spool the files from tar archive
	t.Logf("Spooling input files from tar for job %d.0", clusterID)
	spoolCtx, spoolCancel := context.WithTimeout(ctx, 30*time.Second)
	defer spoolCancel()

	if err := schedd.SpoolJobFilesFromTar(spoolCtx, procAds, bytes.NewReader(tarBuf.Bytes())); err != nil {
		// Save schedd log for debugging
		scheddLogPath := filepath.Join(harness.logDir, "ScheddLog")
		//nolint:gosec // Test code reading from test harness log directory
		if logData, readErr := os.ReadFile(scheddLogPath); readErr == nil {
			lines := strings.Split(string(logData), "\n")
			start := len(lines) - 100
			if start < 0 {
				start = 0
			}
			t.Logf("=== Schedd Log (last 100 lines) ===")
			for _, line := range lines[start:] {
				if line != "" {
					t.Logf("%s", line)
				}
			}
		}
		t.Fatalf("Failed to spool files from tar: %v", err)
	}

	t.Logf("Successfully spooled input files from tar")

	// Wait for job to complete
	t.Logf("Waiting for job to complete...")
	jobCompleted := false
	startTime := time.Now()
	maxWait := 30 * time.Second
	var lastStatus int64 = -1

	for time.Since(startTime) < maxWait {
		queryResult, err := schedd.Query(ctx, fmt.Sprintf("ClusterId == %d", clusterID), []string{"JobStatus"})
		if err != nil {
			t.Logf("Warning: Failed to query job status: %v", err)
		} else if len(queryResult) > 0 {
			jobAd := queryResult[0]
			if statusExpr, ok := jobAd.Lookup("JobStatus"); ok {
				statusVal := statusExpr.Eval(nil)
				if statusInt, err := statusVal.IntValue(); err == nil {
					t.Logf("Job status: %d", statusInt)

					if lastStatus != -1 && statusInt != lastStatus {
						maxWait += 10 * time.Second
						t.Logf("Job status changed - extending timeout")
					}
					lastStatus = statusInt

					if statusInt == 4 {
						jobCompleted = true
						break
					}
				}
			}
		}
		time.Sleep(1 * time.Second)
	}

	if !jobCompleted {
		harness.printScheddLog()
		t.Fatalf("Job did not complete within %v", maxWait)
	}

	// Download the job sandbox
	t.Logf("Downloading job sandbox...")
	var sandboxBuf bytes.Buffer
	constraint := fmt.Sprintf("ClusterId == %d", clusterID)

	downloadCtx, downloadCancel := context.WithTimeout(ctx, 30*time.Second)
	defer downloadCancel()

	errChan := schedd.ReceiveJobSandbox(downloadCtx, constraint, &sandboxBuf)
	if err := <-errChan; err != nil {
		harness.printScheddLog()
		t.Fatalf("Failed to download job sandbox: %v", err)
	}

	t.Logf("Successfully downloaded job sandbox (%d bytes)", sandboxBuf.Len())

	// Verify the output
	tarReader := tar.NewReader(&sandboxBuf)
	filesFound := make(map[string]string)

	for {
		header, err := tarReader.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			t.Fatalf("Failed to read tar entry: %v", err)
		}

		content, err := io.ReadAll(tarReader)
		if err != nil {
			t.Fatalf("Failed to read file content: %v", err)
		}

		baseName := filepath.Base(header.Name)
		filesFound[baseName] = string(content)
		t.Logf("Found file: %s (content: %q)", baseName, string(content))
	}

	// Verify output.txt contains stdin content
	output, ok := filesFound["output.txt"]
	if !ok {
		t.Fatal("output.txt not found in sandbox")
	}

	if !strings.Contains(output, "Content from stdin via tar") {
		t.Errorf("output.txt does not contain expected stdin content")
	}

	// Verify stderr
	stderr, ok := filesFound["job.err"]
	if !ok {
		t.Fatal("job.err not found in sandbox")
	}

	if !strings.Contains(stderr, "stderr message") {
		t.Errorf("stderr does not contain expected message")
	}

	t.Logf("Successfully verified stdin handling from tar archive")
}
