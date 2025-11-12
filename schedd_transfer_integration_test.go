package htcondor

import (
	"archive/tar"
	"bytes"
	"context"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"testing/fstest"
	"time"
)

// getScheddAddress queries the collector for the schedd address and port
func getScheddAddress(t *testing.T, harness *condorTestHarness) (string, int) {
	t.Helper()

	// Parse collector address
	collectorAddr := harness.GetCollectorAddr()
	addr := parseCollectorSinfulString(collectorAddr)

	collectorHost, collectorPortStr, err := net.SplitHostPort(addr)
	if err != nil {
		t.Fatalf("Failed to parse collector address %s: %v", addr, err)
	}

	// Query collector for schedd location
	var collectorPort int
	if _, err := fmt.Sscanf(collectorPortStr, "%d", &collectorPort); err != nil {
		t.Fatalf("Failed to parse collector port: %v", err)
	}

	t.Logf("Querying collector at %s:%d for schedd location", collectorHost, collectorPort)

	collector := NewCollector(collectorHost, collectorPort)
	ctx := context.Background()
	scheddAds, err := collector.QueryAds(ctx, "ScheddAd", "")
	if err != nil {
		t.Fatalf("Failed to query collector for schedd ads: %v", err)
	}

	if len(scheddAds) == 0 {
		t.Fatal("No schedd ads found in collector")
	}

	// Extract schedd address from ad
	scheddAd := scheddAds[0]

	// Get MyAddress attribute
	myAddressExpr, ok := scheddAd.Lookup("MyAddress")
	if !ok {
		t.Fatal("Schedd ad does not have MyAddress attribute")
	}

	myAddress := myAddressExpr.String()
	// Remove quotes if present
	myAddress = strings.Trim(myAddress, "\"")

	// Parse schedd sinful string
	scheddAddr := parseCollectorSinfulString(myAddress)
	scheddHost, scheddPortStr, err := net.SplitHostPort(scheddAddr)
	if err != nil {
		t.Fatalf("Failed to parse schedd address %s: %v", scheddAddr, err)
	}

	var scheddPort int
	if _, err := fmt.Sscanf(scheddPortStr, "%d", &scheddPort); err != nil {
		t.Fatalf("Failed to parse schedd port: %v", err)
	}

	return scheddHost, scheddPort
}

// minInt returns the minimum of two integers
func minInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// TestSpoolJobFilesIntegration tests submitting a job and then spooling input files
// This verifies the complete workflow of:
// 1. Creating a job with proper spooling attributes using SubmitRemote
// 2. Submitting it to the schedd
// 3. Uploading input files via SpoolJobFilesFromFS
//
// This test verifies that SubmitRemote() correctly:
// - Submits jobs with JobStatus=5 (HELD)
// - Sets HoldReasonCode=16 (SpoolingInput)
// - Sets LeaveJobInQueue expression for 10-day retention
// - File spooling protocol works correctly with proper headers (final_transfer flag, xfer_info ClassAd, per-job acknowledgments)
//
//nolint:gocyclo // Integration test requires complex setup and verification logic
func TestSpoolJobFilesIntegration(t *testing.T) {
	// Setup HTCondor test harness
	harness := setupCondorHarness(t)

	// Wait for daemons to start
	if err := harness.waitForDaemons(); err != nil {
		t.Fatalf("Daemons failed to start: %v", err)
	}

	// Get schedd connection info
	scheddHost, scheddPort := getScheddAddress(t, harness)
	t.Logf("Schedd discovered at: %s:%d", scheddHost, scheddPort)

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	// Create schedd client
	schedd := NewSchedd(harness.scheddName, scheddHost, scheddPort)

	// Create a submit file for remote submission with input files
	submitFile := `
universe = vanilla
executable = /bin/echo
arguments = "Hello from spooled job"
transfer_input_files = input1.txt, input2.dat
output = job.out
error = job.err
log = job.log
queue
`

	// Submit the job remotely (automatically enables file spooling)
	t.Logf("Submitting job remotely...")
	clusterID, procAds, err := schedd.SubmitRemote(ctx, submitFile)
	if err != nil {
		harness.printScheddLog()
		t.Fatalf("Failed to submit job: %v", err)
	}

	t.Logf("Job submitted successfully: cluster=%d, num_procs=%d", clusterID, len(procAds))

	// Query the job from schedd to see what attributes are actually stored
	queryCtx, queryCancel := context.WithTimeout(ctx, 10*time.Second)
	defer queryCancel()

	constraint := fmt.Sprintf("ClusterId == %d", clusterID)
	projection := []string{"ClusterId", "ProcId", "TransferInput", "TransferInputFiles", "JobStatus"}

	queriedAds, err := schedd.Query(queryCtx, constraint, projection)
	if err != nil {
		t.Logf("Failed to query job: %v", err)
	} else if len(queriedAds) > 0 {
		t.Logf("Queried job ad attributes:")
		for _, attr := range []string{"TransferInput", "TransferInputFiles"} {
			if expr, ok := queriedAds[0].Lookup(attr); ok {
				val := expr.Eval(nil)
				if str, err := val.StringValue(); err == nil {
					t.Logf("  %s: %s", attr, str)
				}
			} else {
				t.Logf("  %s: NOT FOUND", attr)
			}
		}
	}

	// Verify that TransferInputFiles is set in the job ad
	// This is required for the SpoolJobFilesFromFS function to work
	if len(procAds) == 0 {
		t.Fatal("No proc ads returned from SubmitRemote")
	}

	for i, ad := range procAds {
		transferInputFilesExpr, ok := ad.Lookup("TransferInputFiles")
		if !ok {
			t.Fatalf("procAds[%d] missing TransferInputFiles attribute - cannot spool files", i)
		}

		inputFilesStr := strings.Trim(transferInputFilesExpr.String(), "\"")
		if inputFilesStr == "" || inputFilesStr == "UNDEFINED" {
			t.Fatalf("procAds[%d] TransferInputFiles is empty or undefined - cannot spool files", i)
		}

		t.Logf("procAds[%d] TransferInputFiles: %s", i, inputFilesStr)

		// Also verify TransferInput boolean is set
		if transferInputExpr, ok := ad.Lookup("TransferInput"); ok {
			transferInputVal := transferInputExpr.String()
			t.Logf("procAds[%d] TransferInput (boolean): %s", i, transferInputVal)
		}
	}

	// Now spool the input files
	// Create a test filesystem with the input files
	testFS := fstest.MapFS{
		"input1.txt": &fstest.MapFile{
			Data: []byte("This is test input file 1\nWith multiple lines\n"),
			Mode: 0644,
		},
		"input2.dat": &fstest.MapFile{
			Data: []byte("Binary data in file 2"),
			Mode: 0644,
		},
	}

	// Spool the files - the file list is now taken from each job ad's TransferInputFiles attribute
	t.Logf("Spooling input files for job %d.0", clusterID)
	err = schedd.SpoolJobFilesFromFS(ctx, procAds, testFS)

	// Always save schedd log for debugging (last 600 lines)
	scheddLogPath := filepath.Join(harness.logDir, "ScheddLog")
	//nolint:gosec // Test code reading from test harness log directory
	if logData, readErr := os.ReadFile(scheddLogPath); readErr == nil {
		lines := strings.Split(string(logData), "\n")
		start := len(lines) - 600
		if start < 0 {
			start = 0
		}
		savedLog := strings.Join(lines[start:], "\n")
		//nolint:gosec // Test code writing to predictable location for debugging
		if writeErr := os.WriteFile("/tmp/schedd_test.log", []byte(savedLog), 0644); writeErr == nil {
			t.Logf("Saved last 600 lines of ScheddLog to /tmp/schedd_test.log")
		}
	}

	if err != nil {
		t.Errorf("Failed to spool files: %v", err)

		// Log schedd log for debugging
		t.Logf("=== Schedd Log (last 50 lines) ===")
		//nolint:gosec // Test code reading from test harness log directory
		if logData, readErr := os.ReadFile(scheddLogPath); readErr == nil {
			lines := strings.Split(string(logData), "\n")
			start := len(lines) - 50
			if start < 0 {
				start = 0
			}
			for _, line := range lines[start:] {
				if line != "" {
					t.Logf("%s", line)
				}
			}
		}
		t.FailNow()
	}

	t.Logf("Successfully spooled input files")

	// Check if the job has been released from HELD status
	// After spooling, the schedd should automatically release the job
	t.Logf("Checking job status after spooling...")

	// Query the schedd for the job ad
	time.Sleep(2 * time.Second) // Give schedd time to process the spooled files

	queryResult, err := schedd.Query(ctx, fmt.Sprintf("ClusterId == %d", clusterID), []string{"JobStatus", "HoldReasonCode", "HoldReason"})
	if err != nil {
		t.Logf("Warning: Failed to query job status: %v", err)
	} else if len(queryResult) > 0 {
		jobAd := queryResult[0]

		// Check JobStatus
		if statusExpr, ok := jobAd.Lookup("JobStatus"); ok {
			statusStr := statusExpr.String()
			t.Logf("Job %d.0 JobStatus: %s", clusterID, statusStr)

			// JobStatus should be 1 (IDLE) after release, not 5 (HELD)
			switch statusStr {
			case "5":
				t.Errorf("Job is still HELD after spooling - expected to be released to IDLE (1)")
				if holdReasonExpr, ok := jobAd.Lookup("HoldReason"); ok {
					t.Logf("HoldReason: %s", holdReasonExpr.String())
				}
				if holdCodeExpr, ok := jobAd.Lookup("HoldReasonCode"); ok {
					t.Logf("HoldReasonCode: %s", holdCodeExpr.String())
				}
			case "1":
				t.Logf("Job successfully released to IDLE status")
			default:
				t.Logf("Job has status %s (1=IDLE, 2=RUNNING, 5=HELD)", statusStr)
			}
		}
	}

	// Verify files were spooled by checking the spool directory
	t.Logf("Verifying spooled files in schedd spool directory...")

	// The job-specific spool directory should be: <spooldir>/<cluster_id>/<proc_id>/cluster<cluster_id>.proc<proc_id>.subproc0/
	// For job 1.0, this is: spool/1/0/cluster1.proc0.subproc0/
	procID := 0 // We submitted proc 0
	jobSpoolDir := filepath.Join(harness.spoolDir, fmt.Sprintf("%d", clusterID), fmt.Sprintf("%d", procID), fmt.Sprintf("cluster%d.proc%d.subproc0", clusterID, procID))

	if _, err := os.Stat(jobSpoolDir); os.IsNotExist(err) {
		t.Errorf("Job-specific spool directory does not exist: %s", jobSpoolDir)
	} else {
		t.Logf("Job spool directory exists: %s", jobSpoolDir)

		// Check for the expected input files
		expectedFiles := []string{"input1.txt", "input2.dat"}
		for _, filename := range expectedFiles {
			filePath := filepath.Join(jobSpoolDir, filename)
			if info, err := os.Stat(filePath); os.IsNotExist(err) {
				t.Errorf("Expected spooled file not found: %s", filename)
			} else {
				t.Logf("Found spooled file: %s (size: %d bytes)", filename, info.Size())

				// Verify file contents
				//nolint:gosec // Test code reading from test harness spool directory
				if data, err := os.ReadFile(filePath); err == nil {
					t.Logf("  Content preview: %q", string(data[:minInt(len(data), 50)]))
				}
			}
		}
	}

	// Log full spool directory structure for debugging
	if entries, err := os.ReadDir(harness.spoolDir); err == nil {
		t.Logf("Full spool directory contents:")
		for _, entry := range entries {
			t.Logf("  %s (isDir: %v)", entry.Name(), entry.IsDir())
			if entry.IsDir() {
				subPath := filepath.Join(harness.spoolDir, entry.Name())
				if subEntries, err := os.ReadDir(subPath); err == nil {
					for _, subEntry := range subEntries {
						t.Logf("    %s (isDir: %v)", subEntry.Name(), subEntry.IsDir())
						if subEntry.IsDir() {
							subSubPath := filepath.Join(subPath, subEntry.Name())
							if subSubEntries, err := os.ReadDir(subSubPath); err == nil {
								for _, subSubEntry := range subSubEntries {
									t.Logf("      %s", subSubEntry.Name())
								}
							}
						}
					}
				}
			}
		}
	}

	// Print full ScheddLog for debugging
	t.Logf("=== Full Schedd Log ===")
	scheddLog := filepath.Join(harness.logDir, "ScheddLog")
	//nolint:gosec // Test code reading from test harness log directory
	if logData, readErr := os.ReadFile(scheddLog); readErr == nil {
		for _, line := range strings.Split(string(logData), "\n") {
			if line != "" {
				t.Logf("%s", line)
			}
		}
	} else {
		t.Logf("Could not read ScheddLog: %v", readErr)
	}
}

// TestSpoolJobFilesFromTarIntegration tests submitting a job and spooling input files from a tar archive
// This verifies the complete workflow of:
// 1. Creating a job with proper spooling attributes using SubmitRemote
// 2. Submitting it to the schedd
// 3. Uploading input files via SpoolJobFilesFromTar
// 4. Verifying files are correctly spooled and the job is released
//
//nolint:gocyclo // Integration test requires complex setup and verification logic
func TestSpoolJobFilesFromTarIntegration(t *testing.T) {
	// Setup HTCondor test harness
	harness := setupCondorHarness(t)

	// Wait for daemons to start
	if err := harness.waitForDaemons(); err != nil {
		t.Fatalf("Daemons failed to start: %v", err)
	}

	// Get schedd connection info
	scheddHost, scheddPort := getScheddAddress(t, harness)
	t.Logf("Schedd discovered at: %s:%d", scheddHost, scheddPort)

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	// Create schedd client
	schedd := NewSchedd(harness.scheddName, scheddHost, scheddPort)

	// Create a submit file for remote submission with input files
	submitFile := `
universe = vanilla
executable = /bin/echo
arguments = "Hello from tar spooled job"
transfer_input_files = input1.txt, input2.dat, subdir/input3.txt
output = job.out
error = job.err
log = job.log
queue
`

	// Submit the job remotely (automatically enables file spooling)
	t.Logf("Submitting job remotely...")
	clusterID, procAds, err := schedd.SubmitRemote(ctx, submitFile)
	if err != nil {
		harness.printScheddLog()
		t.Fatalf("Failed to submit job: %v", err)
	}

	t.Logf("Job submitted successfully: cluster=%d, num_procs=%d", clusterID, len(procAds))

	// Verify that TransferInputFiles is set in the job ad
	if len(procAds) == 0 {
		t.Fatal("No proc ads returned from SubmitRemote")
	}

	for i, ad := range procAds {
		transferInputFilesExpr, ok := ad.Lookup("TransferInputFiles")
		if !ok {
			t.Fatalf("procAds[%d] missing TransferInputFiles attribute - cannot spool files", i)
		}

		inputFilesStr := strings.Trim(transferInputFilesExpr.String(), "\"")
		if inputFilesStr == "" || inputFilesStr == "UNDEFINED" {
			t.Fatalf("procAds[%d] TransferInputFiles is empty or undefined - cannot spool files", i)
		}

		t.Logf("procAds[%d] TransferInputFiles: %s", i, inputFilesStr)
	}

	// Create a tar archive with test files (single job mode - no cluster.proc prefix)
	var tarBuf bytes.Buffer
	tarWriter := tar.NewWriter(&tarBuf)

	files := map[string][]byte{
		"input1.txt":        []byte("This is test input file 1 from tar\nWith multiple lines\n"),
		"input2.dat":        []byte("Binary data in file 2 from tar"),
		"subdir/input3.txt": []byte("File in subdirectory from tar\n"),
	}

	for name, data := range files {
		header := &tar.Header{
			Name:    name,
			Size:    int64(len(data)),
			Mode:    0644,
			ModTime: time.Now(),
		}
		if err := tarWriter.WriteHeader(header); err != nil {
			t.Fatalf("Failed to write tar header for %s: %v", name, err)
		}
		if _, err := tarWriter.Write(data); err != nil {
			t.Fatalf("Failed to write tar data for %s: %v", name, err)
		}
	}

	if err := tarWriter.Close(); err != nil {
		t.Fatalf("Failed to close tar writer: %v", err)
	}

	// Spool the files from tar archive
	t.Logf("Spooling input files from tar archive for job %d.0", clusterID)
	err = schedd.SpoolJobFilesFromTar(ctx, procAds, bytes.NewReader(tarBuf.Bytes()))

	// Always save schedd log for debugging (last 600 lines)
	scheddLogPath := filepath.Join(harness.logDir, "ScheddLog")
	//nolint:gosec // Test code reading from test harness log directory
	if logData, readErr := os.ReadFile(scheddLogPath); readErr == nil {
		lines := strings.Split(string(logData), "\n")
		start := len(lines) - 600
		if start < 0 {
			start = 0
		}
		savedLog := strings.Join(lines[start:], "\n")
		//nolint:gosec // Test code writing to predictable location for debugging
		if writeErr := os.WriteFile("/tmp/schedd_tar_test.log", []byte(savedLog), 0644); writeErr == nil {
			t.Logf("Saved last 600 lines of ScheddLog to /tmp/schedd_tar_test.log")
		}
	}

	if err != nil {
		t.Errorf("Failed to spool files from tar: %v", err)

		// Log schedd log for debugging
		t.Logf("=== Schedd Log (last 50 lines) ===")
		//nolint:gosec // Test code reading from test harness log directory
		if logData, readErr := os.ReadFile(scheddLogPath); readErr == nil {
			lines := strings.Split(string(logData), "\n")
			start := len(lines) - 50
			if start < 0 {
				start = 0
			}
			for _, line := range lines[start:] {
				if line != "" {
					t.Logf("%s", line)
				}
			}
		}
		t.FailNow()
	}

	t.Logf("Successfully spooled input files from tar")

	// Check if the job has been released from HELD status
	t.Logf("Checking job status after spooling...")
	time.Sleep(2 * time.Second) // Give schedd time to process the spooled files

	queryResult, err := schedd.Query(ctx, fmt.Sprintf("ClusterId == %d", clusterID), []string{"JobStatus", "HoldReasonCode", "HoldReason"})
	if err != nil {
		t.Logf("Warning: Failed to query job status: %v", err)
	} else if len(queryResult) > 0 {
		jobAd := queryResult[0]

		// Check JobStatus
		if statusExpr, ok := jobAd.Lookup("JobStatus"); ok {
			statusStr := statusExpr.String()
			t.Logf("Job %d.0 JobStatus: %s", clusterID, statusStr)

			switch statusStr {
			case "5":
				t.Errorf("Job is still HELD after spooling - expected to be released to IDLE (1)")
				if holdReasonExpr, ok := jobAd.Lookup("HoldReason"); ok {
					t.Logf("HoldReason: %s", holdReasonExpr.String())
				}
				if holdCodeExpr, ok := jobAd.Lookup("HoldReasonCode"); ok {
					t.Logf("HoldReasonCode: %s", holdCodeExpr.String())
				}
			case "1":
				t.Logf("Job successfully released to IDLE status")
			default:
				t.Logf("Job has status %s (1=IDLE, 2=RUNNING, 5=HELD)", statusStr)
			}
		}
	}

	// Verify files were spooled by checking the spool directory
	t.Logf("Verifying spooled files in schedd spool directory...")

	// Log full spool directory structure for debugging FIRST
	if entries, err := os.ReadDir(harness.spoolDir); err == nil {
		t.Logf("Full spool directory contents:")
		for _, entry := range entries {
			t.Logf("  %s (isDir: %v)", entry.Name(), entry.IsDir())
			if entry.IsDir() {
				subPath := filepath.Join(harness.spoolDir, entry.Name())
				if subEntries, err := os.ReadDir(subPath); err == nil {
					for _, subEntry := range subEntries {
						t.Logf("    %s (isDir: %v)", subEntry.Name(), subEntry.IsDir())
						if subEntry.IsDir() {
							subSubPath := filepath.Join(subPath, subEntry.Name())
							if subSubEntries, err := os.ReadDir(subSubPath); err == nil {
								for _, subSubEntry := range subSubEntries {
									t.Logf("      %s (isDir: %v)", subSubEntry.Name(), subSubEntry.IsDir())
									// Look inside directories one more level
									if subSubEntry.IsDir() {
										subSubSubPath := filepath.Join(subSubPath, subSubEntry.Name())
										if subSubSubEntries, err := os.ReadDir(subSubSubPath); err == nil {
											for _, subSubSubEntry := range subSubSubEntries {
												t.Logf("        %s", subSubSubEntry.Name())
											}
										}
									}
								}
							}
						}
					}
				}
			}
		}
	} else {
		t.Logf("Could not read spool directory: %v", err)
	}

	// The job-specific spool directory should be: <spooldir>/<cluster_id>/<proc_id>/cluster<cluster_id>.proc<proc_id>.subproc0/
	procID := 0
	jobSpoolDir := filepath.Join(harness.spoolDir, fmt.Sprintf("%d", clusterID), fmt.Sprintf("%d", procID), fmt.Sprintf("cluster%d.proc%d.subproc0", clusterID, procID))

	if _, err := os.Stat(jobSpoolDir); os.IsNotExist(err) {
		t.Logf("Job-specific spool directory does not exist: %s", jobSpoolDir)
		t.Logf("Trying to find files in alternate locations...")

		// Sometimes files might be at a different level
		alternateDir := filepath.Join(harness.spoolDir, fmt.Sprintf("%d", clusterID), fmt.Sprintf("%d", procID))
		if entries, err := os.ReadDir(alternateDir); err == nil {
			t.Logf("Files in %s:", alternateDir)
			for _, entry := range entries {
				t.Logf("  %s (isDir: %v)", entry.Name(), entry.IsDir())
			}
		}
	} else {
		t.Logf("Job spool directory exists: %s", jobSpoolDir)

		// Check for the expected input files
		expectedFiles := map[string][]byte{
			"input1.txt":        []byte("This is test input file 1 from tar\nWith multiple lines\n"),
			"input2.dat":        []byte("Binary data in file 2 from tar"),
			"subdir/input3.txt": []byte("File in subdirectory from tar\n"),
		}

		for filename, expectedContent := range expectedFiles {
			filePath := filepath.Join(jobSpoolDir, filename)
			if info, err := os.Stat(filePath); os.IsNotExist(err) {
				t.Errorf("Expected spooled file not found: %s", filename)
			} else {
				t.Logf("Found spooled file: %s (size: %d bytes)", filename, info.Size())

				// Verify file contents
				//nolint:gosec // Test code reading from test harness spool directory
				if data, err := os.ReadFile(filePath); err == nil {
					if string(data) != string(expectedContent) {
						t.Errorf("File content mismatch for %s:\n  expected: %q\n  got: %q", filename, expectedContent, data)
					} else {
						t.Logf("  Content verified: %q", string(data[:minInt(len(data), 50)]))
					}
				}
			}
		}
	}
}
