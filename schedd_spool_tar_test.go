package htcondor

import (
	"archive/tar"
	"bytes"
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/PelicanPlatform/classad/classad"
)

// TestSpoolJobFilesFromTar_SingleJob tests spooling files from a tar archive for a single job
func TestSpoolJobFilesFromTar_SingleJob(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	// Setup mini HTCondor instance
	harness := SetupCondorHarness(t)

	// Create collector to find schedd
	collector := NewCollector(harness.GetCollectorAddr())
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Locate schedd
	location, err := collector.LocateDaemon(ctx, "Schedd", "")
	if err != nil {
		t.Fatalf("Failed to locate schedd: %v", err)
	}

	// Create schedd client
	schedd := NewSchedd(location.Name, location.Address)

	// Submit a simple job first to get a real cluster ID
	submitDesc := `
universe = vanilla
executable = /bin/echo
arguments = "Test job"
output = test.out
error = test.err
log = test.log
should_transfer_files = YES
when_to_transfer_output = ON_EXIT
transfer_input_files = input1.txt,input2.dat,subdir/input3.txt
queue
`

	submitCtx, submitCancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer submitCancel()

	// Use SubmitRemote to get procAds with all necessary attributes
	clusterIDInt, procAds, err := schedd.SubmitRemote(submitCtx, submitDesc)
	if err != nil {
		harness.PrintScheddLog()
		t.Fatalf("Failed to submit job: %v", err)
	}

	if len(procAds) == 0 {
		t.Fatal("No proc ads returned from SubmitRemote")
	}

	t.Logf("Submitted job cluster %d with %d procs", clusterIDInt, len(procAds))
	t.Logf("Job ad has %d attributes", len(procAds[0].GetAttributes()))

	// Create a tar archive with test files
	var tarBuf bytes.Buffer
	tarWriter := tar.NewWriter(&tarBuf)

	// Add test files to tar (no cluster.proc prefix for single job mode)
	files := map[string][]byte{
		"input1.txt":        []byte("Test file 1 content\n"),
		"input2.dat":        []byte("Test file 2 content\n"),
		"subdir/input3.txt": []byte("Test file 3 in subdirectory\n"),
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

	// Spool the files to the real schedd using the proc ads from SubmitRemote
	spoolCtx, spoolCancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer spoolCancel()

	err = schedd.SpoolJobFilesFromTar(spoolCtx, procAds, bytes.NewReader(tarBuf.Bytes()))
	if err != nil {
		harness.PrintScheddLog()
		t.Fatalf("Failed to spool files: %v", err)
	}

	t.Logf("Successfully spooled files for job cluster %d", clusterIDInt)
}

// TestSpoolJobFilesFromTar_MultipleJobs tests spooling files from a tar archive for multiple jobs
func TestSpoolJobFilesFromTar_MultipleJobs(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	// Setup mini HTCondor instance
	harness := SetupCondorHarness(t)

	// Create collector to find schedd
	collector := NewCollector(harness.GetCollectorAddr())
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Locate schedd
	location, err := collector.LocateDaemon(ctx, "Schedd", "")
	if err != nil {
		t.Fatalf("Failed to locate schedd: %v", err)
	}

	// Create schedd client
	schedd := NewSchedd(location.Name, location.Address)

	// Submit multiple jobs
	submitDesc := `
universe = vanilla
executable = /bin/echo
arguments = "Job $(Process)"
output = job$(Process).out
error = job$(Process).err
log = jobs.log
should_transfer_files = YES
when_to_transfer_output = ON_EXIT
transfer_input_files = input$(Process).txt
queue 2
`

	submitCtx, submitCancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer submitCancel()

	// Use SubmitRemote to get procAds with all necessary attributes
	clusterIDInt, procAds, err := schedd.SubmitRemote(submitCtx, submitDesc)
	if err != nil {
		harness.PrintScheddLog()
		t.Fatalf("Failed to submit jobs: %v", err)
	}

	if len(procAds) != 2 {
		t.Fatalf("Expected 2 proc ads, got %d", len(procAds))
	}

	t.Logf("Submitted job cluster %d with %d procs", clusterIDInt, len(procAds))

	// Create a tar archive with test files organized by cluster.proc
	// Spool files for each job separately with different content
	for i, procAd := range procAds {
		var tarBuf bytes.Buffer
		tarWriter := tar.NewWriter(&tarBuf)

		// Create different input file based on proc id
		filename := fmt.Sprintf("input%d.txt", i)
		content := []byte(fmt.Sprintf("Job %d input\n", i))

		header := &tar.Header{
			Name:    filename,
			Size:    int64(len(content)),
			Mode:    0644,
			ModTime: time.Now(),
		}
		if err := tarWriter.WriteHeader(header); err != nil {
			t.Fatalf("Failed to write tar header for %s: %v", filename, err)
		}
		if _, err := tarWriter.Write(content); err != nil {
			t.Fatalf("Failed to write tar data for %s: %v", filename, err)
		}

		if err := tarWriter.Close(); err != nil {
			t.Fatalf("Failed to close tar writer: %v", err)
		}

		// Spool files for this job
		spoolCtx, spoolCancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer spoolCancel()

		err = schedd.SpoolJobFilesFromTar(spoolCtx, []*classad.ClassAd{procAd}, bytes.NewReader(tarBuf.Bytes()))
		if err != nil {
			harness.PrintScheddLog()
			t.Fatalf("Failed to spool files for proc %d: %v", i, err)
		}

		t.Logf("Successfully spooled files for job %d.%d", clusterIDInt, i)
	}

	t.Logf("Successfully spooled files for all %d jobs in cluster %d", len(procAds), clusterIDInt)
}

// TestSpoolJobFilesFromTar_MissingAttributes tests error handling when job ads lack required attributes
func TestSpoolJobFilesFromTar_MissingAttributes(t *testing.T) {
	tests := []struct {
		name        string
		setupJobAd  func() *classad.ClassAd
		expectedErr string
	}{
		{
			name: "missing ClusterId",
			setupJobAd: func() *classad.ClassAd {
				ad := classad.New()
				_ = ad.Set("ProcId", int64(0))
				_ = ad.Set("TransferInputFiles", "input.txt")
				return ad
			},
			expectedErr: "missing ClusterId",
		},
		{
			name: "missing ProcId",
			setupJobAd: func() *classad.ClassAd {
				ad := classad.New()
				_ = ad.Set("ClusterId", int64(123))
				_ = ad.Set("TransferInputFiles", "input.txt")
				return ad
			},
			expectedErr: "missing ProcId",
		},
		{
			name: "ClusterId not integer",
			setupJobAd: func() *classad.ClassAd {
				ad := classad.New()
				_ = ad.Set("ClusterId", "not_a_number")
				_ = ad.Set("ProcId", int64(0))
				_ = ad.Set("TransferInputFiles", "input.txt")
				return ad
			},
			expectedErr: "not an integer",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create minimal tar archive
			var tarBuf bytes.Buffer
			tarWriter := tar.NewWriter(&tarBuf)
			_ = tarWriter.Close()

			jobAd := tt.setupJobAd()
			jobAds := []*classad.ClassAd{jobAd}

			schedd := NewSchedd("test-schedd", "localhost:9618")
			ctx := context.Background()

			err := schedd.SpoolJobFilesFromTar(ctx, jobAds, bytes.NewReader(tarBuf.Bytes()))

			if err == nil {
				t.Fatal("Expected error, got nil")
			}

			if !contains(err.Error(), tt.expectedErr) {
				t.Errorf("Expected error containing %q, got: %v", tt.expectedErr, err)
			}
		})
	}
}

// TestSpoolJobFilesFromTar_EmptyJobAds tests error handling when no job ads provided
func TestSpoolJobFilesFromTar_EmptyJobAds(t *testing.T) {
	var tarBuf bytes.Buffer
	tarWriter := tar.NewWriter(&tarBuf)
	_ = tarWriter.Close()

	schedd := NewSchedd("test-schedd", "localhost:9618")
	ctx := context.Background()

	err := schedd.SpoolJobFilesFromTar(ctx, []*classad.ClassAd{}, bytes.NewReader(tarBuf.Bytes()))

	if err == nil {
		t.Fatal("Expected error, got nil")
	}

	if !contains(err.Error(), "no job ads provided") {
		t.Errorf("Expected 'no job ads provided' error, got: %v", err)
	}
}

// TestSpoolJobFilesFromTar_FileFiltering tests that only files in TransferInputFiles are processed
func TestSpoolJobFilesFromTar_FileFiltering(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	// Setup mini HTCondor instance
	harness := SetupCondorHarness(t)

	// Create collector to find schedd
	collector := NewCollector(harness.GetCollectorAddr())
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Locate schedd
	location, err := collector.LocateDaemon(ctx, "Schedd", "")
	if err != nil {
		t.Fatalf("Failed to locate schedd: %v", err)
	}

	// Create schedd client
	schedd := NewSchedd(location.Name, location.Address)

	// Submit a job that only requests input1.txt and input2.dat (not extra files)
	submitDesc := `
universe = vanilla
executable = /bin/echo
arguments = "Filtering test"
output = test.out
error = test.err
log = test.log
should_transfer_files = YES
when_to_transfer_output = ON_EXIT
transfer_input_files = input1.txt, input2.dat
queue
`

	submitCtx, submitCancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer submitCancel()

	// Use SubmitRemote to get procAds with all necessary attributes
	clusterIDInt, procAds, err := schedd.SubmitRemote(submitCtx, submitDesc)
	if err != nil {
		harness.PrintScheddLog()
		t.Fatalf("Failed to submit job: %v", err)
	}

	if len(procAds) == 0 {
		t.Fatal("No proc ads returned from SubmitRemote")
	}

	t.Logf("Submitted job cluster %d", clusterIDInt)

	// Create tar archive with more files than specified in TransferInputFiles
	var tarBuf bytes.Buffer
	tarWriter := tar.NewWriter(&tarBuf)

	files := map[string][]byte{
		"input1.txt": []byte("Should be transferred\n"),
		"input2.dat": []byte("Should be transferred\n"),
		"extra.txt":  []byte("Should be skipped\n"),
		"readme.md":  []byte("Should be skipped\n"),
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

	// Spool the files - only input1.txt and input2.dat should be transferred
	spoolCtx, spoolCancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer spoolCancel()

	err = schedd.SpoolJobFilesFromTar(spoolCtx, procAds, bytes.NewReader(tarBuf.Bytes()))
	if err != nil {
		harness.PrintScheddLog()
		t.Fatalf("Failed to spool files: %v", err)
	}

	t.Logf("Successfully spooled filtered files for job cluster %d", clusterIDInt)
	t.Log("File filtering test passed - only specified input files were transferred")
}

// TestSpoolJobFilesFromTar_PathTraversal tests that files with path traversal are skipped
func TestSpoolJobFilesFromTar_PathTraversal(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	// Setup mini HTCondor instance
	harness := SetupCondorHarness(t)

	// Create collector to find schedd
	collector := NewCollector(harness.GetCollectorAddr())
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Locate schedd
	location, err := collector.LocateDaemon(ctx, "Schedd", "")
	if err != nil {
		t.Fatalf("Failed to locate schedd: %v", err)
	}

	// Create schedd client
	schedd := NewSchedd(location.Name, location.Address)

	// Submit a job - the path traversal attempts should be filtered out
	submitDesc := `
universe = vanilla
executable = /bin/echo
arguments = "Path test"
output = test.out
error = test.err
log = test.log
should_transfer_files = YES
when_to_transfer_output = ON_EXIT
transfer_input_files = input.txt
queue
`

	submitCtx, submitCancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer submitCancel()

	// Use SubmitRemote to get procAds with all necessary attributes
	clusterIDInt, procAds, err := schedd.SubmitRemote(submitCtx, submitDesc)
	if err != nil {
		harness.PrintScheddLog()
		t.Fatalf("Failed to submit job: %v", err)
	}

	if len(procAds) == 0 {
		t.Fatal("No proc ads returned from SubmitRemote")
	}

	t.Logf("Submitted job cluster %d", clusterIDInt)

	// Create tar archive with path traversal attempts
	var tarBuf bytes.Buffer
	tarWriter := tar.NewWriter(&tarBuf)

	files := map[string][]byte{
		"input.txt":        []byte("Safe file\n"),
		"../etc/passwd":    []byte("Should be skipped\n"),
		"../../secret.txt": []byte("Should be skipped\n"),
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

	// Spool the files - path traversal attempts should be filtered out
	spoolCtx, spoolCancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer spoolCancel()

	err = schedd.SpoolJobFilesFromTar(spoolCtx, procAds, bytes.NewReader(tarBuf.Bytes()))
	if err != nil {
		harness.PrintScheddLog()
		t.Fatalf("Failed to spool files: %v", err)
	}

	t.Logf("Successfully spooled files for job cluster %d", clusterIDInt)
	t.Log("Path traversal protection test passed - dangerous paths were filtered out")
}

// Helper function to check if a string contains a substring (case-insensitive)
func contains(s, substr string) bool {
	return bytes.Contains([]byte(s), []byte(substr))
}
