package htcondor

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestQueueSimple(t *testing.T) {
	submit := `
universe = vanilla
executable = /bin/echo
arguments = test
queue
`

	sf, err := ParseSubmitFile(strings.NewReader(submit))
	if err != nil {
		t.Fatalf("Failed to parse submit file: %v", err)
	}

	if sf.queueCount != 1 {
		t.Errorf("Expected queue count 1, got %d", sf.queueCount)
	}

	result, err := sf.Submit(1000)
	if err != nil {
		t.Fatalf("Submit failed: %v", err)
	}

	if result.NumProcs != 1 {
		t.Errorf("Expected 1 proc, got %d", result.NumProcs)
	}

	if len(result.ProcAds) != 1 {
		t.Errorf("Expected 1 proc ad, got %d", len(result.ProcAds))
	}
}

func TestQueueWithCount(t *testing.T) {
	submit := `
universe = vanilla
executable = /bin/echo
arguments = test
queue 5
`

	sf, err := ParseSubmitFile(strings.NewReader(submit))
	if err != nil {
		t.Fatalf("Failed to parse submit file: %v", err)
	}

	if sf.queueCount != 5 {
		t.Errorf("Expected queue count 5, got %d", sf.queueCount)
	}

	result, err := sf.Submit(1001)
	if err != nil {
		t.Fatalf("Submit failed: %v", err)
	}

	if result.NumProcs != 5 {
		t.Errorf("Expected 5 procs, got %d", result.NumProcs)
	}

	if len(result.ProcAds) != 5 {
		t.Errorf("Expected 5 proc ads, got %d", len(result.ProcAds))
	}

	// Verify ProcIds are sequential
	for i := range result.ProcAds {
		// We can't easily verify ProcId without ClassAd.Get(),
		// but we know they were created successfully
		if result.ProcAds[i] == nil {
			t.Errorf("ProcAd %d is nil", i)
		}
	}
}

func TestQueueInList(t *testing.T) {
	submit := `
universe = vanilla
executable = /bin/echo
arguments = $(item)
queue item in (apple, banana, cherry)
`

	sf, err := ParseSubmitFile(strings.NewReader(submit))
	if err != nil {
		t.Fatalf("Failed to parse submit file: %v", err)
	}

	if sf.queueCount != 3 {
		t.Errorf("Expected queue count 3, got %d", sf.queueCount)
	}

	result, err := sf.Submit(1002)
	if err != nil {
		t.Fatalf("Submit failed: %v", err)
	}

	if result.NumProcs != 3 {
		t.Errorf("Expected 3 procs, got %d", result.NumProcs)
	}

	if len(result.ProcAds) != 3 {
		t.Errorf("Expected 3 proc ads, got %d", len(result.ProcAds))
	}
}

func TestQueueCountInList(t *testing.T) {
	submit := `
universe = vanilla
executable = /bin/echo
arguments = $(fruit)
queue 2 fruit in (apple, banana)
`

	sf, err := ParseSubmitFile(strings.NewReader(submit))
	if err != nil {
		t.Fatalf("Failed to parse submit file: %v", err)
	}

	// 2 jobs per item * 2 items = 4 total
	if sf.queueCount != 4 {
		t.Errorf("Expected queue count 4, got %d", sf.queueCount)
	}

	result, err := sf.Submit(1003)
	if err != nil {
		t.Fatalf("Submit failed: %v", err)
	}

	if result.NumProcs != 4 {
		t.Errorf("Expected 4 procs, got %d", result.NumProcs)
	}
}

func TestQueueFromFile(t *testing.T) {
	// Create a temporary file with test data
	tmpDir := t.TempDir()
	dataFile := filepath.Join(tmpDir, "data.txt")

	data := `red
green
blue
`
	if err := os.WriteFile(dataFile, []byte(data), 0600); err != nil {
		t.Fatalf("Failed to create test file: %v", err)
	}

	submit := `
universe = vanilla
executable = /bin/echo
arguments = $(color)
queue color from "` + dataFile + `"
`

	sf, err := ParseSubmitFileWithOptions(strings.NewReader(submit), SubmitParseOptions{AllowLocalAccess: true})
	if err != nil {
		t.Fatalf("Failed to parse submit file: %v", err)
	}

	if sf.queueCount != 3 {
		t.Errorf("Expected queue count 3, got %d", sf.queueCount)
	}

	result, err := sf.Submit(1004)
	if err != nil {
		t.Fatalf("Submit failed: %v", err)
	}

	if result.NumProcs != 3 {
		t.Errorf("Expected 3 procs, got %d", result.NumProcs)
	}
}

func TestQueueCountFromFile(t *testing.T) {
	// Create a temporary file with test data
	tmpDir := t.TempDir()
	dataFile := filepath.Join(tmpDir, "items.txt")

	data := `item1
item2
`
	if err := os.WriteFile(dataFile, []byte(data), 0600); err != nil {
		t.Fatalf("Failed to create test file: %v", err)
	}

	submit := `
universe = vanilla
executable = /bin/echo
arguments = $(name)
queue 3 name from "` + dataFile + `"
`

	sf, err := ParseSubmitFileWithOptions(strings.NewReader(submit), SubmitParseOptions{AllowLocalAccess: true})
	if err != nil {
		t.Fatalf("Failed to parse submit file: %v", err)
	}

	// 3 jobs per line * 2 lines = 6 total
	if sf.queueCount != 6 {
		t.Errorf("Expected queue count 6, got %d", sf.queueCount)
	}

	result, err := sf.Submit(1005)
	if err != nil {
		t.Fatalf("Submit failed: %v", err)
	}

	if result.NumProcs != 6 {
		t.Errorf("Expected 6 procs, got %d", result.NumProcs)
	}
}

func TestQueueMatching(t *testing.T) {
	// Create temporary files to match
	tmpDir := t.TempDir()

	files := []string{"test1.txt", "test2.txt", "test3.txt"}
	for _, fname := range files {
		fpath := filepath.Join(tmpDir, fname)
		if err := os.WriteFile(fpath, []byte("test"), 0600); err != nil {
			t.Fatalf("Failed to create test file: %v", err)
		}
	}

	// Change to temp directory for glob matching
	oldDir, err := os.Getwd()
	if err != nil {
		t.Fatalf("Failed to get working directory: %v", err)
	}
	defer func() { _ = os.Chdir(oldDir) }()

	if err := os.Chdir(tmpDir); err != nil {
		t.Fatalf("Failed to change directory: %v", err)
	}

	submit := `
universe = vanilla
executable = /bin/echo
arguments = $(ITEM)
queue matching "test*.txt"
`

	sf, err := ParseSubmitFileWithOptions(strings.NewReader(submit), SubmitParseOptions{AllowLocalAccess: true})
	if err != nil {
		t.Fatalf("Failed to parse submit file: %v", err)
	}

	if sf.queueCount != 3 {
		t.Errorf("Expected queue count 3, got %d", sf.queueCount)
	}

	result, err := sf.Submit(1006)
	if err != nil {
		t.Fatalf("Submit failed: %v", err)
	}

	if result.NumProcs != 3 {
		t.Errorf("Expected 3 procs, got %d", result.NumProcs)
	}
}

func TestQueueCountMatching(t *testing.T) {
	// Create temporary files to match
	tmpDir := t.TempDir()

	files := []string{"data1.dat", "data2.dat"}
	for _, fname := range files {
		fpath := filepath.Join(tmpDir, fname)
		if err := os.WriteFile(fpath, []byte("test"), 0600); err != nil {
			t.Fatalf("Failed to create test file: %v", err)
		}
	}

	// Change to temp directory for glob matching
	oldDir, err := os.Getwd()
	if err != nil {
		t.Fatalf("Failed to get working directory: %v", err)
	}
	defer func() { _ = os.Chdir(oldDir) }()

	if err := os.Chdir(tmpDir); err != nil {
		t.Fatalf("Failed to change directory: %v", err)
	}

	submit := `
universe = vanilla
executable = /bin/echo
arguments = $(ITEM)
queue 2 matching "data*.dat"
`

	sf, err := ParseSubmitFileWithOptions(strings.NewReader(submit), SubmitParseOptions{AllowLocalAccess: true})
	if err != nil {
		t.Fatalf("Failed to parse submit file: %v", err)
	}

	// 2 jobs per file * 2 files = 4 total
	if sf.queueCount != 4 {
		t.Errorf("Expected queue count 4, got %d", sf.queueCount)
	}

	result, err := sf.Submit(1007)
	if err != nil {
		t.Fatalf("Submit failed: %v", err)
	}

	if result.NumProcs != 4 {
		t.Errorf("Expected 4 procs, got %d", result.NumProcs)
	}
}

func TestQueueVariableSubstitution(t *testing.T) {
	submit := `
universe = vanilla
executable = /bin/echo
arguments = "Processing $(item)"
output = output_$(item).txt
error = error_$(item).txt
queue item in (alpha, beta, gamma)
`

	sf, err := ParseSubmitFile(strings.NewReader(submit))
	if err != nil {
		t.Fatalf("Failed to parse submit file: %v", err)
	}

	result, err := sf.Submit(1008)
	if err != nil {
		t.Fatalf("Submit failed: %v", err)
	}

	if result.NumProcs != 3 {
		t.Errorf("Expected 3 procs, got %d", result.NumProcs)
	}

	// Verify each job ad has different values due to variable substitution
	// (This would require ClassAd.Get() to fully verify, but we can at least
	// ensure the jobs were created)
	if len(result.ProcAds) != 3 {
		t.Errorf("Expected 3 proc ads, got %d", len(result.ProcAds))
	}
}

func TestQueueMultipleVariablesFromFile(t *testing.T) {
	// Create a temporary file with multiple columns
	tmpDir := t.TempDir()
	dataFile := filepath.Join(tmpDir, "params.txt")

	data := `red circle
green square
blue triangle
`
	if err := os.WriteFile(dataFile, []byte(data), 0600); err != nil {
		t.Fatalf("Failed to create test file: %v", err)
	}

	submit := `
universe = vanilla
executable = /bin/echo
arguments = "$(color) $(shape)"
queue color, shape from "` + dataFile + `"
`

	sf, err := ParseSubmitFileWithOptions(strings.NewReader(submit), SubmitParseOptions{AllowLocalAccess: true})
	if err != nil {
		t.Fatalf("Failed to parse submit file: %v", err)
	}

	if sf.queueCount != 3 {
		t.Errorf("Expected queue count 3, got %d", sf.queueCount)
	}

	result, err := sf.Submit(1009)
	if err != nil {
		t.Fatalf("Submit failed: %v", err)
	}

	if result.NumProcs != 3 {
		t.Errorf("Expected 3 procs, got %d", result.NumProcs)
	}
}

func TestQueueNoMatches(t *testing.T) {
	// Create empty temp directory
	tmpDir := t.TempDir()

	// Change to temp directory
	oldDir, err := os.Getwd()
	if err != nil {
		t.Fatalf("Failed to get working directory: %v", err)
	}
	defer func() { _ = os.Chdir(oldDir) }()

	if err := os.Chdir(tmpDir); err != nil {
		t.Fatalf("Failed to change directory: %v", err)
	}

	submit := `
universe = vanilla
executable = /bin/echo
queue matching "nonexistent*.txt"
`

	sf, err := ParseSubmitFileWithOptions(strings.NewReader(submit), SubmitParseOptions{AllowLocalAccess: true})
	if err != nil {
		t.Fatalf("Failed to parse submit file: %v", err)
	}

	// No matches means no jobs
	if sf.queueCount != 0 {
		t.Errorf("Expected queue count 0, got %d", sf.queueCount)
	}

	result, err := sf.Submit(1010)
	if err != nil {
		t.Fatalf("Submit failed: %v", err)
	}

	if result.NumProcs != 0 {
		t.Errorf("Expected 0 procs, got %d", result.NumProcs)
	}
}
