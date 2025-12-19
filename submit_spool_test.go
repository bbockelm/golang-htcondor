package htcondor

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Tests for copy_to_spool functionality
//
// The copy_to_spool feature allows HTCondor to copy the executable and input
// files to the spool directory before job execution. This is useful for:
// - Jobs with large executables or input files
// - Protecting against file changes after submission
// - Running jobs when the submit host may be unavailable
//
// These tests verify:
// - Unit tests: Proper ClassAd generation with various copy_to_spool settings
// - Integration tests: Comparison with condor_submit behavior
//
// Note: condor_submit handles copy_to_spool via ::send_SpoolFile commands
// in the ClassAd file rather than as a ClassAd attribute, so CopyToSpool
// attribute differences are expected and ignored in integration tests.

// Unit Tests for Spooling Functionality

func TestCopyToSpoolTrue(t *testing.T) {
	submit := `
universe = vanilla
executable = /usr/bin/true
output = test.out
error = test.err
log = test.log
copy_to_spool = true
queue
`

	sf, err := ParseSubmitFile(strings.NewReader(submit))
	if err != nil {
		t.Fatalf("Failed to parse submit file: %v", err)
	}

	result, err := sf.Submit(1)
	if err != nil {
		t.Fatalf("Submit failed: %v", err)
	}

	if len(result.ProcAds) == 0 {
		t.Fatal("No proc ads generated")
	}

	ad := result.ProcAds[0]

	// Verify CopyToSpool attribute
	copyToSpool := ad.EvaluateAttr("CopyToSpool")
	if copyToSpool.IsUndefined() {
		t.Error("CopyToSpool attribute not set")
	} else if copyToSpool.IsBool() {
		val, _ := copyToSpool.BoolValue()
		if !val {
			t.Errorf("Expected CopyToSpool=true, got false")
		}
	}
}

func TestCopyToSpoolFalse(t *testing.T) {
	submit := `
universe = vanilla
executable = /usr/bin/true
output = test.out
error = test.err
log = test.log
copy_to_spool = false
queue
`

	sf, err := ParseSubmitFile(strings.NewReader(submit))
	if err != nil {
		t.Fatalf("Failed to parse submit file: %v", err)
	}

	result, err := sf.Submit(1)
	if err != nil {
		t.Fatalf("Submit failed: %v", err)
	}

	if len(result.ProcAds) == 0 {
		t.Fatal("No proc ads generated")
	}

	ad := result.ProcAds[0]

	// Verify CopyToSpool attribute
	copyToSpool := ad.EvaluateAttr("CopyToSpool")
	if copyToSpool.IsUndefined() {
		t.Error("CopyToSpool attribute not set")
	} else if copyToSpool.IsBool() {
		val, _ := copyToSpool.BoolValue()
		if val {
			t.Errorf("Expected CopyToSpool=false, got true")
		}
	}
}

func TestCopyToSpoolDefault(t *testing.T) {
	// When not specified, CopyToSpool should not be set (or be undefined)
	submit := `
universe = vanilla
executable = /usr/bin/true
output = test.out
error = test.err
log = test.log
queue
`

	sf, err := ParseSubmitFile(strings.NewReader(submit))
	if err != nil {
		t.Fatalf("Failed to parse submit file: %v", err)
	}

	result, err := sf.Submit(1)
	if err != nil {
		t.Fatalf("Submit failed: %v", err)
	}

	if len(result.ProcAds) == 0 {
		t.Fatal("No proc ads generated")
	}

	ad := result.ProcAds[0]

	// CopyToSpool should be undefined when not specified
	copyToSpool := ad.EvaluateAttr("CopyToSpool")
	if !copyToSpool.IsUndefined() {
		t.Logf("CopyToSpool is set to: %v (expected undefined, but may be OK)", copyToSpool)
	}
}

func TestCopyToSpoolWithMultipleJobs(t *testing.T) {
	submit := `
universe = vanilla
executable = /usr/bin/true
output = test_$(Process).out
error = test_$(Process).err
log = test.log
copy_to_spool = true
queue 3
`

	sf, err := ParseSubmitFile(strings.NewReader(submit))
	if err != nil {
		t.Fatalf("Failed to parse submit file: %v", err)
	}

	result, err := sf.Submit(1)
	if err != nil {
		t.Fatalf("Submit failed: %v", err)
	}

	if result.NumProcs != 3 {
		t.Fatalf("Expected 3 jobs, got %d", result.NumProcs)
	}

	// Verify all jobs have CopyToSpool set
	for i, ad := range result.ProcAds {
		copyToSpool := ad.EvaluateAttr("CopyToSpool")
		if copyToSpool.IsUndefined() {
			t.Errorf("Job %d: CopyToSpool attribute not set", i)
		} else if copyToSpool.IsBool() {
			val, _ := copyToSpool.BoolValue()
			if !val {
				t.Errorf("Job %d: Expected CopyToSpool=true, got false", i)
			}
		}
	}
}

func TestCopyToSpoolWithTransferFiles(t *testing.T) {
	submit := `
universe = vanilla
executable = /usr/bin/true
transfer_input_files = input1.txt, input2.txt
copy_to_spool = true
output = test.out
error = test.err
log = test.log
queue
`

	sf, err := ParseSubmitFile(strings.NewReader(submit))
	if err != nil {
		t.Fatalf("Failed to parse submit file: %v", err)
	}

	result, err := sf.Submit(1)
	if err != nil {
		t.Fatalf("Submit failed: %v", err)
	}

	if len(result.ProcAds) == 0 {
		t.Fatal("No proc ads generated")
	}

	ad := result.ProcAds[0]

	// Verify both CopyToSpool and TransferInput are set
	copyToSpool := ad.EvaluateAttr("CopyToSpool")
	if copyToSpool.IsUndefined() {
		t.Error("CopyToSpool attribute not set")
	} else if copyToSpool.IsBool() {
		val, _ := copyToSpool.BoolValue()
		if !val {
			t.Error("Expected CopyToSpool=true")
		}
	}

	transferInput, ok := ad.EvaluateAttrString("TransferInput")
	if !ok || transferInput == "" {
		t.Error("TransferInput attribute not set")
	} else if transferInput != "input1.txt,input2.txt" {
		t.Errorf("Unexpected TransferInput value: %s", transferInput)
	}
}

func TestCopyToSpoolYesNo(t *testing.T) {
	// Test that yes/no values work for copy_to_spool
	testCases := []struct {
		value    string
		expected bool
	}{
		{"yes", true},
		{"YES", true},
		{"Yes", true},
		{"no", false},
		{"NO", false},
		{"No", false},
		{"1", true},
		{"0", false},
		{"TRUE", true},
		{"FALSE", false},
	}

	for _, tc := range testCases {
		t.Run(tc.value, func(t *testing.T) {
			submit := `
universe = vanilla
executable = /usr/bin/true
output = test.out
error = test.err
log = test.log
copy_to_spool = ` + tc.value + `
queue
`

			sf, err := ParseSubmitFile(strings.NewReader(submit))
			if err != nil {
				t.Fatalf("Failed to parse submit file: %v", err)
			}

			result, err := sf.Submit(1)
			if err != nil {
				t.Fatalf("Submit failed: %v", err)
			}

			if len(result.ProcAds) == 0 {
				t.Fatal("No proc ads generated")
			}

			ad := result.ProcAds[0]
			copyToSpool := ad.EvaluateAttr("CopyToSpool")

			if copyToSpool.IsBool() {
				val, _ := copyToSpool.BoolValue()
				if val != tc.expected {
					t.Errorf("For copy_to_spool=%s, expected %v, got %v", tc.value, tc.expected, val)
				}
			} else {
				t.Errorf("CopyToSpool is not a boolean: %v", copyToSpool)
			}
		})
	}
}

// Integration Tests with condor_submit

func TestIntegrationCopyToSpoolTrue(t *testing.T) {
	if !condorSubmitAvailable() {
		t.Skip("condor_submit not available")
	}

	submitContent := `
universe = vanilla
executable = /usr/bin/true
output = spool_test.out
error = spool_test.err
log = spool_test.log
copy_to_spool = true
queue
`

	// Get condor_submit result
	condorAd, err := runCondorSubmit(submitContent)
	if err != nil {
		t.Fatalf("Failed to run condor_submit: %v", err)
	}

	// Get Go library result
	sf, err := ParseSubmitFile(strings.NewReader(submitContent))
	if err != nil {
		t.Fatalf("Failed to parse submit file: %v", err)
	}

	result, err := sf.Submit(1)
	if err != nil {
		t.Fatalf("Submit failed: %v", err)
	}

	if len(result.ProcAds) == 0 {
		t.Fatal("No proc ads generated")
	}

	goAd := result.ProcAds[0]

	// Compare CopyToSpool attribute specifically
	goCopyToSpool := goAd.EvaluateAttr("CopyToSpool")
	condorCopyToSpool := condorAd.EvaluateAttr("CopyToSpool")

	switch {
	case goCopyToSpool.IsUndefined() && condorCopyToSpool.IsUndefined():
		t.Log("Both implementations leave CopyToSpool undefined")
	case goCopyToSpool.IsBool() && condorCopyToSpool.IsBool():
		goVal, _ := goCopyToSpool.BoolValue()
		condorVal, _ := condorCopyToSpool.BoolValue()
		if goVal != condorVal {
			t.Errorf("CopyToSpool mismatch: Go=%v, Condor=%v", goVal, condorVal)
		}
	case !goCopyToSpool.IsUndefined() || !condorCopyToSpool.IsUndefined():
		t.Logf("CopyToSpool types differ: Go=%v, Condor=%v", goCopyToSpool, condorCopyToSpool)
	}

	// Do full comparison
	compareClassAds(t, goAd, condorAd, "CopyToSpoolTrue")
}

func TestIntegrationCopyToSpoolFalse(t *testing.T) {
	if !condorSubmitAvailable() {
		t.Skip("condor_submit not available")
	}

	submitContent := `
universe = vanilla
executable = /usr/bin/true
output = spool_test.out
error = spool_test.err
log = spool_test.log
copy_to_spool = false
queue
`

	// Get condor_submit result
	condorAd, err := runCondorSubmit(submitContent)
	if err != nil {
		t.Fatalf("Failed to run condor_submit: %v", err)
	}

	// Get Go library result
	sf, err := ParseSubmitFile(strings.NewReader(submitContent))
	if err != nil {
		t.Fatalf("Failed to parse submit file: %v", err)
	}

	result, err := sf.Submit(1)
	if err != nil {
		t.Fatalf("Submit failed: %v", err)
	}

	if len(result.ProcAds) == 0 {
		t.Fatal("No proc ads generated")
	}

	goAd := result.ProcAds[0]

	// Compare
	compareClassAds(t, goAd, condorAd, "CopyToSpoolFalse")
}

func TestIntegrationCopyToSpoolWithInputFiles(t *testing.T) {
	if !condorSubmitAvailable() {
		t.Skip("condor_submit not available")
	}

	// Create temporary input files for the test
	tmpDir, err := os.MkdirTemp("", "spool_test_*")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer func() { _ = os.RemoveAll(tmpDir) }()

	inputFile1 := filepath.Join(tmpDir, "input1.txt")
	inputFile2 := filepath.Join(tmpDir, "input2.txt")

	if err := os.WriteFile(inputFile1, []byte("test data 1"), 0600); err != nil {
		t.Fatalf("Failed to create input file: %v", err)
	}
	if err := os.WriteFile(inputFile2, []byte("test data 2"), 0600); err != nil {
		t.Fatalf("Failed to create input file: %v", err)
	}

	submitContent := `
universe = vanilla
executable = /bin/cat
transfer_input_files = ` + inputFile1 + `, ` + inputFile2 + `
copy_to_spool = true
should_transfer_files = YES
when_to_transfer_output = ON_EXIT
output = spool_test.out
error = spool_test.err
log = spool_test.log
queue
`

	// Get condor_submit result
	condorAd, err := runCondorSubmit(submitContent)
	if err != nil {
		t.Fatalf("Failed to run condor_submit: %v", err)
	}

	// Get Go library result
	sf, err := ParseSubmitFile(strings.NewReader(submitContent))
	if err != nil {
		t.Fatalf("Failed to parse submit file: %v", err)
	}

	result, err := sf.Submit(1)
	if err != nil {
		t.Fatalf("Submit failed: %v", err)
	}

	if len(result.ProcAds) == 0 {
		t.Fatal("No proc ads generated")
	}

	goAd := result.ProcAds[0]

	// Compare
	compareClassAds(t, goAd, condorAd, "CopyToSpoolWithInputFiles")
}

func TestIntegrationCopyToSpoolDefault(t *testing.T) {
	if !condorSubmitAvailable() {
		t.Skip("condor_submit not available")
	}

	submitContent := `
universe = vanilla
executable = /usr/bin/true
output = spool_test.out
error = spool_test.err
log = spool_test.log
queue
`

	// Get condor_submit result
	condorAd, err := runCondorSubmit(submitContent)
	if err != nil {
		t.Fatalf("Failed to run condor_submit: %v", err)
	}

	// Get Go library result
	sf, err := ParseSubmitFile(strings.NewReader(submitContent))
	if err != nil {
		t.Fatalf("Failed to parse submit file: %v", err)
	}

	result, err := sf.Submit(1)
	if err != nil {
		t.Fatalf("Submit failed: %v", err)
	}

	if len(result.ProcAds) == 0 {
		t.Fatal("No proc ads generated")
	}

	goAd := result.ProcAds[0]

	// When not specified, both should either not set it or set the same default
	goCopyToSpool := goAd.EvaluateAttr("CopyToSpool")
	condorCopyToSpool := condorAd.EvaluateAttr("CopyToSpool")

	t.Logf("Default CopyToSpool - Go: %v, Condor: %v", goCopyToSpool, condorCopyToSpool)

	// Compare full ClassAds
	compareClassAds(t, goAd, condorAd, "CopyToSpoolDefault")
}

// Test that copy_to_spool works correctly with executable spooling
func TestCopyToSpoolWithExecutable(t *testing.T) {
	// Create a temporary executable
	tmpDir, err := os.MkdirTemp("", "exec_spool_test_*")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer func() { _ = os.RemoveAll(tmpDir) }()

	execPath := filepath.Join(tmpDir, "test_script.sh")
	execContent := "#!/bin/bash\necho 'Hello from spooled executable'\n"

	//nolint:gosec // G306: Script needs to be executable (0700)
	if err := os.WriteFile(execPath, []byte(execContent), 0700); err != nil {
		t.Fatalf("Failed to create executable: %v", err)
	}

	submit := `
universe = vanilla
executable = ` + execPath + `
output = test.out
error = test.err
log = test.log
copy_to_spool = true
queue
`

	sf, err := ParseSubmitFile(strings.NewReader(submit))
	if err != nil {
		t.Fatalf("Failed to parse submit file: %v", err)
	}

	result, err := sf.Submit(1)
	if err != nil {
		t.Fatalf("Submit failed: %v", err)
	}

	if len(result.ProcAds) == 0 {
		t.Fatal("No proc ads generated")
	}

	ad := result.ProcAds[0]

	// Verify CopyToSpool is set
	copyToSpool := ad.EvaluateAttr("CopyToSpool")
	if copyToSpool.IsUndefined() {
		t.Error("CopyToSpool attribute not set")
	}

	// Verify Cmd (executable) is set
	cmd := ad.EvaluateAttr("Cmd")
	if cmd.IsUndefined() {
		t.Error("Cmd attribute not set")
	}
}
