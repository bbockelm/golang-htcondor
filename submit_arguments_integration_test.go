//go:build integration

package htcondor

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestArgumentsIntegration tests argument quoting by submitting actual jobs
// that print each argument on a separate line
func TestArgumentsIntegration(t *testing.T) {
	if !condorSubmitAvailable() {
		t.Skip("condor_submit not available")
	}

	tests := []struct {
		name         string
		args         string
		expectedArgs []string
		isNewStyle   bool
	}{
		{
			name:         "old style - simple",
			args:         `one two three`,
			expectedArgs: []string{"one", "two", "three"},
			isNewStyle:   false,
		},
		{
			name:         "old style - escaped quotes",
			args:         `one \"two\" three`,
			expectedArgs: []string{"one", `"two"`, "three"},
			isNewStyle:   false,
		},
		{
			name:         "new style - simple",
			args:         `"one two three"`,
			expectedArgs: []string{"one", "two", "three"},
			isNewStyle:   true,
		},
		{
			name:         "new style - with spaces",
			args:         `"one 'two with spaces' three"`,
			expectedArgs: []string{"one", "two with spaces", "three"},
			isNewStyle:   true,
		},
		{
			name:         "new style - escaped quotes",
			args:         `"one ""two"" three"`,
			expectedArgs: []string{"one", `"two"`, "three"},
			isNewStyle:   true,
		},
		{
			name:         "new style - complex",
			args:         `"arg1 ""quoted"" 'spacey ''nested'' value' final"`,
			expectedArgs: []string{"arg1", `"quoted"`, "spacey 'nested' value", "final"},
			isNewStyle:   true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create a temporary directory for this test
			tmpDir := t.TempDir()

			// Create a script that prints each argument on a separate line
			scriptPath := filepath.Join(tmpDir, "print_args.sh")
			scriptContent := `#!/bin/bash
# Print each argument on a separate line
for arg in "$@"; do
    echo "$arg"
done
`
			if err := os.WriteFile(scriptPath, []byte(scriptContent), 0755); err != nil {
				t.Fatalf("Failed to create script: %v", err)
			}

			// Create output file paths
			outputPath := filepath.Join(tmpDir, "job.out")
			errorPath := filepath.Join(tmpDir, "job.err")
			logPath := filepath.Join(tmpDir, "job.log")

			// Create submit file
			submitContent := fmt.Sprintf(`
universe = vanilla
executable = %s
arguments = %s
output = %s
error = %s
log = %s
should_transfer_files = YES
when_to_transfer_output = ON_EXIT
queue
`, scriptPath, tt.args, outputPath, errorPath, logPath)

			// Submit the job using Go implementation
			sf, err := ParseSubmitFile(strings.NewReader(submitContent))
			if err != nil {
				t.Fatalf("Failed to parse submit file: %v", err)
			}

			result, err := sf.Submit(10000)
			if err != nil {
				t.Fatalf("Failed to generate job ads: %v", err)
			}

			// Verify the job ad has the correct attribute
			if len(result.ProcAds) == 0 {
				t.Fatal("No proc ads generated")
			}

			ad := result.ProcAds[0]
			if tt.isNewStyle {
				// Should have Arguments attribute
				argsResult := ad.EvaluateAttr("Arguments")
				if argsResult.IsError() {
					t.Errorf("Expected Arguments attribute for new style, got error: %v", argsResult)
				} else {
					t.Logf("Arguments attribute: %v", argsResult)
				}
			} else {
				// Should have Args attribute
				argsResult := ad.EvaluateAttr("Args")
				if argsResult.IsError() {
					t.Errorf("Expected Args attribute for old style, got error: %v", argsResult)
				} else {
					t.Logf("Args attribute: %v", argsResult)
				}
			}

			// Now actually submit the job to HTCondor using our schedd client
			// and wait for it to complete to verify the actual behavior
			// t.Logf("Submitting job to schedd")

			// TODO: Once we have the schedd Submit implementation working,
			// we can uncomment this section to actually run the job
			// and verify the output matches expected arguments

			/*
				ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
				defer cancel()

				clusterID, err := schedd.Submit(ctx, submitContent)
				if err != nil {
					t.Fatalf("Failed to submit job: %v", err)
				}

				t.Logf("Submitted job cluster %s", clusterID)

				// Wait for job to complete (with timeout)
				if err := waitForJobCompletion(ctx, schedd, clusterID, 2*time.Minute); err != nil {
					t.Fatalf("Job did not complete: %v", err)
				}

				// Read output file
				output, err := os.ReadFile(outputPath)
				if err != nil {
					t.Fatalf("Failed to read output file: %v", err)
				}

				// Split output into lines (one argument per line)
				lines := strings.Split(strings.TrimSpace(string(output)), "\n")

				// Compare with expected arguments
				if len(lines) != len(tt.expectedArgs) {
					t.Errorf("Expected %d arguments, got %d:\nExpected: %v\nGot: %v",
						len(tt.expectedArgs), len(lines), tt.expectedArgs, lines)
				}

				for i, expected := range tt.expectedArgs {
					if i >= len(lines) {
						t.Errorf("Missing argument %d: expected %q", i, expected)
						continue
					}
					if lines[i] != expected {
						t.Errorf("Argument %d mismatch:\nExpected: %q\nGot: %q", i, expected, lines[i])
					}
				}
			*/
		})
	}
}

// TestArgumentsCompareWithCondorSubmit compares our argument processing
// with condor_submit using -dry-run
func TestArgumentsCompareWithCondorSubmit(t *testing.T) {
	if !condorSubmitAvailable() {
		t.Skip("condor_submit not available")
	}

	tests := []struct {
		name string
		args string
	}{
		{name: "old simple", args: `one two three`},
		{name: "old escaped", args: `one \"two\" three`},
		{name: "new simple", args: `"one two three"`},
		{name: "new quoted", args: `"one 'two with spaces' three"`},
		{name: "new escaped", args: `"one ""two"" three"`},
		{name: "new complex", args: `"one ""two"" 'spacey ''quoted'' argument'"`},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			submitContent := fmt.Sprintf(`
universe = vanilla
executable = /bin/echo
arguments = %s
queue
`, tt.args)

			// Get ClassAd from condor_submit
			condorAd, err := runCondorSubmit(submitContent)
			if err != nil {
				t.Fatalf("Failed to run condor_submit: %v", err)
			}

			// Get ClassAd from our implementation
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

			// Compare Args attribute
			condorArgs := condorAd.EvaluateAttr("Args")
			goArgs := goAd.EvaluateAttr("Args")

			// Both should exist or both should be undefined
			if condorArgs.IsUndefined() != goArgs.IsUndefined() {
				t.Errorf("Args existence mismatch: condor=%v, go=%v",
					!condorArgs.IsUndefined(), !goArgs.IsUndefined())
			}

			if !condorArgs.IsUndefined() && !goArgs.IsUndefined() {
				condorStr, _ := condorArgs.StringValue()
				goStr, _ := goArgs.StringValue()
				if condorStr != goStr {
					t.Errorf("Args value mismatch:\nCondor: %q\nGo:     %q", condorStr, goStr)
				} else {
					t.Logf("Args match: %q", goStr)
				}
			}

			// Compare Arguments attribute
			condorArguments := condorAd.EvaluateAttr("Arguments")
			goArguments := goAd.EvaluateAttr("Arguments")

			// Both should exist or both should be undefined
			if condorArguments.IsUndefined() != goArguments.IsUndefined() {
				t.Errorf("Arguments existence mismatch: condor=%v, go=%v",
					!condorArguments.IsUndefined(), !goArguments.IsUndefined())
			}

			if !condorArguments.IsUndefined() && !goArguments.IsUndefined() {
				condorStr, _ := condorArguments.StringValue()
				goStr, _ := goArguments.StringValue()
				if condorStr != goStr {
					t.Errorf("Arguments value mismatch:\nCondor: %q\nGo:     %q", condorStr, goStr)
				} else {
					t.Logf("Arguments match: %q", goStr)
				}
			}
		})
	}
}
