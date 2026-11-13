package htcondor

import (
	"strings"
	"testing"
)

// TestArgumentsOldStyle tests the "old style" argument quoting
// In old style:
// - Arguments are space-delimited
// - Backslash escapes double quotes: \" becomes "
// - No special handling of single quotes
func TestArgumentsOldStyle(t *testing.T) {
	tests := []struct {
		name     string
		args     string
		expected string // Expected Args attribute value in ClassAd
	}{
		{
			name:     "simple arguments",
			args:     `one two three`,
			expected: `one two three`,
		},
		{
			name:     "escaped double quotes",
			args:     `one \"two\" 'three'`,
			expected: `one "two" 'three'`,
		},
		{
			name:     "multiple escaped quotes",
			args:     `\"start\" middle \"end\"`,
			expected: `"start" middle "end"`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			submit := `
universe = vanilla
executable = /bin/echo
arguments = ` + tt.args + `
queue
`

			sf, err := ParseSubmitFile(strings.NewReader(submit))
			if err != nil {
				t.Fatalf("Failed to parse submit file: %v", err)
			}

			jobID := JobID{Cluster: 100, Proc: 0}
			ad, err := sf.MakeJobAd(jobID, map[string]string{})
			if err != nil {
				t.Fatalf("Failed to create job ad: %v", err)
			}

			// Get the Args attribute
			argsResult := ad.EvaluateAttr("Args")
			if argsResult.IsError() {
				t.Fatalf("Failed to get Args attribute: %v", argsResult)
			}

			argsStr, err := argsResult.StringValue()
			if err != nil {
				t.Fatalf("Args attribute is not a string: %v", err)
			}

			if argsStr != tt.expected {
				t.Errorf("Args mismatch:\nGot:      %q\nExpected: %q", argsStr, tt.expected)
			}
		})
	}
}

// TestArgumentsNewStyle tests the "new style" argument quoting
// In new style (entire string surrounded by double quotes):
// - Arguments are space/tab delimited
// - Double quotes are escaped by doubling them: "" becomes "
// - Single quotes delimit arguments with embedded spaces
// - Single quotes within single-quoted args are escaped by doubling: ” becomes '
func TestArgumentsNewStyle(t *testing.T) {
	tests := []struct {
		name     string
		args     string
		expected string // Expected Arguments attribute value in ClassAd
	}{
		{
			name:     "simple arguments",
			args:     `"3 simple arguments"`,
			expected: `3 simple arguments`,
		},
		{
			name:     "single quoted argument with spaces",
			args:     `"one 'two with spaces' 3"`,
			expected: `one two' 'with' 'spaces 3`,
		},
		{
			name:     "escaped double quotes",
			args:     `"one ""two"" 'spacey ''quoted'' argument'"`,
			expected: `one "two" spacey' '''quoted''' 'argument`,
		},
		{
			// A tab is a separator in the V2 form, like a space, and the
			// arguments are rejoined with single spaces -- verified
			// against condor_submit.
			name:     "tabs as delimiters",
			args:     "\"one\ttwo\tthree\"",
			expected: "one two three",
		},
		{
			name:     "empty argument",
			args:     `""`,
			expected: ``,
		},
		{
			name:     "mix of quotes",
			args:     `"arg1 ""quoted"" 'single quoted' normal"`,
			expected: `arg1 "quoted" single' 'quoted normal`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			submit := `
universe = vanilla
executable = /bin/echo
arguments = ` + tt.args + `
queue
`

			sf, err := ParseSubmitFile(strings.NewReader(submit))
			if err != nil {
				t.Fatalf("Failed to parse submit file: %v", err)
			}

			jobID := JobID{Cluster: 100, Proc: 0}
			ad, err := sf.MakeJobAd(jobID, map[string]string{})
			if err != nil {
				t.Fatalf("Failed to create job ad: %v", err)
			}

			// Get the Arguments attribute (new style uses Arguments, not Args)
			argumentsResult := ad.EvaluateAttr("Arguments")
			if argumentsResult.IsError() {
				// Try Args as fallback
				argumentsResult = ad.EvaluateAttr("Args")
				if argumentsResult.IsError() {
					t.Fatalf("Failed to get Arguments or Args attribute: %v", argumentsResult)
				}
			}

			argumentsStr, err := argumentsResult.StringValue()
			if err != nil {
				t.Fatalf("Arguments attribute is not a string: %v (result: %v)", err, argumentsResult)
			}

			if argumentsStr != tt.expected {
				t.Errorf("Arguments mismatch:\nGot:      %q\nExpected: %q", argumentsStr, tt.expected)
			}
		})
	}
}

// TestArgumentsDetectStyle verifies that we can detect whether
// old or new style quoting is used
func TestArgumentsDetectStyle(t *testing.T) {
	tests := []struct {
		name       string
		args       string
		isNewStyle bool
	}{
		{
			name:       "new style - surrounded by double quotes",
			args:       `"one two three"`,
			isNewStyle: true,
		},
		{
			name:       "old style - no surrounding quotes",
			args:       `one two three`,
			isNewStyle: false,
		},
		{
			name:       "old style - quotes in middle",
			args:       `one \"two\" three`,
			isNewStyle: false,
		},
		{
			name:       "new style - empty",
			args:       `""`,
			isNewStyle: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			trimmed := strings.TrimSpace(tt.args)
			isNewStyle := strings.HasPrefix(trimmed, `"`) && strings.HasSuffix(trimmed, `"`)

			if isNewStyle != tt.isNewStyle {
				t.Errorf("Style detection mismatch: got %v, expected %v", isNewStyle, tt.isNewStyle)
			}
		})
	}
}

// TestArgumentsComplexCases tests complex edge cases
func TestArgumentsComplexCases(t *testing.T) {
	tests := []struct {
		name     string
		args     string
		attrName string // "Args" for old style, "Arguments" for new style
		expected string
	}{
		{
			// Whitespace between arguments is a separator, so a value of
			// nothing but whitespace is no arguments at all.
			name:     "new style - only spaces",
			args:     `"   "`,
			attrName: "Arguments",
			expected: ``,
		},
		{
			// Same: the list is parsed and written back out, so the
			// padding is gone and the doubled space is one separator.
			name:     "new style - leading/trailing spaces",
			args:     `"  arg1  arg2  "`,
			attrName: "Arguments",
			expected: `arg1 arg2`,
		},
		{
			name:     "old style - backslashes",
			args:     `path\\to\\file`,
			attrName: "Args",
			expected: `path\\to\\file`,
		},
		{
			name:     "new style - backslashes (no special meaning)",
			args:     `"path\\to\\file"`,
			attrName: "Arguments",
			expected: `path\\to\\file`,
		},
		{
			name:     "new style - nested quotes",
			args:     `"'outer ''inner'' outer' normal"`,
			attrName: "Arguments",
			expected: `outer' '''inner''' 'outer normal`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			submit := `
universe = vanilla
executable = /bin/echo
arguments = ` + tt.args + `
queue
`

			sf, err := ParseSubmitFile(strings.NewReader(submit))
			if err != nil {
				t.Fatalf("Failed to parse submit file: %v", err)
			}

			jobID := JobID{Cluster: 100, Proc: 0}
			ad, err := sf.MakeJobAd(jobID, map[string]string{})
			if err != nil {
				t.Fatalf("Failed to create job ad: %v", err)
			}

			// Get the specified attribute
			attrResult := ad.EvaluateAttr(tt.attrName)
			if attrResult.IsError() {
				t.Fatalf("Failed to get %s attribute: %v", tt.attrName, attrResult)
			}

			attrStr, err := attrResult.StringValue()
			if err != nil {
				t.Fatalf("%s attribute is not a string: %v", tt.attrName, err)
			}

			if attrStr != tt.expected {
				t.Errorf("%s mismatch:\nGot:      %q\nExpected: %q", tt.attrName, attrStr, tt.expected)
			}
		})
	}
}

// TestShortQueueRowInheritsClusterArguments pins what condor_submit does when a
// `queue ... from` row leaves a variable out and the arguments expand to
// nothing. SetArguments finds the chained cluster value and returns without
// writing, so the proc keeps proc 0's command line -- it does NOT get an empty
// one under the V2 attribute name. Verified against condor_submit -dry-run:
// with rows `1 7` and `2`, the proc 1 delta carries no Args or Arguments at all.
func TestShortQueueRowInheritsClusterArguments(t *testing.T) {
	sf, err := ParseSubmitFile(strings.NewReader(
		"executable = /bin/sh\nargs = $(Y)\nqueue A,Y from(1 7\n2\n)\n"))
	if err != nil {
		t.Fatalf("ParseSubmitFile: %v", err)
	}
	res, err := sf.Submit(1)
	if err != nil {
		t.Fatalf("Submit: %v", err)
	}
	if len(res.ProcAds) != 2 {
		t.Fatalf("got %d procs, want 2", len(res.ProcAds))
	}
	for i, ad := range res.ProcAds {
		got, _ := ad.EvaluateAttrString("Args")
		if got != "7" {
			t.Errorf("proc %d: Args = %q, want %q", i, got, "7")
		}
		if _, ok := ad.Lookup("Arguments"); ok {
			v, _ := ad.EvaluateAttrString("Arguments")
			t.Errorf("proc %d: has Arguments = %q; condor_submit writes none", i, v)
		}
	}
}
