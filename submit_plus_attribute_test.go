// Test for submit file parsing with + prefix attributes
package htcondor

import (
	"strings"
	"testing"
)

// TestSubmitWithPlusAttribute tests parsing submit files with + prefix attributes
func TestSubmitWithPlusAttribute(t *testing.T) {
	tests := []struct {
		name          string
		submitFile    string
		expectedCount int
		wantError     bool
	}{
		{
			name: "queue 3 with + attribute",
			submitFile: `
universe = vanilla
executable = /bin/sleep
arguments = 300
+MyTestTag = "bulk_test"
queue 3
`,
			expectedCount: 3,
			wantError:     false,
		},
		{
			name: "queue 1 with + attribute",
			submitFile: `
universe = vanilla
executable = /bin/sleep
arguments = 300
+CustomAttr = "test"
queue
`,
			expectedCount: 1,
			wantError:     false,
		},
		{
			name: "queue 5 without + attribute",
			submitFile: `
universe = vanilla
executable = /bin/sleep
arguments = 300
MyTestTag = "bulk_test"
queue 5
`,
			expectedCount: 5,
			wantError:     false,
		},
		{
			name: "multiple + attributes with queue 2",
			submitFile: `
universe = vanilla
executable = /bin/sleep
arguments = 300
+Attr1 = "value1"
+Attr2 = "value2"
+Attr3 = 123
queue 2
`,
			expectedCount: 2,
			wantError:     false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Parse the submit file
			submitFile, err := ParseSubmitFile(strings.NewReader(tt.submitFile))

			if tt.wantError {
				if err == nil {
					t.Errorf("ParseSubmitFile() expected error but got none")
				}
				return
			}

			if err != nil {
				t.Fatalf("ParseSubmitFile() error = %v, wantError %v", err, tt.wantError)
			}

			// Generate job ads
			clusterID := 1
			submitResult, err := submitFile.Submit(clusterID)
			if err != nil {
				t.Fatalf("Submit() error = %v", err)
			}

			// Check the number of procs generated
			if len(submitResult.ProcAds) != tt.expectedCount {
				t.Errorf("Submit() generated %d proc ads, want %d", len(submitResult.ProcAds), tt.expectedCount)
				t.Logf("Submit file content:\n%s", tt.submitFile)
			}

			t.Logf("✓ Successfully parsed and generated %d proc ads", len(submitResult.ProcAds))
		})
	}
}
