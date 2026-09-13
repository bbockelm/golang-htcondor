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
		// wantAttrs is what each generated proc ad must carry, as
		// attribute name -> ClassAd rendering of the value. This is the
		// half the test used to be missing: it checked only how many
		// proc ads came out, so it passed just as happily while every
		// + attribute was being silently dropped on the floor.
		wantAttrs map[string]string
		wantError bool
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
			wantAttrs:     map[string]string{"MyTestTag": `"bulk_test"`},
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
			wantAttrs:     map[string]string{"CustomAttr": `"test"`},
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
			// No '+' here: MyTestTag is an ordinary submit macro, and
			// an ordinary macro must NOT land on the job ad. This is
			// the case that keeps the fix honest in the other
			// direction.
			wantAttrs: map[string]string{"MyTestTag": ""},
			wantError: false,
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
			wantAttrs: map[string]string{
				"Attr1": `"value1"`,
				"Attr2": `"value2"`,
				"Attr3": "123",
			},
			wantError: false,
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

			// Every proc carries the cluster's custom attributes.
			for i, ad := range submitResult.ProcAds {
				for attr, want := range tt.wantAttrs {
					expr, ok := ad.Lookup(attr)
					if want == "" {
						if ok {
							t.Errorf("proc %d: ad has %s = %s; a submit macro without '+' must not become a job attribute",
								i, attr, expr.String())
						}
						continue
					}
					if !ok {
						t.Errorf("proc %d: ad is missing %s (want %s)\nad: %s", i, attr, want, ad.String())
						continue
					}
					if got := expr.String(); got != want {
						t.Errorf("proc %d: %s = %s, want %s", i, attr, got, want)
					}
				}
			}
		})
	}
}
