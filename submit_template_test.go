package htcondor

import (
	"strings"
	"testing"

	"github.com/bbockelm/golang-htcondor/templates"
)

// TestBuiltinTemplatesParseAndExpand walks every built-in batch
// template and proves it round-trips through the same path the web
// UI's /submit page exercises:
//
//  1. Take template.Contents (the submit-file body without queue).
//  2. Append `queue COLS from ((rows))` — the inline form the
//     frontend's buildSubmitFile() emits.
//  3. ParseSubmitFile must succeed (no goyacc "syntax error").
//  4. submitFile.Submit() must produce one proc per row.
//  5. Each row's variable substitutions must land in the expected
//     attribute (e.g. sleep's $(seconds) → Args).
//
// This is the regression-guard for the inline-`((...))` pre-processor
// in submit.go and for the built-in YAML staying parser-clean.
func TestBuiltinTemplatesParseAndExpand(t *testing.T) {
	lib, err := templates.NewLibrary(templates.LibraryConfig{})
	if err != nil {
		t.Fatalf("templates.NewLibrary: %v", err)
	}
	t.Cleanup(func() { _ = lib.Close() })

	all := lib.All("")
	if len(all) == 0 {
		t.Fatalf("expected built-in templates, got 0")
	}

	// Sample row data per template id. Built-in templates have
	// well-known column names so the test can pre-populate sensible
	// values; new templates without an entry below get a single row
	// of placeholders so they still get covered (loosely).
	sampleRows := map[string][][]string{
		"hello-world": {{"alice"}, {"bob"}, {"carol"}},
		"sleep":       {{"5"}, {"30"}, {"60"}},
	}

	for _, tpl := range all {
		t.Run(tpl.ID, func(t *testing.T) {
			rows, ok := sampleRows[tpl.ID]
			if !ok {
				// Default coverage: one row of placeholders so we
				// still exercise the parse+expand path even for
				// templates the test hasn't been taught about yet.
				row := make([]string, len(tpl.Columns))
				for i := range row {
					row[i] = "x"
				}
				rows = [][]string{row}
			}

			body := buildBatchSubmitFile(tpl, rows)
			t.Logf("synthesized submit file:\n%s", body)

			sf, err := ParseSubmitFile(strings.NewReader(body))
			if err != nil {
				t.Fatalf("ParseSubmitFile: %v\n--- body ---\n%s", err, body)
			}

			res, err := sf.Submit(42) // arbitrary cluster id
			if err != nil {
				t.Fatalf("submitFile.Submit: %v", err)
			}
			if len(res.ProcAds) != len(rows) {
				t.Fatalf("expected %d procs (one per row), got %d",
					len(rows), len(res.ProcAds))
			}

			// Spot-check the expected substitutions per template.
			switch tpl.ID {
			case "hello-world":
				// The submit parser converts HTCondor's "new"
				// arguments form back into the "old" Args quoting
				// (using `' '` between args). The starter decodes
				// that back to argv at job-run time. We only need
				// to assert the per-row substitution actually
				// landed in the attribute somewhere.
				for i, ad := range res.ProcAds {
					args, _ := ad.EvaluateAttrString("Args")
					if args == "" {
						args, _ = ad.EvaluateAttrString("Arguments")
					}
					if !strings.Contains(args, rows[i][0]) {
						t.Errorf("proc %d: arguments=%q does not contain row value %q",
							i, args, rows[i][0])
					}
				}
			case "sleep":
				for i, ad := range res.ProcAds {
					args, _ := ad.EvaluateAttrString("Args")
					if args != rows[i][0] {
						t.Errorf("proc %d: Args=%q want %q", i, args, rows[i][0])
					}
				}
			}
		})
	}
}

// TestExpandInlineQueueBlocks_Errors makes sure the pre-processor
// surfaces the classic broken-input cases instead of letting them
// trickle through as opaque "syntax error" from the goyacc layer.
func TestExpandInlineQueueBlocks_Errors(t *testing.T) {
	cases := []struct {
		name      string
		body      string
		wantInErr string
	}{
		{
			name:      "unterminated-block",
			body:      "queue x from ((\n  1\n  2\n", // no closing ))
			wantInErr: "unterminated 'queue ... from ((",
		},
		{
			name:      "empty-block",
			body:      "queue x from ((\n))\n",
			wantInErr: "no rows",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := ParseSubmitFile(strings.NewReader(tc.body))
			if err == nil {
				t.Fatalf("expected error, got nil")
			}
			if !strings.Contains(err.Error(), tc.wantInErr) {
				t.Errorf("error %q does not contain %q", err.Error(), tc.wantInErr)
			}
		})
	}
}

// TestParseErrorIncludesPosition confirms the line/col-aware Error()
// hook lights up. Asks the parser to consume `from /raw/path` outside
// the inline-block pre-processor's notice (we emit it directly as a
// queue line so there's no `((` to trigger expansion). Pre-pre-fix,
// the error was a bare "syntax error"; the new error includes the
// line and column of the offending `/`.
func TestParseErrorIncludesPosition(t *testing.T) {
	body := "executable = /bin/true\nqueue x from /raw/path\n"
	_, err := ParseSubmitFile(strings.NewReader(body))
	if err == nil {
		t.Fatalf("expected parse error, got nil")
	}
	msg := err.Error()
	if !strings.Contains(msg, "line ") {
		t.Errorf("expected line number in error, got: %s", msg)
	}
	if !strings.Contains(msg, "col ") {
		t.Errorf("expected column number in error, got: %s", msg)
	}
}

// buildBatchSubmitFile is the Go-side mirror of the frontend's
// buildSubmitFile: append a `queue cols from ((<rows>))` block to the
// template body. We intentionally produce the exact form the SPA
// emits so this test catches drift in either direction.
func buildBatchSubmitFile(tpl templates.Template, rows [][]string) string {
	body := strings.TrimRight(tpl.Contents, " \t\n")
	if len(tpl.Columns) == 0 {
		return body + "\nqueue\n"
	}
	var sb strings.Builder
	sb.WriteString(body)
	sb.WriteString("\nqueue ")
	sb.WriteString(strings.Join(tpl.Columns, ", "))
	sb.WriteString(" from ((\n")
	for _, r := range rows {
		sb.WriteString("  ")
		sb.WriteString(strings.Join(r, " "))
		sb.WriteByte('\n')
	}
	sb.WriteString("))\n")
	return sb.String()
}
