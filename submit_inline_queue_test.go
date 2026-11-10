package htcondor

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestExpandInlineQueueBlocks_Errors makes sure the pre-processor
// surfaces the classic broken-input cases instead of letting them
// trickle through as opaque "syntax error" from the goyacc layer.
//
// The companion test that walks the built-in web templates through this
// same parser lives in webapi/templates (it needs the templates library,
// which is part of the webapi module).
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
// hook lights up. Pre-pre-fix, the error was a bare "syntax error"; the
// new error includes the line and column of the offending character.
// The input is a parameter name with a '-' in it, which HTCondor's
// is_valid_param_name() rejects and so does this parser -- an unquoted
// path after `from` no longer serves, because that is an item file's
// name now, exactly as condor_submit reads it.
func TestParseErrorIncludesPosition(t *testing.T) {
	body := "executable = /bin/true\na-b = 1\nqueue\n"
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

// TestInlineQueueBlockTempPathWithSpace pins the mechanism the inline
// `((rows))` form depends on. The rows go to a temp file whose path is
// written back into the submit text after `from`, and everything after
// `from` is the item file's name verbatim -- so a path holding a space
// works, and must not be quoted, because quotes would become part of the
// name. Nothing else pins this: every temp path a developer's machine
// hands out happens to be space-free, so the old quoting and the new bare
// path are indistinguishable there.
func TestInlineQueueBlockTempPathWithSpace(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "a dir with spaces")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("TMPDIR", dir)
	if got := os.TempDir(); got != dir {
		t.Skipf("os.TempDir() does not follow TMPDIR here (got %q); nothing to pin", got)
	}

	raw := "executable = /bin/true\narguments = $(sample) $(events)\n" +
		"queue sample, events from ((\n  alpha, 100\n  beta, 200\n))\n"

	sf, err := ParseSubmitFile(strings.NewReader(raw))
	if err != nil {
		t.Fatalf("inline rows must parse when the temp path contains a space: %v", err)
	}
	if got := sf.QueueCount(); got != 2 {
		t.Errorf("QueueCount() = %d, want 2", got)
	}
	if got := sf.QueueVars(); len(got) != 2 || got[0] != "sample" || got[1] != "events" {
		t.Errorf("QueueVars() = %v, want [sample events]", got)
	}
}
