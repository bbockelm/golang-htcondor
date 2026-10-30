package htcondor

import (
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
