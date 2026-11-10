//go:build libcondor_utils

package fuzzsubmit

import "testing"

// The skip has to be narrow or it is a hole: every input it accepts is one
// the fuzzer stops comparing, and the attribute it would have compared is
// whatever that submit file happened to set.
//
// The rejected cases below are the ones that decide that. A file ending in a
// newline is the normal case and is never skipped; a file ending `queue` with
// no newline is the common unterminated shape and has nothing to trim, so it
// is still compared; and whitespace anywhere but the two ends of the final
// line is not what the quirk touches.
func TestUntrimmedFinalLineIsNarrow(t *testing.T) {
	for _, tc := range []struct {
		name string
		src  string
		want bool
	}{
		// What the quirk reaches.
		{"trailing space, unterminated", "executable = a\noutput = o   ", true},
		{"leading space, unterminated", "executable = a\n   output = o", true},
		{"tab", "executable = a\noutput = o\t", true},
		{"a continuation that is the final line", "executable=0\\\n queue", true},
		{"the whole file is one indented line", "   executable = a", true},

		// What it must not.
		{"ends in a newline", "executable = a\noutput = o   \n", false},
		{"ends in a newline, indented last line", "executable = a\n   output = o\n", false},
		{"queue with nothing to trim", "executable = a\nqueue", false},
		{"no whitespace at either end", "executable = a\noutput = o", false},
		{"whitespace only in the middle", "executable = a\nbatch_name = a b", false},
		{"empty", "", false},
		{"a bare newline", "\n", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := untrimmedFinalLine(tc.src); got != tc.want {
				t.Errorf("untrimmedFinalLine(%q) = %v, want %v", tc.src, got, tc.want)
			}
		})
	}
}
