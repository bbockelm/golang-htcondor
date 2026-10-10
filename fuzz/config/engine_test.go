package fuzzconfig

import "testing"

// TestReadsHost pins the guard that keeps fuzz inputs from making the Go
// engine read host files or run commands. It needs no oracle.
func TestReadsHost(t *testing.T) {
	for _, tc := range []struct {
		in   string
		want bool
	}{
		{"FOO = bar\n", false},
		{"INCLUDE_DIR = /etc\n", false},
		{"include : /etc/passwd\n", true},
		{"include ifexist : /nonexistent\n", true},
		{"include command : /bin/true\n", true},
		{"if true\n  include : /etc/passwd\nendif\n", true},
		{"if false\nelse\n  include : /etc/passwd\nendif\n", true},
	} {
		if got := ReadsHost(Prelude(tc.in)); got != tc.want {
			t.Errorf("ReadsHost(%q) = %v, want %v", tc.in, got, tc.want)
		}
	}
}
