package main

import "testing"

// TestValidateDurationHasUnit pins the contract that token lifespan config
// values must include a unit suffix. The motivating bug: a bare number like
// "300" gets treated as nanoseconds by some Go duration parsers, producing a
// 300ns token lifetime that expires before the response leaves the server.
// We reject unit-less input explicitly rather than letting it through.
func TestValidateDurationHasUnit(t *testing.T) {
	cases := []struct {
		in      string
		wantErr bool
	}{
		// Accepted: every valid Go time unit.
		{"1ns", false},
		{"500us", false},
		{"500µs", false},
		{"100ms", false},
		{"30s", false},
		{"5m", false},
		{"1h", false},
		{"168h", false},
		{"2h45m", false},  // compound durations
		{"  1h  ", false}, // surrounding whitespace tolerated
		// Rejected: unit-less and empty.
		{"", true},
		{"   ", true},
		{"300", true},    // plausible mistake — operator means seconds, Go would say ns
		{"3600", true},   // same
		{"1.5", true},    // floating point without unit
		{"abc", true},    // garbage
		{"1d", true},     // "d" looks like a unit but Go duration doesn't have days
		{"1w", true},     // same for weeks
		{"1 hour", true}, // human-readable, not Go syntax
	}
	for _, tc := range cases {
		err := validateDurationHasUnit(tc.in)
		if tc.wantErr && err == nil {
			t.Errorf("validateDurationHasUnit(%q) = nil, want error", tc.in)
		}
		if !tc.wantErr && err != nil {
			t.Errorf("validateDurationHasUnit(%q) = %v, want nil", tc.in, err)
		}
	}
}
