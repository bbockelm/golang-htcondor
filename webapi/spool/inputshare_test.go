package spool

import (
	"testing"

	"github.com/PelicanPlatform/classad/classad"
)

// ProcIDOf feeds every minted upload URL's cluster and proc. An ad it
// cannot read must be refused, not defaulted: a URL addressed to 0.0
// would point at a different job than the caller asked about.
func TestProcIDOf(t *testing.T) {
	ad, err := classad.Parse("[ ClusterId = 42; ProcId = 3 ]")
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	cluster, proc, ok := ProcIDOf(ad)
	if !ok || cluster != 42 || proc != 3 {
		t.Fatalf("ProcIDOf = (%d, %d, %v), want (42, 3, true)", cluster, proc, ok)
	}

	for _, missing := range []string{`[ ProcId = 3 ]`, `[ ClusterId = 42 ]`, `[ Owner = "alice" ]`} {
		bad, perr := classad.Parse(missing)
		if perr != nil {
			t.Fatalf("parse %s: %v", missing, perr)
		}
		if _, _, ok := ProcIDOf(bad); ok {
			t.Fatalf("ProcIDOf accepted %s", missing)
		}
	}
}

// AwaitingInput is the gate that really bounds an upload URL: a job that
// already spooled must refuse another upload however long its token has
// left to run.
func TestAwaitingInput(t *testing.T) {
	for _, tc := range []struct {
		name   string
		ad     string
		expect bool
	}{
		{"held for spooling", "[ JobStatus = 5; HoldReasonCode = 16 ]", true},
		{"held for something else", "[ JobStatus = 5; HoldReasonCode = 13 ]", false},
		{"idle", "[ JobStatus = 1; HoldReasonCode = 16 ]", false},
		{"running", "[ JobStatus = 2 ]", false},
		{"completed", "[ JobStatus = 4 ]", false},
		{"no status at all", "[ ClusterId = 1 ]", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ad, err := classad.Parse(tc.ad)
			if err != nil {
				t.Fatalf("parse %s: %v", tc.ad, err)
			}
			if got := AwaitingInput(ad); got != tc.expect {
				t.Fatalf("AwaitingInput(%s) = %v, want %v", tc.ad, got, tc.expect)
			}
		})
	}
	if AwaitingInput(nil) {
		t.Fatal("a nil ad reported as awaiting input")
	}
}

// The share projection must be a superset of the spool one: dropping an
// allow-set attribute from it puts files in the tar that the schedd
// silently discards.
func TestInputShareProjectionCoversTheSpoolProjection(t *testing.T) {
	have := make(map[string]bool, len(InputShareProjection))
	for _, a := range InputShareProjection {
		have[a] = true
	}
	for _, a := range InputSpoolProjection {
		if !have[a] {
			t.Fatalf("InputShareProjection is missing %q, which the allow-set reads", a)
		}
	}
	for _, a := range []string{"JobStatus", "HoldReasonCode"} {
		if !have[a] {
			t.Fatalf("InputShareProjection is missing %q, which AwaitingInput reads", a)
		}
	}
}
