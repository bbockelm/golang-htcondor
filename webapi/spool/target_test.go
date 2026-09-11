package spool

import "testing"

func TestParseTargetAcceptsBothForms(t *testing.T) {
	tests := []struct {
		in       string
		cluster  int
		proc     int
		allProcs bool
	}{
		{"123.0", 123, 0, false},
		{"123.4", 123, 4, false},
		// A bare cluster id was an error before, so this adds a meaning
		// rather than changing one.
		{"123", 123, 0, true},
		{"  123  ", 123, 0, true},
	}
	for _, tt := range tests {
		t.Run(tt.in, func(t *testing.T) {
			got, err := ParseTarget(tt.in)
			if err != nil {
				t.Fatalf("ParseTarget(%q): %v", tt.in, err)
			}
			if got.Cluster != tt.cluster || got.AllProcs != tt.allProcs {
				t.Errorf("got %+v, want cluster=%d allProcs=%v", got, tt.cluster, tt.allProcs)
			}
			if !tt.allProcs && got.Proc != tt.proc {
				t.Errorf("proc = %d, want %d", got.Proc, tt.proc)
			}
		})
	}
}

func TestParseTargetRejectsNonsense(t *testing.T) {
	// The message has to distinguish the two accepted shapes, because
	// "invalid job_id" alone does not tell a caller which one it meant.
	for _, in := range []string{"", "   ", "abc", "0", "-1", "1.x", "x.1", "1.2.3"} {
		t.Run(in, func(t *testing.T) {
			if _, err := ParseTarget(in); err == nil {
				t.Errorf("ParseTarget(%q) accepted a value it should not", in)
			}
		})
	}
}
