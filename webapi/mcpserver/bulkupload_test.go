package mcpserver

import (
	"strings"
	"testing"
)

func TestParseUploadTargetAcceptsBothForms(t *testing.T) {
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
			got, err := parseUploadTarget(tt.in)
			if err != nil {
				t.Fatalf("parseUploadTarget(%q): %v", tt.in, err)
			}
			if got.cluster != tt.cluster || got.allProcs != tt.allProcs {
				t.Errorf("got %+v, want cluster=%d allProcs=%v", got, tt.cluster, tt.allProcs)
			}
			if !tt.allProcs && got.proc != tt.proc {
				t.Errorf("proc = %d, want %d", got.proc, tt.proc)
			}
		})
	}
}

func TestParseUploadTargetRejectsNonsense(t *testing.T) {
	// The message has to distinguish the two accepted shapes, because
	// "invalid job_id" alone does not tell a caller which one it meant.
	for _, in := range []string{"", "   ", "abc", "0", "-1", "1.x", "x.1", "1.2.3"} {
		t.Run(in, func(t *testing.T) {
			if _, err := parseUploadTarget(in); err == nil {
				t.Errorf("parseUploadTarget(%q) accepted a value it should not", in)
			}
		})
	}
}

func TestUploadNothingToDoIsNotAnError(t *testing.T) {
	// A cluster with nothing held for spooling is the state the caller
	// wanted. Returning an error would make a satisfied request look
	// failed, and an agent would retry it.
	res := uploadNothingToDo(42)
	meta := res["metadata"].(map[string]interface{})
	if meta["procs_spooled"] != 0 || meta["procs_remaining"] != 0 {
		t.Errorf("unexpected counts: %+v", meta)
	}
	text := res["content"].([]map[string]interface{})[0]["text"].(string)
	// It has to say why nothing happened, or the caller cannot tell this
	// from a silent failure.
	if !strings.Contains(text, "HoldReasonCode 16") {
		t.Errorf("the reason nothing was uploaded should be stated: %q", text)
	}
}

func TestSortedKeysIsDeterministic(t *testing.T) {
	// Failure lists go into a tool result an agent reads; unstable order
	// makes two identical outcomes look different.
	m := map[string]string{"9.2": "c", "9.10": "a", "9.1": "b"}
	got := sortedKeys(m)
	want := []string{"9.1", "9.10", "9.2"}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("sortedKeys = %v, want %v", got, want)
		}
	}
}
