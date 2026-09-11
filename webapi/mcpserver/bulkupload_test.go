package mcpserver

import (
	"strings"
	"testing"
)

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
