package mcpserver

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
)

// TestEveryToolIsNamedInTheInstructions: the instructions are what a
// model reads to decide which tool to reach for, so a tool missing from
// them is a tool it will not use. tail_job_output and exec_in_job both
// shipped that way -- listed in tools/list, absent from the prose --
// and the complaint that came back was that they did not exist.
//
// Asserting over the live catalog rather than a hand-kept list is the
// point: the next tool added inherits the check.
func TestEveryToolIsNamedInTheInstructions(t *testing.T) {
	s := &Server{}
	body, err := json.Marshal(s.handleListTools(context.Background(), nil))
	if err != nil {
		t.Fatalf("tools/list: %v", err)
	}
	var parsed struct {
		Tools []struct {
			Name string `json:"name"`
		} `json:"tools"`
	}
	if err := json.Unmarshal(body, &parsed); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if len(parsed.Tools) == 0 {
		t.Fatal("the catalog came back empty; this test would pass vacuously")
	}

	instructions := defaultInstructions("test_schedd")
	var missing []string
	for _, tool := range parsed.Tools {
		if !strings.Contains(instructions, tool.Name) {
			missing = append(missing, tool.Name)
		}
	}
	if len(missing) > 0 {
		t.Errorf("registered but never named in the instructions, so a model will not reach for them: %v", missing)
	}
}
