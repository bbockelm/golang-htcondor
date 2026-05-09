package chat

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
)

// TestReadSSEMultipleToolUseInputsAreIndependent pins a real bug we
// hit on the submit page: when an assistant turn emitted two
// tool_use blocks back-to-back, the first tool's ToolInput slice
// aliased bytes.Buffer storage that the second tool's
// input_json_delta chunks then overwrote. The engine stored both
// events but only the second's bytes survived; json.Marshal of the
// first tool's input later failed with "internal: failed to encode
// chat record" once it tried to render to the SDK wire format.
//
// We pump a synthetic Anthropic SSE stream through readSSE and
// assert that BOTH emitted tool_use events still carry their
// originally-buffered input (i.e. the bytes were copied at emit
// time, not aliased).
func TestReadSSEMultipleToolUseInputsAreIndependent(t *testing.T) {
	stream := strings.Join([]string{
		`event: content_block_start`,
		`data: {"type":"content_block_start","index":0,"content_block":{"type":"tool_use","id":"toolu_A","name":"set_template_body"}}`,
		``,
		`event: content_block_delta`,
		`data: {"type":"content_block_delta","index":0,"delta":{"type":"input_json_delta","partial_json":"{\"contents\":\"executable = /bin/echo\\nqueue 1\"}"}}`,
		``,
		`event: content_block_stop`,
		`data: {"type":"content_block_stop","index":0}`,
		``,
		`event: content_block_start`,
		`data: {"type":"content_block_start","index":1,"content_block":{"type":"tool_use","id":"toolu_B","name":"set_resources"}}`,
		``,
		`event: content_block_delta`,
		`data: {"type":"content_block_delta","index":1,"delta":{"type":"input_json_delta","partial_json":"{\"cpus\":4,\"memory_mb\":8192}"}}`,
		``,
		`event: content_block_stop`,
		`data: {"type":"content_block_stop","index":1}`,
		``,
		`event: message_delta`,
		`data: {"type":"message_delta","delta":{"stop_reason":"tool_use"}}`,
		``,
		`event: message_stop`,
		`data: {"type":"message_stop"}`,
		``,
	}, "\n")

	out := make(chan StreamEvent, 16)
	readSSE(context.Background(), strings.NewReader(stream), out)
	close(out)

	var toolUses []StreamEvent
	for ev := range out {
		if ev.Kind == "tool_use" {
			toolUses = append(toolUses, ev)
		}
	}
	if len(toolUses) != 2 {
		t.Fatalf("got %d tool_use events, want 2: %+v", len(toolUses), toolUses)
	}

	// (a) IDs and names came through correctly.
	if toolUses[0].ToolUseID != "toolu_A" || toolUses[0].ToolName != "set_template_body" {
		t.Errorf("tool[0] ident mismatch: %+v", toolUses[0])
	}
	if toolUses[1].ToolUseID != "toolu_B" || toolUses[1].ToolName != "set_resources" {
		t.Errorf("tool[1] ident mismatch: %+v", toolUses[1])
	}

	// (b) Both inputs are independently parseable as JSON. With the
	// aliasing bug the first slice would either re-decode as the
	// second tool's input or fail entirely.
	var first map[string]any
	if err := json.Unmarshal(toolUses[0].ToolInput, &first); err != nil {
		t.Fatalf("tool[0] input not valid JSON (aliasing bug?): %v; bytes=%s", err, toolUses[0].ToolInput)
	}
	if got, ok := first["contents"].(string); !ok || !strings.Contains(got, "/bin/echo") {
		t.Errorf("tool[0] input lost original payload: %v", first)
	}

	var second map[string]any
	if err := json.Unmarshal(toolUses[1].ToolInput, &second); err != nil {
		t.Fatalf("tool[1] input not valid JSON: %v; bytes=%s", err, toolUses[1].ToolInput)
	}
	if cpus, _ := second["cpus"].(float64); cpus != 4 {
		t.Errorf("tool[1] input wrong cpus: %v", second)
	}

	// (c) The two tools' input slices must NOT alias the same memory
	// — that's the precondition that made the bug latent. Direct
	// pointer compare via &slice[0] catches the regression.
	if len(toolUses[0].ToolInput) > 0 && len(toolUses[1].ToolInput) > 0 &&
		&toolUses[0].ToolInput[0] == &toolUses[1].ToolInput[0] {
		t.Errorf("tool[0] and tool[1] inputs share backing memory")
	}
}
