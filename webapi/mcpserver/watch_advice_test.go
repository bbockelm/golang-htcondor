package mcpserver

import (
	"fmt"
	"strings"
	"testing"
)

// findTool returns the named tool from a catalogue slice.
func findTool(t *testing.T, tools []Tool, name string) Tool {
	t.Helper()
	for _, tool := range tools {
		if tool.Name == name {
			return tool
		}
	}
	t.Fatalf("tool %q not in the catalogue", name)
	return Tool{}
}

func waitParamDescription(t *testing.T, tool Tool) string {
	t.Helper()
	props, ok := tool.InputSchema["properties"].(map[string]interface{})
	if !ok {
		t.Fatal("no properties on the watch_jobs schema")
	}
	param, ok := props["wait_seconds"].(map[string]interface{})
	if !ok {
		t.Fatal("no wait_seconds parameter")
	}
	desc, _ := param["description"].(string)
	return desc
}

// TestAdviceMatchesTheCap: the advice has to change with the cap, because the
// same sentence cannot be right at twenty seconds and at fifteen minutes. A
// short cap means block only for something imminent; a long one means blocking
// is the simple path and check_watches is for going beyond it.
func TestAdviceMatchesTheCap(t *testing.T) {
	short := jobWatchTools(20)
	long := jobWatchTools(870) // the 15m hard stop less the reply margin

	shortDesc := findTool(t, short, "watch_jobs").Description
	longDesc := findTool(t, long, "watch_jobs").Description

	if !strings.Contains(shortDesc, "imminently") {
		t.Errorf("a 20s cap does not warn that blocking is only for imminent events: %q", shortDesc)
	}
	if !strings.Contains(longDesc, "simplest thing to do") {
		t.Errorf("a 14m30s cap does not offer blocking as the simple path: %q", longDesc)
	}
	if strings.Contains(longDesc, "returns immediately;") {
		t.Errorf("a long cap still tells the agent this tool returns immediately: %q", longDesc)
	}
	// Whatever the cap, collecting later must remain on offer: it is the
	// only answer for a wait longer than any cap.
	for _, d := range []string{shortDesc, longDesc} {
		if !strings.Contains(d, "check_watches") {
			t.Errorf("advice does not mention check_watches: %q", d)
		}
	}
}

// TestAdvertisedNumberIsTheCap guards the drift this is meant to prevent: the
// number an agent is given must be the number the transport will honour, at
// every cap, in both the prose and the parameter.
func TestAdvertisedNumberIsTheCap(t *testing.T) {
	for _, cap := range []int{5, 20, 119, 120, 300, 870, 3600} {
		t.Run(fmt.Sprintf("cap=%d", cap), func(t *testing.T) {
			tools := jobWatchTools(cap)
			tool := findTool(t, tools, "watch_jobs")
			desc := waitParamDescription(t, tool)

			if !strings.Contains(desc, fmt.Sprintf("max %d", cap)) {
				t.Errorf("wait_seconds does not advertise the cap %d: %q", cap, desc)
			}
			// No stale number from another tier.
			for _, other := range []int{5, 20, 120, 870} {
				if other == cap {
					continue
				}
				if strings.Contains(desc, fmt.Sprintf("max %d", other)) {
					t.Errorf("wait_seconds advertises %d as well as %d: %q", other, cap, desc)
				}
			}
		})
	}
}

// TestHumanizeSeconds: the spoken form has to agree with the number beside it.
func TestHumanizeSeconds(t *testing.T) {
	cases := []struct {
		secs int
		want string
	}{
		{20, "20 seconds"},
		{89, "89 seconds"},
		{90, "1 minute 30 seconds"},
		{120, "2 minutes"},
		{60, "60 seconds"}, // still seconds: below the 90s cutover
		{870, "14 minutes 30 seconds"},
		{0, "no time at all"},
	}
	for _, tc := range cases {
		if got := humanizeSeconds(tc.secs); got != tc.want {
			t.Errorf("humanizeSeconds(%d) = %q, want %q", tc.secs, got, tc.want)
		}
	}
}

// TestAdviceTierBoundary pins where the advice flips, so moving it is a
// deliberate edit rather than a side effect.
func TestAdviceTierBoundary(t *testing.T) {
	below := waitAdvice(119)
	at := waitAdvice(120)

	if !strings.Contains(below.WaitParam, "only when you expect it imminently") {
		t.Errorf("119s should still be the cautious tier: %q", below.WaitParam)
	}
	if !strings.Contains(at.WaitParam, "Blocking is fine") {
		t.Errorf("120s should be the blocking-is-primary tier: %q", at.WaitParam)
	}
}
