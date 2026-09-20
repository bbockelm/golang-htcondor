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
		t.Fatalf("no properties on the %s schema", tool.Name)
	}
	param, ok := props["wait_seconds"].(map[string]interface{})
	if !ok {
		t.Fatal("no wait_seconds parameter")
	}
	desc, _ := param["description"].(string)
	return desc
}

// TestAdviceSendsWaitingToCheckWatches: the division of labour is the whole
// point of the advice. watch_jobs is told to call once and cannot be called
// repeatedly without re-resolving the same watch, so an agent steered to wait
// there has no correct move for "is it done yet" and falls back to the polling
// loop these tools replace. Whatever the cap, waiting is check_watches.
func TestAdviceSendsWaitingToCheckWatches(t *testing.T) {
	for _, cap := range []int{20, 870} { // 870: the 15m hard stop less the reply margin
		t.Run(fmt.Sprintf("cap=%d", cap), func(t *testing.T) {
			tools := jobWatchTools(cap)
			watchDesc := findTool(t, tools, "watch_jobs").Description
			checkTool := findTool(t, tools, "check_watches")

			if !strings.Contains(watchDesc, "check_watches") {
				t.Errorf("watch_jobs does not name the tool that waits: %q", watchDesc)
			}
			for _, stale := range []string{"simplest thing to do", "Blocking is fine"} {
				if strings.Contains(watchDesc, stale) {
					t.Errorf("watch_jobs still offers its own wait as the normal way to wait (%q): %q", stale, watchDesc)
				}
			}
			if !strings.Contains(checkTool.Description, "wait_seconds") {
				t.Errorf("check_watches does not advertise that it can wait: %q", checkTool.Description)
			}
			props, _ := checkTool.InputSchema["properties"].(map[string]interface{})
			if _, ok := props["wait_seconds"]; !ok {
				t.Errorf("check_watches has no wait_seconds parameter: %+v", props)
			}
		})
	}
}

// TestAdviceRecommendsBelowTheCap: the cap is what this server honours, and
// the client in front of it has a shorter timeout this server cannot see. So
// the number the agent is told to USE is the conservative one, and the cap is
// only there for a caller that asks for it.
func TestAdviceRecommendsBelowTheCap(t *testing.T) {
	desc := waitParamDescription(t, findTool(t, jobWatchTools(870), "check_watches"))
	if !strings.Contains(desc, fmt.Sprintf("Use %d", RecommendedWaitSeconds)) {
		t.Errorf("check_watches does not recommend %ds under a 870s cap: %q", RecommendedWaitSeconds, desc)
	}
	if RecommendedWaitSeconds < 25 || RecommendedWaitSeconds > 45 {
		t.Errorf("the recommended wait is %ds; it has to come back well inside a client timeout of about a minute", RecommendedWaitSeconds)
	}
	// Every blocking knob carries the warning, since neither tool can see
	// what the caller is talking to it through.
	for _, name := range []string{"watch_jobs", "check_watches"} {
		if d := waitParamDescription(t, findTool(t, jobWatchTools(870), name)); !strings.Contains(d, "timeout of its own") {
			t.Errorf("%s does not warn that the transport may cut a long block off: %q", name, d)
		}
	}
	// Where the cap is tighter than the recommendation, the recommendation
	// follows it down rather than advising more than the server will give.
	if got := recommendedWait(5); got != 5 {
		t.Errorf("recommendedWait(5) = %d, want 5", got)
	}
}

// TestAdvertisedNumberIsTheCap guards the drift this is meant to prevent: the
// number an agent is given must be the number this server will honour, at
// every cap, in both the prose and the parameter -- on both tools that block.
func TestAdvertisedNumberIsTheCap(t *testing.T) {
	for _, cap := range []int{5, 20, 119, 120, 300, 870, 3600} {
		for _, name := range []string{"watch_jobs", "check_watches"} {
			t.Run(fmt.Sprintf("%s/cap=%d", name, cap), func(t *testing.T) {
				desc := waitParamDescription(t, findTool(t, jobWatchTools(cap), name))

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

// TestHumanizedCapAgreesWithTheNumber: the spoken cap in the strategy line and
// the digits in the parameter are the same cap, so an agent cannot be told
// "about 14 minutes" beside "max 20".
func TestHumanizedCapAgreesWithTheNumber(t *testing.T) {
	for _, cap := range []int{20, 870} {
		advice := waitAdvice(cap)
		if !strings.Contains(advice.Strategy, humanizeSeconds(cap)) {
			t.Errorf("watch_jobs strategy at cap %d does not speak the cap: %q", cap, advice.Strategy)
		}
		if !strings.Contains(checkAdvice(cap).Waiting, humanizeSeconds(cap)) {
			t.Errorf("check_watches advice at cap %d does not speak the cap: %q", cap, checkAdvice(cap).Waiting)
		}
	}
}
