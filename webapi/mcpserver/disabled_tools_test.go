package mcpserver

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
)

func disabledToolsServer(t *testing.T, spec string) *Server {
	t.Helper()
	s, err := NewServer(Config{
		ScheddName:    "test",
		ScheddAddr:    "127.0.0.1:9618",
		DisabledTools: spec,
	})
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	return s
}

func toolNames(s *Server) map[string]bool {
	out := map[string]bool{}
	for _, t := range s.toolsFor(context.Background()) {
		out[t.Name] = true
	}
	return out
}

// The case this exists for: a site whose policy forbids
// condor_ssh_to_job cannot offer the tools built on it, however the pool
// is configured.
func TestDisabledToolsAreNotOffered(t *testing.T) {
	all := toolNames(disabledToolsServer(t, ""))
	if !all["exec_in_job"] {
		t.Skip("exec_in_job is not in this build's catalogue")
	}

	got := toolNames(disabledToolsServer(t, "exec_in_job"))
	if got["exec_in_job"] {
		t.Error("a disabled tool is still offered")
	}
	// Only the named tool goes; withdrawing one must not withdraw the
	// rest of the catalogue.
	if len(got) != len(all)-1 {
		t.Errorf("catalogue went from %d tools to %d, want %d", len(all), len(got), len(all)-1)
	}
}

// Globs, so a family can go in one setting rather than the operator
// tracking every tool this server might add to it later.
func TestDisabledToolsAcceptGlobs(t *testing.T) {
	all := toolNames(disabledToolsServer(t, ""))
	var sessionTools int
	for name := range all {
		if strings.HasPrefix(name, "interactive_session_") {
			sessionTools++
		}
	}
	if sessionTools == 0 {
		t.Skip("no interactive_session_* tools in this build's catalogue")
	}

	got := toolNames(disabledToolsServer(t, "interactive_session_*"))
	for name := range got {
		if strings.HasPrefix(name, "interactive_session_") {
			t.Errorf("%s survived the glob", name)
		}
	}
	if len(got) != len(all)-sessionTools {
		t.Errorf("the glob removed %d tools, want %d", len(all)-len(got), sessionTools)
	}
}

// Hiding a tool is not disabling it. A client can hold a catalogue from
// before the setting changed -- the SDK transport caches one per scope
// set -- and an agent can name a tool it read about anywhere, so the
// call has to be refused too.
func TestDisabledToolCannotBeCalled(t *testing.T) {
	s := disabledToolsServer(t, "exec_in_job")
	params, _ := json.Marshal(map[string]interface{}{
		"name":      "exec_in_job",
		"arguments": map[string]interface{}{"job_id": "1.0", "command": "hostname"},
	})
	_, err := s.handleCallTool(context.Background(), params)
	if err == nil {
		t.Fatal("a disabled tool was dispatched")
	}
	// The message has to name the setting, because the person who can
	// undo this is reading the agent's transcript, and has to say the
	// tool is gone rather than failing -- an agent told "denied" retries.
	if !strings.Contains(err.Error(), "HTTP_API_MCP_DISABLED_TOOLS") {
		t.Errorf("error does not name the setting: %v", err)
	}
	if !strings.Contains(err.Error(), "do not retry") {
		t.Errorf("error does not tell the agent to stop: %v", err)
	}
}

// Reconfigure is the point of the knob: a tool withdrawn because policy
// changed has to stop working without waiting for agents to reconnect,
// and one restored has to come back.
func TestDisabledToolsFollowReconfigure(t *testing.T) {
	s := disabledToolsServer(t, "")
	if !toolNames(s)["exec_in_job"] {
		t.Skip("exec_in_job is not in this build's catalogue")
	}

	before := s.catalogGen.Load()
	s.SetDisabledTools("exec_in_job")
	if toolNames(s)["exec_in_job"] {
		t.Error("the tool survived a reconfigure that disabled it")
	}
	// The SDK transport caches a built server per scope set, keyed on
	// this generation. Without a bump the setting changes what this
	// server answers and not what most callers are served.
	if s.catalogGen.Load() == before {
		t.Error("the catalogue generation did not move, so cached SDK servers keep the old tool list")
	}

	s.SetDisabledTools("")
	if !toolNames(s)["exec_in_job"] {
		t.Error("clearing the setting did not restore the tool")
	}
}

func TestParseDisabledTools(t *testing.T) {
	for _, tc := range []struct {
		name string
		spec string
		want []string
		bad  int
	}{
		// HTCondor configuration is written both ways, and a list that
		// honoured only one would look like the setting had not taken.
		{"commas", "a, b,c", []string{"a", "b", "c"}, 0},
		{"whitespace", "a b\tc", []string{"a", "b", "c"}, 0},
		{"mixed with blanks", " a , , b ", []string{"a", "b"}, 0},
		{"empty", "", nil, 0},
		// A pattern path.Match cannot parse matches nothing, which is
		// indistinguishable from "your tool is disabled" unless it is
		// reported. It must not take the valid patterns down with it.
		{"malformed is dropped, not fatal", "exec_in_job, [bad", []string{"exec_in_job"}, 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, bad := parseDisabledTools(tc.spec)
			if strings.Join(got, ",") != strings.Join(tc.want, ",") {
				t.Errorf("patterns = %v, want %v", got, tc.want)
			}
			if len(bad) != tc.bad {
				t.Errorf("bad patterns = %v, want %d", bad, tc.bad)
			}
		})
	}
}
