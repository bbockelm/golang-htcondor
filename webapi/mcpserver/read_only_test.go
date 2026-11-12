package mcpserver

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
)

func readOnlyServer(t *testing.T, on bool) *Server {
	t.Helper()
	s, err := NewServer(Config{
		ScheddName: "test",
		ScheddAddr: "127.0.0.1:9618",
		ReadOnly:   on,
	})
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	return s
}

// What the setting is for: everything that only looks is still offered,
// and everything that acts is gone.
func TestReadOnlyOffersOnlyTheReadTools(t *testing.T) {
	full := toolNames(readOnlyServer(t, false))
	got := toolNames(readOnlyServer(t, true))

	if len(got) == 0 {
		t.Fatal("read-only withheld the entire catalogue; it is meant to leave the read tools")
	}
	for name := range got {
		if !readOnlyMCPTools[name] {
			t.Errorf("%s is offered read-only but is not in the read-only classification", name)
		}
	}
	// Every read tool the server would otherwise have offered survives.
	// Withholding one would make the setting cost the user something
	// they were already entitled to.
	for name := range full {
		if readOnlyMCPTools[name] && !got[name] {
			t.Errorf("%s is read-only but was withheld", name)
		}
	}
	if len(got) == len(full) {
		t.Error("read-only withheld nothing, so the catalogue has no write tools to withhold or the gate did not run")
	}
}

// The gap this closes. A forwarded HTCondor IDTOKEN is deliberately
// unscoped -- HTCondor gates it instead -- so the mcp:read scope never
// applies to it and no group policy reaches it. The site's own decision
// has to.
func TestReadOnlyRefusesAnUnscopedCaller(t *testing.T) {
	s := readOnlyServer(t, true)
	if toolNames(s)["submit_job"] {
		t.Fatal("submit_job is offered on a read-only server")
	}

	params, _ := json.Marshal(map[string]interface{}{
		"name":      "submit_job",
		"arguments": map[string]interface{}{"submit_file": "executable = /bin/true\nqueue\n"},
	})
	// context.Background() is the unscoped grant: stdio, or a forwarded
	// HTCondor token. It sees the whole catalogue by design, which is
	// exactly why the refusal cannot live in the scope filter.
	_, err := s.handleCallTool(context.Background(), params)
	if err == nil {
		t.Fatal("a write tool was dispatched on a read-only server")
	}
	// The operator reading the agent's transcript is the one who can
	// change this, so the message names the setting; and the agent has
	// to be told the call will never work, or it tries again with
	// whatever else it holds.
	if !strings.Contains(err.Error(), "HTTP_API_MCP_READ_ONLY") {
		t.Errorf("error does not name the setting: %v", err)
	}
	if !strings.Contains(err.Error(), "no scope, token or retry") {
		t.Errorf("error does not tell the agent its credentials are not the problem: %v", err)
	}
}

// A read tool is dispatched normally: the gate must not be a blanket
// refusal of everything.
func TestReadOnlyStillDispatchesAReadTool(t *testing.T) {
	s := readOnlyServer(t, true)
	params, _ := json.Marshal(map[string]interface{}{
		"name":      "get_version",
		"arguments": map[string]interface{}{},
	})
	if _, err := s.handleCallTool(context.Background(), params); err != nil {
		t.Fatalf("get_version was refused on a read-only server: %v", err)
	}
}

// The setting is dynamic for the moment it is most likely to be reached
// for: an agent has just done something unexpected, and the answer must
// not be "restart the daemon".
func TestReadOnlyFollowsReconfigure(t *testing.T) {
	s := readOnlyServer(t, false)
	if !toolNames(s)["submit_job"] {
		t.Skip("submit_job is not in this build's catalogue")
	}

	before := s.catalogGen.Load()
	s.SetReadOnly(true)
	if toolNames(s)["submit_job"] {
		t.Error("submit_job survived a reconfigure that made the server read-only")
	}
	// The SDK transport caches a built server per scope set, keyed on
	// this generation; without a bump the setting changes what this
	// server answers and not what most callers are served.
	if s.catalogGen.Load() == before {
		t.Error("the catalogue generation did not move, so cached SDK servers keep offering the write tools")
	}

	s.SetReadOnly(false)
	if !toolNames(s)["submit_job"] {
		t.Error("clearing the setting did not restore the write tools")
	}
}

// Off by default: a Config built without thinking about this -- in a
// test, or by a caller written before the field existed -- serves what
// it always served.
func TestReadOnlyDefaultsOff(t *testing.T) {
	if readOnlyServer(t, false).ReadOnly() {
		t.Error("a server built without the setting is read-only")
	}
}
