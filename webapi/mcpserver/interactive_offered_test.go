package mcpserver

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
)

func sessionServer(t *testing.T, offered bool) *Server {
	t.Helper()
	s, err := NewServer(Config{
		ScheddName:                    "test",
		ScheddAddr:                    "127.0.0.1:9618",
		InteractiveSessionsNotOffered: !offered,
	})
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	return s
}

// The hole this closes: a site turns terminals off because its policy
// forbids interactive shells, and an agent starts one anyway through
// the other front door.
func TestStartIsWithheldWhereSessionsAreNotOffered(t *testing.T) {
	if !toolNames(sessionServer(t, true))["interactive_session_start"] {
		t.Skip("interactive_session_start is not in this build's catalogue")
	}

	got := toolNames(sessionServer(t, false))
	if got["interactive_session_start"] {
		t.Error("interactive_session_start is offered where the site offers no sessions")
	}
	// Only starting goes. An agent holding a session has to be able to
	// finish with it and stop it, or turning the setting off strands a
	// job nobody can reach.
	for _, name := range []string{"interactive_session_list", "interactive_session_exec", "interactive_session_stop"} {
		if !got[name] {
			t.Errorf("%s was withheld; only starting a session should be", name)
		}
	}
}

// Withholding it from the catalogue is not enough: a client can hold
// one from before the setting changed.
func TestStartIsRefusedWhereSessionsAreNotOffered(t *testing.T) {
	s := sessionServer(t, false)
	params, _ := json.Marshal(map[string]interface{}{
		"name":      "interactive_session_start",
		"arguments": map[string]interface{}{"session": "work"},
	})
	_, err := s.handleCallTool(context.Background(), params)
	if err == nil {
		t.Fatal("a session was started where the site offers none")
	}
	if !strings.Contains(err.Error(), "HTTP_API_INTERACTIVE_TERMINAL") {
		t.Errorf("error does not name the setting: %v", err)
	}
	// An agent mid-task must not read this as "your session is gone".
	if !strings.Contains(err.Error(), "already running can still be listed") {
		t.Errorf("error does not say existing sessions still work: %v", err)
	}
}

// A reconfigure reaches sessions already connected, and turning the
// setting back on restores the tool.
func TestInteractiveSessionsFollowReconfigure(t *testing.T) {
	s := sessionServer(t, true)
	if !toolNames(s)["interactive_session_start"] {
		t.Skip("interactive_session_start is not in this build's catalogue")
	}

	before := s.catalogGen.Load()
	s.SetInteractiveSessionsOffered(false)
	if toolNames(s)["interactive_session_start"] {
		t.Error("the tool survived a reconfigure that withdrew it")
	}
	if s.catalogGen.Load() == before {
		t.Error("the catalogue generation did not move, so cached SDK servers keep offering the tool")
	}

	s.SetInteractiveSessionsOffered(true)
	if !toolNames(s)["interactive_session_start"] {
		t.Error("turning sessions back on did not restore the tool")
	}
}

// Offered unless the site says otherwise: a Config built without
// thinking about this keeps serving what it served.
func TestInteractiveSessionsDefaultToOffered(t *testing.T) {
	if !sessionServer(t, true).interactiveSessionsOffered() {
		t.Error("a server built without the setting offers no sessions")
	}
}

// The same for a Server built as a literal, which several tests in this
// package do. Written the obvious way round, the zero value withholds
// interactive_session_start and those tests fail on a setting nobody
// set -- which is exactly what happened while this was being written.
func TestAZeroServerOffersSessions(t *testing.T) {
	var s Server
	if !s.interactiveSessionsOffered() {
		t.Error("a Server nobody configured offers no interactive sessions")
	}
}
