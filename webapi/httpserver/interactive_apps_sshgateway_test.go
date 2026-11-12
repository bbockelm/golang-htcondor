package httpserver

import (
	"maps"
	"strings"
	"testing"
)

// The third front door, and the one easiest to leave open: `ssh` to the
// gateway makes a session for a user who has none, without touching any
// of the REST routes the other two gates sit on.
func TestSSHGatewayStartsNoTerminalWhereNoneAreOffered(t *testing.T) {
	s := newInteractiveServer(t, "USER alice@d "+ap1+"\n", nil)
	s.srv.interactive.set(appTerminal, false)

	before := s.aps.counts()
	_, err := s.srv.sshGatewayResolve(s.callerCtx(t), "alice", gatewayTarget(t, s, "+work"), nil)
	if err == nil {
		t.Fatal("ssh started a session where the site offers none")
	}
	if !strings.Contains(err.Error(), "HTTP_API_INTERACTIVE_TERMINAL") {
		t.Errorf("the error does not name the setting: %v", err)
	}
	// The refusal has to be before the submit, not after it: a job
	// created and then disowned is the worst of both.
	if after := s.aps.counts(); !maps.Equal(before, after) {
		t.Errorf("a session was submitted anyway: %v -> %v", before, after)
	}
}

// And with terminals offered, the same call gets past the gate --
// otherwise the test above would pass on a gateway that refuses
// everything.
func TestSSHGatewayStartsATerminalWhenTheyAreOffered(t *testing.T) {
	s := newInteractiveServer(t, "USER alice@d "+ap1+"\n", nil)

	before := s.aps.counts()
	_, err := s.srv.sshGatewayResolve(s.callerCtx(t), "alice", gatewayTarget(t, s, "+work"), nil)
	if err != nil && strings.Contains(err.Error(), "HTTP_API_INTERACTIVE_TERMINAL") {
		t.Fatalf("the gate refused a terminal that is offered: %v", err)
	}
	if after := s.aps.counts(); maps.Equal(before, after) {
		t.Error("no access point was reached, so the gate is not what this test measured")
	}
}
