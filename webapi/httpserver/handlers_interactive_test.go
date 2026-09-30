package httpserver

import (
	"testing"

	"github.com/bbockelm/golang-htcondor/webapi/interactive"
	"github.com/bbockelm/golang-htcondor/webapi/sshgateway"
)

// A session started through MCP or the SSH gateway has to appear on
// the interactive page alongside a browser terminal. They were
// separate surfaces with separate JobBatchName prefixes, so a session
// somebody started by typing `ssh` was invisible on the one page that
// lists what they have running.
func TestInteractiveListRecognisesBothKinds(t *testing.T) {
	for _, tc := range []struct {
		batchName string
		wantKind  string
		wantName  string
		wantOK    bool
	}{
		{interactive.BatchPrefix + "abc123", "terminal", "", true},
		{interactive.SessionBatchPrefix + "work", "session", "work", true},
		{interactive.SessionBatchPrefix + "default", "session", "default", true},
		{"someone-elses-batch", "", "", false},
		{"", "", "", false},
	} {
		t.Run(tc.batchName, func(t *testing.T) {
			kind, name, ok := classifyInteractiveBatchName(tc.batchName)
			if ok != tc.wantOK || kind != tc.wantKind || name != tc.wantName {
				t.Errorf("= (%q, %q, %v), want (%q, %q, %v)",
					kind, name, ok, tc.wantKind, tc.wantName, tc.wantOK)
			}
		})
	}
}

// The ssh command is only printed when there is a gateway to print it
// for. A UI that guessed would show a command that does not work.
func TestSSHCommandOnlyWhenTheGatewayCanBeReached(t *testing.T) {
	withGateway := &Handler{sshGateway: &sshgateway.Listener{}, sshGatewayPublicHost: "ap2001-ssh.example.edu"}
	if got := withGateway.sshCommandForSession("session", "work"); got != "ssh +work@ap2001-ssh.example.edu" {
		t.Errorf("command = %q", got)
	}
	// A terminal is not reachable by name.
	if got := withGateway.sshCommandForSession("terminal", ""); got != "" {
		t.Errorf("a terminal got an ssh command: %q", got)
	}
	// No public host configured: the listen address is :2222 behind a
	// Service that publishes 22 elsewhere, so there is nothing to
	// print.
	noHost := &Handler{sshGateway: &sshgateway.Listener{}}
	if got := noHost.sshCommandForSession("session", "work"); got != "" {
		t.Errorf("a command was printed with no public host: %q", got)
	}
	// Gateway not running at all.
	noGateway := &Handler{sshGatewayPublicHost: "ap2001-ssh.example.edu"}
	if got := noGateway.sshCommandForSession("session", "work"); got != "" {
		t.Errorf("a command was printed with no gateway: %q", got)
	}
}
