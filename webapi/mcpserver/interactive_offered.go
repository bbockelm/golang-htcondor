package mcpserver

import (
	"fmt"

	"github.com/bbockelm/golang-htcondor/logging"
)

// Whether this access point offers interactive sessions at all.
//
// The MCP interactive-session tools and the web console's Terminal are
// two front doors onto one thing: a long-lived job the caller runs
// commands in. So the site setting that closes one closes the other
// (HTTP_API_INTERACTIVE_TERMINAL). A site that turns terminals off
// because its policy forbids interactive shells, and then finds an
// agent starting them, has been given a setting that does not mean what
// it says.
//
// Only STARTING is withheld, which is the same line the HTTP side
// draws: an agent that already has a session can still run in it, list
// it and stop it, so turning the setting off drains sessions instead of
// stranding jobs nobody can reach.
//
// Tools a site does not want for other reasons remain
// HTTP_API_MCP_DISABLED_TOOLS' business; this one is not an MCP policy
// but the access point's, arriving here because the capability is
// shared.

// SetInteractiveSessionsOffered records whether new interactive
// sessions may be started. Called at startup and on a reconfigure.
func (s *Server) SetInteractiveSessionsOffered(on bool) {
	if s.interactiveSessionsOff.Swap(!on) == !on {
		return
	}
	if !on {
		s.logger.Info(logging.DestinationMCP,
			"This access point does not offer interactive sessions (HTTP_API_INTERACTIVE_TERMINAL); interactive_session_start is withdrawn")
	} else {
		s.logger.Info(logging.DestinationMCP, "Interactive sessions are offered again")
	}
	s.InvalidateCatalog()
}

// interactiveSessionsOffered reports whether a new session may be
// started.
func (s *Server) interactiveSessionsOffered() bool {
	return !s.interactiveSessionsOff.Load()
}

// errInteractiveSessionsNotOffered is what a caller gets for trying to
// start one where the site does not offer them. It names the setting,
// for whoever reads the transcript, and says the existing tools still
// work so an agent mid-task knows it has not lost the session it holds.
func errInteractiveSessionsNotOffered() error {
	return fmt.Errorf("this access point does not offer interactive sessions (HTTP_API_INTERACTIVE_TERMINAL), so no new one can be started; " +
		"sessions already running can still be listed, used and stopped")
}
