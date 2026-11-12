package mcpserver

import "github.com/bbockelm/golang-htcondor/logging"

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

// Whether anything may reach into a running job at all.
//
// The access point's HTTP_API_SSH_TO_JOB, arriving here for the same
// reason the terminal setting does: a site that forbids
// condor_ssh_to_job forbids it however the request is dressed, and an
// agent is a way of dressing it.
//
// It withdraws more than the terminal setting, and less than
// everything. Starting a session and running a command in one both go
// into the sandbox, as exec_in_job does, so all three go. Listing
// sessions reads the queue and stopping one removes a job: neither
// touches the sandbox, and withdrawing them would leave an agent
// holding sessions it could not clean up.

// SetSSHToJobOffered records whether anything may reach into a running
// job. Called at startup and on a reconfigure.
func (s *Server) SetSSHToJobOffered(on bool) {
	if s.sshToJobOff.Swap(!on) == !on {
		return
	}
	if !on {
		s.logger.Info(logging.DestinationMCP,
			"This access point allows nothing to reach into a running job (HTTP_API_SSH_TO_JOB); "+
				"exec_in_job, interactive_session_start and interactive_session_exec are withdrawn")
	} else {
		s.logger.Info(logging.DestinationMCP, "Reaching into a running job is allowed again")
	}
	s.InvalidateCatalog()
}

// sshToJobTools are the tools that reach into a running job's sandbox.
var sshToJobTools = map[string]bool{
	"exec_in_job":               true,
	"interactive_session_start": true,
	"interactive_session_exec":  true,
}

// toolWithheldBySite reports whether the ACCESS POINT (rather than this
// server's own MCP settings, or the caller's scopes) does not offer a
// tool, and what to say about it.
//
// One function rather than a check per setting at each call site,
// because there are two settings and three places that have to agree:
// the catalogue, the dispatcher, and whatever the next transport turns
// out to be.
func (s *Server) toolWithheldBySite(name string) (string, bool) {
	if s.sshToJobOff.Load() && sshToJobTools[name] {
		return "this access point does not allow anything to reach into a running job (HTTP_API_SSH_TO_JOB), so %q is not available to any caller; " +
			"a job's output and files are still readable, and a session can still be listed and stopped", true
	}
	if !s.interactiveSessionsOffered() && name == "interactive_session_start" {
		return "this access point does not offer interactive sessions (HTTP_API_INTERACTIVE_TERMINAL), so %q cannot start one; " +
			"sessions already running can still be listed, used and stopped", true
	}
	return "", false
}
