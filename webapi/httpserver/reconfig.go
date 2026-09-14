package httpserver

// Dynamic parameters: the setters a reconfigure (SIGHUP, or condor_reconfig via
// DC_RECONFIG) calls on an already-running server.
//
// Most of this server's configuration is read once, at startup, and copied into
// the Handler and its sub-servers, so changing it in the config file does
// nothing until the daemon restarts. A parameter becomes dynamic by growing a
// setter here and an entry in the daemon's reconfigure table; anything without
// one is reported to the operator as requiring a restart rather than silently
// ignored.
//
// A setter runs on the reconfigure goroutine while requests are being served,
// so it must be safe to call concurrently with the reads it affects. That is
// the constraint that decides whether a parameter can be dynamic at all: values
// baked into a constructed object (a database handle, a listener, an OAuth2
// issuer that signed already-outstanding tokens) cannot simply be swapped.

// SetMCPInstructions installs new deployment-specific MCP instructions.
// No-op when MCP is disabled, since there is then no server to tell.
//
// Only sessions that initialize after this call see the new text; MCP hands an
// agent its instructions once, in the initialize response.
func (h *Handler) SetMCPInstructions(instructions string) {
	if h.mcpServer == nil {
		return
	}
	h.mcpServer.SetInstructions(instructions)
}
