package httpserver

import "github.com/bbockelm/golang-htcondor/logging"

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

// SetMCPSkillsDir reloads the site skill library.
//
// Called on every reconfigure, not only when the configured path changes:
// the usual reason to reload is that the checkout the path points at has
// been updated, which a diff of the setting cannot see. Reading a few
// dozen Markdown files is cheap enough to do unconditionally.
//
// No-op when MCP is disabled, since there is then no server to tell.
func (h *Handler) SetMCPSkillsDir(dir string) {
	if h.mcpServer == nil {
		return
	}
	h.mcpSkillsDir = dir
	h.mcpServer.SetSkillsDir(dir)
}

// The authorization group lists are dynamic.
//
// They are the settings an operator most often gets wrong on a first
// deployment -- somebody is locked out, or somebody is not locked out --
// and each is only a membership test on a request, with nothing
// constructed from it. Swapping one therefore cannot invalidate an
// outstanding token or a live connection the way the issuer or the
// database path would.
//
// A groupSet stores its list in an atomic pointer, so these run on the
// reconfigure goroutine while requests read the same lists.
//
// Existing SESSIONS are not re-evaluated here. A login already granted
// keeps its grant until it refreshes, at which point the reauthorization
// path re-runs the policy against the new lists -- so tightening a group
// takes effect on the next refresh rather than mid-request.

// SetMCPAccessGroups installs the groups required for MCP access.
func (h *Handler) SetMCPAccessGroups(raw string) { h.mcpAccessGroups.set(raw) }

// SetMCPReadGroups installs the groups required for MCP read access.
func (h *Handler) SetMCPReadGroups(raw string) { h.mcpReadGroups.set(raw) }

// SetMCPWriteGroups installs the groups required for MCP write access.
func (h *Handler) SetMCPWriteGroups(raw string) { h.mcpWriteGroups.set(raw) }

// SetWebUIAccessGroups installs the groups required to log in to the web
// interface. Emptying it restores the fallback to the MCP access groups.
func (h *Handler) SetWebUIAccessGroups(raw string) { h.webuiAccessGroups.set(raw) }

// SetWebUIAdminGroups installs the groups required for the admin pages.
//
// Emptying it disables the admin UI, which is what an empty value has
// always meant, so this can switch the admin surface off without a
// restart as well as change who reaches it.
func (h *Handler) SetWebUIAdminGroups(raw string) { h.webuiAdminGroups.set(raw) }

// SetSuperuserGroups installs the groups permitted to use superuser mode.
//
// Membership only. Superuser mode builds a policy object and a signing
// identity at startup, and only when a group was configured then, so this
// cannot switch the feature ON in a running daemon -- it says so rather
// than appearing to succeed. Emptying it DOES switch it off, since every
// check goes through the group list.
func (h *Handler) SetSuperuserGroups(raw string) {
	h.superuserGroups.set(raw)
	if h.superuserPolicy == nil && h.superuserGroups.configured() {
		h.logger.Warn(logging.DestinationHTTP,
			"HTTP_API_SUPERUSER_GROUP now names a group, but superuser mode was not started; "+
				"it is built at startup and needs a restart to enable",
			"groups", h.superuserGroups.String())
	}
}
