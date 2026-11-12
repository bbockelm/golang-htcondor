package mcpserver

import (
	"fmt"

	"github.com/bbockelm/golang-htcondor/logging"
)

// Serving MCP read-only, by the installation's decision.
//
// The scope model already has a read-only setting: a token granted
// mcp:read and not mcp:write sees only the tools in readOnlyMCPTools.
// That is the CALLER's authorization, though, and it leaves two ways to
// hold the full write surface that no group policy reaches -- a
// forwarded HTCondor IDTOKEN, which is deliberately unscoped because
// HTCondor gates it instead, and a grant made before the policy
// changed. An operator who wants their users to have agents without
// those agents being able to submit, remove or edit anything has to be
// able to say so once, about the server, rather than hope every path
// that reaches it carries the right scopes.
//
// So this is a site decision applied where the site's other decisions
// are applied: beside HTTP_API_MCP_DISABLED_TOOLS, at the two places
// every transport passes through. It withholds the same set the read
// scope withholds, which is what makes it maintainable -- readOnlyMCPTools
// is the one classification, kept honest against the readOnlyHint
// annotations by TestAnnotationsAgreeWithReadOnlyClassification, so a
// write tool added tomorrow is covered by this knob the day it lands
// rather than the day somebody remembers to list it.

// SetReadOnly turns the site-wide read-only surface on or off. It is the
// dynamic half of HTTP_API_MCP_READ_ONLY: a reconfigure calls this.
//
// The catalogue is invalidated for the reason SetDisabledTools does it:
// the SDK transport caches a built server per scope set, so without this
// the setting would change what this server answers and not what most
// callers are served.
func (s *Server) SetReadOnly(on bool) {
	if s.readOnly.Swap(on) == on {
		return
	}
	if on {
		s.logger.Info(logging.DestinationMCP,
			"MCP is read-only by configuration (HTTP_API_MCP_READ_ONLY); no tool that changes anything is offered or accepted")
	} else {
		s.logger.Info(logging.DestinationMCP,
			"MCP is no longer read-only; the full tool surface is offered again")
	}
	s.InvalidateCatalog()
}

// ReadOnly reports whether the site has made this server read-only.
func (s *Server) ReadOnly() bool { return s.readOnly.Load() }

// toolWithheldByReadOnly reports whether a tool is one the read-only
// setting withholds. False when the setting is off, so the ordinary
// catalogue is unaffected.
func (s *Server) toolWithheldByReadOnly(name string) bool {
	return s.readOnly.Load() && !readOnlyMCPTools[name]
}

// errToolReadOnly is what a caller gets for a tool withheld by the
// read-only setting. It names the setting, because the operator reading
// the agent's transcript is the one who can change it, and says plainly
// that nothing the caller does will make the call work -- an agent told
// only "denied" tries the next credential it has.
func errToolReadOnly(name string) error {
	return fmt.Errorf("this access point serves MCP read-only (HTTP_API_MCP_READ_ONLY), so the %q tool is not available to any caller; "+
		"no scope, token or retry changes that, and the read-only tools are the ones listed by tools/list", name)
}
