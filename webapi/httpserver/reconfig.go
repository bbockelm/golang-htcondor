package httpserver

import (
	"strconv"
	"strings"

	"github.com/bbockelm/golang-htcondor/logging"
)

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

// SetMCPDisabledTools installs the site's disabled-tool patterns.
//
// No-op when MCP is disabled, since there is then no server to tell.
func (h *Handler) SetMCPDisabledTools(spec string) {
	if h.mcpServer == nil {
		return
	}
	h.mcpServer.SetDisabledTools(spec)
}

// SetMCPReadOnly turns the site-wide read-only MCP surface on or off.
//
// Dynamic for the reason the disabled-tool list is: an operator who
// discovers their agents can act when they meant them only to look
// should be able to stop it now, for the sessions already connected,
// rather than at the next restart.
//
// The grant side is not re-run here. Tokens already carrying mcp:write
// keep carrying it until they refresh, and it buys them nothing: the
// refusal is in the tool server, which every transport passes through.
//
// No-op when MCP is disabled, since there is then no server to tell.
func (h *Handler) SetMCPReadOnly(spec string) {
	if h.mcpServer == nil {
		return
	}
	readOnly := h.reconfigBool("HTTP_API_MCP_READ_ONLY", spec, false)
	h.mcpReadOnly.Store(readOnly)
	h.mcpServer.SetReadOnly(readOnly)
}

// reconfigOffered reads a setting for a feature that is ON unless the
// operator turns it off, returning that default for an empty or
// unparseable value and saying so in the log.
//
// Deliberately not reconfigBool(name, spec, true): there the default is
// the caller's to choose, and it is chosen differently by different
// settings. Here it is the same for all three, and a parameter that
// every caller passes the same value to is one a reader has to check.
func (h *Handler) reconfigOffered(name, spec string) bool {
	spec = strings.TrimSpace(spec)
	if spec == "" {
		return true
	}
	v, err := strconv.ParseBool(spec)
	if err != nil {
		h.logger.Error(logging.DestinationHTTP,
			"Reconfigure: ignoring a setting that is not a boolean; the feature stays offered",
			"setting", name, "value", spec)
		return true
	}
	return v
}

// SetInteractiveJupyter turns the JupyterLab application on or off.
//
// This and the two below are dynamic because nothing is constructed
// from them: each is a check made when a session is created, and the
// list /auth/me publishes is read per request, so a reconfigure reaches
// the next launch and the next page load. The alternative -- restarting
// the daemon -- drops every live notebook and terminal to stop new ones
// being made, which is the opposite of what these settings are careful
// about.
func (h *Handler) SetInteractiveJupyter(spec string) {
	h.interactive.set(appJupyter, h.reconfigOffered("HTTP_API_INTERACTIVE_JUPYTER", spec))
}

// SetInteractiveVSCode turns the VS Code application on or off.
func (h *Handler) SetInteractiveVSCode(spec string) {
	h.interactive.set(appVSCode, h.reconfigOffered("HTTP_API_INTERACTIVE_VSCODE", spec))
}

// SetInteractiveTerminal turns the Terminal application on or off,
// and with it the MCP tool that starts the same kind of session.
func (h *Handler) SetInteractiveTerminal(spec string) {
	on := h.reconfigOffered("HTTP_API_INTERACTIVE_TERMINAL", spec)
	h.interactive.set(appTerminal, on)
	// The MCP interactive-session tools are the other front door onto
	// the same thing, so they follow it. See interactive_apps.go.
	if h.mcpServer != nil {
		h.mcpServer.SetInteractiveSessionsOffered(on)
	}
}

// SetMCPRedactSecrets turns credential masking on tool results on or off.
//
// The two masking settings are applied together because the rule set is
// built from both, and a reconfigure delivers one parameter at a time --
// so each setter records its own and re-applies the pair.
//
// No-op when MCP is disabled, since there is then no server to tell.
func (h *Handler) SetMCPRedactSecrets(spec string) {
	if h.mcpServer == nil {
		return
	}
	h.mcpDisableSecretRedaction = !h.reconfigBool("HTTP_API_MCP_REDACT_SECRETS", spec, true)
	h.applyMCPRedaction()
}

// reconfigBool parses a boolean setting delivered by a reconfigure,
// keeping def when it is unset or unparseable.
//
// Startup fails hard on a malformed boolean, because an operator who got
// one wrong should find out before the daemon is serving. A reconfigure
// cannot do that -- the daemon is already up and holding connections --
// so a typo keeps the previous meaning and is logged. Which value a typo
// falls back to is the whole decision here, and for masking it is "on":
// the alternative is a setting that silently stops protecting anything
// and reads, in the config file, as though it still does.
func (h *Handler) reconfigBool(name, spec string, def bool) bool {
	spec = strings.TrimSpace(spec)
	if spec == "" {
		return def
	}
	v, err := strconv.ParseBool(spec)
	if err != nil {
		h.logger.Error(logging.DestinationHTTP,
			"Reconfigure: ignoring a setting that is not a boolean; keeping the default",
			"setting", name, "value", spec, "default", def)
		return def
	}
	return v
}

// SetMCPRedactDisabledRules installs the site's turned-off masking rules.
//
// No-op when MCP is disabled, since there is then no server to tell.
func (h *Handler) SetMCPRedactDisabledRules(spec string) {
	if h.mcpServer == nil {
		return
	}
	h.mcpRedactDisabledRules = spec
	h.applyMCPRedaction()
}

func (h *Handler) applyMCPRedaction() {
	h.mcpServer.SetSecretRedaction(!h.mcpDisableSecretRedaction, h.mcpRedactDisabledRules)
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

// SetMCPAdminGroups installs the groups whose members may read every
// user's jobs through MCP. Emptying it revokes the privilege for
// everyone -- these two, unlike the read/write groups above, have no
// fallback to a broader group.
func (h *Handler) SetMCPAdminGroups(raw string) { h.mcpAdminGroups.set(raw) }

// SetMCPSuperuserGroups installs the groups whose members may change
// another user's jobs through MCP.
func (h *Handler) SetMCPSuperuserGroups(raw string) { h.mcpSuperuserGroups.set(raw) }

// SetWebUIAccessGroups installs the groups required to log in to the web
// interface. Emptying it restores the fallback to the MCP access groups.
func (h *Handler) SetWebUIAccessGroups(raw string) { h.webuiAccessGroups.set(raw) }

// SetWebUIAppOnlyGroups installs the groups whose members land in their
// site app rather than the dashboard. Reloadable for the same reason
// the others are: a site adds a lab mid-semester.
func (h *Handler) SetWebUIAppOnlyGroups(raw string) { h.webuiAppOnlyGroups.set(raw) }

// SetWebUIAdminGroups installs the groups required for the admin pages.
//
// Emptying it disables the admin UI, which is what an empty value has
// always meant, so this can switch the admin surface off without a
// restart as well as change who reaches it.
func (h *Handler) SetWebUIAdminGroups(raw string) { h.webuiAdminGroups.set(raw) }

// The web UI's branding is dynamic.
//
// Each setting is read when a page or an asset is served and nothing is
// built from any of it, so a site can try a logo, a colour or a name and
// see the result on the next page load. The two that name files --
// the branding directory and the stylesheet -- are re-checked here as
// well, which is how a path that was wrong at startup starts working
// without a restart.

// SetWebUISiteName installs the name in the sidebar and the browser tab.
func (h *Handler) SetWebUISiteName(v string) {
	h.branding.update(func(o *brandingOptions) { o.SiteName = v })
}

// SetWebUISiteTagline installs the line under the name in the sidebar.
func (h *Handler) SetWebUISiteTagline(v string) {
	h.branding.update(func(o *brandingOptions) { o.SiteTagline = v })
}

// SetWebUIFooterLogos installs the footer's institutional band. A value
// that does not parse leaves the previous band in place and says so in
// the log.
func (h *Handler) SetWebUIFooterLogos(v string) {
	h.branding.update(func(o *brandingOptions) { o.FooterLogos = v })
}

// SetWebUIBrandingDir installs the directory served under /branding/.
func (h *Handler) SetWebUIBrandingDir(v string) {
	h.branding.update(func(o *brandingOptions) { o.Dir = v })
}

// SetWebUICustomCSS installs the stylesheet served at /branding.css.
func (h *Handler) SetWebUICustomCSS(v string) {
	h.branding.update(func(o *brandingOptions) { o.CSSFile = v })
}

// SetWebUIFavicon installs the browser tab icon.
func (h *Handler) SetWebUIFavicon(v string) {
	h.branding.update(func(o *brandingOptions) { o.Favicon = v })
}

// SetSuperuserGroups installs the groups permitted to use superuser mode.
//
// Membership only. Superuser mode builds a policy object and a signing
// identity at startup, and only when a group was configured then, so this
// cannot switch the feature ON in a running daemon -- it says so rather
// than appearing to succeed. Emptying it DOES switch it off, since every
// check goes through the group list.
func (h *Handler) SetSuperuserGroups(raw string) {
	h.superuserGroups.set(raw)
	h.warnIfSuperuserNeedsRestart("HTTP_API_SUPERUSER_GROUP")
}

// SetProjectLeadsFile installs HTTP_API_PROJECT_LEADS_FILE and re-reads it.
//
// Called on every reconfigure, not only when the path changes: the usual
// reason to reconfigure is that the file was edited. (The file is also
// re-checked for changes on its own every few seconds, so an edit takes
// effect without a reconfigure; this makes it immediate.)
//
// Like SetSuperuserGroups, this cannot switch superuser mode ON in a running
// daemon that started without it.
func (h *Handler) SetProjectLeadsFile(path string) {
	h.projectLeads.SetFile(path)
	h.warnIfSuperuserNeedsRestart("HTTP_API_PROJECT_LEADS_FILE")
}

// ReloadAPAssignment re-reads the access point assignment's files -- the
// mapfile, the REST token file -- and drops cached answers, so an edited
// mapfile places the next submission. A mapfile that no longer parses
// keeps the last good map, and says so in the log. A no-op outside
// multi-AP mode.
func (h *Handler) ReloadAPAssignment() {
	if h.multi == nil || h.multi.assign == nil {
		return
	}
	if err := h.multi.assign.Reload(); err != nil {
		h.logger.Error(logging.DestinationHTTP, "Reconfigure: could not reload the access point assignment; keeping what was loaded",
			"error", err)
		return
	}
	h.logger.Info(logging.DestinationHTTP, "Reconfigure: reloaded the access point assignment",
		"backends", h.multi.assign.Backends())
}

// SetProjectLeadsGroup installs HTTP_API_PROJECT_LEADS_GROUP.
func (h *Handler) SetProjectLeadsGroup(pattern string) {
	h.projectLeads.SetPattern(pattern)
	h.warnIfSuperuserNeedsRestart("HTTP_API_PROJECT_LEADS_GROUP")
}

// warnIfSuperuserNeedsRestart says so when a reconfigure configured somebody
// to use superuser mode on a daemon that started with it off.
func (h *Handler) warnIfSuperuserNeedsRestart(param string) {
	if h.superuserPolicy == nil && (h.superuserGroups.configured() || h.projectLeads.configured()) {
		h.logger.Warn(logging.DestinationHTTP,
			param+" now configures superuser mode, but it was not started; "+
				"it is built at startup and needs a restart to enable")
	}
}
