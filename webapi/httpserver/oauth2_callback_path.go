package httpserver

import "github.com/bbockelm/golang-htcondor/webapi/httpserver/webui"

// Where the OAuth2 SSO callback lives.
//
// Every OAuth2 endpoint sits under /mcp/ because MCP is what first needed
// them. That reads correctly on a server whose only surface is MCP, and
// oddly on one that also serves a web UI: a person logging in to the UI is
// bounced through a URL naming a protocol they are not using.
//
// So the callback follows what the server actually serves. The rest of the
// OAuth2 endpoints keep their paths: they are named in published metadata
// (RFC 8414) and in registered clients, and moving them buys nothing that
// the callback's visibility does.

const (
	// mcpCallbackPath is the callback on an MCP-only server, and remains
	// served everywhere -- see OAuth2CallbackPath.
	mcpCallbackPath = "/mcp/oauth2/callback"
	// webUICallbackPath is the callback when this server also serves the
	// web UI.
	webUICallbackPath = "/oauth2/callback"
)

// OAuth2CallbackPath is the path this server advertises as its redirect URI:
// the plain one when the web UI is compiled in, the MCP-scoped one otherwise.
//
// Both are always routed. A redirect URI is registered with the upstream
// identity provider, and an authorization already in flight across a restart
// or an upgrade comes back to whichever path it was started with; answering
// only the current one would strand it.
func OAuth2CallbackPath() string {
	if webui.IsEmbedded() {
		return webUICallbackPath
	}
	return mcpCallbackPath
}
