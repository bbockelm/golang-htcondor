package httpserver

// Where the OAuth2 endpoints live.
//
// Every OAuth2 endpoint sits under /mcp/ because MCP is what first needed
// them. That reads correctly on a server whose only surface is MCP, and
// oddly on one that also serves a web UI: a person logging in to the UI is
// bounced through a URL naming a protocol they are not using.
//
// So the advertised paths follow what the server actually serves: the
// /mcp/oauth2/ spelling only where MCP is all there is, the plain
// /oauth2/ one everywhere else. Where MCP is on, both are routed, because
// clients registered against the old spelling keep it. Where MCP is off,
// /mcp/ is not routed at all -- such a server never served OAuth2 under
// that prefix, so nothing holds it.

const (
	// mcpCallbackPath is the callback on an MCP-only server, and remains
	// served wherever MCP is -- see OAuth2CallbackPath.
	mcpCallbackPath = "/mcp/oauth2/callback"
	// webUICallbackPath is the callback when this server also serves the
	// web UI, or does not serve MCP.
	webUICallbackPath = "/oauth2/callback"

	// mcpDeviceVerifyPath is where a device-flow user approves a login on
	// an MCP-only server, and remains served wherever MCP is.
	mcpDeviceVerifyPath = "/mcp/oauth2/device/verify"
	// webUIDeviceVerifyPath is the same page on every other server.
	webUIDeviceVerifyPath = "/oauth2/device/verify"
)

// plainOAuth2Paths reports whether a server advertises its OAuth2
// endpoints under /oauth2/ rather than /mcp/oauth2/.
//
// The /mcp/ spelling is kept only where MCP is the whole surface: that is
// what such a server has always advertised. With a web UI the plain path
// is what a person should see; without MCP the /mcp/ one is not routed.
func plainOAuth2Paths(webUIEnabled, mcpEnabled bool) bool {
	return webUIEnabled || !mcpEnabled
}

// OAuth2CallbackPath is the path a server with this surface advertises as
// its redirect URI.
//
// Wherever MCP is on, both callback paths are routed. A redirect URI is
// registered with the upstream identity provider, and an authorization
// already in flight across a restart or an upgrade comes back to whichever
// path it was started with; answering only the current one would strand
// it.
func OAuth2CallbackPath(webUIEnabled, mcpEnabled bool) string {
	if plainOAuth2Paths(webUIEnabled, mcpEnabled) {
		return webUICallbackPath
	}
	return mcpCallbackPath
}

// deviceVerifyPathFor is the device verification page for a server that
// does (plain) or does not advertise the plain OAuth2 paths.
//
// Same reasoning as OAuth2CallbackPath, and it matters more here. The
// callback is a redirect a browser follows without reading; this URL is
// printed in a terminal for a person to copy, and `ssh` users on a server
// with a web UI were being sent to a path naming a protocol they are not
// using.
func deviceVerifyPathFor(plain bool) string {
	if plain {
		return webUIDeviceVerifyPath
	}
	return mcpDeviceVerifyPath
}

// oauth2EndpointPathFor is the path of the named OAuth2 endpoint
// ("authorize", "token", ...) for a server that does (plain) or does not
// advertise the plain OAuth2 paths.
func oauth2EndpointPathFor(plain bool, name string) string {
	if plain {
		return "/oauth2/" + name
	}
	return "/mcp/oauth2/" + name
}

// plainOAuth2Paths reports whether this server advertises its OAuth2
// endpoints under /oauth2/. See the package-level function.
func (h *Handler) plainOAuth2Paths() bool {
	return plainOAuth2Paths(h.webUIEnabled, h.mcpEnabled)
}

// oauth2EndpointPath is the path this server advertises for an OAuth2
// endpoint, given its name ("authorize", "token", ...).
//
// Every OAuth2 endpoint sits under /mcp/ because MCP is what first
// needed them, and the name has outlived the reason: these serve the web
// UI, editor extensions and anything else that speaks OAuth2.
//
// Where MCP is on, both paths are routed. A client discovers these once
// and keeps them -- a dynamically registered client may hold them for as
// long as its registration lasts -- so withdrawing the old one would
// strand every client that registered before the change.
func (h *Handler) oauth2EndpointPath(name string) string {
	return oauth2EndpointPathFor(h.plainOAuth2Paths(), name)
}

// oauth2CallbackPath is the redirect URI path this server advertises.
func (h *Handler) oauth2CallbackPath() string {
	return OAuth2CallbackPath(h.webUIEnabled, h.mcpEnabled)
}

// deviceVerifyPath is the path this server puts in a device
// authorization's verification_uri.
//
// Wherever MCP is on, both are routed, for the same reason the callback's
// two are: a device authorization issued before a restart or an upgrade
// carries the URL it was issued with, and its user has up to ten minutes
// to open it.
func (h *Handler) deviceVerifyPath() string {
	return deviceVerifyPathFor(h.plainOAuth2Paths())
}

// oauth2EndpointNames are the endpoints routed under each served prefix.
// The callback and device verification page are routed separately,
// having moved first.
var oauth2EndpointNames = []string{
	"authorize",
	"consent",
	"token",
	"introspect",
	"revoke",
	"register",
	"device/authorize",
}
