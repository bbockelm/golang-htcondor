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

	// mcpDeviceVerifyPath is where a device-flow user approves a login on
	// an MCP-only server, and remains served everywhere.
	mcpDeviceVerifyPath = "/mcp/oauth2/device/verify"
	// webUIDeviceVerifyPath is the same page when this server also serves
	// the web UI.
	webUIDeviceVerifyPath = "/oauth2/device/verify"
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

// OAuth2DeviceVerifyPath is the path this server puts in a device
// authorization's verification_uri: the plain one when the web UI is
// compiled in, the MCP-scoped one otherwise.
//
// Same reasoning as OAuth2CallbackPath, and it matters more here. The
// callback is a redirect a browser follows without reading; this URL is
// printed in a terminal for a person to copy, and `ssh` users on a server
// with a web UI were being sent to a path naming a protocol they are not
// using.
//
// Both are always routed, for the same reason the callback's two are: a
// device authorization issued before a restart or an upgrade carries the
// URL it was issued with, and its user has up to ten minutes to open it.
func OAuth2DeviceVerifyPath() string {
	return deviceVerifyPathFor(webui.IsEmbedded())
}

// deviceVerifyPathFor is the choice itself, separated from how this build
// answers it.
//
// Test builds do not embed the frontend, so a test calling
// OAuth2DeviceVerifyPath() exercises one branch and asserts whichever
// answer it got -- it passes against a function that ignores the flag
// entirely. Found by mutation.
func deviceVerifyPathFor(embedded bool) string {
	if embedded {
		return webUIDeviceVerifyPath
	}
	return mcpDeviceVerifyPath
}

// deviceVerifyPath is the seam the device authorization composes its
// verification_uri through.
//
// A variable rather than a direct call so a test can make it differ from
// the default. Test builds do not embed the frontend, so every expression
// that could stand in for it -- the exported function, the MCP constant,
// a hardcoded string -- evaluates the same there, and a test comparing
// them asserts nothing. Found by mutation: reverting the composition to a
// hardcoded "/mcp/oauth2/device/verify" broke nothing.
var deviceVerifyPath = OAuth2DeviceVerifyPath

// oauth2EndpointPathFor is the choice for every other OAuth2 endpoint:
// the plain path when the web UI is compiled in, the MCP-scoped one
// otherwise.
//
// Separated from how this build answers it for the same reason
// deviceVerifyPathFor is -- test builds do not embed the frontend, so a
// test calling the exported wrapper exercises one branch and asserts
// whichever answer it got, which passes against a function that ignores
// the flag entirely.
func oauth2EndpointPathFor(embedded bool, name string) string {
	if embedded {
		return "/oauth2/" + name
	}
	return "/mcp/oauth2/" + name
}

// OAuth2EndpointPath is the path this server advertises for an OAuth2
// endpoint, given its name ("authorize", "token", ...).
//
// Every OAuth2 endpoint sits under /mcp/ because MCP is what first
// needed them, and the name has outlived the reason: these serve the web
// UI, editor extensions and anything else that speaks OAuth2. The
// callback and the device verification page already moved, being the
// two a person reads; this is the rest.
//
// Both paths are always routed. A client discovers these once and keeps
// them -- a dynamically registered client may hold them for as long as
// its registration lasts -- so withdrawing the old one would strand
// every client that registered before the change.
func OAuth2EndpointPath(name string) string {
	return oauth2EndpointPathFor(webui.IsEmbedded(), name)
}

// oauth2EndpointNames are the endpoints served under both prefixes.
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
