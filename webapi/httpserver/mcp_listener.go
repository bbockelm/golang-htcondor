package httpserver

import (
	"net/http"
	"strings"
)

// The MCP surface: what an MCP client needs and nothing else.
//
// /mcp/ covers both the protocol endpoint and the authorization server's
// own endpoints. The well-known documents are how a client discovers that
// authorization server in the first place, so they have to be reachable
// wherever the protocol is. Health checks are here because whatever
// watches a port needs to be able to ask about it.
const (
	mcpPathPrefix         = "/mcp/"
	wellKnownAuthServer   = "/.well-known/oauth-authorization-server"
	wellKnownResourcePath = "/.well-known/oauth-protected-resource"
	healthzPath           = "/healthz"
	readyzPath            = "/readyz"
)

// isMCPSurfacePath reports whether path belongs to the MCP surface.
func isMCPSurfacePath(path string) bool {
	switch {
	case strings.HasPrefix(path, mcpPathPrefix):
		return true
	case path == wellKnownAuthServer:
		return true
	case path == wellKnownResourcePath || strings.HasPrefix(path, wellKnownResourcePath+"/"):
		return true
	case path == healthzPath || path == readyzPath:
		return true
	default:
		return false
	}
}

// isMCPProtocolPath reports whether path is the MCP protocol endpoint
// itself, as opposed to the authorization endpoints around it.
func isMCPProtocolPath(path string) bool {
	return path == mcpMessagePath
}

// mcpSurfaceOnly restricts a handler to the MCP surface.
//
// It fronts the listener an operator gave MCP so that putting MCP on its
// own port is worth doing: the point of the separate port is that it can
// be firewalled differently from the web UI, which only holds if the web
// UI and the REST API are not also answering there.
func mcpSurfaceOnly(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !isMCPSurfacePath(r.URL.Path) {
			http.NotFound(w, r)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// withoutMCPProtocol removes the MCP protocol endpoint from a handler.
//
// It fronts the main listener once MCP has a port of its own, for the
// other half of the same reason: MCP still answering on the original port
// would leave the surface exactly as wide as before.
//
// Only the protocol endpoint is removed. The authorization endpoints stay
// on both, because a client that reaches either port has to be able to
// finish authenticating, and because the web UI's consent screens live
// under the same prefix.
func withoutMCPProtocol(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if isMCPProtocolPath(r.URL.Path) {
			http.NotFound(w, r)
			return
		}
		next.ServeHTTP(w, r)
	})
}
