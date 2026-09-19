package mcpserver

import (
	"net/http"
	"sort"
	"strings"
	"sync"

	"github.com/modelcontextprotocol/go-sdk/auth"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// This server's tool catalogue is per-caller: a read-only token must not see
// the write tools, because an insufficient_scope rejection still tells a
// hostile client the whole attack surface. The SDK registers tools on a
// server, not on a request.
//
// The two models meet by building one server per distinct granted-scope set
// and choosing between them per request, which is what the streamable
// handler's per-request server hook is for. Callers present the same few sets
// over and over, so this is a handful of servers, not one per request.

// scopedServers caches an SDK server per granted-scope set, per catalogue
// generation.
type scopedServers struct {
	build func(scopes []string) *mcp.Server
	// gen reports the current catalogue generation. A reconfigure changes
	// the instructions and can change the catalogue, and a cached server
	// holds both -- so the cache is dropped rather than served stale.
	gen func() uint64

	mu      sync.Mutex
	builtAt uint64
	by      map[string]*mcp.Server
}

func newScopedServers(build func([]string) *mcp.Server, gen func() uint64) *scopedServers {
	return &scopedServers{build: build, gen: gen, by: map[string]*mcp.Server{}}
}

// scopeKey is the cache key: the granted scopes, order-independent.
func scopeKey(scopes []string) string {
	c := append([]string(nil), scopes...)
	sort.Strings(c)
	return strings.Join(c, " ")
}

func (c *scopedServers) get(scopes []string) *mcp.Server {
	key := scopeKey(scopes)
	c.mu.Lock()
	defer c.mu.Unlock()
	if gen := c.gen(); gen != c.builtAt {
		c.by = map[string]*mcp.Server{}
		c.builtAt = gen
	}
	if srv, ok := c.by[key]; ok {
		return srv
	}
	srv := c.build(scopes)
	c.by[key] = srv
	return srv
}

// SDKHTTPHandler serves MCP over the SDK's streamable HTTP transport.
//
// Stateless is not a tuning choice: the SEP-2575 protocol (2026-07-28) is only
// supported when the transport is stateless, so it is what the current spec
// revision requires. It costs the session id -- empty in this mode -- which
// was read for log correlation and bound nothing.
//
// verify is where this deployment's OAuth2 plugs in: the SDK never learns what
// a token is, only what it grants, so fosite is wrapped rather than replaced
// and every OAuth2 endpoint is untouched.
func (s *Server) SDKHTTPHandler(verify auth.TokenVerifier) http.Handler {
	cache := newScopedServers(s.sdkServerFor, s.catalogGen.Load)

	h := mcp.NewStreamableHTTPHandler(func(r *http.Request) *mcp.Server {
		info := auth.TokenInfoFromContext(r.Context())
		if info == nil {
			// Unreachable behind RequireBearerToken. Returning nil makes the
			// handler answer 400 rather than serve an unscoped catalogue,
			// which is the safe direction for a bug here.
			return nil
		}
		return cache.get(info.Scopes)
	}, &mcp.StreamableHTTPOptions{Stateless: true, JSONResponse: true})

	return auth.RequireBearerToken(verify, &auth.RequireBearerTokenOptions{
		// A forwarded HTCondor IDTOKEN has no expiry this server knows --
		// the schedd is what validates it -- and the SDK rejects a missing
		// expiration by default. Left on, that refuses every CLI user
		// holding condor_token_fetch output while every OAuth2 client keeps
		// working, which is the kind of breakage that reaches one group of
		// users and nobody else.
		//
		// Not a weakening: the caller has already been authenticated by the
		// time this runs, and an expiry we DO know is still passed through
		// and still checked here.
		AllowMissingExpiration: true,
	})(sdkHTTPMiddleware(h))
}
