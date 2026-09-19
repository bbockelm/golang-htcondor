package httpserver

import (
	"context"
	"net/http"

	"github.com/modelcontextprotocol/go-sdk/auth"
	"github.com/ory/fosite"
)

// Routing /mcp through the upstream SDK's transport instead of the hand-rolled
// JSON-RPC handler.
//
// The two share everything about WHO the caller is -- mcpAuthContext -- and
// differ only in who owns the wire. Selected by HTTP_API_MCP_TRANSPORT so a
// deployment can move and move back without a rebuild.

// sdkTokenInfoKey carries what this server's own authentication established
// into the SDK's bearer middleware.
type sdkTokenInfoKey struct{}

func withSDKTokenInfo(ctx context.Context, info *auth.TokenInfo) context.Context {
	return context.WithValue(ctx, sdkTokenInfoKey{}, info)
}

func sdkTokenInfoFrom(ctx context.Context) *auth.TokenInfo {
	info, _ := ctx.Value(sdkTokenInfoKey{}).(*auth.TokenInfo)
	return info
}

// mcpSDKHandler serves /mcp over the SDK transport.
func (h *Handler) mcpSDKHandler() http.Handler {
	// The SDK asks a TokenVerifier what a token grants. This deployment has
	// already answered that -- fosite validated it, and for a forwarded
	// HTCondor token the schedd does -- so the verifier reports what
	// mcpAuthContext found rather than validating a second time by different
	// rules.
	verify := func(ctx context.Context, _ string, _ *http.Request) (*auth.TokenInfo, error) {
		if info := sdkTokenInfoFrom(ctx); info != nil {
			return info, nil
		}
		return nil, auth.ErrInvalidToken
	}
	return h.mcpSDKAuth(h.mcpServer.SDKHTTPHandler(verify))
}

// sdkTokenInfoFor is what the SDK is told the caller was granted.
//
// A returned function rather than three lines inline because the two cases
// are not observable from outside: an OAuth2 caller and a forwarded HTCondor
// caller both reach the same tools when the scopes are dropped, so nothing a
// request can show distinguishes carrying them from losing them.
//
// Nil scopes for a forwarded HTCondor token is deliberate, not a gap: the
// catalogue filter reads nil as "no scope constraint", and HTCondor gates
// that caller -- the same division the built-in transport makes.
func sdkTokenInfoFor(token fosite.AccessRequester) *auth.TokenInfo {
	info := &auth.TokenInfo{}
	if token == nil {
		return info
	}
	info.Scopes = token.GetGrantedScopes()
	if sess := token.GetSession(); sess != nil {
		info.Expiration = sess.GetExpiresAt(fosite.AccessToken)
	}
	return info
}

// mcpSDKAuth authenticates the request and builds the context the tools run
// in, before the SDK sees the body.
//
// This is the same enrichment the built-in transport does, and deliberately
// not the same gating: there, one server answers everyone and the method is
// checked against the caller's scopes; here the caller's server has only the
// tools those scopes allow, so an unpermitted tool does not exist to call.
func (h *Handler) mcpSDKAuth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		r.Body = http.MaxBytesReader(w, r.Body, maxMCPBody)

		ctx, token, ok := h.mcpAuthContext(w, r)
		if !ok {
			return
		}

		ctx = withSDKTokenInfo(ctx, sdkTokenInfoFor(token))

		// Keep the write deadline ahead of a call that is still running, so a
		// tool that is deliberately waiting is bounded by the hard stop
		// rather than by the server-wide HTTP_API_WRITE_TIMEOUT. Same
		// treatment the built-in transport gets; the SDK handler is an
		// ordinary http.Handler, so this wraps it unchanged.
		ctx, stopExtending := h.progressiveWriteDeadline(ctx, w)
		defer stopExtending()

		next.ServeHTTP(w, r.WithContext(ctx))
	})
}
