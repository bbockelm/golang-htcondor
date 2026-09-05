package httpserver

import (
	"net/http"

	"github.com/bbockelm/golang-htcondor/webapi/httpserver/apikey"
)

// The condor:/* scopes an API key can be minted with. Kept next to the
// gate that enforces them rather than inlined as string literals at
// each use.
const (
	condorScopeRead  = "condor:/READ"
	condorScopeWrite = "condor:/WRITE"
)

// condorScopeForMethod is the authorization a request needs, derived
// from its method: anything that does not mutate needs READ, everything
// else needs WRITE.
//
// This is coarser than HTCondor's own model, and deliberately so. The
// point is to reject a request carrying the wrong kind of credential
// before it reaches the schedd or the mirror at all, so a write-only
// key cannot be used to hammer a read endpoint (or the reverse). The
// fine-grained answer still comes from HTCondor, which sees the same
// limits in the token.
func condorScopeForMethod(method string) string {
	switch method {
	case http.MethodGet, http.MethodHead, http.MethodOptions:
		return condorScopeRead
	default:
		return condorScopeWrite
	}
}

// requireCondorScope gates a handler that reaches HTCondor data --
// the schedd, the collector, or the htcondordb mirror -- on the API
// key's condor:/* scopes.
//
// It applies to API-key callers only. Every other credential is
// authorized by its own path (a session by its groups, an OAuth2
// bearer by its granted scopes), and none of them carry these scopes,
// so gating them here would reject them all. Detection is a cheap
// prefix check on the bearer, which keeps this an outright no-op for
// non-API-key requests rather than an extra lookup on every call.
//
// Rejecting here rather than inside the handler is the point: the
// request is refused before any schedd RPC or mirror query is issued,
// so a key with the wrong scope costs a string comparison and a key
// lookup instead of backend load.
func (s *Handler) requireCondorScope(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, err := extractBearerToken(r)
		if err != nil || !apikey.LooksLikeKey(raw) {
			next.ServeHTTP(w, r)
			return
		}

		ctx, err := s.authenticateAPIKey(r, raw)
		if err != nil {
			// Deliberately unspecific: distinguishing "no such key"
			// from "wrong secret" tells an attacker their guessed id
			// was real. Same reasoning as authenticateAPIKey's own
			// error handling.
			s.writeError(w, http.StatusUnauthorized, "Invalid API key")
			return
		}

		want := condorScopeForMethod(r.Method)
		if !ContainsScope(ctx, want) {
			s.writeError(w, http.StatusForbidden,
				"API key lacks the "+want+" scope required for this request")
			return
		}

		// Hand the authenticated context downstream so the handler
		// does not repeat the lookup.
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}
