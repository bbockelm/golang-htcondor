package httpserver

import (
	"net/http"
	"slices"
	"strings"

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

// condorScopeForRequest is the authorization a request needs.
//
// By method, except for the routes that reach into a running job: the
// job and Jupyter proxies, an SSH session, and warming the transport
// they share. Those run the caller's code with the caller's identity
// whatever the method -- a GET is enough to open a notebook kernel's
// websocket -- and the Jupyter proxy never consults the schedd at all,
// so nothing downstream would refuse a read-only credential there.
func condorScopeForRequest(r *http.Request) string {
	if reachesIntoJob(r.URL.Path) {
		return condorScopeWrite
	}
	return condorScopeForMethod(r.Method)
}

// reachesIntoJob reports whether p is a route that connects to a
// running job rather than to a daemon.
func reachesIntoJob(p string) bool {
	if rest, ok := strings.CutPrefix(p, "/api/v1/jobs/"); ok {
		parts := strings.Split(rest, "/")
		if len(parts) < 2 {
			return false
		}
		switch parts[1] {
		case "proxy", "ssh", "warm":
			return true
		}
		return false
	}
	if rest, ok := strings.CutPrefix(p, "/api/v1/jupyter/instances/"); ok {
		_, after, _ := strings.Cut(rest, "/")
		verb, _, _ := strings.Cut(after, "/")
		return verb == "proxy"
	}
	return false
}

// grantAdmitsCondor reports whether a scoped credential's scopes admit
// want (condorScopeRead or condorScopeWrite).
//
// Decided the way the credential's minted IDTOKEN is limited, so this
// refuses what the schedd would: condor:/* scopes when there are any,
// mapped one to one; otherwise an OAuth2 grant's mcp:* scopes, mcp:write
// admitting both and mcp:read only READ. A credential with neither --
// a metrics-only API key, a grant approved for nothing -- admits nothing.
func grantAdmitsCondor(scopes []string, want string) bool {
	level := strings.TrimPrefix(want, "condor:/")
	if hasCondorScopes(scopes) {
		return slices.Contains(mapCondorScopesToAuthz(scopes), level)
	}
	write := slices.Contains(scopes, "mcp:write")
	if level == "WRITE" {
		return write
	}
	return write || slices.Contains(scopes, "mcp:read")
}

// bearerGrantScopes reports the scopes of the OAuth2 grant behind a
// bearer this server issued, and whether it is one. Any other bearer --
// a forwarded HTCondor IDTOKEN, or one that does not authenticate at all
// -- is unscoped here; what it may do is settled by the handler and the
// schedd.
//
// The token cache answers for a bearer already seen, and introspection
// for one that is not. Deliberately not createAuthenticatedContext,
// which would mint a credential and ask the schedd who the caller is
// only for the handler to do both again.
func (s *Handler) bearerGrantScopes(r *http.Request, bearer string) ([]string, bool) {
	if s.tokenCache != nil {
		if entry, ok := s.tokenCache.Get(bearer); ok {
			return entry.Scopes, entry.Scoped
		}
	}
	if s.oauth2Provider == nil {
		return nil, false
	}
	ar, err := s.oauth2Provider.IntrospectAccessToken(r.Context(), bearer)
	if err != nil {
		return nil, false
	}
	return ar.GetGrantedScopes(), true
}

// requireCondorScope gates a handler that reaches HTCondor data --
// the schedd, the collector, or the htcondordb mirror -- or a running
// job, on the caller's scopes.
//
// It applies to every scoped credential: an API key, and an OAuth2
// access token this server issued, including one granted nothing. A
// credential with no scope model -- a browser session, a trusted user
// header, a forwarded HTCondor IDTOKEN -- is authorized by its own path
// and passes through.
//
// Rejecting here rather than inside the handler is the point: the
// request is refused before any schedd RPC or mirror query is issued,
// and before a job proxy that never asks the schedd anything forwards
// it into the job.
func (s *Handler) requireCondorScope(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, err := extractBearerToken(r)
		if err != nil {
			next.ServeHTTP(w, r)
			return
		}
		want := condorScopeForRequest(r)

		if !apikey.LooksLikeKey(raw) {
			scopes, scoped := s.bearerGrantScopes(r, raw)
			if scoped && !grantAdmitsCondor(scopes, want) {
				s.writeError(w, http.StatusForbidden,
					"This token lacks the "+want+" scope required for this request")
				return
			}
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
		set, _ := scopedCredential(ctx)
		scopes := make([]string, 0, len(set))
		for scope := range set {
			scopes = append(scopes, scope)
		}
		if !grantAdmitsCondor(scopes, want) {
			s.writeError(w, http.StatusForbidden,
				"API key lacks the "+want+" scope required for this request")
			return
		}

		// Hand the authenticated context downstream so the handler
		// does not repeat the lookup.
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}
