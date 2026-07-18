package httpserver

import (
	"context"
	"errors"
	"fmt"
	"net/http"

	htcondor "github.com/bbockelm/golang-htcondor"
	"github.com/bbockelm/golang-htcondor/logging"
	"github.com/bbockelm/golang-htcondor/webapi/httpserver/apikey"
)

// API-key authentication.
//
// Auth precedence vs. JWT / sessions: API keys are detected by their
// distinctive `htca-v1-` Bearer-token prefix and short-circuit BEFORE
// the JWT/opaque-token validation path. The two methods can't be
// confused — JWT tokens never start with `htca-v1-` — so detection
// is unambiguous and there's no fallback / ambiguous-error case to
// handle.
//
// What an API key DOES authenticate:
//   - HTTP-layer identity: the request's effective user becomes the
//     key's creator (the admin who minted it).
//   - Scopes: a set of capability strings the request can use.
//     /metrics checks for the `metrics` scope; other endpoints can
//     opt in similarly.
//
// What an API key does NOT authenticate:
//   - The schedd CEDAR session. API keys produce no SecurityConfig
//     and cannot talk to schedd / collector RPCs. Endpoints that
//     need the schedd (jobs, templates, etc.) will fail naturally
//     with "no schedd auth" — they don't accidentally accept API
//     keys via a partially-populated context. This is by design: the
//     attacker-leak risk for an API key is "scrape /metrics" not
//     "remove every job in the queue".
//
// The whole feature can be disabled at config time by leaving the
// admin UI off (no admin → no key minting); existing keys keep
// working until soft-deleted.

// scopesContextKey is the context key under which we stash the
// scope set authenticated by the request's API key. Other auth
// methods (JWTs, sessions) leave it absent — handlers that gate
// on a specific scope should check ContainsScope which treats
// "no scopes attached" as "scope not present".
type scopesContextKey struct{}

// withAPIKeyScopes attaches the API key's authorized scopes to the
// context. Stored as a `map[string]struct{}` for O(1) membership
// checks; the public read API uses ContainsScope.
func withAPIKeyScopes(ctx context.Context, scopes []string) context.Context {
	if len(scopes) == 0 {
		return ctx
	}
	set := make(map[string]struct{}, len(scopes))
	for _, s := range scopes {
		set[s] = struct{}{}
	}
	return context.WithValue(ctx, scopesContextKey{}, set)
}

// ContainsScope reports whether the request's API key was minted
// with the named scope. Returns false when the request was NOT
// authenticated via an API key (or was authenticated via one with
// different scopes). Use this in handlers that want to opt into
// API-key access.
func ContainsScope(ctx context.Context, scope string) bool {
	v, _ := ctx.Value(scopesContextKey{}).(map[string]struct{})
	if v == nil {
		return false
	}
	_, ok := v[scope]
	return ok
}

// authenticatedViaAPIKey reports whether the current request was
// authenticated via an API key. Used by /metrics to differentiate
// "browser session, ignore scope check" from "bearer token, must
// have metrics scope". The flag lives in the same context map keyed
// to a private struct so it can't accidentally collide.
type apiKeyMarkerKey struct{}

func withAPIKeyMarker(ctx context.Context) context.Context {
	return context.WithValue(ctx, apiKeyMarkerKey{}, true)
}

// AuthenticatedViaAPIKey reports whether ctx was set up by the
// API-key auth path (rather than a JWT, OAuth2 token, or browser
// session). Some authorization decisions only make sense for API
// keys (e.g. "API keys must have an explicit scope; sessions don't").
func AuthenticatedViaAPIKey(ctx context.Context) bool {
	v, _ := ctx.Value(apiKeyMarkerKey{}).(bool)
	return v
}

// authenticateAPIKey is the API-key arm of the Bearer-token auth
// path. It parses the presented key, looks up the row, verifies
// the secret hash, and returns a context populated with the
// authenticated user (= the key's creator) and the key's scope set.
//
// The caller should only invoke this when extractBearerToken
// returned a string that LooksLikeKey is true for — non-API-key
// tokens fall through to the JWT/opaque path.
//
// Errors are returned to the caller; the caller decides whether to
// log them (we never echo specifics to the client beyond "401
// unauthorized" — leaking "wrong secret for this key_id" tells an
// attacker their guessed id was real).
func (s *Handler) authenticateAPIKey(r *http.Request, raw string) (context.Context, error) {
	if s.apiKeyStore == nil {
		// Only happens during very partial test setup; the prod
		// constructor always sets it.
		return nil, errors.New("api key store not configured")
	}
	parsed, err := apikey.Parse(raw)
	if err != nil {
		return nil, fmt.Errorf("api key parse: %w", err)
	}
	row, err := s.apiKeyStore.LookupActive(r.Context(), parsed.KeyID)
	if err != nil {
		return nil, fmt.Errorf("api key lookup: %w", err)
	}
	if err := parsed.VerifySecret(row.SecretHash); err != nil {
		return nil, fmt.Errorf("api key verify: %w", err)
	}

	// Touch last_used_at best-effort. Done with the request's own
	// context so a client cancel propagates (no goroutine leak).
	s.apiKeyStore.TouchLastUsed(r.Context(), row.KeyID)

	ctx := r.Context()
	ctx = htcondor.WithAuthenticatedUser(ctx, row.Creator)
	ctx = withAPIKeyScopes(ctx, row.Scopes)
	ctx = withAPIKeyMarker(ctx)
	if s.logger != nil {
		s.logger.Debug(logging.DestinationSecurity, "Authenticated via API key",
			"key_id", row.KeyID,
			"creator", row.Creator,
			"scopes", row.Scopes,
		)
	}
	return ctx, nil
}
