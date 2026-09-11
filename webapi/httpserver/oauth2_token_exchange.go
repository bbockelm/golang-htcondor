package httpserver

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/ory/fosite"

	"github.com/bbockelm/golang-htcondor/logging"
)

// RFC 8693 OAuth 2.0 Token Exchange.
//
// Stage C1: the subject_token is one THIS server issued (an access token); the
// exchanging (actor) client is authenticated and must hold the token_exchange
// grant; the result acts AS the subject but records the actor for delegation
// (an `act` claim / Session.Actor); and scope can only be narrowed, never
// expanded -- consistent with the "an IDTOKEN narrows, never expands" model the
// schedd relies on. External trusted-issuer subject tokens are stage C2.

const tokenExchangeGrantType = "urn:ietf:params:oauth:grant-type:token-exchange"

const (
	tokenTypeAccessToken = "urn:ietf:params:oauth:token-type:access_token"
)

// handleTokenExchange implements the token-exchange grant. It is dispatched from
// handleOAuth2Token before fosite's pipeline (which has no handler for this
// grant), mirroring the device-code branch.
func (h *Handler) handleTokenExchange(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	// Authenticate the exchanging (actor) client. Token exchange is
	// confidential-only, and the client must have opted into the grant.
	client, err := h.oauth2Provider.AuthenticateClient(ctx, r, r.PostForm)
	if err != nil {
		h.writeOAuthError(w, http.StatusUnauthorized, "invalid_client", "client authentication failed")
		return
	}
	if client.IsPublic() {
		h.writeOAuthError(w, http.StatusBadRequest, "invalid_client",
			"token exchange requires a confidential client")
		return
	}
	if !containsString(client.GetGrantTypes(), tokenExchangeGrantType) {
		h.writeOAuthError(w, http.StatusBadRequest, "unauthorized_client",
			"this client is not permitted to perform token exchange")
		return
	}

	subjectToken := r.FormValue("subject_token")
	subjectTokenType := r.FormValue("subject_token_type")
	if subjectToken == "" || subjectTokenType == "" {
		h.writeOAuthError(w, http.StatusBadRequest, "invalid_request",
			"subject_token and subject_token_type are required")
		return
	}
	if rt := r.FormValue("requested_token_type"); rt != "" && rt != tokenTypeAccessToken {
		h.writeOAuthError(w, http.StatusBadRequest, "invalid_request",
			"only an access_token may be requested")
		return
	}

	// Resolve the subject token to its subject and the ceiling of scopes it may
	// obtain. Access tokens this server issued and (when configured) JWTs from
	// trusted external issuers are both accepted.
	subject, subjectScopes, subjectGroups, err := h.resolveSubjectToken(ctx, subjectToken, subjectTokenType, client)
	if err != nil {
		// Deliberately terse: never echo token contents or introspection
		// internals back to the caller.
		h.logger.Info(logging.DestinationHTTP, "Token exchange rejected",
			"client_id", client.GetID(), "reason", err.Error())
		h.writeOAuthError(w, http.StatusBadRequest, "invalid_grant", "subject_token is not valid for exchange")
		return
	}

	// Scope-down: the result may only narrow the subject's authorization.
	requested := strings.Fields(r.FormValue("scope"))
	granted := subjectScopes
	if len(requested) > 0 {
		granted = intersectScopes(requested, subjectScopes)
		if len(granted) == 0 {
			h.writeOAuthError(w, http.StatusBadRequest, "invalid_scope",
				"requested scope is not within the subject token's grant")
			return
		}
	}

	// The result acts AS the subject and records the actor client (delegation).
	session := DefaultOpenIDConnectSession(subject)
	session.Actor = client.GetID()
	session.Groups = subjectGroups

	// Mint an opaque access token via the low-level strategy (the device-code
	// path's template). No refresh token: an exchanged token is short-lived and
	// the actor re-exchanges rather than holding a long-lived refresh credential.
	ar := fosite.NewAccessRequest(session)
	ar.Client = client
	ar.GrantTypes = fosite.Arguments{tokenExchangeGrantType}
	for _, s := range granted {
		ar.GrantScope(s)
	}
	setStandardTokenExpiries(ctx, h.oauth2Provider.config, session)

	strategy := h.oauth2Provider.GetStrategy()
	accessToken, _, err := strategy.GenerateAccessToken(ctx, ar)
	if err != nil {
		h.logger.Error(logging.DestinationHTTP, "Token exchange: generate access token", "error", err)
		h.writeOAuthError(w, http.StatusInternalServerError, "server_error", "could not issue token")
		return
	}
	signature := strategy.AccessTokenSignature(ctx, accessToken)
	if err := h.oauth2Provider.GetStorage().CreateAccessTokenSession(ctx, signature, ar); err != nil {
		h.logger.Error(logging.DestinationHTTP, "Token exchange: store access token", "error", err)
		h.writeOAuthError(w, http.StatusInternalServerError, "server_error", "could not issue token")
		return
	}

	h.clientUsage.Record(client.GetID(), subject, time.Now())
	h.logger.Info(logging.DestinationHTTP, "Token exchanged",
		"actor", client.GetID(), "subject", subject, "scope", strings.Join(granted, " "))

	resp := map[string]interface{}{
		"access_token":      accessToken,
		"issued_token_type": tokenTypeAccessToken,
		"token_type":        "Bearer",
		"expires_in":        int(h.oauth2Provider.config.GetAccessTokenLifespan(ctx).Seconds()),
		"scope":             strings.Join(granted, " "),
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")
	w.WriteHeader(http.StatusOK)
	if err := json.NewEncoder(w).Encode(resp); err != nil {
		h.logger.Error(logging.DestinationHTTP, "Token exchange: encode response", "error", err)
	}
}

// resolveSubjectToken validates the subject token and returns the subject, the
// ceiling of scopes the exchanged token may obtain, and any group list.
//
//   - An access token this server issued: the ceiling is the subject's own
//     granted scopes.
//   - A JWT from a configured trusted external issuer (subject_token_type jwt or
//     id_token): the ceiling is the issuer's allowed scopes, further bounded by
//     the exchanging (actor) client's own scopes, and the subject is namespaced
//     to the issuer's identity domain. Only available when issuers are
//     configured (stage C2).
func (h *Handler) resolveSubjectToken(ctx context.Context, token, tokenType string, actor fosite.Client) (string, []string, []string, error) {
	switch tokenType {
	case tokenTypeAccessToken:
		ar, err := h.oauth2Provider.IntrospectAccessToken(ctx, token)
		if err != nil {
			return "", nil, nil, fmt.Errorf("subject_token introspection failed: %w", err)
		}
		subject := ar.GetSession().GetSubject()
		if subject == "" {
			return "", nil, nil, fmt.Errorf("subject_token has no subject")
		}
		var groups []string
		if s, ok := ar.GetSession().(*Session); ok {
			groups = s.Groups
		}
		return subject, ar.GetGrantedScopes(), groups, nil

	case tokenTypeJWT, tokenTypeIDToken:
		if h.extIssuers == nil {
			return "", nil, nil, fmt.Errorf("external subject tokens are not accepted")
		}
		identity, groups, issuerAllowed, err := h.extIssuers.validate(ctx, token)
		if err != nil {
			return "", nil, nil, err
		}
		// The external token carries no authorization in our system: bound it by
		// the issuer's declared ceiling AND the actor client's own scopes.
		ceiling := intersectScopes(issuerAllowed, actor.GetScopes())
		return identity, ceiling, groups, nil

	default:
		return "", nil, nil, fmt.Errorf("unsupported subject_token_type %q", tokenType)
	}
}
