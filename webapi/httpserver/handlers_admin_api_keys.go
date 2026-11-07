package httpserver

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	htcondor "github.com/bbockelm/golang-htcondor"
	"github.com/bbockelm/golang-htcondor/logging"
	"github.com/bbockelm/golang-htcondor/webapi/httpserver/apikey"
)

// adminAPIKeyDTO is the JSON shape returned by the admin endpoints.
// Notice the missing fields: secret_hash NEVER appears, and the full
// minted key only appears in the create-response (it's not on this
// type). Keeping it that way prevents any accidental list-side leak.
type adminAPIKeyDTO struct {
	KeyID      string     `json:"key_id"`
	Name       string     `json:"name"`
	Scopes     []string   `json:"scopes"`
	Creator    string     `json:"creator"`
	CreatedAt  time.Time  `json:"created_at"`
	ExpiresAt  *time.Time `json:"expires_at,omitempty"`
	DeletedAt  *time.Time `json:"deleted_at,omitempty"`
	LastUsedAt *time.Time `json:"last_used_at,omitempty"`
	// Service distinguishes an automation's credential from the
	// minter's own. Shown in the listing because the two are revoked
	// differently and an operator auditing keys needs to tell them
	// apart at a glance.
	Service bool `json:"service"`
	// EntitlementsCheckedAt is when this key's entitlements were last
	// confirmed. Omitted for a key that carries none, and meaningless
	// for a service key, which holds them without re-confirmation.
	EntitlementsCheckedAt *time.Time `json:"entitlements_checked_at,omitempty"`
}

// rowToAdminDTO drops the secret_hash and renames fields to JSON-
// friendly snake_case. Keep this the only path that converts a row
// to the admin shape so a future refactor that adds a sensitive
// column doesn't accidentally leak it.
func rowToAdminDTO(r apiKeyRow) adminAPIKeyDTO {
	return adminAPIKeyDTO{
		KeyID:      r.KeyID,
		Name:       r.Name,
		Scopes:     r.Scopes,
		Creator:    r.Creator,
		CreatedAt:  r.CreatedAt,
		ExpiresAt:  r.ExpiresAt,
		DeletedAt:  r.DeletedAt,
		LastUsedAt: r.LastUsedAt,
		Service:    r.Service,

		EntitlementsCheckedAt: entitlementsCheckedFor(r),
	}
}

// entitlementsCheckedFor reports the last-verified timestamp only where
// it means something: a key with no entitlement has nothing to verify,
// and a service key is not verified at all.
func entitlementsCheckedFor(r apiKeyRow) *time.Time {
	if r.Service || len(heldEntitlements(r.Scopes)) == 0 {
		return nil
	}
	return r.EntitlementsCheckedAt
}

// validScopes is the closed set of scope strings an API key can be
// minted with. Adding a new one means: (a) appending here, (b)
// teaching the matching handler to check for it via ContainsScope.
// Refusing unknown scopes keeps the auth surface auditable — every
// scope an attacker could request is one we've explicitly blessed.
var validScopes = map[string]string{
	"metrics": "Read /metrics (Prometheus exposition).",

	// condor:/* scopes are carried into the IDTOKEN minted for the key
	// as HTCondor authorization limits, so the schedd enforces them.
	// A key holding only condor:/READ cannot be used to write even on
	// a codepath here that neglects to check scopes. Same vocabulary
	// the OAuth2/MCP path already uses, mapped by
	// mapCondorScopesToAuthz.
	"condor:/READ": "Query the schedd as the key's creator. Read-only: the token cannot write.",
	// Not a superset of READ: mapCondorScopesToAuthz maps scopes to
	// authorizations one-to-one, so a key expected to both query and
	// act needs both scopes selected.
	"condor:/WRITE": "Act on the creator's jobs (submit, hold, release, remove). Does not grant READ; select both to query as well.",

	// An ENTITLEMENT rather than an endpoint: it says whose records the
	// key may see, not which door it may knock on. Granted only to a
	// minter who holds it, and re-verified on use unless the key is a
	// service key. See apikey_entitlements.go.
	scopePoolRead:  "Read every user's records, not just the creator's. Granted only to an administrator who holds it; on a key that is not a service key it lapses when the creator's entitlement does.",
	scopePoolWrite: "Act on every user's records: remove, hold, release, edit. Does not grant pool:read; select both to see them as well. Same entitlement rules as pool:read.",
}

// handleAdminListAPIKeys handles GET /api/v1/admin/api-keys.
// Returns the calling admin's own keys, including soft-deleted rows
// (with deleted_at populated). Newest first.
func (s *Handler) handleAdminListAPIKeys(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		s.writeError(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}
	if !s.requireAdmin(w, r) {
		return
	}
	creator := s.adminUsername(r)
	if creator == "" {
		s.writeError(w, http.StatusUnauthorized, "Authenticated session has no username")
		return
	}
	rows, err := s.apiKeyStore.ListByCreator(r.Context(), creator)
	if err != nil {
		s.logger.Error(logging.DestinationHTTP, "API key list failed", "creator", creator, "error", err)
		s.writeError(w, http.StatusInternalServerError, "Failed to list API keys")
		return
	}
	out := make([]adminAPIKeyDTO, 0, len(rows))
	for _, r := range rows {
		out = append(out, rowToAdminDTO(r))
	}
	s.writeJSON(w, http.StatusOK, map[string]any{
		"api_keys":     out,
		"valid_scopes": validScopes,
	})
}

// adminAPIKeyCreateRequest is the POST body for minting a new key.
// Expiration: pass `expires_at` as RFC 3339, or omit / set to empty
// for "never expires". `scopes` MUST be non-empty (a key with no
// scope can't authorize anything).
type adminAPIKeyCreateRequest struct {
	Name   string   `json:"name"`
	Scopes []string `json:"scopes"`
	// ExpiresAt is RFC 3339, or omitted for "never expires". A service
	// key may not omit it.
	ExpiresAt *time.Time `json:"expires_at,omitempty"`
	// Service marks this key as an automation's credential rather than
	// the minter's own. It changes how the key's entitlements are held
	// -- granted once here instead of re-verified on every use -- which
	// is why it also requires an expiry.
	Service bool `json:"service,omitempty"`
}

// adminAPIKeyCreateResponse contains the FULL minted key — show it
// once and don't store it. Subsequent list calls only return the
// metadata DTO without the secret.
type adminAPIKeyCreateResponse struct {
	APIKey adminAPIKeyDTO `json:"api_key"`
	// Note is a plain-language caveat about the key just minted, or
	// empty when there is none. Said here because the mint request is
	// the last moment anybody is looking: an entitlement that will
	// lapse unattended is not something to discover from a dashboard
	// that quietly narrowed.
	Note string `json:"note,omitempty"`
	// Key is the wire-format value the user pastes into the
	// Authorization header. Returned ONCE in the create response
	// and never recoverable afterward.
	Key string `json:"key"`
}

// handleAdminCreateAPIKey handles POST /api/v1/admin/api-keys.
// Mints a new key for the calling admin, persists the row, and
// returns the full key value once.
func (s *Handler) handleAdminCreateAPIKey(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		s.writeError(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}
	if !s.requireAdmin(w, r) {
		return
	}
	creator := s.adminUsername(r)
	if creator == "" {
		s.writeError(w, http.StatusUnauthorized, "Authenticated session has no username")
		return
	}

	var req adminAPIKeyCreateRequest
	setBodyLimit(w, r, 4096)
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(&req); err != nil {
		s.writeError(w, http.StatusBadRequest, fmt.Sprintf("Invalid request body: %v", err))
		return
	}
	req.Name = strings.TrimSpace(req.Name)
	if req.Name == "" {
		s.writeError(w, http.StatusBadRequest, "name is required (a label for the admin's reference)")
		return
	}
	if len(req.Name) > 200 {
		s.writeError(w, http.StatusBadRequest, "name too long (max 200 characters)")
		return
	}
	if len(req.Scopes) == 0 {
		s.writeError(w, http.StatusBadRequest, "at least one scope is required")
		return
	}
	// Reject unknown scopes — the closed set is intentional.
	for _, sc := range req.Scopes {
		if _, ok := validScopes[sc]; !ok {
			s.writeError(w, http.StatusBadRequest,
				fmt.Sprintf("unknown scope %q", sc))
			return
		}
	}
	// A condor:/* scope only means anything if this server can actually
	// mint IDTOKENs. Refuse here rather than minting a key that looks
	// valid in the UI and then fails authentication on every use.
	if hasCondorScopes(req.Scopes) && (s.signingKeyPath == "" || s.trustDomain == "") {
		s.writeError(w, http.StatusBadRequest,
			"condor:/* scopes require SIGNING_KEY and TRUST_DOMAIN to be configured on this server")
		return
	}
	// Reject already-expired requests immediately. A key that's
	// born dead is just confusing.
	if req.ExpiresAt != nil && !req.ExpiresAt.After(time.Now()) {
		s.writeError(w, http.StatusBadRequest, "expires_at must be in the future")
		return
	}
	// An entitlement is granted from the minter's own, so a minter may
	// not hand out what they do not hold. requireAdmin has already
	// established the session this reads; the check is written out
	// rather than left implicit because it is the one line that has to
	// change when service administration and pool reads stop being the
	// same group.
	for _, sc := range heldEntitlements(req.Scopes) {
		if !s.isWebUIAdmin(r) {
			s.writeError(w, http.StatusForbidden,
				fmt.Sprintf("granting %s requires holding it yourself", sc))
			return
		}
	}
	if err := validateServiceKeyExpiry(req.Scopes, req.Service, req.ExpiresAt, s.serviceKeyMaxLifetime()); err != nil {
		s.writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	minted, err := apikey.Mint()
	if err != nil {
		s.logger.Error(logging.DestinationHTTP, "API key mint failed", "error", err)
		s.writeError(w, http.StatusInternalServerError, "Failed to mint API key")
		return
	}
	createdAt, err := s.apiKeyStore.Insert(r.Context(),
		minted.KeyID, minted.SecretHash, req.Name, creator, req.Scopes, req.ExpiresAt, req.Service)
	if err != nil {
		s.logger.Error(logging.DestinationHTTP, "API key insert failed", "error", err, "creator", creator)
		s.writeError(w, http.StatusInternalServerError, "Failed to persist API key")
		return
	}
	s.logger.Info(logging.DestinationHTTP, "API key minted",
		"key_id", minted.KeyID, "creator", creator,
		"scopes", req.Scopes, "name", req.Name, "service", req.Service)

	dto := adminAPIKeyDTO{
		KeyID:     minted.KeyID,
		Name:      req.Name,
		Scopes:    req.Scopes,
		Creator:   creator,
		CreatedAt: createdAt,
		ExpiresAt: req.ExpiresAt,
		Service:   req.Service,
	}
	s.writeJSON(w, http.StatusCreated, adminAPIKeyCreateResponse{
		APIKey: dto,
		Key:    minted.Full,
		Note:   s.mintNote(r.Context(), creator, req.Scopes, req.Service),
	})
}

// handleAdminDeleteAPIKey handles DELETE /api/v1/admin/api-keys/{key_id}.
// Soft-delete: the row stays for audit but the key stops
// authenticating immediately. Only the creator can delete.
func (s *Handler) handleAdminDeleteAPIKey(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodDelete {
		s.writeError(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}
	if !s.requireAdmin(w, r) {
		return
	}
	creator := s.adminUsername(r)
	if creator == "" {
		s.writeError(w, http.StatusUnauthorized, "Authenticated session has no username")
		return
	}
	keyID := strings.TrimPrefix(r.URL.Path, "/api/v1/admin/api-keys/")
	if keyID == "" || strings.Contains(keyID, "/") {
		s.writeError(w, http.StatusBadRequest, "Invalid key_id")
		return
	}
	if err := s.apiKeyStore.SoftDelete(r.Context(), keyID, creator); err != nil {
		// 404 covers both "no such key" and "you don't own this key" —
		// we deliberately don't leak which.
		s.writeError(w, http.StatusNotFound, "API key not found")
		return
	}
	s.logger.Info(logging.DestinationHTTP, "API key soft-deleted",
		"key_id", keyID, "creator", creator)
	s.writeJSON(w, http.StatusOK, map[string]string{
		"status": "deleted",
		"key_id": keyID,
	})
}

// adminUsername returns the authenticated admin's username from
// either the session cookie (browser path) or the validated bearer
// token (API path). Used by the API-key admin endpoints to set
// `creator`. Returns "" when no username is available; callers
// should treat that as a 401-equivalent.
func (s *Handler) adminUsername(r *http.Request) string {
	if sess, ok := s.getSessionFromRequest(r); ok && sess.Username != "" {
		return sess.Username
	}
	// Fallback for non-cookie flows. The request context isn't
	// populated yet at this layer (createAuthenticatedContext only
	// runs from within requireAuthentication, not requireAdmin), so
	// the session cookie is the only data we have.
	if u := htcondor.GetAuthenticatedUserFromContext(r.Context()); u != "" {
		return u
	}
	return ""
}

// validateServiceKeyExpiry enforces the one rule that makes a service
// key's frozen entitlement safe to grant: it has to end.
//
// A service key holds its entitlements without further proof, so the
// expiry is the only thing bounding them -- "never expires" is exactly
// the property that turns a convenience into a standing grant nobody
// revisits, and re-minting is how the entitlement gets re-attested.
//
// The rule applies only to a service key that actually carries an
// entitlement. A service key scoped to /metrics is freezing nothing
// about a person and has no more reason to expire than any other key.
func validateServiceKeyExpiry(scopes []string, service bool, expiresAt *time.Time, maxLifetime time.Duration) error {
	if !service || len(heldEntitlements(scopes)) == 0 {
		return nil
	}
	if expiresAt == nil {
		return fmt.Errorf("a service key carrying an entitlement must set expires_at; " +
			"re-minting it is how the entitlement is re-attested")
	}
	if expiresAt.After(time.Now().Add(maxLifetime)) {
		return fmt.Errorf("expires_at is further out than this server allows for a service key (%s)", maxLifetime)
	}
	return nil
}

// serviceKeyMaxLifetime caps how far out a service key's expiry may be
// set.
func (s *Handler) serviceKeyMaxLifetime() time.Duration {
	if s.serviceKeyMaxTTL > 0 {
		return s.serviceKeyMaxTTL
	}
	return defaultServiceKeyMaxLifetime
}

// mintNote warns about a key that will not behave the way the person
// minting it is likely to expect, or returns "" when it will.
//
// The case worth saying out loud: an entitlement on a key that is not a
// service key, in a deployment with no way to re-verify it. That key
// works when its minter tests it and stops working an hour later, with
// no error -- the listing it feeds simply narrows to one user's
// records. Nothing about the request says so, so the response does.
func (s *Handler) mintNote(ctx context.Context, creator string, scopes []string, service bool) string {
	if service || len(heldEntitlements(scopes)) == 0 {
		return ""
	}
	if _, answered := s.liveGroupEntitlement(ctx, creator); answered {
		return ""
	}
	return fmt.Sprintf(
		"This key's entitlement will lapse %s after it is minted: this server has no way to confirm "+
			"that you still hold it, and an unconfirmed entitlement is not honored indefinitely. "+
			"A credential meant to run unattended should be minted as a service key.",
		s.entitlementTTL())
}
