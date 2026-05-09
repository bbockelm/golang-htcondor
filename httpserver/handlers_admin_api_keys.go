package httpserver

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	htcondor "github.com/bbockelm/golang-htcondor"
	"github.com/bbockelm/golang-htcondor/httpserver/apikey"
	"github.com/bbockelm/golang-htcondor/logging"
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
	}
}

// validScopes is the closed set of scope strings an API key can be
// minted with. Adding a new one means: (a) appending here, (b)
// teaching the matching handler to check for it via ContainsScope.
// Refusing unknown scopes keeps the auth surface auditable — every
// scope an attacker could request is one we've explicitly blessed.
var validScopes = map[string]string{
	"metrics": "Read /metrics (Prometheus exposition).",
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
	Name      string     `json:"name"`
	Scopes    []string   `json:"scopes"`
	ExpiresAt *time.Time `json:"expires_at,omitempty"`
}

// adminAPIKeyCreateResponse contains the FULL minted key — show it
// once and don't store it. Subsequent list calls only return the
// metadata DTO without the secret.
type adminAPIKeyCreateResponse struct {
	APIKey adminAPIKeyDTO `json:"api_key"`
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
	r.Body = http.MaxBytesReader(w, r.Body, 4096)
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
	// Reject already-expired requests immediately. A key that's
	// born dead is just confusing.
	if req.ExpiresAt != nil && !req.ExpiresAt.After(time.Now()) {
		s.writeError(w, http.StatusBadRequest, "expires_at must be in the future")
		return
	}

	minted, err := apikey.Mint()
	if err != nil {
		s.logger.Error(logging.DestinationHTTP, "API key mint failed", "error", err)
		s.writeError(w, http.StatusInternalServerError, "Failed to mint API key")
		return
	}
	createdAt, err := s.apiKeyStore.Insert(r.Context(),
		minted.KeyID, minted.SecretHash, req.Name, creator, req.Scopes, req.ExpiresAt)
	if err != nil {
		s.logger.Error(logging.DestinationHTTP, "API key insert failed", "error", err, "creator", creator)
		s.writeError(w, http.StatusInternalServerError, "Failed to persist API key")
		return
	}
	s.logger.Info(logging.DestinationHTTP, "API key minted",
		"key_id", minted.KeyID, "creator", creator,
		"scopes", req.Scopes, "name", req.Name)

	dto := adminAPIKeyDTO{
		KeyID:     minted.KeyID,
		Name:      req.Name,
		Scopes:    req.Scopes,
		Creator:   creator,
		CreatedAt: createdAt,
		ExpiresAt: req.ExpiresAt,
	}
	s.writeJSON(w, http.StatusCreated, adminAPIKeyCreateResponse{
		APIKey: dto,
		Key:    minted.Full,
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
