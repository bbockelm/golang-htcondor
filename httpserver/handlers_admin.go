package httpserver

import (
	"database/sql"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/bbockelm/golang-htcondor/logging"
)

// requireAdmin gates admin endpoints on (1) a valid session and (2) the
// session including the configured admin group. Writes the appropriate
// error response and returns false if the caller should bail.
//
// Returns 503 when WebUIAdminGroup is unset — the admin UI is opt-in via
// configuration; treating "no group configured" as 403 would be more
// confusing than helpful.
func (s *Handler) requireAdmin(w http.ResponseWriter, r *http.Request) bool {
	if s.webuiAdminGroup == "" {
		s.writeError(w, http.StatusServiceUnavailable,
			"Admin UI is disabled. Set HTTP_API_WEBUI_ADMIN_GROUP to enable.")
		return false
	}
	session, ok := s.getSessionFromRequest(r)
	if !ok {
		s.writeError(w, http.StatusUnauthorized, "Authentication required")
		return false
	}
	if !hasGroup(session.Groups, s.webuiAdminGroup) {
		s.writeError(w, http.StatusForbidden,
			fmt.Sprintf("Admin access requires membership in group %q", s.webuiAdminGroup))
		return false
	}
	return true
}

// AdminClient is the SPA-facing shape for an OAuth2 client. We mirror
// only the fields useful for an "audit + cleanup" UI; secrets are never
// returned (they're hashed in storage anyway, but we still strip them
// out of the response shape on principle).
type AdminClient struct {
	ID            string    `json:"id"`
	RedirectURIs  []string  `json:"redirect_uris,omitempty"`
	GrantTypes    []string  `json:"grant_types,omitempty"`
	ResponseTypes []string  `json:"response_types,omitempty"`
	Scopes        []string  `json:"scopes,omitempty"`
	Public        bool      `json:"public"`
	CreatedAt     time.Time `json:"created_at"`
}

// AdminToken is the SPA-facing shape for an OAuth2 access/refresh token
// row. We never expose the raw token signature — only its prefix as a
// fingerprint, so admins can correlate against logs without being able
// to use the token themselves.
type AdminToken struct {
	Kind            string    `json:"kind"` // "access" or "refresh"
	SignaturePrefix string    `json:"signature_prefix"`
	ClientID        string    `json:"client_id"`
	Subject         string    `json:"subject,omitempty"`
	Scopes          []string  `json:"scopes,omitempty"`
	Active          bool      `json:"active"`
	RequestedAt     time.Time `json:"requested_at"`
	ExpiresAt       time.Time `json:"expires_at,omitempty"`
}

// handleAdminListClients handles GET /api/v1/admin/oauth2/clients.
func (s *Handler) handleAdminListClients(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		s.writeError(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}
	if !s.requireAdmin(w, r) {
		return
	}
	if s.oauth2Provider == nil {
		s.writeJSON(w, http.StatusOK, map[string]any{"clients": []AdminClient{}})
		return
	}

	db := s.oauth2Provider.GetStorage().GetDB()
	rows, err := db.QueryContext(r.Context(),
		`SELECT id, redirect_uris, grant_types, response_types, scopes, public, created_at
		 FROM oauth2_clients ORDER BY created_at DESC`)
	if err != nil {
		s.logger.Error(logging.DestinationHTTP, "Failed to list OAuth2 clients", "error", err)
		s.writeError(w, http.StatusInternalServerError, "Failed to list clients")
		return
	}
	defer func() { _ = rows.Close() }()

	clients := []AdminClient{}
	for rows.Next() {
		var c AdminClient
		var redirectURIs, grantTypes, responseTypes, scopes string
		var public int
		if err := rows.Scan(&c.ID, &redirectURIs, &grantTypes, &responseTypes,
			&scopes, &public, &c.CreatedAt); err != nil {
			s.logger.Warn(logging.DestinationHTTP, "Skipping malformed client row", "error", err)
			continue
		}
		c.RedirectURIs = splitNonEmpty(redirectURIs)
		c.GrantTypes = splitNonEmpty(grantTypes)
		c.ResponseTypes = splitNonEmpty(responseTypes)
		c.Scopes = splitNonEmpty(scopes)
		c.Public = public != 0
		clients = append(clients, c)
	}

	s.writeJSON(w, http.StatusOK, map[string]any{"clients": clients})
}

// handleAdminDeleteClient handles DELETE /api/v1/admin/oauth2/clients/{id}.
// Removes the client and any tokens issued under it. Useful for cleaning
// up dynamic-client-registration churn that often piles up on shared APs.
func (s *Handler) handleAdminDeleteClient(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodDelete {
		s.writeError(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}
	if !s.requireAdmin(w, r) {
		return
	}
	clientID := strings.TrimPrefix(r.URL.Path, "/api/v1/admin/oauth2/clients/")
	if clientID == "" || strings.Contains(clientID, "/") {
		s.writeError(w, http.StatusBadRequest, "Invalid client ID")
		return
	}
	if s.oauth2Provider == nil {
		s.writeError(w, http.StatusServiceUnavailable, "OAuth2 provider not configured")
		return
	}

	db := s.oauth2Provider.GetStorage().GetDB()
	// Cascade: tokens reference client_id but lack FK constraints in this
	// schema. Delete in order so we never leave orphan tokens that fail
	// later GetClient lookups.
	for _, table := range []string{
		"oauth2_access_tokens",
		"oauth2_refresh_tokens",
		"oauth2_authorization_codes",
		"oauth2_oidc_sessions",
		"oauth2_pkce_requests",
		"oauth2_device_codes",
	} {
		// gosec G202: table is from a fixed allowlist above, not user input.
		if _, err := db.ExecContext(r.Context(),
			"DELETE FROM "+table+" WHERE client_id = ?", clientID); err != nil { //nolint:gosec
			s.logger.Warn(logging.DestinationHTTP, "Failed to clean up tokens for client",
				"table", table, "client_id", clientID, "error", err)
		}
	}
	res, err := db.ExecContext(r.Context(),
		"DELETE FROM oauth2_clients WHERE id = ?", clientID)
	if err != nil {
		s.writeError(w, http.StatusInternalServerError,
			fmt.Sprintf("Failed to delete client: %v", err))
		return
	}
	rows, _ := res.RowsAffected()
	if rows == 0 {
		s.writeError(w, http.StatusNotFound, "Client not found")
		return
	}
	s.logger.Info(logging.DestinationHTTP, "Admin deleted OAuth2 client", "client_id", clientID)
	s.writeJSON(w, http.StatusOK, map[string]string{"status": "deleted", "client_id": clientID})
}

// handleAdminListTokens handles GET /api/v1/admin/oauth2/tokens. Lists
// access and refresh tokens, newest first, with the signature redacted.
//
// Query params:
//
//	limit (default 200, max 1000)
//	client_id — filter to one client
//	active_only (default true) — drop expired/revoked rows
func (s *Handler) handleAdminListTokens(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		s.writeError(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}
	if !s.requireAdmin(w, r) {
		return
	}
	if s.oauth2Provider == nil {
		s.writeJSON(w, http.StatusOK, map[string]any{"tokens": []AdminToken{}})
		return
	}

	limit := 200
	if v := r.URL.Query().Get("limit"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			if n > 1000 {
				n = 1000
			}
			limit = n
		}
	}
	clientFilter := r.URL.Query().Get("client_id")
	activeOnly := true
	if v := r.URL.Query().Get("active_only"); v != "" {
		if b, err := strconv.ParseBool(v); err == nil {
			activeOnly = b
		}
	}

	db := s.oauth2Provider.GetStorage().GetDB()
	tokens := []AdminToken{}
	tokens = append(tokens, queryTokenTable(r, db, "oauth2_access_tokens", "access",
		clientFilter, activeOnly, limit, s.logger)...)
	tokens = append(tokens, queryTokenTable(r, db, "oauth2_refresh_tokens", "refresh",
		clientFilter, activeOnly, limit, s.logger)...)

	// Sort the merged list by RequestedAt descending and clamp to limit.
	// We do this in-memory rather than via UNION because the schemas
	// differ slightly (refresh tokens allow NULL expires_at) and a
	// portable, readable query for both gets ugly.
	for i := 0; i < len(tokens); i++ {
		for j := i + 1; j < len(tokens); j++ {
			if tokens[j].RequestedAt.After(tokens[i].RequestedAt) {
				tokens[i], tokens[j] = tokens[j], tokens[i]
			}
		}
	}
	if len(tokens) > limit {
		tokens = tokens[:limit]
	}

	s.writeJSON(w, http.StatusOK, map[string]any{"tokens": tokens})
}

func queryTokenTable(
	r *http.Request, db *sql.DB, table, kind, clientFilter string,
	activeOnly bool, limit int, logger *logging.Logger,
) []AdminToken {
	// gosec G202: table is selected by the caller from a fixed allowlist
	// (oauth2_access_tokens / oauth2_refresh_tokens), not from user input.
	//nolint:gosec
	q := "SELECT signature, client_id, subject, scopes, active, requested_at, expires_at FROM " + table
	args := []any{}
	conds := []string{}
	if clientFilter != "" {
		conds = append(conds, "client_id = ?")
		args = append(args, clientFilter)
	}
	if activeOnly {
		conds = append(conds, "active != 0")
		conds = append(conds, "(expires_at IS NULL OR expires_at > ?)")
		args = append(args, time.Now().UTC())
	}
	if len(conds) > 0 {
		q += " WHERE " + strings.Join(conds, " AND ")
	}
	q += " ORDER BY requested_at DESC LIMIT ?"
	args = append(args, limit)

	rows, err := db.QueryContext(r.Context(), q, args...)
	if err != nil {
		logger.Error(logging.DestinationHTTP, "Failed to list tokens",
			"table", table, "error", err)
		return nil
	}
	defer func() { _ = rows.Close() }()

	out := make([]AdminToken, 0, limit)
	for rows.Next() {
		var sig, clientID, subject, scopes string
		var active int
		var requestedAt time.Time
		var expiresAt sql.NullTime
		if err := rows.Scan(&sig, &clientID, &subject, &scopes, &active,
			&requestedAt, &expiresAt); err != nil {
			logger.Warn(logging.DestinationHTTP, "Skipping malformed token row",
				"table", table, "error", err)
			continue
		}
		t := AdminToken{
			Kind:            kind,
			SignaturePrefix: redactSignature(sig),
			ClientID:        clientID,
			Subject:         subject,
			Scopes:          splitNonEmpty(scopes),
			Active:          active != 0,
			RequestedAt:     requestedAt,
		}
		if expiresAt.Valid {
			t.ExpiresAt = expiresAt.Time
		}
		out = append(out, t)
	}
	return out
}

// AdminLogsResponse wraps the buffer entries with a hint when the buffer
// hasn't been initialized — the SPA shows a different empty state for
// "no logs yet" vs "feature not wired up".
type AdminLogsResponse struct {
	Enabled bool                  `json:"enabled"`
	Entries []logging.BufferEntry `json:"entries"`
}

// handleAdminLogs handles GET /api/v1/admin/logs. Returns up to `limit`
// (default 1000) recent log entries from the in-memory ring buffer.
func (s *Handler) handleAdminLogs(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		s.writeError(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}
	if !s.requireAdmin(w, r) {
		return
	}

	if s.logBuffer == nil {
		s.writeJSON(w, http.StatusOK, AdminLogsResponse{Enabled: false, Entries: nil})
		return
	}

	limit := 1000
	if v := r.URL.Query().Get("limit"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			limit = n
		}
	}

	s.writeJSON(w, http.StatusOK, AdminLogsResponse{
		Enabled: true,
		Entries: s.logBuffer.Entries(limit),
	})
}

// splitNonEmpty splits on whitespace/comma and drops empty results. The
// underlying storage uses both depending on which fosite version wrote
// the row, so we accept either.
func splitNonEmpty(s string) []string {
	if s == "" {
		return nil
	}
	fields := strings.FieldsFunc(s, func(r rune) bool {
		return r == ',' || r == ' ' || r == '\t' || r == '\n'
	})
	out := make([]string, 0, len(fields))
	for _, f := range fields {
		f = strings.TrimSpace(f)
		if f != "" {
			out = append(out, f)
		}
	}
	return out
}

// redactSignature returns a short fingerprint of a token signature.
// Eight characters is enough to disambiguate concurrent tokens in the
// admin UI without giving an attacker meaningful prefix material.
func redactSignature(sig string) string {
	if len(sig) <= 8 {
		return sig + "..."
	}
	return sig[:8] + "..."
}
