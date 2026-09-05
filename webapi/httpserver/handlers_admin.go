package httpserver

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"net/http"
	"regexp"
	"sort"
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
// isWebUIAdmin reports whether the browser session attached to r belongs
// to the configured admin group. Returns false for any path that
// doesn't have a session (bearer-token API callers, no group
// configured, no cookie). Use this for soft policy decisions like
// "should this query default to all-jobs?" — for hard authorization
// gates use requireAdmin which writes a 401/403/503 directly.
func (s *Handler) isWebUIAdmin(r *http.Request) bool {
	if s.webuiAdminGroup == "" {
		return false
	}
	session, ok := s.getSessionFromRequest(r)
	if !ok {
		return false
	}
	return hasGroup(session.Groups, s.webuiAdminGroup)
}

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

	// Name is what the client called itself at registration (RFC 7591
	// client_name). Empty for seeded clients and for anything registered
	// before we started keeping it.
	Name string `json:"name,omitempty"`
	// Notes is the operator's own annotation, editable from the UI. It
	// is the only identifying field available for clients that predate
	// provenance tracking.
	Notes string `json:"notes,omitempty"`
	// Origin is "dynamic", "seeded", or empty for unknown. Empty is not
	// the same as "not dynamic" -- it means nobody recorded the answer.
	Origin string `json:"origin,omitempty"`
	// LastUsedAt is when this client last obtained a token. Absent means
	// never, which for a dynamically registered client usually means an
	// app registered once and never came back.
	//
	// Written on a debounced background flush, so it can lag real usage
	// by up to a flush interval. It is a "roughly when", not an audit
	// record; oauth2_access_tokens has the per-token history.
	LastUsedAt *time.Time `json:"last_used_at,omitempty"`
	// RecentUsers is a rolling sample of the last few distinct subjects
	// to obtain a token through this client, newest first.
	RecentUsers []AdminClientUse `json:"recent_users,omitempty"`
}

// AdminClientUse is one entry of a client's recent-users sample.
type AdminClientUse struct {
	Subject string    `json:"subject"`
	At      time.Time `json:"at"`
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

	// Flush any debounced usage first so the list reflects a token
	// issued moments ago rather than making an admin wait out the
	// interval and wonder whether the column works.
	s.clientUsage.FlushNow(r.Context())

	db := s.oauth2Provider.GetStorage().GetDB()
	rows, err := db.QueryContext(r.Context(),
		`SELECT id, redirect_uris, grant_types, response_types, scopes, public, created_at,
		        client_name, notes, origin, last_used_at, recent_users
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
		var name, notes, origin, recentUsers string
		var lastUsed sql.NullTime
		if err := rows.Scan(&c.ID, &redirectURIs, &grantTypes, &responseTypes,
			&scopes, &public, &c.CreatedAt,
			&name, &notes, &origin, &lastUsed, &recentUsers); err != nil {
			s.logger.Warn(logging.DestinationHTTP, "Skipping malformed client row", "error", err)
			continue
		}
		c.RedirectURIs = decodeStringList(redirectURIs)
		c.GrantTypes = decodeStringList(grantTypes)
		c.ResponseTypes = decodeStringList(responseTypes)
		c.Scopes = decodeStringList(scopes)
		c.Public = public != 0

		p := scanProvenance(name, notes, origin, lastUsed, recentUsers)
		c.Name, c.Notes, c.Origin, c.LastUsedAt = p.Name, p.Notes, string(p.Origin), p.LastUsedAt
		for _, u := range p.RecentUsers {
			c.RecentUsers = append(c.RecentUsers, AdminClientUse(u))
		}
		clients = append(clients, c)
	}

	s.writeJSON(w, http.StatusOK, map[string]any{"clients": clients})
}

// adminClientNotesRequest is the PATCH body for annotating a client.
type adminClientNotesRequest struct {
	Notes string `json:"notes"`
}

// maxClientNotesLen bounds an operator annotation. Generous for a note
// and small enough that the column cannot be used as a data store.
const maxClientNotesLen = 4096

// handleAdminUpdateClient handles PATCH /api/v1/admin/oauth2/clients/{id}.
//
// The only editable field is the note. Everything else on a client row
// is either the client's own assertion at registration or something this
// server derived, and letting an admin rewrite those would turn the
// provenance columns into a place to record a belief rather than a fact.
func (s *Handler) handleAdminUpdateClient(w http.ResponseWriter, r *http.Request) {
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

	var req adminClientNotesRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<16)).Decode(&req); err != nil {
		s.writeError(w, http.StatusBadRequest, fmt.Sprintf("Invalid request body: %v", err))
		return
	}
	if len(req.Notes) > maxClientNotesLen {
		s.writeError(w, http.StatusBadRequest,
			fmt.Sprintf("Notes are limited to %d characters", maxClientNotesLen))
		return
	}

	found, err := setClientNotes(r.Context(), s.oauth2Provider.GetStorage().GetDB(),
		clientID, req.Notes)
	if err != nil {
		s.logger.Error(logging.DestinationHTTP, "Failed to update client notes",
			"client_id", clientID, "error", err)
		s.writeError(w, http.StatusInternalServerError, "Failed to update client")
		return
	}
	if !found {
		s.writeError(w, http.StatusNotFound, "Client not found")
		return
	}
	s.writeJSON(w, http.StatusOK, map[string]string{"notes": req.Notes})
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
			Scopes:          decodeStringList(scopes),
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

// AdminCondorConfigEntry is one (key, value) row from the HTCondor
// config that we surface to the admin info page. Sensitive values
// (matched by sensitiveCondorKeyPattern) come back with Redacted=true
// and an empty Value so the admin can SEE the key is set without the
// raw value rendering on screen — defense-in-depth even though
// HTCondor convention is that secrets are paths, not literals.
type AdminCondorConfigEntry struct {
	Key      string `json:"key"`
	Value    string `json:"value,omitempty"`
	Redacted bool   `json:"redacted,omitempty"`
	// IsDefault reports that this key still holds HTCondor's compiled-in
	// value — nothing in this deployment's config files or environment
	// touched it. Roughly a thousand of the ~1085 keys in a stock config
	// are in this state, which is what makes an unfiltered dump tedious
	// to read, so the SPA offers to hide them.
	IsDefault bool `json:"is_default,omitempty"`
}

// AdminCondorConfigResponse is the full readout. Configured=false means
// no HTCondor config object was wired into this server; treat as
// "feature unavailable on this deployment" client-side.
type AdminCondorConfigResponse struct {
	Configured bool                     `json:"configured"`
	Entries    []AdminCondorConfigEntry `json:"entries"`
	// ModifiedCount is how many entries this deployment actually set,
	// so the SPA can label its filter without counting client-side.
	ModifiedCount int `json:"modified_count"`
}

// sensitiveCondorKeyPattern matches config keys whose VALUES we mask
// before returning. HTCondor convention is that secrets live in
// referenced files (passwords.d/POOL, pool_password, …) — so the
// values here are usually paths, not bytes. But operators occasionally
// stash credentials in env-derived knobs; redact anything that looks
// secret-named to keep the admin readout safe to leave on screen.
//
// Match is case-insensitive and substring-based against the key.
var sensitiveCondorKeyPattern = regexp.MustCompile(
	`(?i)(PASSWORD|SECRET|PRIVATE_?KEY|API_?KEY|TOKEN|BEARER|CLIENT_?SECRET)`,
)

// handleAdminCondorConfig handles GET /api/v1/admin/condor-config.
// Returns every key the HTCondor config object knows about, sorted
// case-insensitively, with sensitive-looking values redacted.
//
// We deliberately do NOT support filter parameters server-side — the
// SPA filters client-side after fetch (the full readout is on the
// order of a few KiB compressed; not worth a query param round-trip).
func (s *Handler) handleAdminCondorConfig(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		s.writeError(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}
	if !s.requireAdmin(w, r) {
		return
	}

	if s.htcondorConfig == nil {
		// No HTCondor config wired up (e.g. demo path that never
		// loaded one). 200 with configured=false so the SPA renders
		// "config unavailable" instead of an error.
		s.writeJSON(w, http.StatusOK, AdminCondorConfigResponse{Configured: false})
		return
	}

	keys := s.htcondorConfig.Keys()
	sort.Slice(keys, func(i, j int) bool {
		return strings.ToLower(keys[i]) < strings.ToLower(keys[j])
	})

	entries := make([]AdminCondorConfigEntry, 0, len(keys))
	modified := 0
	for _, k := range keys {
		isDefault := s.htcondorConfig.IsDefault(k)
		if !isDefault {
			modified++
		}
		if sensitiveCondorKeyPattern.MatchString(k) {
			// Still report default-ness for a redacted key: knowing
			// whether a password knob was set at all is useful and
			// leaks nothing about its value.
			entries = append(entries, AdminCondorConfigEntry{
				Key: k, Redacted: true, IsDefault: isDefault,
			})
			continue
		}
		val, _ := s.htcondorConfig.Get(k)
		entries = append(entries, AdminCondorConfigEntry{
			Key: k, Value: val, IsDefault: isDefault,
		})
	}
	s.writeJSON(w, http.StatusOK, AdminCondorConfigResponse{
		Configured:    true,
		Entries:       entries,
		ModifiedCount: modified,
	})
}

// decodeStringList turns a stored list column into a slice.
//
// The OAuth2 storage writes these columns with json.Marshal, so a client's
// scopes arrive as `["openid","mcp:read"]`. Splitting that on commas — which
// is what this code did until the admin UI started showing entries like
// `["openid"` and `"mcp:read"]` — hands the SPA JSON fragments to render as
// list items. Parse the JSON when it looks like JSON, and keep the old
// splitting as a fallback for any row written before the storage settled on
// that encoding.
func decodeStringList(s string) []string {
	trimmed := strings.TrimSpace(s)
	if trimmed == "" {
		return nil
	}
	if strings.HasPrefix(trimmed, "[") {
		var out []string
		if err := json.Unmarshal([]byte(trimmed), &out); err == nil {
			cleaned := make([]string, 0, len(out))
			for _, v := range out {
				if v = strings.TrimSpace(v); v != "" {
					cleaned = append(cleaned, v)
				}
			}
			if len(cleaned) == 0 {
				return nil
			}
			return cleaned
		}
		// Malformed JSON: fall through rather than dropping the value
		// entirely, so an admin still sees *something* to debug with.
	}
	return splitNonEmpty(trimmed)
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

// AdminRevokeRequest is the body of a token revocation request.
type AdminRevokeRequest struct {
	// Subject is the user whose grants should be revoked. Matched exactly
	// against the subject recorded on each token row, which is the same
	// value the OAuth2 session carries (typically the username claim, not
	// the schedd's "user@domain" form).
	Subject string `json:"subject"`
}

// AdminRevokeResponse reports what was revoked.
type AdminRevokeResponse struct {
	Subject string `json:"subject"`
	// Revoked counts token rows deactivated across both issuers.
	Revoked int64 `json:"revoked"`
	// OAuth2 and IDP break that count down by issuer, so an operator can
	// tell whether the user held MCP grants, IDP grants, or both.
	OAuth2 int64 `json:"oauth2"`
	IDP    int64 `json:"idp"`
}

// handleAdminRevokeTokens handles POST /api/v1/admin/oauth2/revoke.
//
// It cuts off one user immediately, across every client they have authorized.
// The refresh-time revocation oracles cover the steady state, but they only
// act when the user's client next presents a refresh token, and only when an
// oracle can actually observe the removal — an upstream IDP deleting an
// account is invisible from here. This is the unconditional lever for the
// cases nothing else catches.
//
// Access tokens already issued remain valid until they expire on their own
// (they are self-contained as far as the client is concerned, though this
// server does introspect them against storage, so marking the rows inactive
// does take effect on the next request). What this guarantees is that no new
// tokens can be minted from the user's refresh tokens.
func (s *Handler) handleAdminRevokeTokens(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		s.writeError(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}
	if !s.requireAdmin(w, r) {
		return
	}

	r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
	var req AdminRevokeRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.writeError(w, http.StatusBadRequest, "Invalid request body")
		return
	}
	req.Subject = strings.TrimSpace(req.Subject)
	if req.Subject == "" {
		s.writeError(w, http.StatusBadRequest, "subject is required")
		return
	}

	resp := AdminRevokeResponse{Subject: req.Subject}

	if s.oauth2Provider != nil {
		n, err := s.oauth2Provider.GetStorage().RevokeAllForSubject(r.Context(), req.Subject)
		if err != nil {
			s.logger.Error(logging.DestinationHTTP, "Failed to revoke OAuth2 grants",
				"subject", req.Subject, "error", err)
			s.writeError(w, http.StatusInternalServerError, "Failed to revoke grants")
			return
		}
		resp.OAuth2 = n
	}
	if s.idpProvider != nil {
		n, err := s.idpProvider.GetStorage().RevokeAllForSubject(r.Context(), req.Subject)
		if err != nil {
			s.logger.Error(logging.DestinationHTTP, "Failed to revoke IDP grants",
				"subject", req.Subject, "error", err)
			s.writeError(w, http.StatusInternalServerError, "Failed to revoke grants")
			return
		}
		resp.IDP = n
	}
	resp.Revoked = resp.OAuth2 + resp.IDP

	// Log at Info: this is an administrative action on someone else's
	// access and belongs in the audit trail whether or not it matched
	// anything.
	s.logger.Info(logging.DestinationHTTP, "Administrator revoked OAuth2 grants",
		"subject", req.Subject, "revoked", resp.Revoked,
		"oauth2", resp.OAuth2, "idp", resp.IDP)

	s.writeJSON(w, http.StatusOK, resp)
}
