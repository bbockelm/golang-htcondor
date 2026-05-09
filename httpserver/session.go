package httpserver

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"time"
)

// SessionData represents the data stored in a session.
//
// Note: this struct used to carry a Token field that was reserved for
// per-session HTCondor token storage. The column was never written
// to and the field is gone — the schema migration in
// 0002_envelope_encryption.sql drops `http_sessions.token` to remove
// the unused secret-shaped column. Per-user tokens, when needed,
// flow through the OAuth2 / IDP storage tables instead.
type SessionData struct {
	Username  string    // Authenticated username
	Groups    []string  // User groups from IDP (for scope filtering)
	CreatedAt time.Time // When the session was created
	ExpiresAt time.Time // When the session expires
}

// SessionStore manages HTTP sessions with SQLite persistence
type SessionStore struct {
	db  *sql.DB       // Database connection (shared with OAuth2Storage)
	ttl time.Duration // Session time-to-live
}

// NewSessionStore creates a new session store with database persistence
// The db parameter should be the same database connection used by OAuth2Storage
func NewSessionStore(db *sql.DB, ttl time.Duration) (*SessionStore, error) {
	if ttl == 0 {
		ttl = 24 * time.Hour // Default: 24 hours
	}

	store := &SessionStore{
		db:  db,
		ttl: ttl,
	}

	// Create sessions table if it doesn't exist
	if err := store.createTable(); err != nil {
		return nil, fmt.Errorf("failed to create sessions table: %w", err)
	}

	return store, nil
}

// createTable creates the sessions table in the database. This is
// a fallback for callers who construct a SessionStore against a DB
// that hasn't been put through goose migrations (e.g., a test
// fixture using sql.Open directly). In production the unified
// migration in 0001_init.sql + 0002_envelope_encryption.sql is
// authoritative; this CREATE TABLE IF NOT EXISTS just keeps the
// out-of-band test path working.
func (s *SessionStore) createTable() error {
	schema := `
	CREATE TABLE IF NOT EXISTS http_sessions (
		session_id TEXT PRIMARY KEY,
		username TEXT NOT NULL,
		created_at TIMESTAMP NOT NULL,
		expires_at TIMESTAMP NOT NULL,
		groups_json TEXT,
		updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
	);

	CREATE INDEX IF NOT EXISTS idx_sessions_expires ON http_sessions(expires_at);
	CREATE INDEX IF NOT EXISTS idx_sessions_username ON http_sessions(username);
	`

	ctx := context.Background()
	_, err := s.db.ExecContext(ctx, schema)
	if err != nil {
		return err
	}

	// Migrate existing tables: add groups_json column if it doesn't exist
	_, _ = s.db.ExecContext(ctx, `ALTER TABLE http_sessions ADD COLUMN groups_json TEXT`)

	return nil
}

// generateSessionID generates a cryptographically secure random session ID
func generateSessionID() (string, error) {
	b := make([]byte, 32) // 256 bits
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("failed to generate session ID: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

// Create creates a new session for the given username and groups
func (s *SessionStore) Create(username string, groups ...[]string) (string, *SessionData, error) {
	sessionID, err := generateSessionID()
	if err != nil {
		return "", nil, err
	}

	now := time.Now()
	session := &SessionData{
		Username:  username,
		CreatedAt: now,
		ExpiresAt: now.Add(s.ttl),
	}
	if len(groups) > 0 {
		session.Groups = groups[0]
	}

	// Serialize groups as JSON
	var groupsJSON sql.NullString
	if len(session.Groups) > 0 {
		data, err := json.Marshal(session.Groups)
		if err != nil {
			return "", nil, fmt.Errorf("failed to serialize groups: %w", err)
		}
		groupsJSON = sql.NullString{String: string(data), Valid: true}
	}

	// Store session in database. The `token` column was dropped in
	// migration 0002 — the field was reserved but never populated,
	// and an unused secret-shaped column on disk was a footgun.
	ctx := context.Background()
	_, err = s.db.ExecContext(ctx,
		`INSERT INTO http_sessions (session_id, username, created_at, expires_at, groups_json)
		 VALUES (?, ?, ?, ?, ?)`,
		sessionID, session.Username, session.CreatedAt, session.ExpiresAt, groupsJSON)
	if err != nil {
		return "", nil, fmt.Errorf("failed to store session in database: %w", err)
	}

	return sessionID, session, nil
}

// Get retrieves a session by ID
// Returns nil if session doesn't exist or has expired
func (s *SessionStore) Get(sessionID string) *SessionData {
	ctx := context.Background()

	var session SessionData
	var groupsJSON sql.NullString

	err := s.db.QueryRowContext(ctx,
		`SELECT username, created_at, expires_at, groups_json
		 FROM http_sessions
		 WHERE session_id = ? AND expires_at > ?`,
		sessionID, time.Now()).Scan(&session.Username, &session.CreatedAt, &session.ExpiresAt, &groupsJSON)

	if err != nil {
		// Session not found or expired
		return nil
	}

	if groupsJSON.Valid && groupsJSON.String != "" {
		_ = json.Unmarshal([]byte(groupsJSON.String), &session.Groups)
	}

	return &session
}

// Delete removes a session
func (s *SessionStore) Delete(sessionID string) {
	ctx := context.Background()
	_, _ = s.db.ExecContext(ctx, `DELETE FROM http_sessions WHERE session_id = ?`, sessionID)
}

// Cleanup removes expired sessions
func (s *SessionStore) Cleanup() {
	ctx := context.Background()
	_, _ = s.db.ExecContext(ctx, `DELETE FROM http_sessions WHERE expires_at <= ?`, time.Now())
}

// Size returns the number of active sessions
func (s *SessionStore) Size() int {
	ctx := context.Background()
	var count int
	err := s.db.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM http_sessions WHERE expires_at > ?`,
		time.Now()).Scan(&count)
	if err != nil {
		return 0
	}
	return count
}

// sessionCookieName is the name of the HTTP session cookie
const sessionCookieName = "htcondor_session"

// setSessionCookie sets an HTTP session cookie.
//
// Cookie attributes:
//   - HttpOnly: prevents JS readout (XSS containment).
//   - Secure: only sent over HTTPS.
//   - SameSite=Strict: NOT sent on cross-site requests (top-level
//     navigation OR subresource). The SPA is served from the same
//     origin as the API, so all in-app navigation works. The
//     cross-site impact: a user clicking a bookmark / Slack link to
//     a deep page will appear logged-out and bounce through SSO once
//     before reaching the page (one extra hop, not broken). The
//     IdP-role flow (/idp/* hosted by this server) similarly may
//     pick up an extra hop when a relying party redirects in
//     cross-site; the /idp/login page handles re-authentication.
//
// Strict is preferred over Lax here because Lax still allows
// top-level GET navigation to carry the cookie, which is a CSRF
// foothold for any state-changing endpoint that accidentally
// accepts GET. Switching to Strict closes that class of bug at the
// cookie layer rather than relying on per-endpoint method checks.
func (s *Handler) setSessionCookie(w http.ResponseWriter, sessionID string, expiresAt time.Time) {
	// Determine if we should use Secure flag (HTTPS only)
	// In production, sessions should only be transmitted over HTTPS
	secure := true // Default to secure
	// TODO: Could make this configurable via Server.Config

	cookie := &http.Cookie{
		Name:     sessionCookieName,
		Value:    sessionID,
		Path:     "/",
		Expires:  expiresAt,
		MaxAge:   int(time.Until(expiresAt).Seconds()),
		HttpOnly: true,                    // Prevent JavaScript access
		Secure:   secure,                  // HTTPS only in production
		SameSite: http.SameSiteStrictMode, // CSRF — see doc comment
	}

	http.SetCookie(w, cookie)
}

// getSessionCookie retrieves the session cookie from the request
func getSessionCookie(r *http.Request) (string, error) {
	cookie, err := r.Cookie(sessionCookieName)
	if err != nil {
		return "", err
	}
	return cookie.Value, nil
}

// clearSessionCookie clears the session cookie.
// SameSite must match setSessionCookie so the browser correctly
// scopes the deletion request to a same-site response.
func (s *Handler) clearSessionCookie(w http.ResponseWriter) {
	cookie := &http.Cookie{
		Name:     sessionCookieName,
		Value:    "",
		Path:     "/",
		MaxAge:   -1, // Delete cookie
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteStrictMode,
	}
	http.SetCookie(w, cookie)
}

// getSessionFromRequest extracts session data from the request
// Returns the session data and true if a valid session exists
func (s *Handler) getSessionFromRequest(r *http.Request) (*SessionData, bool) {
	sessionID, err := getSessionCookie(r)
	if err != nil {
		return nil, false
	}

	if s.sessionStore == nil {
		return nil, false
	}

	session := s.sessionStore.Get(sessionID)
	if session == nil {
		return nil, false
	}

	return session, true
}
