package httpserver

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/base64"
	"fmt"
	"net/http"
	"time"
)

// SessionData represents the data stored in a session
type SessionData struct {
	Username  string    // Authenticated username
	CreatedAt time.Time // When the session was created
	ExpiresAt time.Time // When the session expires
	Token     string    // HTCondor token for this session (optional)
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

// createTable creates the sessions table in the database
func (s *SessionStore) createTable() error {
	schema := `
	CREATE TABLE IF NOT EXISTS http_sessions (
		session_id TEXT PRIMARY KEY,
		username TEXT NOT NULL,
		created_at TIMESTAMP NOT NULL,
		expires_at TIMESTAMP NOT NULL,
		token TEXT,
		updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
	);

	CREATE INDEX IF NOT EXISTS idx_sessions_expires ON http_sessions(expires_at);
	CREATE INDEX IF NOT EXISTS idx_sessions_username ON http_sessions(username);
	`

	_, err := s.db.ExecContext(context.Background(), schema)
	return err
}

// generateSessionID generates a cryptographically secure random session ID
func generateSessionID() (string, error) {
	b := make([]byte, 32) // 256 bits
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("failed to generate session ID: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

// Create creates a new session for the given username
func (s *SessionStore) Create(username string) (string, *SessionData, error) {
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

	// Store session in database
	ctx := context.Background()
	_, err = s.db.ExecContext(ctx,
		`INSERT INTO http_sessions (session_id, username, created_at, expires_at, token)
		 VALUES (?, ?, ?, ?, ?)`,
		sessionID, session.Username, session.CreatedAt, session.ExpiresAt, session.Token)
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
	var token sql.NullString

	err := s.db.QueryRowContext(ctx,
		`SELECT username, created_at, expires_at, token
		 FROM http_sessions
		 WHERE session_id = ? AND expires_at > ?`,
		sessionID, time.Now()).Scan(&session.Username, &session.CreatedAt, &session.ExpiresAt, &token)

	if err != nil {
		// Session not found or expired
		return nil
	}

	if token.Valid {
		session.Token = token.String
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

// setSessionCookie sets an HTTP session cookie
func (s *Server) setSessionCookie(w http.ResponseWriter, sessionID string, expiresAt time.Time) {
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
		HttpOnly: true,                 // Prevent JavaScript access
		Secure:   secure,               // HTTPS only in production
		SameSite: http.SameSiteLaxMode, // CSRF protection
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

// clearSessionCookie clears the session cookie
func (s *Server) clearSessionCookie(w http.ResponseWriter) {
	cookie := &http.Cookie{
		Name:     sessionCookieName,
		Value:    "",
		Path:     "/",
		MaxAge:   -1, // Delete cookie
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteLaxMode,
	}
	http.SetCookie(w, cookie)
}

// getSessionFromRequest extracts session data from the request
// Returns the session data and true if a valid session exists
func (s *Server) getSessionFromRequest(r *http.Request) (*SessionData, bool) {
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
