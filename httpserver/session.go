package httpserver

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"net/http"
	"sync"
	"time"
)

// SessionData represents the data stored in a session
type SessionData struct {
	Username  string    // Authenticated username
	CreatedAt time.Time // When the session was created
	ExpiresAt time.Time // When the session expires
	Token     string    // HTCondor token for this session (optional)
}

// SessionStore manages HTTP sessions
type SessionStore struct {
	mu       sync.RWMutex
	sessions map[string]*SessionData // key is session ID
	ttl      time.Duration           // Session time-to-live
}

// NewSessionStore creates a new session store
func NewSessionStore(ttl time.Duration) *SessionStore {
	if ttl == 0 {
		ttl = 24 * time.Hour // Default: 24 hours
	}
	return &SessionStore{
		sessions: make(map[string]*SessionData),
		ttl:      ttl,
	}
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

	s.mu.Lock()
	s.sessions[sessionID] = session
	s.mu.Unlock()

	return sessionID, session, nil
}

// Get retrieves a session by ID
// Returns nil if session doesn't exist or has expired
func (s *SessionStore) Get(sessionID string) *SessionData {
	s.mu.RLock()
	session, exists := s.sessions[sessionID]
	s.mu.RUnlock()

	if !exists {
		return nil
	}

	// Check if expired
	if time.Now().After(session.ExpiresAt) {
		s.Delete(sessionID)
		return nil
	}

	return session
}

// Delete removes a session
func (s *SessionStore) Delete(sessionID string) {
	s.mu.Lock()
	delete(s.sessions, sessionID)
	s.mu.Unlock()
}

// Cleanup removes expired sessions
func (s *SessionStore) Cleanup() {
	s.mu.Lock()
	defer s.mu.Unlock()

	now := time.Now()
	for id, session := range s.sessions {
		if now.After(session.ExpiresAt) {
			delete(s.sessions, id)
		}
	}
}

// Size returns the number of active sessions
func (s *SessionStore) Size() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.sessions)
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
