package httpserver

import (
	"database/sql"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	_ "github.com/glebarez/sqlite"
)

// createTestSessionStore creates a session store with an in-memory database for testing
func createTestSessionStore(t *testing.T, ttl time.Duration) *SessionStore {
	t.Helper()
	
	// Use in-memory database for tests
	db, err := sql.Open("sqlite", ":memory:")
	if err != nil {
		t.Fatalf("Failed to open test database: %v", err)
	}
	
	store, err := NewSessionStore(db, ttl)
	if err != nil {
		t.Fatalf("Failed to create session store: %v", err)
	}
	
	return store
}

func TestSessionStore(t *testing.T) {
	store := createTestSessionStore(t, 1*time.Hour)

	// Test Create
	sessionID, session, err := store.Create("testuser")
	if err != nil {
		t.Fatalf("Failed to create session: %v", err)
	}

	if session.Username != "testuser" {
		t.Errorf("Expected username 'testuser', got '%s'", session.Username)
	}

	if sessionID == "" {
		t.Error("Session ID should not be empty")
	}

	if session.ExpiresAt.Before(time.Now()) {
		t.Error("Session should not be expired immediately after creation")
	}

	// Test Get
	retrieved := store.Get(sessionID)
	if retrieved == nil {
		t.Fatal("Failed to retrieve session")
	}

	if retrieved.Username != "testuser" {
		t.Errorf("Expected username 'testuser', got '%s'", retrieved.Username)
	}

	// Test Delete
	store.Delete(sessionID)
	if retrieved := store.Get(sessionID); retrieved != nil {
		t.Error("Session should be deleted")
	}

	// Test Size
	if store.Size() != 0 {
		t.Errorf("Expected 0 sessions, got %d", store.Size())
	}
}

func TestSessionStoreExpiration(t *testing.T) {
	store := createTestSessionStore(t, 100*time.Millisecond)

	sessionID, _, err := store.Create("testuser")
	if err != nil {
		t.Fatalf("Failed to create session: %v", err)
	}

	// Session should be retrievable immediately
	if session := store.Get(sessionID); session == nil {
		t.Fatal("Session should be retrievable immediately after creation")
	}

	// Wait for expiration
	time.Sleep(150 * time.Millisecond)

	// Session should be expired
	if session := store.Get(sessionID); session != nil {
		t.Error("Session should be expired")
	}
}

func TestSessionStoreCleanup(t *testing.T) {
	store := createTestSessionStore(t, 100*time.Millisecond)

	// Create multiple sessions
	for i := 0; i < 5; i++ {
		_, _, err := store.Create("user")
		if err != nil {
			t.Fatalf("Failed to create session: %v", err)
		}
	}

	if store.Size() != 5 {
		t.Errorf("Expected 5 sessions, got %d", store.Size())
	}

	// Wait for expiration
	time.Sleep(150 * time.Millisecond)

	// Cleanup
	store.Cleanup()

	if store.Size() != 0 {
		t.Errorf("Expected 0 sessions after cleanup, got %d", store.Size())
	}
}

func TestGenerateSessionID(t *testing.T) {
	// Test that session IDs are unique
	ids := make(map[string]bool)
	for i := 0; i < 100; i++ {
		id, err := generateSessionID()
		if err != nil {
			t.Fatalf("Failed to generate session ID: %v", err)
		}
		if ids[id] {
			t.Errorf("Duplicate session ID generated: %s", id)
		}
		ids[id] = true
	}
}

func TestSessionCookie(t *testing.T) {
	// Create a test server with a temporary database
	tempDir := t.TempDir()
	cfg := Config{
		ListenAddr:   "127.0.0.1:0",
		ScheddName:   "test",
		ScheddAddr:   "127.0.0.1:9618",
		SessionTTL:   1 * time.Hour,
		OAuth2DBPath: tempDir + "/test.db", // Use temp dir for database
	}

	server, err := NewServer(cfg)
	if err != nil {
		t.Fatalf("Failed to create server: %v", err)
	}

	// Test setSessionCookie
	w := httptest.NewRecorder()
	sessionID := "test-session-id"
	expiresAt := time.Now().Add(1 * time.Hour)

	server.setSessionCookie(w, sessionID, expiresAt)

	cookies := w.Result().Cookies()
	if len(cookies) != 1 {
		t.Fatalf("Expected 1 cookie, got %d", len(cookies))
	}

	cookie := cookies[0]
	if cookie.Name != sessionCookieName {
		t.Errorf("Expected cookie name '%s', got '%s'", sessionCookieName, cookie.Name)
	}
	if cookie.Value != sessionID {
		t.Errorf("Expected cookie value '%s', got '%s'", sessionID, cookie.Value)
	}
	if !cookie.HttpOnly {
		t.Error("Cookie should be HttpOnly")
	}
	if !cookie.Secure {
		t.Error("Cookie should be Secure")
	}
	if cookie.SameSite != http.SameSiteLaxMode {
		t.Errorf("Expected SameSite=Lax, got %v", cookie.SameSite)
	}

	// Test getSessionCookie
	req := httptest.NewRequest("GET", "/", nil)
	req.AddCookie(&http.Cookie{
		Name:  sessionCookieName,
		Value: sessionID,
	})

	retrievedID, err := getSessionCookie(req)
	if err != nil {
		t.Fatalf("Failed to get session cookie: %v", err)
	}
	if retrievedID != sessionID {
		t.Errorf("Expected session ID '%s', got '%s'", sessionID, retrievedID)
	}
}

func TestGetSessionFromRequest(t *testing.T) {
	// Create a test server with a temporary database
	tempDir := t.TempDir()
	cfg := Config{
		ListenAddr:   "127.0.0.1:0",
		ScheddName:   "test",
		ScheddAddr:   "127.0.0.1:9618",
		SessionTTL:   1 * time.Hour,
		OAuth2DBPath: tempDir + "/test.db", // Use temp dir for database
	}

	server, err := NewServer(cfg)
	if err != nil {
		t.Fatalf("Failed to create server: %v", err)
	}

	// Create a session
	sessionID, session, err := server.sessionStore.Create("testuser")
	if err != nil {
		t.Fatalf("Failed to create session: %v", err)
	}

	// Test with valid session cookie
	req := httptest.NewRequest("GET", "/", nil)
	req.AddCookie(&http.Cookie{
		Name:  sessionCookieName,
		Value: sessionID,
	})

	retrievedSession, ok := server.getSessionFromRequest(req)
	if !ok {
		t.Fatal("Failed to get session from request")
	}
	if retrievedSession.Username != session.Username {
		t.Errorf("Expected username '%s', got '%s'", session.Username, retrievedSession.Username)
	}

	// Test with invalid session cookie
	req = httptest.NewRequest("GET", "/", nil)
	req.AddCookie(&http.Cookie{
		Name:  sessionCookieName,
		Value: "invalid-session-id",
	})

	_, ok = server.getSessionFromRequest(req)
	if ok {
		t.Error("Should not get session with invalid session ID")
	}

	// Test with no session cookie
	req = httptest.NewRequest("GET", "/", nil)
	_, ok = server.getSessionFromRequest(req)
	if ok {
		t.Error("Should not get session when no cookie is present")
	}
}

func TestClearSessionCookie(t *testing.T) {
	// Create a test server with a temporary database
	tempDir := t.TempDir()
	cfg := Config{
		ListenAddr:   "127.0.0.1:0",
		ScheddName:   "test",
		ScheddAddr:   "127.0.0.1:9618",
		SessionTTL:   1 * time.Hour,
		OAuth2DBPath: tempDir + "/test.db", // Use temp dir for database
	}

	server, err := NewServer(cfg)
	if err != nil {
		t.Fatalf("Failed to create server: %v", err)
	}

	w := httptest.NewRecorder()
	server.clearSessionCookie(w)

	cookies := w.Result().Cookies()
	if len(cookies) != 1 {
		t.Fatalf("Expected 1 cookie, got %d", len(cookies))
	}

	cookie := cookies[0]
	if cookie.Name != sessionCookieName {
		t.Errorf("Expected cookie name '%s', got '%s'", sessionCookieName, cookie.Name)
	}
	if cookie.Value != "" {
		t.Errorf("Expected empty cookie value, got '%s'", cookie.Value)
	}
	if cookie.MaxAge != -1 {
		t.Errorf("Expected MaxAge=-1, got %d", cookie.MaxAge)
	}
}
