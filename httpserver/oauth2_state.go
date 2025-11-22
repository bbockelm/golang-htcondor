package httpserver

import (
	"crypto/rand"
	"encoding/base64"
	"sync"
	"time"

	"github.com/ory/fosite"
)

// OAuth2StateEntry represents a stored OAuth2 authorization state
type OAuth2StateEntry struct {
	AuthorizeRequest fosite.AuthorizeRequester
	Timestamp        time.Time
	OriginalURL      string // Original URL to redirect back to after authentication
	Username         string // Authenticated username for consent flow
}

// OAuth2StateStore manages OAuth2 state parameters for the authorization flow
type OAuth2StateStore struct {
	mu      sync.RWMutex
	entries map[string]*OAuth2StateEntry
}

// NewOAuth2StateStore creates a new OAuth2 state store
func NewOAuth2StateStore() *OAuth2StateStore {
	store := &OAuth2StateStore{
		entries: make(map[string]*OAuth2StateEntry),
	}
	// Start cleanup goroutine
	go store.cleanupExpired()
	return store
}

// GenerateState generates a secure random state parameter
func (s *OAuth2StateStore) GenerateState() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.URLEncoding.EncodeToString(b), nil
}

// Store stores an authorize request with the given state
func (s *OAuth2StateStore) Store(state string, ar fosite.AuthorizeRequester) {
	s.StoreWithURL(state, ar, "")
}

// StoreWithURL stores an authorize request with the given state and original URL
func (s *OAuth2StateStore) StoreWithURL(state string, ar fosite.AuthorizeRequester, originalURL string) {
	s.StoreWithUsername(state, ar, originalURL, "")
}

// StoreWithUsername stores an authorize request with the given state, original URL, and username
func (s *OAuth2StateStore) StoreWithUsername(state string, ar fosite.AuthorizeRequester, originalURL, username string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.entries[state] = &OAuth2StateEntry{
		AuthorizeRequest: ar,
		Timestamp:        time.Now(),
		OriginalURL:      originalURL,
		Username:         username,
	}
}

// Get retrieves and removes an authorize request for the given state
func (s *OAuth2StateStore) Get(state string) (fosite.AuthorizeRequester, bool) {
	ar, _, ok := s.GetWithURL(state)
	return ar, ok
}

// GetWithURL retrieves and removes an authorize request for the given state along with the original URL
func (s *OAuth2StateStore) GetWithURL(state string) (fosite.AuthorizeRequester, string, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	entry, ok := s.entries[state]
	if !ok {
		return nil, "", false
	}
	// Remove entry after retrieval (one-time use)
	delete(s.entries, state)
	return entry.AuthorizeRequest, entry.OriginalURL, true
}

// GetWithUsername retrieves an authorize request for the given state along with username (without removing)
func (s *OAuth2StateStore) GetWithUsername(state string) (fosite.AuthorizeRequester, string, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	entry, ok := s.entries[state]
	if !ok {
		return nil, "", false
	}
	return entry.AuthorizeRequest, entry.Username, true
}

// Remove removes an entry for the given state
func (s *OAuth2StateStore) Remove(state string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.entries, state)
}

// cleanupExpired periodically removes expired state entries
func (s *OAuth2StateStore) cleanupExpired() {
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()

	for range ticker.C {
		s.mu.Lock()
		now := time.Now()
		for state, entry := range s.entries {
			// Remove entries older than 10 minutes
			if now.Sub(entry.Timestamp) > 10*time.Minute {
				delete(s.entries, state)
			}
		}
		s.mu.Unlock()
	}
}
