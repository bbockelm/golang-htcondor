package httpserver

import (
	"container/list"
	"context"
	"crypto/rand"
	"encoding/base64"
	"sync"
	"time"

	"github.com/ory/fosite"
)

// Limits on the state store. Entries are created by unauthenticated
// requests (any logged-out page view that starts a login), so neither
// their number nor their size may be left to the caller.
const (
	// oauth2StateLifetime is how long a state may wait for its callback.
	oauth2StateLifetime = 10 * time.Minute
	// maxOAuth2StateEntries bounds the number of pending states; the
	// oldest are evicted beyond it.
	maxOAuth2StateEntries = 10000
	// maxOAuth2StateBytes bounds their approximate total size, since an
	// authorize request carries its whole query string.
	maxOAuth2StateBytes = 32 << 20
	// maxOAuth2StateURLLen bounds the return URL kept with a state. A
	// longer one is dropped and the login returns to "/".
	maxOAuth2StateURLLen = 2048
)

// OAuth2StateEntry represents a stored OAuth2 authorization state
type OAuth2StateEntry struct {
	AuthorizeRequest fosite.AuthorizeRequester
	Timestamp        time.Time
	OriginalURL      string   // Original URL to redirect back to after authentication
	Username         string   // Authenticated username for consent flow
	Groups           []string // User groups for scope filtering in consent flow
	// BrowserBinding is the login-binding nonce held in a cookie by the
	// browser that started this login (see login_binding.go). The SSO
	// callback accepts the state only from a browser presenting it.
	// Empty for states that are not a round trip through the IdP.
	BrowserBinding string

	state string        // key, for eviction
	size  int           // approximate bytes held, for the size budget
	elem  *list.Element // position in OAuth2StateStore.order
}

// OAuth2StateStore manages OAuth2 state parameters for the authorization flow
type OAuth2StateStore struct {
	mu         sync.RWMutex
	entries    map[string]*OAuth2StateEntry
	order      *list.List // *OAuth2StateEntry, oldest first
	bytes      int        // sum of entry sizes
	maxEntries int
	maxBytes   int
	wg         sync.WaitGroup // Track cleanup goroutine
}

// NewOAuth2StateStore creates a new OAuth2 state store
// Call Start() to begin the cleanup goroutine
func NewOAuth2StateStore() *OAuth2StateStore {
	return &OAuth2StateStore{
		entries:    make(map[string]*OAuth2StateEntry),
		order:      list.New(),
		maxEntries: maxOAuth2StateEntries,
		maxBytes:   maxOAuth2StateBytes,
	}
}

// Start begins the cleanup goroutine
func (s *OAuth2StateStore) Start(ctx context.Context) {
	s.wg.Add(1)
	go s.cleanupExpired(ctx)
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
func (s *OAuth2StateStore) StoreWithUsername(state string, ar fosite.AuthorizeRequester, originalURL, username string, groups ...[]string) {
	entry := &OAuth2StateEntry{
		AuthorizeRequest: ar,
		OriginalURL:      originalURL,
		Username:         username,
	}
	if len(groups) > 0 {
		entry.Groups = groups[0]
	}
	s.insert(state, entry)
}

// StoreForBrowser stores the state of a login that leaves for the IdP
// and comes back through the SSO callback. binding is the nonce the
// starting browser was given; the callback requires it back.
func (s *OAuth2StateStore) StoreForBrowser(state string, ar fosite.AuthorizeRequester, originalURL, binding string) {
	s.insert(state, &OAuth2StateEntry{
		AuthorizeRequest: ar,
		OriginalURL:      originalURL,
		BrowserBinding:   binding,
	})
}

// insert adds entry under state, evicting the oldest entries while the
// store is over its count or size limit.
func (s *OAuth2StateStore) insert(state string, entry *OAuth2StateEntry) {
	if len(entry.OriginalURL) > maxOAuth2StateURLLen {
		entry.OriginalURL = ""
	}
	entry.state = state
	entry.size = len(state) + len(entry.OriginalURL) + len(entry.Username) + len(entry.BrowserBinding)
	for _, g := range entry.Groups {
		entry.size += len(g)
	}
	if entry.AuthorizeRequest != nil {
		for k, vs := range entry.AuthorizeRequest.GetRequestForm() {
			for _, v := range vs {
				entry.size += len(k) + len(v)
			}
		}
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	entry.Timestamp = time.Now() // under the lock, so order is also age order
	if old, ok := s.entries[state]; ok {
		s.removeLocked(old)
	}
	for s.order.Len() > 0 && (s.order.Len() >= s.maxEntries || s.bytes+entry.size > s.maxBytes) {
		s.removeLocked(s.order.Front().Value.(*OAuth2StateEntry))
	}
	entry.elem = s.order.PushBack(entry)
	s.entries[state] = entry
	s.bytes += entry.size
}

// removeLocked drops entry from the store. Caller holds s.mu.
func (s *OAuth2StateStore) removeLocked(entry *OAuth2StateEntry) {
	delete(s.entries, entry.state)
	s.order.Remove(entry.elem)
	s.bytes -= entry.size
}

// Take retrieves and removes the entry for state (one-time use).
func (s *OAuth2StateStore) Take(state string) (*OAuth2StateEntry, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	entry, ok := s.entries[state]
	if !ok {
		return nil, false
	}
	s.removeLocked(entry)
	return entry, true
}

// Len returns the number of pending states.
func (s *OAuth2StateStore) Len() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.entries)
}

// Get retrieves and removes an authorize request for the given state
func (s *OAuth2StateStore) Get(state string) (fosite.AuthorizeRequester, bool) {
	ar, _, ok := s.GetWithURL(state)
	return ar, ok
}

// GetWithURL retrieves and removes an authorize request for the given state along with the original URL
func (s *OAuth2StateStore) GetWithURL(state string) (fosite.AuthorizeRequester, string, bool) {
	entry, ok := s.Take(state)
	if !ok {
		return nil, "", false
	}
	return entry.AuthorizeRequest, entry.OriginalURL, true
}

// GetWithUsername retrieves an authorize request for the given state along with username and groups (without removing)
func (s *OAuth2StateStore) GetWithUsername(state string) (fosite.AuthorizeRequester, string, []string, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	entry, ok := s.entries[state]
	if !ok {
		return nil, "", nil, false
	}
	return entry.AuthorizeRequest, entry.Username, entry.Groups, true
}

// Remove removes an entry for the given state
func (s *OAuth2StateStore) Remove(state string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if entry, ok := s.entries[state]; ok {
		s.removeLocked(entry)
	}
}

// cleanupExpired periodically removes expired state entries
func (s *OAuth2StateStore) cleanupExpired(ctx context.Context) {
	defer s.wg.Done()

	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			s.mu.Lock()
			now := time.Now()
			// Oldest first, so stop at the first one still live.
			for s.order.Len() > 0 {
				entry := s.order.Front().Value.(*OAuth2StateEntry)
				if now.Sub(entry.Timestamp) <= oauth2StateLifetime {
					break
				}
				s.removeLocked(entry)
			}
			s.mu.Unlock()
		}
	}
}

// Wait waits for the cleanup goroutine to finish
func (s *OAuth2StateStore) Wait() {
	s.wg.Wait()
}
