package droppriv

import (
	"context"
	"fmt"
	"sync"
	"time"
)

// UserInfo contains user and group information.
type UserInfo struct {
	UID       uint32
	GID       uint32
	Username  string
	Groupname string
	HomeDir   string
	Shell     string
}

// LookupStrategy defines the interface for UID/GID lookup implementations.
type LookupStrategy interface {
	// LookupUser looks up a user by username and returns user info.
	LookupUser(ctx context.Context, username string) (*UserInfo, error)

	// Name returns the name of this lookup strategy.
	Name() string
}

// cacheEntry stores cached lookup results with expiration.
type cacheEntry struct {
	info      *UserInfo
	expiresAt time.Time
}

// CachedLookup wraps a lookup strategy with caching.
type CachedLookup struct {
	strategy LookupStrategy
	cache    map[string]*cacheEntry
	cacheTTL time.Duration
	mu       sync.RWMutex
}

// NewCachedLookup creates a new cached lookup with the given strategy and TTL.
func NewCachedLookup(strategy LookupStrategy, ttl time.Duration) *CachedLookup {
	return &CachedLookup{
		strategy: strategy,
		cache:    make(map[string]*cacheEntry),
		cacheTTL: ttl,
	}
}

// LookupUser looks up a user, using cache if available.
func (c *CachedLookup) LookupUser(ctx context.Context, username string) (*UserInfo, error) {
	// Try cache first
	c.mu.RLock()
	if entry, ok := c.cache[username]; ok && time.Now().Before(entry.expiresAt) {
		c.mu.RUnlock()
		return entry.info, nil
	}
	c.mu.RUnlock()

	// Cache miss or expired, do actual lookup
	info, err := c.strategy.LookupUser(ctx, username)
	if err != nil {
		return nil, err
	}

	// Store in cache
	c.mu.Lock()
	c.cache[username] = &cacheEntry{
		info:      info,
		expiresAt: time.Now().Add(c.cacheTTL),
	}
	c.mu.Unlock()

	return info, nil
}

// Name returns the name of the underlying strategy.
func (c *CachedLookup) Name() string {
	return c.strategy.Name()
}

// ClearCache clears all cached entries.
func (c *CachedLookup) ClearCache() {
	c.mu.Lock()
	c.cache = make(map[string]*cacheEntry)
	c.mu.Unlock()
}

// defaultLookup is the global lookup instance, initialized on first use.
var (
	defaultLookup     LookupStrategy
	defaultLookupOnce sync.Once
)

// DefaultLookup returns the default lookup strategy for the system.
func DefaultLookup() LookupStrategy {
	defaultLookupOnce.Do(func() {
		defaultLookup = NewCachedLookup(selectBestStrategy(), time.Minute)
	})
	return defaultLookup
}

// selectBestStrategy is defined in uidgid_select.go and uidgid_select_nocgo.go
// with different implementations based on CGO availability.

// LookupUser is a convenience function using the default lookup strategy.
func LookupUser(ctx context.Context, username string) (*UserInfo, error) {
	return DefaultLookup().LookupUser(ctx, username)
}

// ErrUserNotFound is returned when a user is not found.
type ErrUserNotFound struct {
	Username string
}

func (e *ErrUserNotFound) Error() string {
	return fmt.Sprintf("user not found: %s", e.Username)
}
