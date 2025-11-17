// Package ratelimit provides rate limiting capabilities for HTCondor queries.
// It implements both global and per-user rate limiting with support for
// HTCondor configuration parameters.
package ratelimit

import (
	"context"
	"errors"
	"fmt"
	"sync"

	"golang.org/x/time/rate"
)

// Error represents a rate limiting error
type Error struct {
	Message string
}

func (e *Error) Error() string {
	return e.Message
}

// IsRateLimitError checks if an error is a rate limit error
func IsRateLimitError(err error) bool {
	var rateLimitErr *Error
	return errors.As(err, &rateLimitErr)
}

// Limiter provides rate limiting with both global and per-user limits
type Limiter struct {
	// Global rate limiter for all requests
	globalLimiter *rate.Limiter
	// Per-user rate limiters
	userLimiters map[string]*rate.Limiter
	mu           sync.RWMutex
	// Rate limit for individual users (requests per second)
	perUserRate float64
	// Burst size for individual users
	perUserBurst int
}

// NewLimiter creates a new rate limiter with specified rates
// globalRate: requests per second for all requests (0 = unlimited)
// perUserRate: requests per second per user (0 = unlimited)
func NewLimiter(globalRate, perUserRate float64) *Limiter {
	var globalLimiter *rate.Limiter
	if globalRate > 0 {
		// Use burst size of 2x the rate to allow short bursts
		burst := int(globalRate * 2)
		if burst < 1 {
			burst = 1
		}
		globalLimiter = rate.NewLimiter(rate.Limit(globalRate), burst)
	}

	perUserBurst := 1
	if perUserRate > 0 {
		perUserBurst = int(perUserRate * 2)
		if perUserBurst < 1 {
			perUserBurst = 1
		}
	}

	return &Limiter{
		globalLimiter: globalLimiter,
		userLimiters:  make(map[string]*rate.Limiter),
		perUserRate:   perUserRate,
		perUserBurst:  perUserBurst,
	}
}

// getUserLimiter gets or creates a rate limiter for a specific user
func (l *Limiter) getUserLimiter(username string) *rate.Limiter {
	if l.perUserRate <= 0 {
		return nil
	}

	l.mu.RLock()
	limiter, exists := l.userLimiters[username]
	l.mu.RUnlock()

	if exists {
		return limiter
	}

	// Create new limiter for this user
	l.mu.Lock()
	defer l.mu.Unlock()

	// Double-check after acquiring write lock
	if limiter, exists := l.userLimiters[username]; exists {
		return limiter
	}

	limiter = rate.NewLimiter(rate.Limit(l.perUserRate), l.perUserBurst)
	l.userLimiters[username] = limiter
	return limiter
}

// Allow checks if a request from the given username should be allowed
// Returns an error if rate limit is exceeded
func (l *Limiter) Allow(username string) error {
	if username == "" {
		username = "unauthenticated"
	}

	// Check global limit first
	if l.globalLimiter != nil {
		if !l.globalLimiter.Allow() {
			return &Error{Message: "global rate limit exceeded"}
		}
	}

	// Check per-user limit
	if l.perUserRate > 0 {
		userLimiter := l.getUserLimiter(username)
		if userLimiter != nil && !userLimiter.Allow() {
			return &Error{Message: fmt.Sprintf("rate limit exceeded for user %s", username)}
		}
	}

	return nil
}

// Wait blocks until a request from the given username is allowed or context is cancelled
// Returns an error if context is cancelled
func (l *Limiter) Wait(ctx context.Context, username string) error {
	if username == "" {
		username = "unauthenticated"
	}

	// Wait for global limit
	if l.globalLimiter != nil {
		if err := l.globalLimiter.Wait(ctx); err != nil {
			return &Error{Message: fmt.Sprintf("global rate limit wait cancelled: %v", err)}
		}
	}

	// Wait for per-user limit
	if l.perUserRate > 0 {
		userLimiter := l.getUserLimiter(username)
		if userLimiter != nil {
			if err := userLimiter.Wait(ctx); err != nil {
				return &Error{Message: fmt.Sprintf("rate limit wait cancelled for user %s: %v", username, err)}
			}
		}
	}

	return nil
}

// Reset clears all per-user rate limiters
// This is useful for testing or periodic cleanup
func (l *Limiter) Reset() {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.userLimiters = make(map[string]*rate.Limiter)
}

// Stats returns statistics about the rate limiter
type Stats struct {
	GlobalRate   float64
	PerUserRate  float64
	UserCount    int
	GlobalTokens float64
	GlobalBurst  int
	PerUserBurst int
}

// GetStats returns current statistics about the rate limiter
func (l *Limiter) GetStats() Stats {
	l.mu.RLock()
	defer l.mu.RUnlock()

	stats := Stats{
		PerUserRate:  l.perUserRate,
		PerUserBurst: l.perUserBurst,
		UserCount:    len(l.userLimiters),
	}

	if l.globalLimiter != nil {
		stats.GlobalRate = float64(l.globalLimiter.Limit())
		stats.GlobalBurst = l.globalLimiter.Burst()
		stats.GlobalTokens = l.globalLimiter.Tokens()
	}

	return stats
}

// Manager manages separate rate limiters for schedd and collector queries
type Manager struct {
	scheddLimiter    *Limiter
	collectorLimiter *Limiter
}

// NewManager creates a new rate limiter manager
func NewManager(scheddGlobalRate, scheddPerUserRate, collectorGlobalRate, collectorPerUserRate float64) *Manager {
	return &Manager{
		scheddLimiter:    NewLimiter(scheddGlobalRate, scheddPerUserRate),
		collectorLimiter: NewLimiter(collectorGlobalRate, collectorPerUserRate),
	}
}

// AllowSchedd checks if a schedd query from the given username should be allowed
func (m *Manager) AllowSchedd(username string) error {
	return m.scheddLimiter.Allow(username)
}

// WaitSchedd blocks until a schedd query from the given username is allowed
func (m *Manager) WaitSchedd(ctx context.Context, username string) error {
	return m.scheddLimiter.Wait(ctx, username)
}

// AllowCollector checks if a collector query from the given username should be allowed
func (m *Manager) AllowCollector(username string) error {
	return m.collectorLimiter.Allow(username)
}

// WaitCollector blocks until a collector query from the given username is allowed
func (m *Manager) WaitCollector(ctx context.Context, username string) error {
	return m.collectorLimiter.Wait(ctx, username)
}

// GetScheddStats returns statistics for the schedd rate limiter
func (m *Manager) GetScheddStats() Stats {
	return m.scheddLimiter.GetStats()
}

// GetCollectorStats returns statistics for the collector rate limiter
func (m *Manager) GetCollectorStats() Stats {
	return m.collectorLimiter.GetStats()
}

// ResetAll resets all rate limiters
func (m *Manager) ResetAll() {
	m.scheddLimiter.Reset()
	m.collectorLimiter.Reset()
}
