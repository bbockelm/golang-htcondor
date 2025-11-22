// Package httpserver provides HTTP API handlers for HTCondor operations.
package httpserver

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/bbockelm/cedar/security"
	htcondor "github.com/bbockelm/golang-htcondor"
	jwt "github.com/golang-jwt/jwt/v5"
)

// authContextKey is the type for the authentication context key
type authContextKey struct{}

// WithToken creates a context that includes authentication token information
// This sets up the security configuration for cedar to use TOKEN authentication
func WithToken(ctx context.Context, token string) context.Context {
	return context.WithValue(ctx, authContextKey{}, token)
}

// GetTokenFromContext retrieves the token from the context
func GetTokenFromContext(ctx context.Context) (string, bool) {
	token, ok := ctx.Value(authContextKey{}).(string)
	return token, ok
}

// ConfigureSecurityForToken configures security settings to use the provided token
// This is a helper function to set up cedar's security configuration for TOKEN authentication
func ConfigureSecurityForToken(token string) (*security.SecurityConfig, error) {
	return ConfigureSecurityForTokenWithCache(token, nil)
}

// ConfigureSecurityForTokenWithCache configures security settings with an optional session cache
// If sessionCache is nil, the global cache will be used
func ConfigureSecurityForTokenWithCache(token string, sessionCache *security.SessionCache) (*security.SecurityConfig, error) {
	if token == "" {
		return nil, fmt.Errorf("empty token provided")
	}

	// Create a security configuration that uses TOKEN authentication
	// The token content is stored in TokenFile field (cedar supports both file paths and direct content)
	secConfig := &security.SecurityConfig{
		AuthMethods:    []security.AuthMethod{security.AuthToken},
		Authentication: security.SecurityRequired,
		CryptoMethods:  []security.CryptoMethod{security.CryptoAES},
		Encryption:     security.SecurityOptional,
		Integrity:      security.SecurityOptional,
		Token:          token,
		SessionCache:   sessionCache, // Use provided cache or nil for global
	}

	return secConfig, nil
}

// GetSecurityConfigFromToken retrieves the token from context and creates a SecurityConfig
// This is a convenience function for HTTP handlers to convert context token to SecurityConfig
func GetSecurityConfigFromToken(ctx context.Context) (*security.SecurityConfig, error) {
	token, ok := GetTokenFromContext(ctx)
	if !ok || token == "" {
		return nil, fmt.Errorf("no token in context")
	}

	return ConfigureSecurityForToken(token)
}

// GetScheddWithToken creates a schedd connection configured with token authentication
// This wraps the schedd to use token authentication from context
//
//nolint:revive // ctx parameter reserved for future use
func GetScheddWithToken(ctx context.Context, schedd *htcondor.Schedd) (*htcondor.Schedd, error) {
	// For now, we return the schedd as-is since the authentication is handled
	// at the cedar level during connection establishment. In the future, we may
	// need to extend the htcondor.Schedd API to accept SecurityConfig directly.
	//
	// TODO: Extend htcondor.Schedd to accept SecurityConfig or token in Query/Submit methods
	return schedd, nil
}

// TokenCacheEntry represents a cached token with its expiration and associated session cache
type TokenCacheEntry struct {
	Token         string
	Username      string // Username extracted from JWT (for rate limiting)
	Expiration    time.Time
	SessionCache  *security.SessionCache
	expiryTimer   *time.Timer
	cancelCleanup func()
}

// TokenCache manages validated tokens and their associated session caches
type TokenCache struct {
	mu      sync.RWMutex
	entries map[string]*TokenCacheEntry // key is the token string
}

// NewTokenCache creates a new token cache
func NewTokenCache() *TokenCache {
	return &TokenCache{
		entries: make(map[string]*TokenCacheEntry),
	}
}

// parseJWTClaims extracts username and expiration from a JWT token using the JWT library
// Returns the username, expiration time, or an error if parsing fails
func parseJWTClaims(token string) (username string, expiration time.Time, err error) {
	// Parse the token without verification (we just need to read claims)
	parser := jwt.NewParser(jwt.WithoutClaimsValidation())
	parsedToken, _, parseErr := parser.ParseUnverified(token, &jwt.RegisteredClaims{})
	if parseErr != nil {
		return "", time.Time{}, fmt.Errorf("failed to parse JWT: %w", parseErr)
	}

	// Extract standard claims
	claims, ok := parsedToken.Claims.(*jwt.RegisteredClaims)
	if !ok {
		return "", time.Time{}, fmt.Errorf("failed to extract JWT claims")
	}

	// Check if subject is set
	if claims.Subject == "" {
		return "", time.Time{}, fmt.Errorf("JWT missing sub claim")
	}

	// Check if expiration is set
	if claims.ExpiresAt == nil {
		return "", time.Time{}, fmt.Errorf("JWT missing exp claim")
	}

	return claims.Subject, claims.ExpiresAt.Time, nil
}

// Add adds a validated token to the cache with a session cache
// If the token is already in the cache, returns the existing entry
// Automatically schedules cleanup when the token expires
func (tc *TokenCache) Add(token string) (*TokenCacheEntry, error) {
	tc.mu.Lock()
	defer tc.mu.Unlock()

	// Check if already cached
	if entry, exists := tc.entries[token]; exists {
		// Check if expired
		if time.Now().After(entry.Expiration) {
			// Remove expired entry
			delete(tc.entries, token)
		} else {
			return entry, nil
		}
	}

	// Parse token to get username and expiration
	username, expiration, err := parseJWTClaims(token)
	if err != nil {
		return nil, fmt.Errorf("failed to parse token claims: %w", err)
	}

	// Check if already expired
	if time.Now().After(expiration) {
		return nil, fmt.Errorf("token is already expired")
	}

	// Create a new session cache for this token
	sessionCache := security.NewSessionCache()

	// Create context for cleanup goroutine
	ctx, cancel := context.WithCancel(context.Background())

	entry := &TokenCacheEntry{
		Token:         token,
		Username:      username,
		Expiration:    expiration,
		SessionCache:  sessionCache,
		cancelCleanup: cancel,
	}

	// Schedule automatic cleanup when token expires
	duration := time.Until(expiration)
	entry.expiryTimer = time.AfterFunc(duration, func() {
		tc.Remove(token)
	})

	tc.entries[token] = entry
	_ = ctx // Silence unused variable warning

	return entry, nil
}

// Get retrieves a token cache entry if it exists and is not expired
func (tc *TokenCache) Get(token string) (*TokenCacheEntry, bool) {
	tc.mu.RLock()
	defer tc.mu.RUnlock()

	entry, exists := tc.entries[token]
	if !exists {
		return nil, false
	}

	// Check if expired
	if time.Now().After(entry.Expiration) {
		return nil, false
	}

	return entry, true
}

// Remove removes a token from the cache and cancels its cleanup timer
func (tc *TokenCache) Remove(token string) {
	tc.mu.Lock()
	defer tc.mu.Unlock()

	entry, exists := tc.entries[token]
	if !exists {
		return
	}

	// Cancel the expiry timer
	if entry.expiryTimer != nil {
		entry.expiryTimer.Stop()
	}

	// Cancel the cleanup goroutine context
	if entry.cancelCleanup != nil {
		entry.cancelCleanup()
	}

	delete(tc.entries, token)
}

// Size returns the number of cached tokens
func (tc *TokenCache) Size() int {
	tc.mu.RLock()
	defer tc.mu.RUnlock()
	return len(tc.entries)
}
