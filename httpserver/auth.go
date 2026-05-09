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
	return ConfigureSecurityForTokenWithCacheAndFallback(token, sessionCache, false)
}

// ConfigureSecurityForTokenWithCacheAndFallback configures security settings with optional session cache
// and optional FS authentication fallback.
//
// allowFSFallback semantics:
//
//   - true  (user-header mode): the token is generated locally per
//     request and not signed with anything the schedd recognises, so
//     we APPEND FS as a fallback for use against a same-host schedd
//     where the OS-user identity is acceptable.
//
//   - false (session/JWT mode): the token IS signed by us with the
//     pool's signing key, the schedd validates it, and its `sub`
//     claim is the user we want recorded as the job Owner. We
//     therefore REMOVE FS from the offered methods, so the schedd
//     can't pick it during negotiation. (Cedar's negotiation walks
//     the server's preference order and selects the first method
//     also offered by the client; HTCondor's default lists FS
//     first, so leaving FS in the client's list lets FS win on a
//     same-host schedd, and the schedd then records the OS user
//     instead of the token's identity. We saw this in
//     session_integration_test.go: jobs submitted via session
//     cookie were owned by `vscode` — the test runner's UID — not
//     by the JWT subject `testuser@trust.domain`.)
//
// Authentication methods otherwise come from SEC_CLIENT_AUTHENTICATION_METHODS
// / SEC_DEFAULT_AUTHENTICATION_METHODS in the loaded HTCondor
// configuration. This was previously a hardcoded `[TOKEN]` list,
// which broke any pool that expects SSL alongside IDTOKENS.
//
// Implementation: delegates to htcondor.NewClientSecurityConfig for
// the configured-methods-aware base, then applies the FS rule above.
// Other call sites (file_transfer, schedd_ssh, mcpserver) use
// NewClientSecurityConfig directly; the httpserver-only
// allowFSFallback knob lives here so we don't drag it into the root
// package's API.
func ConfigureSecurityForTokenWithCacheAndFallback(token string, sessionCache *security.SessionCache, allowFSFallback bool) (*security.SecurityConfig, error) {
	if token == "" {
		return nil, fmt.Errorf("empty token provided")
	}

	// command=0 / peerName="" — ConfigureSecurityForToken is the
	// generic builder used to seed a request ctx; the actual command
	// and peer are filled in by GetSecurityConfigOrDefault on the
	// down-stream call site.
	secConfig, err := htcondor.NewClientSecurityConfig(context.Background(), token, "", 0, "CLIENT", sessionCache)
	if err != nil {
		return nil, err
	}

	if allowFSFallback {
		if !containsAuthMethod(secConfig.AuthMethods, security.AuthFS) {
			// User-header mode appends FS so an unsigned generated
			// token can still authenticate locally. Idempotent: don't
			// duplicate when FS is already in the configured list.
			secConfig.AuthMethods = append(secConfig.AuthMethods, security.AuthFS)
		}
	} else {
		// Session/JWT mode: strip FS so the schedd can't pick it and
		// authenticate us as the OS user instead of the JWT subject.
		// See the doc comment above for the full incident reference.
		secConfig.AuthMethods = stripAuthMethod(secConfig.AuthMethods, security.AuthFS)
	}

	// Authentication should always be REQUIRED for a token-bearing
	// client connection: we have a credential, we expect the peer to
	// authenticate us. Other security levels stay as loaded from the
	// config; only fix them up if the config didn't.
	if secConfig.Authentication == "" {
		secConfig.Authentication = security.SecurityRequired
	}
	if len(secConfig.CryptoMethods) == 0 {
		secConfig.CryptoMethods = []security.CryptoMethod{security.CryptoAES}
	}
	if secConfig.Encryption == "" {
		secConfig.Encryption = security.SecurityOptional
	}
	if secConfig.Integrity == "" {
		secConfig.Integrity = security.SecurityOptional
	}

	return secConfig, nil
}

// containsAuthMethod reports whether `m` is in `list`. Tiny helper so
// the dedupe logic above stays linear and obvious.
func containsAuthMethod(list []security.AuthMethod, m security.AuthMethod) bool {
	for _, x := range list {
		if x == m {
			return true
		}
	}
	return false
}

// stripAuthMethod returns list with all occurrences of m removed,
// preserving order. Used by ConfigureSecurityForTokenWithCacheAndFallback
// in session/JWT mode to drop FS so a same-host schedd can't negotiate
// it and authenticate the connection as the OS user instead of the JWT
// subject.
func stripAuthMethod(list []security.AuthMethod, m security.AuthMethod) []security.AuthMethod {
	out := make([]security.AuthMethod, 0, len(list))
	for _, x := range list {
		if x != m {
			out = append(out, x)
		}
	}
	return out
}

// ConfigureSecurityForCollectorPing builds a SecurityConfig used solely
// by the periodic collector ping. The collector ping is read-only —
// we just need *some* mutually agreeable handshake — so this offers
// both TOKEN and SSL. That's useful when the daemon's token does not
// match the collector's IssuerKeys (an issuer rotation, a misconfigured
// TrustDomain, etc.): SSL keeps /readyz green via a path that has
// nothing to do with JWT signing. The schedd path — which DOES need
// the token's identity for authz — keeps using TOKEN only.
//
// SSL is always offered (even with no client cert/key on disk) because
// many collectors permit anonymous SSL: the client only verifies the
// server's cert and connects as ANONYMOUS@…, which is enough for a
// read-only ping. Cedar's SSL auth handles empty CertFile/KeyFile as
// "no client cert presented" and empty CAFile as "use the system trust
// store" — see cedar/security/ssl_auth.go and cmd/ssl-test/main.go.
//
// serverName is used by cedar's SSL handshake for hostname/SAN
// verification. Without it, cedar falls back to the literal string
// "unknown" and verification fails ("certificate is valid for
// host.example.com, ..., not unknown"). Pass the bare hostname of the
// collector address — see hostFromCondorAddress in handler.go.
//
// `token` may be empty; in that case only SSL is offered.
func ConfigureSecurityForCollectorPing(token, serverName string) (*security.SecurityConfig, error) {
	methods := []security.AuthMethod{security.AuthSSL}
	if token != "" {
		// TOKEN first so cedar prefers it when both work — token
		// auth gives us a real identity in the schedd's logs vs.
		// the anonymous-SSL session.
		methods = []security.AuthMethod{security.AuthToken, security.AuthSSL}
	}

	// Best-effort credential lookup. Empty values are fine: cedar
	// treats them as "no client cert" / "system trust store".
	certFile, keyFile, caFile, _ := htcondor.LookupSSLClientCredentials()

	return &security.SecurityConfig{
		AuthMethods:    methods,
		Authentication: security.SecurityRequired,
		CryptoMethods:  []security.CryptoMethod{security.CryptoAES},
		Encryption:     security.SecurityOptional,
		Integrity:      security.SecurityOptional,
		Token:          token,
		CertFile:       certFile,
		KeyFile:        keyFile,
		CAFile:         caFile,
		ServerName:     serverName,
	}, nil
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

// TokenCacheEntry represents a cached token with its expiration and associated session cache.
//
// Identity-trust note: Username is parsed from the JWT WITHOUT
// verifying the signature (we have no local way to verify — the only
// authoritative validator is the schedd's CEDAR handshake, which
// happens later when we make a schedd call). Until that handshake
// succeeds, the Username reflects whatever the client put in the
// token's `sub` claim and MUST NOT be used as authoritative identity
// (e.g. for filtering jobs to "owned by me", recording the Owner
// when minting a share URL, or any other authorization decision).
//
// Validated reports whether at least one schedd op has succeeded with
// this token. Code paths that need authoritative identity should
// gate on Validated; code paths that only need a stable bucket key
// (rate-limit per-token / per-username) can use Username directly.
type TokenCacheEntry struct {
	Token         string
	Username      string // sub from the JWT — unverified until Validated == true
	Validated     bool   // true once a schedd op authenticated successfully with this token
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

	//nolint:gosec // G118: cancel is stored in entry.cancelCleanup and called during Remove()
	_, cancel := context.WithCancel(context.Background())

	entry := &TokenCacheEntry{
		Token: token,
		// AddValidated is the constructor for tokens that the caller
		// has already verified (e.g. opaque-token introspection
		// against the OAuth2 storage succeeded). Mark Validated so
		// callers using ValidatedUsername see this identity
		// immediately without waiting for a schedd handshake.
		Username:      username,
		Validated:     true,
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

	return entry, nil
}

// requestTokenContextKey carries the bearer token through the request
// so the response-wrapping middleware in ServeHTTP can mark it
// validated after a successful (2xx) response. See markValidatedOnSuccess
// for the rationale.
type requestTokenContextKey struct{}

// withRequestToken stashes the token on the context so the
// response-status middleware can find it.
func withRequestToken(ctx context.Context, token string) context.Context {
	if token == "" {
		return ctx
	}
	return context.WithValue(ctx, requestTokenContextKey{}, token)
}

// requestTokenFromContext retrieves the token previously stashed via
// withRequestToken. Returns "" if none is set.
func requestTokenFromContext(ctx context.Context) string {
	if v, ok := ctx.Value(requestTokenContextKey{}).(string); ok {
		return v
	}
	return ""
}

// AddValidated adds a pre-validated token (e.g. opaque token) to the cache
func (tc *TokenCache) AddValidated(token, username string, expiration time.Time) (*TokenCacheEntry, error) {
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

	// Check if already expired
	if time.Now().After(expiration) {
		return nil, fmt.Errorf("token is already expired")
	}

	// Create a new session cache for this token
	sessionCache := security.NewSessionCache()

	//nolint:gosec // G118: cancel is stored in entry.cancelCleanup and called during Remove()
	_, cancel := context.WithCancel(context.Background())

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

// MarkValidated promotes a cached token to "validated" status, meaning
// a schedd op has authenticated successfully with it. Callers may
// optionally pass an authoritativeUsername observed from the schedd
// handshake — if non-empty and different from the JWT-claimed
// username, the entry is updated to the schedd-authoritative value
// (this protects against any case where the unverified sub claim
// disagreed with the schedd's interpretation).
//
// Idempotent: safe to call repeatedly per request.
func (tc *TokenCache) MarkValidated(token, authoritativeUsername string) {
	tc.mu.Lock()
	defer tc.mu.Unlock()
	entry, ok := tc.entries[token]
	if !ok {
		return
	}
	if authoritativeUsername != "" && entry.Username != authoritativeUsername {
		entry.Username = authoritativeUsername
	}
	entry.Validated = true
}

// ValidatedUsername returns the username for a token only if it has
// been marked validated via a successful schedd handshake. Use this
// in code paths that must rely on authoritative identity (job-owner
// filtering, share-URL minting, audit logs). For loose use cases
// (rate-limit bucket key) the Get-and-read-Username pattern is fine.
//
// Returns "" if the token is unknown, expired, or not yet validated.
func (tc *TokenCache) ValidatedUsername(token string) string {
	tc.mu.RLock()
	defer tc.mu.RUnlock()
	entry, ok := tc.entries[token]
	if !ok {
		return ""
	}
	if time.Now().After(entry.Expiration) {
		return ""
	}
	if !entry.Validated {
		return ""
	}
	return entry.Username
}
