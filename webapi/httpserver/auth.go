// Package httpserver provides HTTP API handlers for HTCondor operations.
package httpserver

import (
	"container/list"
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/bbockelm/cedar/security"
	htcondor "github.com/bbockelm/golang-htcondor"
	"github.com/bbockelm/golang-htcondor/config"
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
//   - true: APPEND FS to the offered methods. No production call site
//     passes this any more. It was used for user-header mode, on the
//     premise that such a token was "generated locally per request and
//     not signed with anything the schedd recognises" -- which was not
//     true. extractOrGenerateToken signs the header-mode token with the
//     same s.signingKeyPath and s.trustDomain as the session-mode one,
//     so the schedd validates both identically, and appending FS only
//     let FS win the negotiation and hide the caller's identity behind
//     the daemon's OS user. Retained for the tests that pin the
//     append/strip behaviour itself.
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
	return configureSecurityForToken(nil, token, sessionCache, allowFSFallback)
}

// configureSecurityForToken is ConfigureSecurityForTokenWithCacheAndFallback
// reading the configured base from cfg (nil: the process-wide default). The
// Handler calls it with its ClientConfig.
func configureSecurityForToken(cfg *config.Config, token string, sessionCache *security.SessionCache, allowFSFallback bool) (*security.SecurityConfig, error) {
	if token == "" {
		return nil, fmt.Errorf("empty token provided")
	}

	// command=0 / peerName="" — ConfigureSecurityForToken is the
	// generic builder used to seed a request ctx; the actual command
	// and peer are filled in by GetSecurityConfigOrDefault on the
	// down-stream call site.
	secConfig, err := htcondor.NewClientSecurityConfigWithConfig(context.Background(), cfg, token, "", 0, "CLIENT", sessionCache)
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
	return configureSecurityForCollectorPing(nil, token, serverName)
}

// configureSecurityForCollectorPing is ConfigureSecurityForCollectorPing
// reading the SSL client credentials from cfg (nil: the process-wide
// default).
func configureSecurityForCollectorPing(cfg *config.Config, token, serverName string) (*security.SecurityConfig, error) {
	methods := []security.AuthMethod{security.AuthSSL}
	if token != "" {
		// TOKEN first so cedar prefers it when both work — token
		// auth gives us a real identity in the schedd's logs vs.
		// the anonymous-SSL session.
		methods = []security.AuthMethod{security.AuthToken, security.AuthSSL}
	}

	// Best-effort credential lookup. Empty values are fine: cedar
	// treats them as "no client cert" / "system trust store".
	certFile, keyFile, caFile, _ := htcondor.LookupSSLClientCredentialsWithConfig(cfg)

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
// Validated reports whether the identity has been established by
// something other than the token's own claims: this server verified
// the bearer itself (AddValidated), or a CEDAR handshake reported who
// it is (MarkValidated). Code paths that need authoritative identity
// should gate on Validated; code paths that only need a stable bucket
// key (rate-limit per-token / per-username) can use Username directly.
type TokenCacheEntry struct {
	Token     string
	Username  string // sub from the JWT — unverified until Validated == true
	Validated bool   // true once the identity was established other than from the token's claims

	// CondorCredential is what CEDAR should authenticate with for this
	// bearer, when that is not the bearer itself.
	//
	// An opaque access token this server issued carries no signature
	// the schedd knows, so one is minted from it. Minting happens once,
	// on the request that first sees the token; without somewhere to
	// keep the result, every later request for the same bearer hands
	// CEDAR the opaque string instead -- which it cannot use, and which
	// leaves it to fall through to whatever credential the daemon
	// itself has.
	//
	// Empty for a bearer that is already a credential HTCondor can
	// verify, where the bearer is used directly.
	CondorCredential string

	// Scopes are the scopes the grant behind this bearer carries, for
	// the handlers that gate on them. Kept here for the same reason as
	// CondorCredential: they are resolved once, and a later request
	// that could not see them would read an approved-for-less grant as
	// carrying no restriction at all.
	Scopes []string

	Expiration   time.Time
	SessionCache *security.SessionCache

	// evictAt is when the cache drops the entry: Expiration, or sooner
	// (see tokenCacheUnvalidatedResidency).
	evictAt time.Time
	// elem is the entry's place in its recency list, lru the list.
	elem *list.Element
	lru  *list.List
}

// SetCondorCredential records the credential and scopes resolved for a
// bearer, so later requests for it do not have to resolve them again --
// and, more to the point, do not proceed without them.
func (tc *TokenCache) SetCondorCredential(token, credential string, scopes []string) {
	tc.mu.Lock()
	defer tc.mu.Unlock()
	entry, ok := tc.entries[token]
	if !ok {
		return
	}
	entry.CondorCredential = credential
	entry.Scopes = append([]string(nil), scopes...)
}

const (
	// tokenCacheMaxEntries bounds the cache. Add accepts any
	// well-formed JWT with a sub and a future exp -- the schedd, not
	// this server, checks the signature -- so the number of entries is
	// chosen by whoever sends requests, not by how many users there are.
	tokenCacheMaxEntries = 4096

	// tokenCacheUnvalidatedResidency is the longest an entry nobody has
	// verified stays, whatever exp the token claims; that exp is the
	// sender's choice. Dropping a legitimate bearer's entry costs it a
	// new CEDAR handshake on its next request and nothing else: the
	// entry holds the sessions it can resume, not its identity.
	tokenCacheUnvalidatedResidency = 10 * time.Minute

	// tokenCacheValidatedResidency is the longest a verified entry
	// stays. Adding the bearer again repeats the verification that
	// produced it (introspection, for an opaque access token).
	tokenCacheValidatedResidency = time.Hour

	// tokenCacheSweepInterval is how often an insert also drops every
	// entry past its time. Lookups ignore such entries regardless.
	tokenCacheSweepInterval = time.Minute
)

// TokenCache manages validated tokens and their associated session caches.
//
// Bounded: at most maxEntries, with entries nobody has verified evicted
// first (least recently used) and kept at most
// tokenCacheUnvalidatedResidency. A flood of unverified bearers
// therefore displaces other unverified bearers -- each of which just
// re-handshakes -- and not a verified one.
type TokenCache struct {
	mu      sync.Mutex
	entries map[string]*TokenCacheEntry // key is the token string

	// unvalidated and validated order the entries by last use, most
	// recent at the front.
	unvalidated *list.List
	validated   *list.List

	// trustDomain, when set, is the only issuer Add accepts. See
	// checkIssuer.
	trustDomain string

	maxEntries int
	now        func() time.Time
	lastSweep  time.Time
}

// NewTokenCache creates a new token cache that accepts a token from
// any issuer.
func NewTokenCache() *TokenCache {
	return newTokenCache("")
}

// newTokenCache creates a token cache whose Add refuses a token
// issued by anything but trustDomain ("" accepts any issuer).
func newTokenCache(trustDomain string) *TokenCache {
	return &TokenCache{
		entries:     make(map[string]*TokenCacheEntry),
		unvalidated: list.New(),
		validated:   list.New(),
		trustDomain: trustDomain,
		maxEntries:  tokenCacheMaxEntries,
		now:         time.Now,
	}
}

// parseJWTClaims parses token without verifying it and returns its
// registered claims, requiring sub and exp.
func parseJWTClaims(token string) (*jwt.RegisteredClaims, error) {
	// Parse the token without verification (we just need to read claims)
	parser := jwt.NewParser(jwt.WithoutClaimsValidation())
	parsedToken, _, parseErr := parser.ParseUnverified(token, &jwt.RegisteredClaims{})
	if parseErr != nil {
		return nil, fmt.Errorf("failed to parse JWT: %w", parseErr)
	}

	// Extract standard claims
	claims, ok := parsedToken.Claims.(*jwt.RegisteredClaims)
	if !ok {
		return nil, fmt.Errorf("failed to extract JWT claims")
	}

	// Check if subject is set
	if claims.Subject == "" {
		return nil, fmt.Errorf("JWT missing sub claim")
	}

	// Check if expiration is set
	if claims.ExpiresAt == nil {
		return nil, fmt.Errorf("JWT missing exp claim")
	}

	return claims, nil
}

// checkIssuer refuses a token issued outside this pool's trust domain.
//
// HTCondor presents an IDTOKEN only to a daemon whose trust domain is
// the token's iss, so such a token can never authenticate the caller
// here; handing it to CEDAR leaves CEDAR to look for some other
// credential to present instead. It is refused before it is cached or
// used.
//
// A SciToken (asymmetric signature) is exempt: its iss is an external
// issuer by design, and the schedd checks it against its own SciTokens
// configuration rather than TRUST_DOMAIN. With no trust domain
// configured there is nothing to compare against.
func (tc *TokenCache) checkIssuer(token, issuer string) error {
	if tc.trustDomain == "" || issuer == tc.trustDomain {
		return nil
	}
	if security.IsSciToken(token) {
		return nil
	}
	return fmt.Errorf("token issuer %q is not this pool's trust domain", issuer)
}

// Add caches a token, with a session cache of its own, without
// validating it. If the token is already cached, returns the existing
// entry.
func (tc *TokenCache) Add(token string) (*TokenCacheEntry, error) {
	tc.mu.Lock()
	defer tc.mu.Unlock()
	now := tc.now()

	if entry, ok := tc.lookupLocked(token, now); ok {
		return entry, nil
	}

	claims, err := parseJWTClaims(token)
	if err != nil {
		return nil, fmt.Errorf("failed to parse token claims: %w", err)
	}
	expiration := claims.ExpiresAt.Time

	// Check if already expired
	if now.After(expiration) {
		return nil, fmt.Errorf("token is already expired")
	}
	if err := tc.checkIssuer(token, claims.Issuer); err != nil {
		return nil, err
	}

	entry := &TokenCacheEntry{
		Token: token,
		// Username is the sub from parseJWTClaims, which parses
		// WITHOUT verifying the signature -- this server checks no JWT
		// signatures at all, because the schedd is the trust root and
		// authenticates the forwarded token over CEDAR.
		//
		// So Validated stays false here, and the entry's Username is
		// not an identity: ValidatedUsername returns "" for it, and
		// createAuthenticatedContext asks the schedd who the caller
		// is instead. That is what makes a forged token resolve to
		// nobody instead of to whatever it claims.
		//
		// This field carried Validated: true until 2026-09, which made
		// an unverified sub the request identity from the first
		// request -- the "ParseUnverified trusts sub" issue
		// createAuthenticatedContext's comment says the 2026-05 audit
		// removed. It was reachable: a JWT with a garbage signature
		// resolved to its own sub, and any endpoint deciding on
		// identity alone, without a schedd round trip to re-check it
		// (saved templates, Jupyter sessions, chat history), answered
		// for that user.
		Username:     claims.Subject,
		Expiration:   expiration,
		SessionCache: security.NewSessionCache(),
	}
	tc.insertLocked(entry, now, tokenCacheUnvalidatedResidency)
	return entry, nil
}

// AddValidated adds a pre-validated token (e.g. opaque token) to the cache
func (tc *TokenCache) AddValidated(token, username string, expiration time.Time) (*TokenCacheEntry, error) {
	tc.mu.Lock()
	defer tc.mu.Unlock()
	now := tc.now()

	if entry, ok := tc.lookupLocked(token, now); ok {
		return entry, nil
	}

	// Check if already expired
	if now.After(expiration) {
		return nil, fmt.Errorf("token is already expired")
	}

	entry := &TokenCacheEntry{
		Token: token,
		// The caller has already verified this token (opaque-token
		// introspection against the OAuth2 storage succeeded), so mark
		// it validated: ValidatedUsername is what callers read the
		// identity from, and it returns "" for an unvalidated entry.
		// Without this, a function named AddValidated stored its
		// identity where nothing could see it, and every opaque OAuth2
		// access token authenticated as nobody -- /api/v1/whoami
		// answered {"authenticated":true,"user":""} and owner-scoped
		// MCP tools refused the call.
		Username:     username,
		Validated:    true,
		Expiration:   expiration,
		SessionCache: security.NewSessionCache(),
	}
	tc.insertLocked(entry, now, tokenCacheValidatedResidency)
	return entry, nil
}

// sessionCacheFor returns the session cache kept for user, creating it
// if there is none. user names a private partition this server chose --
// a user it authenticated itself (a session cookie), or a credential's
// session tag (see mintedCredentialSessionTag) -- on a TokenCache used
// for that keyspace alone: the key is not a token and must not share a
// keyspace with bearers. The entry is bounded and expires like a
// verified one; a new one only means new CEDAR handshakes.
func (tc *TokenCache) sessionCacheFor(user string) *security.SessionCache {
	if tc == nil {
		return security.NewSessionCache()
	}
	tc.mu.Lock()
	defer tc.mu.Unlock()
	now := tc.now()
	key := "session:" + user
	if entry, ok := tc.lookupLocked(key, now); ok {
		return entry.SessionCache
	}
	entry := &TokenCacheEntry{
		Token:        key,
		Username:     user,
		Validated:    true,
		Expiration:   now.Add(tokenCacheValidatedResidency),
		SessionCache: security.NewSessionCache(),
	}
	tc.insertLocked(entry, now, tokenCacheValidatedResidency)
	return entry.SessionCache
}

// lookupLocked returns the live entry for token, marking it used, and
// drops one that is past its time. tc.mu must be held.
func (tc *TokenCache) lookupLocked(token string, now time.Time) (*TokenCacheEntry, bool) {
	entry, ok := tc.entries[token]
	if !ok {
		return nil, false
	}
	if now.After(entry.evictAt) {
		tc.removeLocked(entry)
		return nil, false
	}
	entry.lru.MoveToFront(entry.elem)
	return entry, true
}

// insertLocked adds entry, to stay at most residency (and never past
// its Expiration), making room first if the cache is full. tc.mu must
// be held.
func (tc *TokenCache) insertLocked(entry *TokenCacheEntry, now time.Time, residency time.Duration) {
	if now.Sub(tc.lastSweep) >= tokenCacheSweepInterval || len(tc.entries) >= tc.maxEntries {
		tc.sweepLocked(now)
	}
	for len(tc.entries) >= tc.maxEntries {
		// Least recently used, unverified first.
		victim := tc.unvalidated.Back()
		if victim == nil {
			victim = tc.validated.Back()
		}
		if victim == nil {
			break
		}
		tc.removeLocked(victim.Value.(*TokenCacheEntry))
	}

	entry.evictAt = now.Add(residency)
	if entry.Expiration.Before(entry.evictAt) {
		entry.evictAt = entry.Expiration
	}
	entry.lru = tc.unvalidated
	if entry.Validated {
		entry.lru = tc.validated
	}
	entry.elem = entry.lru.PushFront(entry)
	tc.entries[entry.Token] = entry
}

// sweepLocked drops every entry past its time. tc.mu must be held.
func (tc *TokenCache) sweepLocked(now time.Time) {
	tc.lastSweep = now
	for _, entry := range tc.entries {
		if now.After(entry.evictAt) {
			tc.removeLocked(entry)
		}
	}
}

// removeLocked drops entry. tc.mu must be held.
func (tc *TokenCache) removeLocked(entry *TokenCacheEntry) {
	entry.lru.Remove(entry.elem)
	delete(tc.entries, entry.Token)
}

// Get retrieves a token cache entry if it exists and is not expired
func (tc *TokenCache) Get(token string) (*TokenCacheEntry, bool) {
	tc.mu.Lock()
	defer tc.mu.Unlock()
	return tc.lookupLocked(token, tc.now())
}

// Remove removes a token from the cache
func (tc *TokenCache) Remove(token string) {
	tc.mu.Lock()
	defer tc.mu.Unlock()
	if entry, ok := tc.entries[token]; ok {
		tc.removeLocked(entry)
	}
}

// Size returns the number of cached tokens that have not expired
func (tc *TokenCache) Size() int {
	tc.mu.Lock()
	defer tc.mu.Unlock()
	tc.sweepLocked(tc.now())
	return len(tc.entries)
}

// MarkValidated promotes a cached token to "validated" status, with
// authoritativeUsername (if non-empty) replacing the JWT-claimed
// username.
//
// The only acceptable evidence is an identity a CEDAR handshake
// reported for a connection that authenticated with this token. A
// successful HTTP response is not evidence: plenty of endpoints answer
// 2xx without ever presenting the token to a daemon.
//
// Idempotent: safe to call repeatedly per request.
func (tc *TokenCache) MarkValidated(token, authoritativeUsername string) {
	tc.mu.Lock()
	defer tc.mu.Unlock()
	now := tc.now()
	entry, ok := tc.lookupLocked(token, now)
	if !ok {
		return
	}
	if authoritativeUsername != "" && entry.Username != authoritativeUsername {
		entry.Username = authoritativeUsername
	}
	if entry.Validated {
		return
	}
	tc.removeLocked(entry)
	entry.Validated = true
	tc.insertLocked(entry, now, tokenCacheValidatedResidency)
}

// ValidatedUsername returns the username for a token only if it has
// been validated (see TokenCacheEntry.Validated). Use this
// in code paths that must rely on authoritative identity (job-owner
// filtering, share-URL minting, audit logs). For loose use cases
// (rate-limit bucket key) the Get-and-read-Username pattern is fine.
//
// Returns "" if the token is unknown, expired, or not yet validated.
func (tc *TokenCache) ValidatedUsername(token string) string {
	tc.mu.Lock()
	defer tc.mu.Unlock()
	entry, ok := tc.lookupLocked(token, tc.now())
	if !ok || !entry.Validated {
		return ""
	}
	return entry.Username
}

// resolveCachedBearer reports the credential and scopes a request
// should use for a bearer the cache already knows, given the bearer
// itself as the fallback.
//
// Separated from createAuthenticatedContext so it can be tested:
// that function cannot be driven through this branch in a unit test,
// because resolving the caller pings a schedd.
//
// The empty case is the one that mattered. An opaque access token is
// not a credential HTCondor can verify, so one is minted from it --
// once, on the request that first sees the bearer. Returning the
// bearer here when nothing was recorded is correct for a bearer that
// IS already a usable credential, and was wrong for every opaque one,
// because CEDAR then had nothing to present and fell through to
// whatever credential the daemon itself has.
func resolveCachedBearer(entry *TokenCacheEntry, bearer string) (credential string, scopes []string) {
	if entry == nil {
		return bearer, nil
	}
	credential = bearer
	if entry.CondorCredential != "" {
		credential = entry.CondorCredential
	}
	return credential, entry.Scopes
}
