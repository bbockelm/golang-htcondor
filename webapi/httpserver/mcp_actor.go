package httpserver

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"strings"
	"sync"
	"time"

	"golang.org/x/time/rate"

	"github.com/bbockelm/golang-htcondor/logging"
)

const (
	// mcpActorTTL bounds how long a forwarded IDTOKEN's resolved
	// identity is reused. Short enough that a revoked or re-issued
	// token stops scoping queries within minutes, long enough that a
	// chatty MCP session pays for one handshake rather than one per
	// call.
	mcpActorTTL = 5 * time.Minute

	// mcpActorFailTTL is how long a token that could NOT be resolved is
	// remembered as unresolvable. Without it, a client retrying with a
	// token the schedd rejects would put a handshake on the schedd per
	// request.
	mcpActorFailTTL = 30 * time.Second

	// mcpActorResolveRate bounds how many NEW identities may be
	// resolved per second, with a burst of twice that. Resolution is
	// the one thing an unauthenticated caller can make this server ask
	// of the schedd: a forged JWT with the pool's issuer classifies as
	// a forwarded IDTOKEN, and each distinct one is a cache miss. The
	// limit means a flood of them costs the schedd a bounded trickle of
	// handshakes instead of one per request; callers whose identity
	// cannot be resolved are simply treated as unauthenticated, which
	// owner-scoped tools already refuse.
	mcpActorResolveRate = 5
)

// mcpActorCache maps a forwarded HTCondor IDTOKEN to the identity the
// schedd said it authenticates as. Keyed by a digest of the token so
// the process does not keep a second copy of every bearer it has seen.
type mcpActorCache struct {
	mu      sync.Mutex
	entries map[string]mcpActorEntry
	// limiter throttles resolutions that miss the cache. Created on
	// first use so a zero-value cache works.
	limiter *rate.Limiter
}

type mcpActorEntry struct {
	// actor is empty for a negative entry: this token was tried and
	// could not be resolved.
	actor   string
	expires time.Time
}

// allowResolve reports whether a cache miss may spend a schedd handshake
// resolving an identity now.
func (c *mcpActorCache) allowResolve() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.limiter == nil {
		c.limiter = rate.NewLimiter(rate.Limit(mcpActorResolveRate), mcpActorResolveRate*2)
	}
	return c.limiter.Allow()
}

// get returns the cached actor for a token. The second result reports
// whether the cache has an answer at all; an entry whose actor is empty
// is a remembered failure, which answers "unauthenticated" without
// touching the schedd again.
func (c *mcpActorCache) get(token string) (string, bool) {
	key := mcpActorKey(token)
	c.mu.Lock()
	defer c.mu.Unlock()
	entry, ok := c.entries[key]
	if !ok {
		return "", false
	}
	if time.Now().After(entry.expires) {
		delete(c.entries, key)
		return "", false
	}
	return entry.actor, true
}

func (c *mcpActorCache) put(token, actor string, ttl time.Duration) {
	key := mcpActorKey(token)
	now := time.Now()
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.entries == nil {
		c.entries = make(map[string]mcpActorEntry)
	}
	// Drop anything already stale on the way past. The map only ever
	// holds one entry per distinct bearer seen in the last TTL, so this
	// is all the eviction it needs.
	for k, e := range c.entries {
		if now.After(e.expires) {
			delete(c.entries, k)
		}
	}
	c.entries[key] = mcpActorEntry{actor: actor, expires: now.Add(ttl)}
}

func mcpActorKey(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}

// actorForSession resolves who this request authenticates as on the
// schedd, for the owner-scoping the MCP tools apply. cacheKey is the
// caller's bearer, used only to key the answer.
//
// The answer comes from the schedd, not from any token claim: ctx
// already carries the request's SecurityConfig, so a DC_NOP ping
// authenticates exactly as the subsequent tool call will and the schedd
// reports back the identity it mapped the caller to. That matters for
// both kinds of bearer. For a forwarded IDTOKEN, the claim is unverified
// here — trusting it would be the mistake the REST path's token cache
// exists to avoid. For an OAuth2 bearer the username claim is verified,
// but it is OUR name for the caller, not necessarily the identity the
// schedd attributes the connection to (a pool preferring FS over TOKEN
// attributes it to the process user), and it is the schedd's answer that
// decides which jobs are theirs.
//
// Returns "" when the identity cannot be established, which leaves the
// request unauthenticated: owner-scoped tools then refuse it, the
// correct outcome for a bearer the schedd will not accept anyway. Both
// outcomes are cached, and a miss is rate-limited, so resolution cannot
// be used to amplify unauthenticated requests into schedd handshakes.
func (h *Handler) actorForSession(ctx context.Context, cacheKey string) string {
	if actor, ok := h.mcpActors.get(cacheKey); ok {
		return actor
	}
	if !h.mcpActors.allowResolve() {
		h.logger.Warn(logging.DestinationHTTP, "Skipping identity resolution: too many unresolved bearers; owner-scoped MCP tools will refuse this call")
		return ""
	}

	result, err := h.getSchedd().Ping(ctx)
	if err != nil {
		h.logger.Warn(logging.DestinationHTTP, "Could not resolve the caller's identity with the schedd; owner-scoped MCP tools will refuse this call", "error", err)
		h.mcpActors.put(cacheKey, "", mcpActorFailTTL)
		return ""
	}
	if result.User == "" {
		h.logger.Warn(logging.DestinationHTTP, "Schedd reported no authenticated identity for this caller; owner-scoped MCP tools will refuse this call")
		h.mcpActors.put(cacheKey, "", mcpActorFailTTL)
		return ""
	}

	h.mcpActors.put(cacheKey, result.User, mcpActorTTL)
	h.logger.Info(logging.DestinationHTTP, "Resolved caller identity with the schedd", "actor", result.User)
	return result.User
}

// describeCredentialSubject reports the `sub` a credential carries, for
// a log line that says which identity a request was about to present.
//
// Unverified by construction -- it is read straight out of the payload
// without checking the signature -- so it is only ever used for
// logging, never for a decision. Returns a short description rather
// than an error, because a log line is not worth failing a request
// over.
func describeCredentialSubject(token string) string {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return "opaque"
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return "unreadable"
	}
	var claims struct {
		Subject string `json:"sub"`
		Issuer  string `json:"iss"`
	}
	if err := json.Unmarshal(payload, &claims); err != nil {
		return "unreadable"
	}
	if claims.Subject == "" {
		return "no subject"
	}
	if claims.Issuer != "" {
		return claims.Subject + " (iss " + claims.Issuer + ")"
	}
	return claims.Subject
}

// shortTag abbreviates a session tag for a log line. The full digest
// says nothing a reader can use; the point is only whether two requests
// share one.
func shortTag(tag string) string {
	if len(tag) > 12 {
		return tag[:12]
	}
	return tag
}

// sessionTagFor decides the cedar session tag a request's credential
// carries.
//
// cedar's client session cache is keyed {SecurityTag, address,
// command}, and by {address, command} alone when the tag is empty.
// Every REST caller reaches the same schedd with the same commands, so
// an untagged config shares one cache entry across callers.
//
// userTag is the username, and is set only in user-header mode: there
// the token is regenerated per request -- new jti, new iat -- so a
// digest of it would differ every time and no session would ever be
// reused. Everywhere else the tag is a digest of the credential rather
// than a claim read out of it, because a claim is attacker-chosen.
func sessionTagFor(userTag, credential string) string {
	if userTag != "" {
		return userTag
	}
	return mcpActorKey(credential)
}
