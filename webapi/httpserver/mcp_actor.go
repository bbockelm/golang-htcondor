package httpserver

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net"
	"net/http"
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
	// handshakes instead of one per request.
	//
	// The budget is per source address. One budget for the whole
	// process let a single client sending unknown bearers use up every
	// other caller's resolutions, and a caller refused resolution has
	// no identity at all.
	mcpActorResolveRate = 5

	// mcpActorResolveGlobalRate is the ceiling over every source
	// together, with a burst of twice that. The per-source budget
	// keeps one client from starving the rest; this keeps many of them
	// from turning into an unbounded number of schedd handshakes.
	mcpActorResolveGlobalRate = 25

	// mcpActorMaxSources bounds the per-source table. A source idle for
	// mcpActorSourceIdle has a full bucket again, so forgetting it
	// changes nothing; when the table is full of sources that are not
	// idle it is cleared, which hands every source a fresh budget and
	// leaves the global ceiling to bound the cost.
	mcpActorMaxSources = 10000
	mcpActorSourceIdle = time.Minute
)

// errActorResolveThrottled is returned when an identity could not be
// resolved because the request's source, or every source together, has
// used its resolution budget. It is
// a refusal of the request, not an answer: proceeding with no identity
// would treat a caller who did authenticate as one who did not.
var errActorResolveThrottled = errors.New("too many new credentials are waiting to be verified; retry shortly")

// mcpActorCache maps a forwarded HTCondor IDTOKEN to the identity the
// schedd said it authenticates as. Keyed by a digest of the token so
// the process does not keep a second copy of every bearer it has seen.
type mcpActorCache struct {
	mu      sync.Mutex
	entries map[string]mcpActorEntry
	// limiter is the global ceiling on resolutions that miss the cache,
	// and sources the per-source budgets under it. Created on first use
	// so a zero-value cache works.
	limiter   *rate.Limiter
	sources   map[string]*mcpActorSource
	lastSweep time.Time
}

// mcpActorSource is one source address's resolution budget.
type mcpActorSource struct {
	limiter *rate.Limiter
	lastUse time.Time
}

type mcpActorEntry struct {
	// actor is empty for a negative entry: this token was tried and
	// could not be resolved.
	actor   string
	expires time.Time
}

// allowResolve reports whether a cache miss from source may spend a
// schedd handshake resolving an identity now.
//
// The source's own budget is charged first, so a source that is over
// it does not also drain the global ceiling everybody else shares.
func (c *mcpActorCache) allowResolve(source string) bool {
	now := time.Now()
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.limiter == nil {
		c.limiter = rate.NewLimiter(rate.Limit(mcpActorResolveGlobalRate), mcpActorResolveGlobalRate*2)
	}
	src, ok := c.sources[source]
	if !ok {
		c.sweepSourcesLocked(now)
		src = &mcpActorSource{limiter: rate.NewLimiter(rate.Limit(mcpActorResolveRate), mcpActorResolveRate*2)}
		c.sources[source] = src
	}
	src.lastUse = now
	if !src.limiter.AllowN(now, 1) {
		return false
	}
	return c.limiter.AllowN(now, 1)
}

// sweepSourcesLocked makes room for a new source. Called with c.mu held.
func (c *mcpActorCache) sweepSourcesLocked(now time.Time) {
	if c.sources == nil {
		c.sources = make(map[string]*mcpActorSource)
		c.lastSweep = now
		return
	}
	if len(c.sources) < mcpActorMaxSources && now.Sub(c.lastSweep) < mcpActorSourceIdle {
		return
	}
	c.lastSweep = now
	for k, src := range c.sources {
		if now.Sub(src.lastUse) >= mcpActorSourceIdle {
			delete(c.sources, k)
		}
	}
	if len(c.sources) >= mcpActorMaxSources {
		clear(c.sources)
	}
}

// actorResolveSource is the address a resolution is charged to: the
// client as clientIP resolves it, with an IPv6 address reduced to its
// /64, since one host commonly holds a whole /64 and would otherwise
// have a budget per address.
func actorResolveSource(r *http.Request, trusted []*net.IPNet) string {
	addr := clientIP(r, trusted)
	ip := net.ParseIP(addr)
	if ip == nil || ip.To4() != nil {
		return addr
	}
	return ip.Mask(net.CIDRMask(64, 128)).String() + "/64"
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
// outcomes are cached.
//
// Not rate-limited itself: callers go through resolveActor, which
// charges a miss to the request's source first.
func (h *Handler) actorForSession(ctx context.Context, cacheKey string) string {
	if actor, ok := h.mcpActors.get(cacheKey); ok {
		return actor
	}

	result, err := h.pingAsCaller(ctx)
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

// resolveActor is actorForSession behind the per-source limiter: a
// cache miss is charged to the source r came from, so resolution
// cannot be used to amplify unauthenticated requests into schedd
// handshakes, and one source sending unknown bearers cannot use up
// the resolutions of every other.
//
// A refusal is errActorResolveThrottled, never "": the caller must fail
// the request rather than carry on with no identity.
func (h *Handler) resolveActor(ctx context.Context, r *http.Request, cacheKey string) (string, error) {
	if actor, ok := h.mcpActors.get(cacheKey); ok {
		return actor, nil
	}
	source := actorResolveSource(r, h.trustedProxies)
	if !h.mcpActors.allowResolve(source) {
		h.logger.Warn(logging.DestinationHTTP, "Refusing request: too many unverified credentials from this source",
			"source", source)
		return "", errActorResolveThrottled
	}
	return h.actorForSession(ctx, cacheKey), nil
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
// userTag is set only in user-header mode, where the token is
// regenerated per request -- new jti, new iat -- so a digest of it
// would differ every time and no session would ever be reused; it is
// derived from what this server minted the token for (see
// mintedCredentialSessionTag). Everywhere else the tag is a digest of
// the credential rather than a claim read out of it, because a claim
// is attacker-chosen.
func sessionTagFor(userTag, credential string) string {
	if userTag != "" {
		return userTag
	}
	return mcpActorKey(credential)
}

// writeActorThrottled answers a request refused by resolveActor: 429,
// because the credential may be perfectly good and a 401 would tell the
// client to discard it.
func (h *Handler) writeActorThrottled(w http.ResponseWriter, err error) {
	w.Header().Set("Retry-After", "1")
	h.writeError(w, http.StatusTooManyRequests, err.Error())
}
