package httpserver

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"sync"
	"time"

	"github.com/bbockelm/golang-htcondor/logging"
)

// mcpActorTTL bounds how long a forwarded IDTOKEN's resolved identity
// is reused. Short enough that a revoked or re-issued token stops
// scoping queries within minutes, long enough that a chatty MCP session
// pays for one handshake rather than one per call.
const mcpActorTTL = 5 * time.Minute

// mcpActorCache maps a forwarded HTCondor IDTOKEN to the identity the
// schedd said it authenticates as. Keyed by a digest of the token so
// the process does not keep a second copy of every bearer it has seen.
type mcpActorCache struct {
	mu      sync.Mutex
	entries map[string]mcpActorEntry
}

type mcpActorEntry struct {
	actor   string
	expires time.Time
}

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

// actorForForwardedToken resolves who a forwarded HTCondor IDTOKEN
// authenticates as, for the owner-scoping the MCP tools apply.
//
// The answer comes from the schedd, not from the token: ctx already
// carries the caller's SecurityConfig, so a DC_NOP ping authenticates
// with that token and the schedd reports back the identity it mapped
// the caller to. Reading `sub` here instead would mean trusting an
// unverified claim for an authorization decision — the same mistake the
// REST path's token cache exists to avoid.
//
// Returns "" when the ping fails, which leaves the request
// unauthenticated: owner-scoped tools then refuse it, which is the
// correct outcome for a token the schedd will not accept anyway.
func (h *Handler) actorForForwardedToken(ctx context.Context, token string) string {
	if actor, ok := h.mcpActors.get(token); ok {
		return actor
	}

	result, err := h.schedd.Ping(ctx)
	if err != nil {
		h.logger.Warn(logging.DestinationHTTP, "Could not resolve the identity of a forwarded HTCondor token; owner-scoped MCP tools will refuse this call", "error", err)
		return ""
	}
	if result.User == "" {
		h.logger.Warn(logging.DestinationHTTP, "Schedd reported no authenticated identity for a forwarded HTCondor token; owner-scoped MCP tools will refuse this call")
		return ""
	}

	h.mcpActors.put(token, result.User, mcpActorTTL)
	h.logger.Info(logging.DestinationHTTP, "Resolved forwarded HTCondor token identity", "actor", result.User)
	return result.User
}
