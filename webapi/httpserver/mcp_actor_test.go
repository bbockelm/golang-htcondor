package httpserver

import (
	"testing"
	"time"
)

// TestMCPActorCacheHitAndExpiry checks the cache answers for the token
// it was given, only for that token, and only until the TTL runs out —
// a stale or crossed entry would owner-scope a caller's MCP tools to
// somebody else's jobs.
func TestMCPActorCacheHitAndExpiry(t *testing.T) {
	var c mcpActorCache

	if _, ok := c.get("tok-a"); ok {
		t.Fatal("empty cache must not answer")
	}

	c.put("tok-a", "alice@uid.domain", time.Minute)
	got, ok := c.get("tok-a")
	if !ok || got != "alice@uid.domain" {
		t.Fatalf("get(tok-a) = %q, %v; want the stored actor", got, ok)
	}
	if _, ok := c.get("tok-b"); ok {
		t.Error("a different token must not hit another token's entry")
	}

	c.put("tok-b", "bob@uid.domain", -time.Second) // already expired
	if got, ok := c.get("tok-b"); ok {
		t.Errorf("expired entry returned %q", got)
	}
	// Still there for the live token.
	if _, ok := c.get("tok-a"); !ok {
		t.Error("expiring one entry must not drop the others")
	}
}

// TestMCPActorCacheEvictsStale checks put() clears entries whose TTL has
// passed, so a long-lived server does not accumulate one entry per
// bearer it has ever seen.
func TestMCPActorCacheEvictsStale(t *testing.T) {
	var c mcpActorCache
	for _, tok := range []string{"a", "b", "c"} {
		c.put(tok, "user", -time.Second)
	}
	c.put("live", "user", time.Minute)

	c.mu.Lock()
	n := len(c.entries)
	c.mu.Unlock()
	if n != 1 {
		t.Errorf("expected only the live entry to remain, got %d entries", n)
	}
}

// TestMCPActorKeyIsADigest checks the cache key is not the bearer
// itself: the process should not keep a second copy of every token it
// has seen.
func TestMCPActorKeyIsADigest(t *testing.T) {
	token := "header.payload.signature"
	key := mcpActorKey(token)
	if key == token {
		t.Fatal("cache key is the raw token")
	}
	if len(key) != 64 {
		t.Errorf("expected a sha256 hex digest, got %d chars", len(key))
	}
	if mcpActorKey(token) != key {
		t.Error("key must be stable for the same token")
	}
	if mcpActorKey(token+"x") == key {
		t.Error("different tokens must get different keys")
	}
}

// TestMCPActorCacheRemembersFailures checks the negative entry: a token
// the schedd would not accept must be answered from cache rather than
// costing another handshake on every retry.
func TestMCPActorCacheRemembersFailures(t *testing.T) {
	var c mcpActorCache
	c.put("bad", "", time.Minute)

	actor, ok := c.get("bad")
	if !ok {
		t.Fatal("a remembered failure must answer from the cache")
	}
	if actor != "" {
		t.Errorf("a remembered failure must resolve to no actor, got %q", actor)
	}
}

// TestMCPActorResolveRateLimit is the anti-amplification guard: a forged
// JWT carrying the pool's issuer classifies as a forwarded IDTOKEN, so
// every distinct one is a cache miss. Only a bounded number may reach
// the schedd.
func TestMCPActorResolveRateLimit(t *testing.T) {
	var c mcpActorCache

	allowed := 0
	for i := 0; i < 500; i++ {
		if c.allowResolve() {
			allowed++
		}
	}
	if allowed == 0 {
		t.Fatal("the limiter must allow the first resolutions through")
	}
	// Burst is 2x the per-second rate; a tight loop takes well under a
	// second, so anything near 500 means the limiter is not limiting.
	if allowed > mcpActorResolveRate*2+2 {
		t.Errorf("limiter allowed %d resolutions in a burst, want about %d", allowed, mcpActorResolveRate*2)
	}
}

// TestMCPActorKeyIsUsableAsASecurityTag pins the property the session
// isolation depends on: the tag is derived from the whole bearer, so two
// callers can never share one — including when an attacker copies a
// victim's `sub` claim into their own token.
func TestMCPActorKeyIsUsableAsASecurityTag(t *testing.T) {
	alice := "header.eyJzdWIiOiJhbGljZSJ9.alice-signature"
	forged := "header.eyJzdWIiOiJhbGljZSJ9.attacker-signature" // same claims, different token
	if mcpActorKey(alice) == mcpActorKey(forged) {
		t.Error("tokens sharing a sub claim must not share a session tag")
	}
	if mcpActorKey(alice) == "" {
		t.Error("tag must not be empty: cedar falls back to keying sessions by address alone")
	}
}
