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
