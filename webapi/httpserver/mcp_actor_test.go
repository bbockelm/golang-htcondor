package httpserver

import (
	"encoding/base64"
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

// Two different credentials must never share a cedar session, which is
// what the tag decides: the cache is keyed {SecurityTag, address,
// command}, and every REST caller reaches the same address with the
// same commands.
func TestSessionTagsDifferPerCredential(t *testing.T) {
	a := mcpActorKey("token-one")
	b := mcpActorKey("token-two")
	if a == b {
		t.Fatal("two credentials produced the same session tag")
	}
	if a == "" || b == "" {
		t.Fatal("an empty tag shares the cache with every other empty tag")
	}
	// Stable, or the same caller would never reuse a session.
	if mcpActorKey("token-one") != a {
		t.Error("the tag is not stable for one credential")
	}
}

// The tag must not be derived from a claim: a claim is attacker-chosen,
// so a forged `sub` would select somebody else's session.
func TestSessionTagIsNotTheSubjectClaim(t *testing.T) {
	// Two tokens with the same `sub` but different signatures.
	one := jwtWithClaims(t, `{"sub":"victim@example.edu"}`, "sig-one")
	two := jwtWithClaims(t, `{"sub":"victim@example.edu"}`, "sig-two")
	if mcpActorKey(one) == mcpActorKey(two) {
		t.Error("the tag collapses two distinct credentials that merely claim the same subject")
	}
}

func TestDescribeCredentialSubject(t *testing.T) {
	withIssuer := jwtWithClaims(t, `{"sub":"bbockelm@chtc.wisc.edu","iss":"ap.example.edu"}`, "x")
	if got := describeCredentialSubject(withIssuer); got != "bbockelm@chtc.wisc.edu (iss ap.example.edu)" {
		t.Errorf("describeCredentialSubject = %q", got)
	}
	if got := describeCredentialSubject("not-a-jwt"); got != "opaque" {
		t.Errorf("an opaque token described as %q", got)
	}
	if got := describeCredentialSubject(jwtWithClaims(t, `{}`, "x")); got != "no subject" {
		t.Errorf("a subjectless token described as %q", got)
	}
	// Never panics or leaks on rubbish: it runs on every request.
	for _, bad := range []string{"", "a.b", "a.!!!.c", "a.e30.c.d"} {
		_ = describeCredentialSubject(bad)
	}
}

func jwtWithClaims(t *testing.T, claims, signature string) string {
	t.Helper()
	enc := func(s string) string { return base64.RawURLEncoding.EncodeToString([]byte(s)) }
	return enc(`{"alg":"HS256"}`) + "." + enc(claims) + "." + enc(signature)
}

// Every request must carry a tag, whichever branch it came through.
// An empty one shares a cedar cache entry with every other empty one,
// and every REST caller reaches the same schedd with the same commands.
func TestSessionTagForIsNeverEmpty(t *testing.T) {
	if got := sessionTagFor("", "some-credential"); got == "" {
		t.Error("a bearer request would carry no tag")
	}
	if got := sessionTagFor("alice", ""); got != "alice" {
		t.Errorf("user-header mode tagged %q, want the username", got)
	}
	// Even with nothing to go on, something rather than nothing.
	if got := sessionTagFor("", ""); got == "" {
		t.Error("an empty credential produced an empty tag")
	}
}

func TestSessionTagForSeparatesCallers(t *testing.T) {
	if sessionTagFor("", "token-alice") == sessionTagFor("", "token-bob") {
		t.Error("two bearers share one tag")
	}
	if sessionTagFor("alice", "") == sessionTagFor("bob", "") {
		t.Error("two users share one tag")
	}
	// And the same caller keeps one, or no session is ever reused.
	// Computed into variables because the linter reads the inline form
	// as comparing an expression with itself, which is exactly the
	// stability being asserted.
	first := sessionTagFor("", "token-alice")
	second := sessionTagFor("", "token-alice")
	if first != second {
		t.Error("one bearer got two tags")
	}
}

// user-header mode must not tag by the credential: the token is
// regenerated per request, so the tag would differ every time and no
// session would ever be reused.
func TestUserHeaderModeTagsByUserNotCredential(t *testing.T) {
	first := sessionTagFor("alice", "generated-token-1")
	second := sessionTagFor("alice", "generated-token-2")
	if first != second {
		t.Errorf("one user got two tags across regenerated tokens, %q then %q", first, second)
	}
}
