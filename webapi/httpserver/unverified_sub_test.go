package httpserver

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/bbockelm/golang-htcondor/webapi/templates"
)

// forgedToken builds a JWT with a real header and payload and a
// signature that is simply wrong.
func forgedToken(t *testing.T, sub string) string {
	t.Helper()
	header, err := json.Marshal(map[string]interface{}{"alg": "HS256", "typ": "JWT", "kid": "POOL"})
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().Unix()
	payload, err := json.Marshal(map[string]interface{}{
		"sub": sub,
		"iss": "test.domain",
		"iat": now,
		"exp": now + 3600,
	})
	if err != nil {
		t.Fatal(err)
	}
	return base64.RawURLEncoding.EncodeToString(header) + "." +
		base64.RawURLEncoding.EncodeToString(payload) + "." +
		base64.RawURLEncoding.EncodeToString([]byte("not-a-signature-at-all"))
}

// A token nobody signed must not name its bearer.
//
// This server verifies no JWT signatures -- deliberately: the schedd is
// the trust root and authenticates the forwarded token over CEDAR. What
// follows from that is that the sub claim is worth nothing until a
// schedd op has succeeded with the token, and the whole point of
// TokenCacheEntry.Validated is to hold that line.
//
// It did not hold it until 2026-09: TokenCache.Add marked every
// freshly parsed token validated, so this exact request answered
// authenticated=true, user="victim@test.domain". Endpoints that decide
// on identity alone, with no schedd round trip to re-check it -- saved
// templates, Jupyter sessions, chat history -- answered for the victim.
func TestForgedTokenResolvesToNobody(t *testing.T) {
	s, err := NewServer(newTestConfig(t))
	if err != nil {
		t.Fatalf("Failed to create server: %v", err)
	}

	req := httptest.NewRequestWithContext(context.Background(),
		http.MethodGet, "/api/v1/whoami", nil)
	req.Header.Set("Authorization", "Bearer "+forgedToken(t, "victim@test.domain"))

	w := httptest.NewRecorder()
	s.handleWhoAmI(w, req)

	resp := w.Result()
	defer func() {
		if err := resp.Body.Close(); err != nil {
			t.Errorf("Failed to close response body: %v", err)
		}
	}()

	var whoami WhoAmIResponse
	if err := json.NewDecoder(resp.Body).Decode(&whoami); err != nil {
		t.Fatalf("Failed to decode response: %v", err)
	}
	if whoami.User != "" {
		t.Errorf("a token with a garbage signature resolved to %q", whoami.User)
	}
}

// The cache must not promote an identity on its own -- only a
// successful schedd op does that, through MarkValidated.
func TestTokenCacheDoesNotValidateOnAdd(t *testing.T) {
	tc := NewTokenCache()

	token := createTestJWTToken(3600)
	if _, err := tc.Add(token); err != nil {
		t.Fatalf("Add: %v", err)
	}

	if got := tc.ValidatedUsername(token); got != "" {
		t.Errorf("ValidatedUsername = %q straight after Add; the sub was never verified by anyone", got)
	}

	// What a successful schedd op does.
	tc.MarkValidated(token, "alice@test.domain")
	if got := tc.ValidatedUsername(token); got != "alice@test.domain" {
		t.Errorf("ValidatedUsername = %q after MarkValidated, want alice@test.domain", got)
	}
}

// An owner-scoped endpoint must refuse a caller it cannot name rather
// than widening the query. A listing that cannot name its owner is a
// listing of the whole queue.
func TestOwnerScopedRouteRefusesAnUnnamedCaller(t *testing.T) {
	s, err := NewServer(newTestConfig(t))
	if err != nil {
		t.Fatalf("Failed to create server: %v", err)
	}

	req := httptest.NewRequestWithContext(context.Background(),
		http.MethodGet, "/api/v1/jobs", nil)
	req.Header.Set("Authorization", "Bearer "+forgedToken(t, "victim@test.domain"))

	w := httptest.NewRecorder()
	s.handleJobs(w, req)

	if got := w.Result().StatusCode; got != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401 for a caller that cannot be named", got)
	}
}

// The concrete consequence, end to end: saved templates live in this
// server's own database and are gated on the request identity alone --
// no schedd round trip re-checks them. So if a forged token can name a
// user, it can read that user's templates.
//
// With the identity gate restored the forged caller is nobody, and
// nobody sees only the global and built-in templates.
func TestForgedTokenCannotReadAnotherUsersTemplates(t *testing.T) {
	s, err := NewServer(newTestConfig(t))
	if err != nil {
		t.Fatalf("Failed to create server: %v", err)
	}
	if s.templateLibrary == nil {
		t.Skip("no template store configured in this build")
	}

	// The victim saves a template.
	const victim = "victim@test.domain"
	if _, err := s.templateLibrary.Save(templates.Template{
		Name:        "victim-private-template",
		Description: "should not be visible to anyone else",
		Contents:    "executable = secret.sh\nqueue\n",
	}, victim); err != nil {
		t.Fatalf("seeding the victim's template: %v", err)
	}

	// The attacker asks for the victim's templates with a token nobody
	// signed.
	req := httptest.NewRequestWithContext(context.Background(),
		http.MethodGet, "/api/v1/templates", nil)
	req.Header.Set("Authorization", "Bearer "+forgedToken(t, victim))
	w := httptest.NewRecorder()
	s.handleTemplates(w, req)

	resp := w.Result()
	defer func() {
		if err := resp.Body.Close(); err != nil {
			t.Errorf("Failed to close response body: %v", err)
		}
	}()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(body), "victim-private-template") {
		t.Errorf("a forged token read the victim's saved template; body: %s", body)
	}

	// And the victim still sees their own, so the gate is not simply
	// breaking the feature.
	own, err := s.templateLibrary.AllWithError(victim)
	if err != nil {
		t.Fatalf("loading the victim's own templates: %v", err)
	}
	var found bool
	for _, tpl := range own {
		if tpl.Name == "victim-private-template" {
			found = true
		}
	}
	if !found {
		t.Error("the victim cannot see their own template")
	}
}
