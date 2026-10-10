package httpserver

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	htcondor "github.com/bbockelm/golang-htcondor"
	"github.com/bbockelm/golang-htcondor/webapi/httpserver/apikey"
)

type tokenClaims struct {
	Sub   string `json:"sub"`
	Scope string `json:"scope"`
	Exp   int64  `json:"exp"`
	JTI   string `json:"jti"`
}

func claimsOf(t *testing.T, token string) tokenClaims {
	t.Helper()
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		t.Fatalf("not a JWT: %q", token)
	}
	raw, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		t.Fatal(err)
	}
	var c tokenClaims
	if err := json.Unmarshal(raw, &c); err != nil {
		t.Fatal(err)
	}
	return c
}

// Every credential this server mints for a caller carries the means to mint
// it again, for the same subject and authorization, so work that outlives
// the request is not left holding an expired token. A token the caller
// presented has nothing to renew it from.
func TestMintedCredentialsAreRenewable(t *testing.T) {
	f := twoOwnerScheddServer(t)
	h := f.s.Handler

	renewed := func(t *testing.T, ctx context.Context) (before, after tokenClaims) {
		t.Helper()
		cred, ok := htcondor.CallerCredentialFromContext(ctx)
		if !ok {
			t.Fatal("no credential on the context")
		}
		if !cred.Renewable() {
			t.Fatal("a credential this server minted cannot be renewed")
		}
		fresh, err := cred.Renew(context.Background())
		if err != nil {
			t.Fatalf("Renew: %v", err)
		}
		return claimsOf(t, cred.Token()), claimsOf(t, fresh.Token())
	}
	request := func(auth func(*http.Request)) context.Context {
		t.Helper()
		r := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/api/v1/jobs", nil)
		auth(r)
		ctx, err := h.createAuthenticatedContext(r)
		if err != nil {
			t.Fatalf("createAuthenticatedContext: %v", err)
		}
		return ctx
	}

	t.Run("session cookie", func(t *testing.T) {
		before, after := renewed(t, request(f.session(t, "alice")))
		if after.Sub != "alice@test.domain" || after.Sub != before.Sub || after.JTI == before.JTI {
			t.Errorf("renewed %+v from %+v; want a new token for alice@test.domain", after, before)
		}
	})

	t.Run("MCP grant", func(t *testing.T) {
		ctx, err := h.withCondorCredential(context.Background(), "alice", []string{"condor:/READ"})
		if err != nil {
			t.Fatal(err)
		}
		before, after := renewed(t, ctx)
		if after.Sub != "alice@test.domain" || after.Scope != before.Scope || after.Scope != "condor:/READ" {
			t.Errorf("renewed %+v from %+v; want alice@test.domain limited to condor:/READ again", after, before)
		}
	})

	t.Run("presented IDTOKEN", func(t *testing.T) {
		cred, ok := htcondor.CallerCredentialFromContext(request(f.bearer(t, "alice")))
		if !ok {
			t.Fatal("no credential on the context")
		}
		if cred.Renewable() {
			t.Error("a token the caller presented is renewable")
		}
	})
}

// An API key's credential renews only while the key is active, and an opaque
// grant's only until the grant itself expires.
func TestCredentialRenewalEndsWithItsSource(t *testing.T) {
	t.Run("API key", func(t *testing.T) {
		h := condorTestHandler(t)
		h.credentialSessions = newTokenCache("")
		minted, err := apikey.Mint()
		if err != nil {
			t.Fatal(err)
		}
		if _, err := h.apiKeyStore.Insert(context.Background(), minted.KeyID, minted.SecretHash, "test",
			"alice@test.example.org", []string{"condor:/READ"}, nil); err != nil {
			t.Fatal(err)
		}
		ctx, err := h.authenticateAPIKey(requestWithBearer(t, minted.Full), minted.Full)
		if err != nil {
			t.Fatal(err)
		}
		cred, _ := htcondor.CallerCredentialFromContext(ctx)
		fresh, err := cred.Renew(context.Background())
		if err != nil {
			t.Fatalf("renewing an active key's credential: %v", err)
		}
		if c := claimsOf(t, fresh.Token()); c.Sub != "alice@test.example.org" || c.Scope != "condor:/READ" {
			t.Errorf("renewed %+v; want alice@test.example.org limited to condor:/READ", c)
		}
		if err := h.apiKeyStore.SoftDelete(context.Background(), minted.KeyID, "alice@test.example.org"); err != nil {
			t.Fatal(err)
		}
		if _, err := cred.Renew(context.Background()); err == nil {
			t.Error("a revoked key's credential was renewed")
		}
	})

	t.Run("opaque grant", func(t *testing.T) {
		h := twoOwnerScheddServer(t).s.Handler
		live := h.grantReminter("opaque-a", "alice", []string{"condor:/READ"}, time.Now().Add(time.Hour))
		if tok, err := live(); err != nil || claimsOf(t, tok).Scope != "condor:/READ" {
			t.Errorf("renewing within the grant: token %q, err %v", tok, err)
		}
		over := h.grantReminter("opaque-b", "alice", []string{"condor:/READ"}, time.Now().Add(-time.Second))
		if _, err := over(); !errors.Is(err, errGrantExpired) {
			t.Errorf("renewing past the grant's expiry: err = %v, want errGrantExpired", err)
		}
	})
}
