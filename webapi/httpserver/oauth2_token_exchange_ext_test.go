package httpserver

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"net/http"
	"net/url"
	"testing"
	"time"

	jose "github.com/go-jose/go-jose/v4"
)

func TestParseTrustedIssuers(t *testing.T) {
	// Valid; identity_domain defaults to the issuer host.
	iss, err := parseTrustedIssuers(`[{"issuer":"https://idp.example.org","jwks_uri":"https://idp.example.org/jwks","audience":"htcondor-mcp","allowed_scopes":["condor:/READ"]}]`)
	if err != nil {
		t.Fatalf("valid config errored: %v", err)
	}
	if len(iss) != 1 || iss[0].IdentityDomain != "idp.example.org" {
		t.Errorf("identity_domain default = %q, want idp.example.org", iss[0].IdentityDomain)
	}
	// Empty -> no issuers, no error.
	if got, err := parseTrustedIssuers("  "); err != nil || got != nil {
		t.Errorf("empty config: got %v, %v", got, err)
	}
	// Missing required fields / non-https jwks -> error.
	for _, bad := range []string{
		`[{"issuer":"https://x","audience":"a"}]`,                            // no jwks_uri
		`[{"issuer":"https://x","jwks_uri":"http://x/jwks","audience":"a"}]`, // http jwks
		`[{"jwks_uri":"https://x/jwks","audience":"a"}]`,                     // no issuer
		`not json`,
	} {
		if _, err := parseTrustedIssuers(bad); err == nil {
			t.Errorf("expected error for %q", bad)
		}
	}
}

// signedJWT signs claims with key/kid and returns the compact JWT.
func signedJWT(t *testing.T, key *rsa.PrivateKey, kid string, claims map[string]any) string {
	t.Helper()
	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.RS256, Key: key},
		(&jose.SignerOptions{}).WithHeader("kid", kid).WithType("JWT"))
	if err != nil {
		t.Fatal(err)
	}
	payload, _ := json.Marshal(claims)
	obj, err := signer.Sign(payload)
	if err != nil {
		t.Fatal(err)
	}
	s, err := obj.CompactSerialize()
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func jwksJSON(t *testing.T, key *rsa.PrivateKey, kid string) []byte {
	t.Helper()
	ks := jose.JSONWebKeySet{Keys: []jose.JSONWebKey{
		{Key: &key.PublicKey, KeyID: kid, Algorithm: "RS256", Use: "sig"},
	}}
	b, err := json.Marshal(ks)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// extValidatorFixture builds a validator whose JWKS fetch is served from memory.
func extValidatorFixture(t *testing.T, key *rsa.PrivateKey, kid string) *extIssuerValidator {
	t.Helper()
	issuers, err := parseTrustedIssuers(`[{"issuer":"https://idp.example.org","jwks_uri":"https://idp.example.org/jwks","audience":"htcondor-mcp","identity_domain":"idp.example.org","allowed_scopes":["condor:/READ","mcp:read"]}]`)
	if err != nil {
		t.Fatal(err)
	}
	fetch := func(_ context.Context, _ string) ([]byte, error) { return jwksJSON(t, key, kid), nil }
	return newExtIssuerValidator(issuers, fetch)
}

func TestExtIssuerValidate(t *testing.T) {
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	v := extValidatorFixture(t, key, "k1")
	now := time.Now()

	good := signedJWT(t, key, "k1", map[string]any{
		"iss": "https://idp.example.org", "sub": "alice", "aud": "htcondor-mcp",
		"exp": now.Add(time.Hour).Unix(), "iat": now.Unix(), "groups": []string{"cms"},
	})
	id, groups, allowed, err := v.validate(context.Background(), good)
	if err != nil {
		t.Fatalf("valid token rejected: %v", err)
	}
	if id != "alice@idp.example.org" {
		t.Errorf("identity = %q, want alice@idp.example.org (namespaced)", id)
	}
	if len(groups) != 1 || groups[0] != "cms" {
		t.Errorf("groups = %v", groups)
	}
	if len(allowed) != 2 {
		t.Errorf("allowed ceiling = %v, want the issuer's 2 scopes", allowed)
	}

	// Rejections.
	untrusted := signedJWT(t, key, "k1", map[string]any{"iss": "https://evil.example", "sub": "x", "aud": "htcondor-mcp", "exp": now.Add(time.Hour).Unix()})
	if _, _, _, err := v.validate(context.Background(), untrusted); err == nil {
		t.Error("untrusted issuer must be rejected")
	}
	badAud := signedJWT(t, key, "k1", map[string]any{"iss": "https://idp.example.org", "sub": "x", "aud": "someone-else", "exp": now.Add(time.Hour).Unix()})
	if _, _, _, err := v.validate(context.Background(), badAud); err == nil {
		t.Error("wrong audience must be rejected")
	}
	expired := signedJWT(t, key, "k1", map[string]any{"iss": "https://idp.example.org", "sub": "x", "aud": "htcondor-mcp", "exp": now.Add(-time.Hour).Unix()})
	if _, _, _, err := v.validate(context.Background(), expired); err == nil {
		t.Error("expired token must be rejected")
	}
	// Signed by a DIFFERENT key -> signature fails against the JWKS.
	otherKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	forged := signedJWT(t, otherKey, "k1", map[string]any{"iss": "https://idp.example.org", "sub": "x", "aud": "htcondor-mcp", "exp": now.Add(time.Hour).Unix()})
	if _, _, _, err := v.validate(context.Background(), forged); err == nil {
		t.Error("a token signed by an unknown key must be rejected")
	}
}

func TestTokenExchangeExternalEndToEnd(t *testing.T) {
	server, _ := newProvenanceServer(t)
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	server.extIssuers = extValidatorFixture(t, key, "k1")

	// Actor client: token_exchange grant, scopes overlap the issuer's ceiling
	// only on condor:/READ (so mcp:read is bounded out by the actor).
	secret := insertConfidentialClient(t, server, "gateway",
		[]string{tokenExchangeGrantType}, []string{"condor:/READ"})

	now := time.Now()
	extToken := signedJWT(t, key, "k1", map[string]any{
		"iss": "https://idp.example.org", "sub": "bob", "aud": "htcondor-mcp",
		"exp": now.Add(time.Hour).Unix(), "iat": now.Unix(),
	})

	rec := postTokenExchange(t, server, url.Values{
		"grant_type":         {tokenExchangeGrantType},
		"client_id":          {"gateway"},
		"client_secret":      {secret},
		"subject_token":      {extToken},
		"subject_token_type": {tokenTypeJWT},
	})
	if rec.Code != http.StatusOK {
		t.Fatalf("external exchange status %d: %s", rec.Code, rec.Body.String())
	}
	var resp struct {
		AccessToken string `json:"access_token"`
		Scope       string `json:"scope"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	// Ceiling = issuer {condor:/READ, mcp:read} ∩ actor {condor:/READ} = condor:/READ.
	if resp.Scope != "condor:/READ" {
		t.Errorf("scope = %q, want condor:/READ (issuer ∩ actor)", resp.Scope)
	}
	ar, err := server.oauth2Provider.IntrospectAccessToken(context.Background(), resp.AccessToken)
	if err != nil {
		t.Fatalf("introspect: %v", err)
	}
	if ar.GetSession().GetSubject() != "bob@idp.example.org" {
		t.Errorf("subject = %q, want bob@idp.example.org (namespaced)", ar.GetSession().GetSubject())
	}
	if s, ok := ar.GetSession().(*Session); !ok || s.Actor != "gateway" {
		t.Errorf("actor not recorded")
	}
}

// Without configured issuers, an external subject token is refused.
func TestTokenExchangeExternalDisabled(t *testing.T) {
	server, _ := newProvenanceServer(t)
	secret := insertConfidentialClient(t, server, "gw2", []string{tokenExchangeGrantType}, []string{"condor:/READ"})
	rec := postTokenExchange(t, server, url.Values{
		"grant_type": {tokenExchangeGrantType}, "client_id": {"gw2"}, "client_secret": {secret},
		"subject_token": {"whatever.jwt.here"}, "subject_token_type": {tokenTypeJWT},
	})
	if rec.Code == http.StatusOK {
		t.Error("external subject token must be refused when no issuers are configured")
	}
}
