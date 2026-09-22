package httpserver

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

// This server is an OAuth2 authorization server, not an OpenID provider.
//
// It used to advertise otherwise while publishing no jwks_uri and serving
// no JWKS, which is not a cosmetic inconsistency: authlib (what OpenWebUI
// uses) sees an id_token in the token response alongside the nonce it
// sent, tries to validate it, looks for jwks_uri and fails the entire
// login with `Missing "jwks_uri" in metadata`.
//
// Two halves have to stay true together. Advertising OIDC without a JWKS
// is a promise that cannot be kept, and issuing an id_token invites a
// client to try to keep it.
func TestMetadataDoesNotClaimToBeAnOpenIDProvider(t *testing.T) {
	server, oauth2Provider, _, _ := setupTestOAuth2Server(t)
	defer func() {
		if err := oauth2Provider.Close(); err != nil {
			t.Errorf("closing provider: %v", err)
		}
	}()

	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet,
		"/.well-known/oauth-authorization-server", nil)
	rec := httptest.NewRecorder()
	server.handleOAuth2Metadata(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("metadata returned %d", rec.Code)
	}
	var meta map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &meta); err != nil {
		t.Fatalf("decoding metadata: %v", err)
	}

	// Either publish the keys or do not claim to sign ID tokens.
	if _, ok := meta["jwks_uri"]; !ok {
		for _, field := range []string{"id_token_signing_alg_values_supported", "subject_types_supported"} {
			if v, present := meta[field]; present {
				t.Errorf("metadata advertises %s=%v with no jwks_uri; a client cannot verify what it is promised", field, v)
			}
		}
	}

	rts, _ := meta["response_types_supported"].([]any)
	for _, rt := range rts {
		if s, _ := rt.(string); strings.Contains(s, "id_token") {
			t.Errorf("response_types_supported offers %q, which this server does not issue", s)
		}
	}
}

// The other half: the TOKEN response must not carry an id_token, because
// that is what makes an OIDC-aware client try to validate one.
//
// It has to be the token endpoint. For response_type=code the ID token
// appears there, not on the authorize response -- an earlier version of
// this test checked the authorize response, passed, and went on passing
// with the OIDC handler put back, which is no test at all.
func TestTokenResponseCarriesNoIDToken(t *testing.T) {
	f := newReauthFixture(t, Config{})

	// openid is still requested and still GRANTED. Refusing the scope
	// would fail registration for the many clients that ask for it as a
	// matter of course; it simply no longer produces an ID token.
	code := f.consent(t, "alice", nil, "openid offline_access mcp:read")
	status, body := f.token(t, url.Values{
		"grant_type":   {"authorization_code"},
		"code":         {code},
		"redirect_uri": {"http://localhost:8080/callback"},
	})
	if status != http.StatusOK {
		t.Fatalf("code exchange failed with %d: %v", status, body)
	}

	if _, ok := body["id_token"]; ok {
		t.Error("the token response carries an id_token; an OIDC client will try to validate it " +
			"and fail on the missing jwks_uri")
	}
	if scope, _ := body["scope"].(string); !strings.Contains(scope, "openid") {
		t.Errorf("openid was not granted (scope=%q), so this proves nothing about ID tokens", scope)
	}
	if _, ok := body["access_token"].(string); !ok {
		t.Error("no access token was issued")
	}
}
