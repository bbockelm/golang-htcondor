package httpserver

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/bbockelm/golang-htcondor/logging"
)

// ssoErrorPageServer is a server with SSO configured, so the callback gets
// past its "OAuth2 not configured" guard and reaches the failures below.
func ssoErrorPageServer(t *testing.T) *Server {
	t.Helper()
	logger, err := logging.New(&logging.Config{OutputPath: "stderr"})
	if err != nil {
		t.Fatal(err)
	}
	s, err := NewServer(Config{ //nolint:gosec // G101: test credentials
		Logger:             logger,
		WebUIEnabled:       true,
		OAuth2ClientID:     "test-client",
		OAuth2ClientSecret: "test-secret",
		OAuth2AuthURL:      "https://idp.example.com/authorize",
		OAuth2TokenURL:     "https://idp.example.com/token",
		OAuth2RedirectURL:  "https://server.example.com" + webUICallbackPath,
		OAuth2Scopes:       []string{"openid", "profile", "email"},
		OAuth2Issuer:       "https://server.example.com",
		ScheddName:         "test-schedd",
		ScheddAddr:         "127.0.0.1:9618",
		OAuth2DBPath:       t.TempDir() + "/sessions.db",
	})
	if err != nil {
		t.Fatal(err)
	}
	s.setupRoutes()
	return s
}

// A sign-in refused by the identity provider is a browser landing on a
// redirect, so it gets a page, not a JSON object. The regression: an IdP
// that rejected a scope left every person who tried to log in looking at
// {"error":"Unauthorized","message":"Authentication failed: ..."} .
//
// The provider's own words still reach the screen -- that detail is the
// only thing distinguishing one refusal from another, and whoever is
// reading it is usually the person who has to fix the IdP.
func TestSSOCallbackRefusalRendersAPage(t *testing.T) {
	s := ssoErrorPageServer(t)
	const desc = `Malformed scope parameter. Unrecognized scope "profile"`

	target := webUICallbackPath + "?" + url.Values{
		"error":             {"invalid_scope"},
		"error_description": {desc},
	}.Encode()
	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, target, nil)
	rec := httptest.NewRecorder()
	s.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401", rec.Code)
	}
	if ct := rec.Header().Get("Content-Type"); !strings.HasPrefix(ct, "text/html") {
		t.Errorf("Content-Type = %q, want text/html", ct)
	}
	body := rec.Body.String()
	if strings.HasPrefix(strings.TrimSpace(body), "{") {
		t.Errorf("the browser was handed a JSON body: %s", body)
	}
	if !strings.Contains(body, "<!DOCTYPE html>") {
		t.Errorf("not an HTML page: %s", body)
	}
	// Escaped, since the provider's text reaches the page.
	if !strings.Contains(body, "Unrecognized scope &#34;profile&#34;") {
		t.Errorf("the page does not carry the provider's reason: %s", body)
	}
	if !strings.Contains(body, "Sign-in failed") {
		t.Errorf("the page does not say what failed: %s", body)
	}
}

// The provider's reason is escaped, not injected: an IdP that returns
// markup in error_description cannot put it in this page.
func TestSSOCallbackRefusalEscapesTheProvidersText(t *testing.T) {
	s := ssoErrorPageServer(t)
	target := webUICallbackPath + "?" + url.Values{
		"error":             {"invalid_scope"},
		"error_description": {`<img src=x onerror="alert(1)">`},
	}.Encode()
	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, target, nil)
	rec := httptest.NewRecorder()
	s.ServeHTTP(rec, req)

	if body := rec.Body.String(); strings.Contains(body, "<img src=x") {
		t.Errorf("the provider's markup reached the page unescaped: %s", body)
	}
}

// An error code with no description still names something.
func TestSSOCallbackRefusalWithoutADescription(t *testing.T) {
	s := ssoErrorPageServer(t)
	target := webUICallbackPath + "?error=access_denied"
	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, target, nil)
	rec := httptest.NewRecorder()
	s.ServeHTTP(rec, req)

	if body := rec.Body.String(); !strings.Contains(body, "access_denied") {
		t.Errorf("the page names neither a reason nor the error code: %s", body)
	}
}

// The other ways the callback gives up are browser landings too.
func TestSSOCallbackOtherFailuresRenderPages(t *testing.T) {
	for _, tc := range []struct{ name, query string }{
		{"no state or code", ""},
		{"unknown state", "?state=nosuchstate&code=abc"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := ssoErrorPageServer(t)
			req := httptest.NewRequestWithContext(context.Background(),
				http.MethodGet, webUICallbackPath+tc.query, nil)
			rec := httptest.NewRecorder()
			s.ServeHTTP(rec, req)

			if ct := rec.Header().Get("Content-Type"); !strings.HasPrefix(ct, "text/html") {
				t.Errorf("Content-Type = %q, want text/html", ct)
			}
			if strings.HasPrefix(strings.TrimSpace(rec.Body.String()), "{") {
				t.Errorf("the browser was handed a JSON body: %s", rec.Body.String())
			}
		})
	}
}
