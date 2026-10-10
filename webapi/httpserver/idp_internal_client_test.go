package httpserver

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/ory/fosite"
	"golang.org/x/crypto/bcrypt"
)

// legacyIDPClientSecret is the secret every installation's internal IdP
// client used to share.
const legacyIDPClientSecret = "internal-secret"

// startIDPServer brings up a server with the built-in IdP. seed, when
// set, runs against the IdP's storage before Start, the way an earlier
// release's rows are already there when an upgraded server starts.
func startIDPServer(t *testing.T, seed func(*IDPStorage)) *Server {
	t.Helper()
	cfg := newTestConfig(t)
	cfg.Logger = testLogger(t)
	dbPath := t.TempDir() + "/idp.db"
	cfg.OAuth2DBPath = dbPath
	cfg.EnableIDP = true
	cfg.IDPDBPath = dbPath
	s, err := NewServer(cfg)
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	if seed != nil {
		seed(s.idpProvider.storage)
	}
	ln, err := (&net.ListenConfig{}).Listen(context.Background(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	if err := s.Handler.Start(t.Context(), ln, "http"); err != nil {
		t.Fatalf("Start: %v", err)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = s.Shutdown(ctx)
	})
	return s
}

// idpTokenAs posts an authorization-code exchange to /idp/token as the
// internal client with the given secret. The code is made up: only how
// the client authentication went matters here.
func idpTokenAs(t *testing.T, s *Server, secret string) *httptest.ResponseRecorder {
	t.Helper()
	form := url.Values{
		"grant_type":   {"authorization_code"},
		"code":         {"not-a-real-code"},
		"redirect_uri": {s.oauth2Config.RedirectURL},
	}
	req := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/idp/token",
		strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetBasicAuth(idpInternalClientID, secret)
	w := httptest.NewRecorder()
	s.ServeHTTP(w, req)
	return w
}

// The internal client's secret is this deployment's own, so the one
// every installation used to share no longer authenticates -- whether the
// client is created fresh or was stored by an earlier release.
func TestIDPInternalClientRefusesTheSharedSecret(t *testing.T) {
	for name, seed := range map[string]func(*IDPStorage){
		"fresh": nil,
		"stored by an earlier release": func(st *IDPStorage) {
			hashed, err := bcrypt.GenerateFromPassword([]byte(legacyIDPClientSecret), bcrypt.MinCost)
			if err != nil {
				t.Fatal(err)
			}
			if err := st.CreateClient(context.Background(), &fosite.DefaultClient{
				ID:            idpInternalClientID,
				Secret:        hashed,
				RedirectURIs:  []string{"http://127.0.0.1/oauth2/callback"},
				ResponseTypes: []string{"code"},
				GrantTypes:    []string{"authorization_code", "refresh_token"},
				Scopes:        []string{"openid", "profile", "email"},
			}); err != nil {
				t.Fatal(err)
			}
		},
	} {
		t.Run(name, func(t *testing.T) {
			s := startIDPServer(t, seed)

			w := idpTokenAs(t, s, legacyIDPClientSecret)
			if w.Code != http.StatusUnauthorized || !strings.Contains(w.Body.String(), "invalid_client") {
				t.Errorf("shared secret: %d %s, want 401 invalid_client", w.Code, w.Body.String())
			}

			// The secret the server's own SSO presents still authenticates:
			// the exchange gets as far as the made-up code.
			own := s.idpInternalClientSecret()
			if own == legacyIDPClientSecret || s.oauth2Config.ClientSecret != own {
				t.Fatalf("SSO presents %q, want the derived secret", s.oauth2Config.ClientSecret)
			}
			w = idpTokenAs(t, s, own)
			if w.Code != http.StatusBadRequest || !strings.Contains(w.Body.String(), "invalid_grant") {
				t.Errorf("own secret: %d %s, want 400 invalid_grant", w.Code, w.Body.String())
			}
		})
	}
}
