// Copyright 2026 Morgridge Institute for Research
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package httpserver

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
)

// sshCertHandler is a Handler that can mint tokens for a user header
// and sign certificates, which is the least plumbing these two
// endpoints need.
func sshCertHandler(t *testing.T, withCA bool) *Handler {
	t.Helper()

	dir := t.TempDir()
	keyPath := filepath.Join(dir, "POOL")
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i + 3)
	}
	if err := os.WriteFile(keyPath, key, 0o600); err != nil {
		t.Fatalf("write signing key: %v", err)
	}

	h := &Handler{
		logger:                   testLogger(t),
		userHeader:               "X-Test-User",
		userHeaderUnsafeAllowAll: true,
		signingKeyPath:           keyPath,
		trustDomain:              "test.htcondor.org",
		uidDomain:                "test.htcondor.org",
	}
	if withCA {
		_, priv, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatalf("generate CA: %v", err)
		}
		signer, err := ssh.NewSignerFromKey(priv)
		if err != nil {
			t.Fatalf("CA signer: %v", err)
		}
		h.sshCASigner = signer
	}
	return h
}

func userPublicKey(t *testing.T) string {
	t.Helper()
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	sshPub, err := ssh.NewPublicKey(pub)
	if err != nil {
		t.Fatalf("public key: %v", err)
	}
	return strings.TrimSpace(string(ssh.MarshalAuthorizedKey(sshPub)))
}

func postCert(t *testing.T, h *Handler, user, body string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequestWithContext(context.Background(), http.MethodPost,
		"/api/v1/ssh/certificate", strings.NewReader(body))
	if user != "" {
		req.Header.Set("X-Test-User", user)
	}
	rec := httptest.NewRecorder()
	h.handleSSHCertificate(rec, req)
	return rec
}

// The certificate names the caller, and the request has no say in it.
//
// There is deliberately no principal field on sshCertRequest: the name
// signed is the one createAuthenticatedContext resolved. Asserting it
// here so that adding such a field later has to break a test.
func TestCertificateIsIssuedForTheAuthenticatedAccount(t *testing.T) {
	h := sshCertHandler(t, true)
	pub := userPublicKey(t)

	rec := postCert(t, h, "alice", `{"public_key":"`+pub+`","principal":"root","user":"root"}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
	}

	var resp sshCertResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if resp.Principal != "alice" {
		t.Errorf("principal = %q, want the authenticated account", resp.Principal)
	}

	parsed, _, _, _, err := ssh.ParseAuthorizedKey([]byte(resp.Certificate))
	if err != nil {
		t.Fatalf("the certificate does not parse: %v", err)
	}
	cert, ok := parsed.(*ssh.Certificate)
	if !ok {
		t.Fatal("the response is not a certificate")
	}
	if len(cert.ValidPrincipals) != 1 || cert.ValidPrincipals[0] != "alice" {
		t.Errorf("valid principals = %v, want exactly [alice]", cert.ValidPrincipals)
	}
	if cert.CertType != ssh.UserCert {
		t.Errorf("cert type = %d, want a user certificate", cert.CertType)
	}
}

// No caller, no certificate. This endpoint hands out a credential, so
// an unauthenticated request must not reach the signing code at all.
func TestCertificateRequiresAuthentication(t *testing.T) {
	h := sshCertHandler(t, true)
	rec := postCert(t, h, "", `{"public_key":"`+userPublicKey(t)+`"}`)
	if rec.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401; body = %s", rec.Code, rec.Body.String())
	}
}

// Asked for a week, given the cap. A client wanting a long-lived
// certificate wants a certificate, not an error -- but it does not get
// to choose how long this deployment trusts it.
func TestCertificateLifetimeIsCapped(t *testing.T) {
	h := sshCertHandler(t, true)
	rec := postCert(t, h, "alice",
		`{"public_key":"`+userPublicKey(t)+`","lifetime_seconds":604800}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
	}
	var resp sshCertResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if got := time.Until(resp.ValidBefore); got > sshCertMaxLifetime+time.Minute {
		t.Errorf("certificate is valid for %v, past the %v cap", got, sshCertMaxLifetime)
	}
}

func TestCertificateShorterLifetimeIsHonoured(t *testing.T) {
	h := sshCertHandler(t, true)
	rec := postCert(t, h, "alice",
		`{"public_key":"`+userPublicKey(t)+`","lifetime_seconds":300}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
	}
	var resp sshCertResponse
	_ = json.Unmarshal(rec.Body.Bytes(), &resp)
	if got := time.Until(resp.ValidBefore); got > 10*time.Minute {
		t.Errorf("asked for 5 minutes, got %v", got)
	}
}

func TestCertificateRejectsUnusableKeys(t *testing.T) {
	h := sshCertHandler(t, true)
	for _, tc := range []struct{ name, body string }{
		{"not a key", `{"public_key":"hello"}`},
		{"empty", `{"public_key":""}`},
		{"not json", `nope`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if rec := postCert(t, h, "alice", tc.body); rec.Code != http.StatusBadRequest {
				t.Errorf("status = %d, want 400; body = %s", rec.Code, rec.Body.String())
			}
		})
	}
}

// Sending a certificate instead of a key means the caller picked the
// wrong file, and signing it would produce something nothing accepts.
func TestCertificateRejectsACertificateAsTheKey(t *testing.T) {
	h := sshCertHandler(t, true)
	rec := postCert(t, h, "alice", `{"public_key":"`+userPublicKey(t)+`"}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("setup: status = %d", rec.Code)
	}
	var first sshCertResponse
	_ = json.Unmarshal(rec.Body.Bytes(), &first)

	again := postCert(t, h, "alice", `{"public_key":`+quoteJSON(first.Certificate)+`}`)
	if again.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400; body = %s", again.Code, again.Body.String())
	}
}

// Without a CA the answer is 503, not 500 and not 404: the deployment
// works, it just does not do this.
func TestCertificateWithoutACAIsUnavailable(t *testing.T) {
	h := sshCertHandler(t, false)
	rec := postCert(t, h, "alice", `{"public_key":"`+userPublicKey(t)+`"}`)
	if rec.Code != http.StatusServiceUnavailable {
		t.Errorf("status = %d, want 503; body = %s", rec.Code, rec.Body.String())
	}
}

func TestSSHCAIsPublishedInAUsableForm(t *testing.T) {
	h := sshCertHandler(t, true)
	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/api/v1/ssh/ca", nil)
	req.Header.Set("X-Test-User", "alice")
	rec := httptest.NewRecorder()
	h.handleSSHCA(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
	}
	var resp sshCAResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if _, _, _, _, err := ssh.ParseAuthorizedKey([]byte(resp.PublicKey)); err != nil {
		t.Errorf("the published CA key does not parse: %v", err)
	}
	// The line is meant to be pasted into known_hosts as-is.
	if !strings.HasPrefix(resp.KnownHostsLine, "@cert-authority * ") {
		t.Errorf("known_hosts line is not usable as-is: %q", resp.KnownHostsLine)
	}
	if !strings.HasPrefix(resp.Fingerprint, "SHA256:") {
		t.Errorf("fingerprint = %q", resp.Fingerprint)
	}
}

func quoteJSON(s string) string {
	b, _ := json.Marshal(s)
	return string(b)
}

// postCertScoped issues the request with a scoped credential attached,
// the way an API key or an OAuth2 grant arrives.
func postCertScoped(t *testing.T, h *Handler, user string, scopes []string, body string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequestWithContext(withAPIKeyScopes(context.Background(), scopes),
		http.MethodPost, "/api/v1/ssh/certificate", strings.NewReader(body))
	req.Header.Set("X-Test-User", user)
	rec := httptest.NewRecorder()
	h.handleSSHCertificate(rec, req)
	return rec
}

// A certificate grants condor:/WRITE and a shell. A credential holding
// less must not be able to trade up to it.
//
// This is the escalation an adversarial review found: an API key
// minted for HTTP-only scopes authenticates here perfectly well, and
// without this gate it walked away with a 12-hour credential for the
// schedd.
func TestCertificateRefusesAnUnderScopedCredential(t *testing.T) {
	h := sshCertHandler(t, true)
	pub := userPublicKey(t)

	for _, tc := range []struct {
		name   string
		scopes []string
	}{
		{"http-only api key", []string{"metrics:read"}},
		{"read-only grant", []string{"openid", "condor:/READ"}},
		{"mcp only", []string{"mcp:read", "mcp:write"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rec := postCertScoped(t, h, "alice", tc.scopes, `{"public_key":"`+pub+`"}`)
			if rec.Code != http.StatusForbidden {
				t.Errorf("status = %d, want 403; body = %s", rec.Code, rec.Body.String())
			}
		})
	}
}

func TestCertificateAllowsACredentialHoldingTheScope(t *testing.T) {
	h := sshCertHandler(t, true)
	rec := postCertScoped(t, h, "alice", []string{"openid", "condor:/WRITE"},
		`{"public_key":"`+userPublicKey(t)+`"}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
	}
}

// A browser session carries no scopes because that route has no scope
// model. Refusing those would refuse every human who came to enroll.
func TestCertificateAllowsAnUnscopedSession(t *testing.T) {
	h := sshCertHandler(t, true)
	if rec := postCert(t, h, "alice", `{"public_key":"`+userPublicKey(t)+`"}`); rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
	}
}

// A certificate is public and long-lived, so a weak key under one is a
// third-party-forgeable credential for that account rather than just
// the holder's own problem.
func TestCertificateRefusesWeakKeys(t *testing.T) {
	h := sshCertHandler(t, true)

	small, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate rsa: %v", err)
	}
	pub, err := ssh.NewPublicKey(&small.PublicKey)
	if err != nil {
		t.Fatalf("public key: %v", err)
	}
	line := strings.TrimSpace(string(ssh.MarshalAuthorizedKey(pub)))

	rec := postCert(t, h, "alice", `{"public_key":`+quoteJSON(line)+`}`)
	if rec.Code != http.StatusBadRequest {
		t.Errorf("a 2048-bit RSA key was accepted: status = %d, body = %s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "3072") {
		t.Errorf("the refusal does not say what is required: %s", rec.Body.String())
	}
}

func TestCertificateAcceptsAStrongRSAKey(t *testing.T) {
	h := sshCertHandler(t, true)
	big, err := rsa.GenerateKey(rand.Reader, 3072)
	if err != nil {
		t.Fatalf("generate rsa: %v", err)
	}
	pub, err := ssh.NewPublicKey(&big.PublicKey)
	if err != nil {
		t.Fatalf("public key: %v", err)
	}
	line := strings.TrimSpace(string(ssh.MarshalAuthorizedKey(pub)))
	if rec := postCert(t, h, "alice", `{"public_key":`+quoteJSON(line)+`}`); rec.Code != http.StatusOK {
		t.Errorf("a 3072-bit RSA key was refused: %s", rec.Body.String())
	}
}

// time.Duration is nanoseconds, so a large lifetime_seconds wraps --
// and a wrapped negative slips past a `> max` check entirely. The
// clamp is applied in seconds, before the multiply.
func TestCertificateLifetimeCannotOverflow(t *testing.T) {
	h := sshCertHandler(t, true)
	for _, secs := range []string{"9223372036854775807", "9223372036", "604800"} {
		t.Run(secs, func(t *testing.T) {
			rec := postCert(t, h, "alice",
				`{"public_key":"`+userPublicKey(t)+`","lifetime_seconds":`+secs+`}`)
			if rec.Code != http.StatusOK {
				t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
			}
			var resp sshCertResponse
			if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
				t.Fatalf("decode: %v", err)
			}
			d := time.Until(resp.ValidBefore)
			if d > sshCertMaxLifetime+time.Minute {
				t.Errorf("valid for %v, past the %v cap", d, sshCertMaxLifetime)
			}
			if d <= 0 {
				t.Errorf("valid for %v -- the lifetime wrapped", d)
			}
		})
	}
}

// A credential carrying NO scopes at all must still be refused.
//
// scopedCredential reports `scoped` as false for an empty scope set, so
// a gate written only around it lets a zero-scope API key straight
// through -- and that caller reaches the schedd with no credential of
// its own, where GetSecurityConfigOrDefault falls back to this daemon's
// configuration. Same shape as the gaps closed on /api/v1/jupyter,
// /api/v1/chat and /api/v1/apps.
func TestCertificateRefusesAZeroScopeAPIKey(t *testing.T) {
	h := sshCertHandler(t, true)

	body := `{"public_key": "` + userPublicKey(t) + `"}`
	req := httptest.NewRequestWithContext(withAPIKeyMarker(context.Background()),
		http.MethodPost, "/api/v1/ssh/certificate", strings.NewReader(body))
	req.Header.Set("X-Test-User", "bbockelm")
	rec := httptest.NewRecorder()
	h.handleSSHCertificate(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Errorf("status = %d, want %d; body: %s", rec.Code, http.StatusForbidden, rec.Body.String())
	}
}

// The CA response tells a client where the gateway is, so it needs no
// configuration of its own. This server already knows the name -- it is
// the certificate's principal -- and used to keep it to itself.
func TestSSHCAAdvertisesTheGateway(t *testing.T) {
	h := sshCertHandler(t, true)
	h.sshGatewayPublicHost = "ap.example.edu:2222, alias.example.org"

	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/api/v1/ssh/ca", nil)
	req.Header.Set("X-Test-User", "bbockelm")
	rec := httptest.NewRecorder()
	h.handleSSHCA(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d: %s", rec.Code, rec.Body.String())
	}
	var body struct {
		GatewayHost string `json:"gateway_host"`
		GatewayPort int    `json:"gateway_port"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if body.GatewayHost != "ap.example.edu" || body.GatewayPort != 2222 {
		t.Errorf("advertised %q:%d, want ap.example.edu:2222", body.GatewayHost, body.GatewayPort)
	}
}

// Unset means unset. Guessing the listen address would send clients to
// a port that is usually not the one open to them: a container on :2222
// sits behind a service publishing 22 somewhere else.
func TestSSHCAOmitsAnUnconfiguredGateway(t *testing.T) {
	h := sshCertHandler(t, true)

	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/api/v1/ssh/ca", nil)
	req.Header.Set("X-Test-User", "bbockelm")
	rec := httptest.NewRecorder()
	h.handleSSHCA(rec, req)

	if strings.Contains(rec.Body.String(), "gateway_host") {
		t.Errorf("an unconfigured gateway was advertised anyway: %s", rec.Body.String())
	}
}
