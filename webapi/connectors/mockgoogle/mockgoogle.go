// Package mockgoogle is a stand-in for Google's OAuth2 and Drive
// endpoints, for testing connectors without a Google client, a consent
// screen or a Drive account.
//
// # Provenance, which is the whole point
//
// A mock built from what we ASSUME an API does will agree with code
// built from the same assumption, and the tests go green and wrong.
// This repository has been there: the ClassAd wire format once had
// code, tests and documentation agreeing with each other and all three
// incorrect. So every behaviour here is tagged with where it came from,
// and there are three tiers.
//
// [GOOGLE] Transcribed from Google's "Using OAuth 2.0 for Web Server
// Applications", https://developers.google.com/identity/protocols/oauth2/web-server,
// read 2026-11-21, from the part of the page returned verbatim:
//
//   - authorization endpoint https://accounts.google.com/o/oauth2/v2/auth
//   - token endpoint https://oauth2.googleapis.com/token
//   - revocation endpoint https://oauth2.googleapis.com/revoke, taking
//     the credential as a "token" parameter, 200 on success
//   - authorization parameters: client_id, redirect_uri, response_type,
//     scope (all required); access_type, state, include_granted_scopes,
//     enable_granular_consent, login_hint, prompt
//   - code-exchange parameters: client_id, client_secret (OPTIONAL),
//     code, grant_type=authorization_code, redirect_uri
//   - code-exchange response fields: access_token, expires_in,
//     refresh_token, refresh_token_expires_in, scope, token_type
//   - token_type is always "Bearer"
//   - refresh_token is present only when access_type=offline was set on
//     the authorization request
//   - prompt=consent is how an application that already holds a refresh
//     token gets a new one issued
//   - error codes: access_denied, invalid_client, deleted_client,
//     invalid_grant, redirect_uri_mismatch, invalid_request
//   - invalid_grant on a code exchange means the code is invalid or
//     malformed; on a refresh it means the token "may have expired or
//     has been invalidated"
//   - an application should ignore unrecognized response fields
//
// [RFC] From RFC 6749, because Google's page does NOT document it. The
// page names the error codes but never shows an error body, so the
// {"error": ..., "error_description": ...} envelope here is the RFC's
// shape carrying Google's code names. If a real exchange ever disagrees,
// this is the first thing to suspect.
//
// [UNVERIFIED] Reached only through a model summary of the page's tail,
// or from third-party sources, and NOT relied on by any behaviour here:
// whether a refresh response returns a new refresh_token (the page does
// not say), per-user refresh token limits, and the seven-day refresh
// expiry reported for clients left in "Testing" publishing status, which
// is not on this page at all.
//
// # PKCE
//
// Google's web-server page does NOT document code_challenge or
// code_challenge_method; it is written for a confidential client with a
// secret. This mock accepts and verifies PKCE when the authorization
// request carries a challenge, and ignores it otherwise, so a connector
// may use it without this mock asserting that Google requires it.
// Treat PKCE support here as [RFC] (7636), not [GOOGLE].
package mockgoogle

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"
)

// Config is the client registration the mock will accept.
type Config struct {
	ClientID     string
	ClientSecret string
	RedirectURI  string
}

// grant is one issued authorization, keyed by its code.
type grant struct {
	user          string
	scope         string
	redirectURI   string
	codeChallenge string
	method        string
	offline       bool
	used          bool
}

// token is an issued refresh token and what it can do.
type token struct {
	user    string
	scope   string
	revoked bool
}

// Server is the mock. Build one with New and close it with Close.
type Server struct {
	*httptest.Server
	t   *testing.T
	cfg Config

	mu sync.Mutex
	// codes issued by the authorization endpoint, by code.
	codes map[string]*grant
	// refresh tokens issued by the token endpoint, by token.
	refresh map[string]*token
	// access tokens currently valid, by token.
	access map[string]*token
	// files the application may read, by file id. Under drive.file this
	// is the set the user has picked; the mock records it rather than
	// inventing it, so a test says which files were picked.
	files map[string][]byte
	// listable is what files.list returns, by file id -> name.
	listable map[string]string

	// nextStatuses is a queue of HTTP statuses to return instead of
	// doing the work, for exercising retry and failure paths.
	nextStatuses []int
	// denyAuthorization makes the authorization endpoint redirect with
	// error=access_denied, which is what a user clicking "cancel" does.
	denyAuthorization bool

	seq int
}

// New starts a mock and registers its cleanup.
func New(t *testing.T, cfg Config) *Server {
	t.Helper()
	s := &Server{
		t:        t,
		cfg:      cfg,
		codes:    map[string]*grant{},
		refresh:  map[string]*token{},
		access:   map[string]*token{},
		files:    map[string][]byte{},
		listable: map[string]string{},
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/o/oauth2/v2/auth", s.handleAuthorize)
	mux.HandleFunc("/token", s.handleToken)
	mux.HandleFunc("/revoke", s.handleRevoke)
	mux.HandleFunc("/drive/v3/files", s.handleFilesList)
	mux.HandleFunc("/drive/v3/files/", s.handleFileGet)
	s.Server = httptest.NewServer(mux)
	t.Cleanup(s.Close)
	return s
}

// AuthorizationURL stands in for accounts.google.com/o/oauth2/v2/auth.
func (s *Server) AuthorizationURL() string { return s.URL + "/o/oauth2/v2/auth" }

// TokenURL stands in for oauth2.googleapis.com/token.
func (s *Server) TokenURL() string { return s.URL + "/token" }

// RevokeURL stands in for oauth2.googleapis.com/revoke.
func (s *Server) RevokeURL() string { return s.URL + "/revoke" }

// DriveBaseURL stands in for www.googleapis.com/drive/v3.
func (s *Server) DriveBaseURL() string { return s.URL + "/drive/v3" }

// --- what a test sets up ----------------------------------------------

// PickFile makes a file readable by the application, which is what the
// Picker does under the drive.file scope: picking IS the grant.
func (s *Server) PickFile(id, name string, content []byte) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.files[id] = content
	s.listable[id] = name
}

// Revoke invalidates a refresh token, as the user withdrawing the
// application's access does. A later refresh then fails invalid_grant.
func (s *Server) Revoke(refreshToken string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if tok, ok := s.refresh[refreshToken]; ok {
		tok.revoked = true
	}
}

// FailNext queues HTTP statuses to return in place of doing the work.
func (s *Server) FailNext(statuses ...int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.nextStatuses = append(s.nextStatuses, statuses...)
}

// DenyAuthorization makes the next authorization redirect carry
// error=access_denied, which is a user clicking cancel.
func (s *Server) DenyAuthorization(deny bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.denyAuthorization = deny
}

// AccessTokenValid reports whether an access token this mock issued is
// still one it would accept, for a test that wants to assert a token
// was actually minted rather than reused.
func (s *Server) AccessTokenValid(tok string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	_, ok := s.access[tok]
	return ok
}

func (s *Server) takeStatus() (int, bool) {
	if len(s.nextStatuses) == 0 {
		return 0, false
	}
	code := s.nextStatuses[0]
	s.nextStatuses = s.nextStatuses[1:]
	return code, true
}

func (s *Server) mint(prefix string) string {
	s.seq++
	return fmt.Sprintf("%s-%d", prefix, s.seq)
}

// --- OAuth2 -----------------------------------------------------------

// handleAuthorize is the authorization endpoint.
//
// [GOOGLE] client_id, redirect_uri, response_type and scope are
// required; a redirect_uri that does not match returns
// redirect_uri_mismatch; state is returned as given.
func (s *Server) handleAuthorize(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()

	// redirect_uri is checked before anything is redirected anywhere:
	// bouncing an error to an unregistered URI would be an open
	// redirector, which is the bug this check exists to prevent.
	redirect := q.Get("redirect_uri")
	if redirect == "" || redirect != s.cfg.RedirectURI {
		writeOAuthError(w, http.StatusBadRequest, "redirect_uri_mismatch",
			"the redirect_uri does not match a registered URI")
		return
	}
	if q.Get("client_id") != s.cfg.ClientID {
		writeOAuthError(w, http.StatusUnauthorized, "invalid_client", "unknown client_id")
		return
	}

	back, err := url.Parse(redirect)
	if err != nil {
		writeOAuthError(w, http.StatusBadRequest, "invalid_request", "unparseable redirect_uri")
		return
	}
	rq := back.Query()
	if state := q.Get("state"); state != "" {
		rq.Set("state", state)
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	if s.denyAuthorization {
		// [GOOGLE] the page's own example: ...?error=access_denied
		rq.Set("error", "access_denied")
		back.RawQuery = rq.Encode()
		http.Redirect(w, r, back.String(), http.StatusFound) //nolint:gosec // G710: back is parsed from redirect, which was compared against s.cfg.RedirectURI at the top of this handler; an unregistered URI never reaches here
		return
	}
	if q.Get("response_type") != "code" {
		rq.Set("error", "invalid_request")
		back.RawQuery = rq.Encode()
		http.Redirect(w, r, back.String(), http.StatusFound) //nolint:gosec // G710: back is parsed from redirect, which was compared against s.cfg.RedirectURI at the top of this handler; an unregistered URI never reaches here
		return
	}
	if strings.TrimSpace(q.Get("scope")) == "" {
		rq.Set("error", "invalid_request")
		back.RawQuery = rq.Encode()
		http.Redirect(w, r, back.String(), http.StatusFound) //nolint:gosec // G710: back is parsed from redirect, which was compared against s.cfg.RedirectURI at the top of this handler; an unregistered URI never reaches here
		return
	}

	code := s.mint("code")
	s.codes[code] = &grant{
		user:          "mock-user",
		scope:         q.Get("scope"),
		redirectURI:   redirect,
		codeChallenge: q.Get("code_challenge"),
		method:        q.Get("code_challenge_method"),
		// [GOOGLE] a refresh token comes back only when the
		// authorization request asked for offline access.
		offline: q.Get("access_type") == "offline",
	}

	rq.Set("code", code)
	back.RawQuery = rq.Encode()
	http.Redirect(w, r, back.String(), http.StatusFound) //nolint:gosec // G710: back is parsed from redirect, which was compared against s.cfg.RedirectURI at the top of this handler; an unregistered URI never reaches here
}

func (s *Server) handleToken(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	if code, ok := s.takeStatus(); ok {
		s.mu.Unlock()
		writeOAuthError(w, code, "temporarily_unavailable", "rigged by the test")
		return
	}
	s.mu.Unlock()

	if err := r.ParseForm(); err != nil {
		writeOAuthError(w, http.StatusBadRequest, "invalid_request", "unparseable body")
		return
	}
	switch r.PostForm.Get("grant_type") {
	case "authorization_code":
		s.exchangeCode(w, r)
	case "refresh_token":
		s.refreshToken(w, r)
	default:
		// [GOOGLE] names invalid_request among its error codes.
		writeOAuthError(w, http.StatusBadRequest, "invalid_request",
			"grant_type must be authorization_code or refresh_token")
	}
}

func (s *Server) exchangeCode(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if !s.clientOK(r) {
		writeOAuthError(w, http.StatusUnauthorized, "invalid_client", "bad client credentials")
		return
	}

	g, ok := s.codes[r.PostForm.Get("code")]
	if !ok {
		// [GOOGLE] "The supplied authorization code is invalid or in the
		// wrong format."
		writeOAuthError(w, http.StatusBadRequest, "invalid_grant",
			"the supplied authorization code is invalid or in the wrong format")
		return
	}
	if g.used {
		// An authorization code is single use. Google's page does not
		// spell this out, but reusing one is among the things it says
		// produce invalid_grant, and RFC 6749 §4.1.2 requires it.
		writeOAuthError(w, http.StatusBadRequest, "invalid_grant",
			"the authorization code has already been redeemed")
		return
	}
	if r.PostForm.Get("redirect_uri") != g.redirectURI {
		writeOAuthError(w, http.StatusBadRequest, "redirect_uri_mismatch",
			"the redirect_uri does not match the authorization request")
		return
	}
	// [RFC 7636] only when the authorization request carried a
	// challenge; Google's web-server page documents no PKCE at all.
	if g.codeChallenge != "" && !verifyPKCE(g, r.PostForm.Get("code_verifier")) {
		writeOAuthError(w, http.StatusBadRequest, "invalid_grant", "PKCE verification failed")
		return
	}
	g.used = true

	at := s.mint("access")
	s.access[at] = &token{user: g.user, scope: g.scope}

	resp := map[string]any{
		"access_token": at,
		"expires_in":   3920, // [GOOGLE] the value in the page's own example
		"token_type":   "Bearer",
		"scope":        g.scope,
	}
	if g.offline {
		rt := s.mint("refresh")
		s.refresh[rt] = &token{user: g.user, scope: g.scope}
		resp["refresh_token"] = rt
	}
	writeJSON(w, http.StatusOK, resp)
}

func (s *Server) refreshToken(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if !s.clientOK(r) {
		writeOAuthError(w, http.StatusUnauthorized, "invalid_client", "bad client credentials")
		return
	}
	tok, ok := s.refresh[r.PostForm.Get("refresh_token")]
	if !ok || tok.revoked {
		// [GOOGLE] on a refresh, invalid_grant means "the token may have
		// expired or has been invalidated".
		writeOAuthError(w, http.StatusBadRequest, "invalid_grant",
			"token has been expired or revoked")
		return
	}

	at := s.mint("access")
	s.access[at] = &token{user: tok.user, scope: tok.scope}

	// No refresh_token in the response. Google's page does not say
	// whether one comes back on a refresh, and its refresh example does
	// not show one -- so the mock does the thing the documentation
	// shows rather than the thing we might prefer. A connector that
	// depends on receiving a new refresh token here would be depending
	// on something undocumented, and this is where it finds out.
	writeJSON(w, http.StatusOK, map[string]any{
		"access_token": at,
		"expires_in":   3920,
		"token_type":   "Bearer",
	})
}

// clientOK checks the client credentials.
//
// [GOOGLE] client_secret is listed as OPTIONAL on the code exchange, so
// a request that omits it is not refused for that reason alone; one that
// sends a WRONG secret is.
func (s *Server) clientOK(r *http.Request) bool {
	if r.PostForm.Get("client_id") != s.cfg.ClientID {
		if id, secret, ok := r.BasicAuth(); ok {
			return id == s.cfg.ClientID && secret == s.cfg.ClientSecret
		}
		return false
	}
	if got := r.PostForm.Get("client_secret"); got != "" && got != s.cfg.ClientSecret {
		return false
	}
	return true
}

// handleRevoke is the revocation endpoint.
//
// [GOOGLE] takes the credential as a "token" parameter and answers 200
// on success; the page's sample sends it as a query parameter.
func (s *Server) handleRevoke(w http.ResponseWriter, r *http.Request) {
	_ = r.ParseForm()
	tok := r.FormValue("token")

	s.mu.Lock()
	defer s.mu.Unlock()
	if t, ok := s.refresh[tok]; ok {
		t.revoked = true
		w.WriteHeader(http.StatusOK)
		return
	}
	if _, ok := s.access[tok]; ok {
		delete(s.access, tok)
		w.WriteHeader(http.StatusOK)
		return
	}
	// [GOOGLE, SUMMARY] errors return 400.
	writeOAuthError(w, http.StatusBadRequest, "invalid_token", "unknown token")
}

// --- Drive ------------------------------------------------------------

func (s *Server) handleFileGet(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	if code, ok := s.takeStatus(); ok {
		s.mu.Unlock()
		writeDriveError(w, code, "rigged", "rigged by the test")
		return
	}
	s.mu.Unlock()

	if !s.bearerOK(r) {
		writeDriveError(w, http.StatusUnauthorized, "authError", "Invalid Credentials")
		return
	}
	id := strings.TrimPrefix(r.URL.Path, "/drive/v3/files/")

	s.mu.Lock()
	content, ok := s.files[id]
	s.mu.Unlock()
	if !ok {
		// Under drive.file a file the application was never granted
		// does not exist as far as the application is concerned, so this
		// is 404 and not 403. That distinction is what gdrive2_plugin
		// explains in a hold reason.
		writeDriveError(w, http.StatusNotFound, "notFound", "File not found: "+id+".")
		return
	}
	if r.URL.Query().Get("alt") != "media" {
		writeJSON(w, http.StatusOK, map[string]any{"id": id, "name": s.listable[id]})
		return
	}
	w.Header().Set("Content-Type", "application/octet-stream")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(content)
}

func (s *Server) handleFilesList(w http.ResponseWriter, r *http.Request) {
	if !s.bearerOK(r) {
		writeDriveError(w, http.StatusUnauthorized, "authError", "Invalid Credentials")
		return
	}
	// drive.file narrows a listing to what the application may already
	// see, so the mock lists only picked files whatever the query says.
	s.mu.Lock()
	defer s.mu.Unlock()
	files := make([]map[string]string, 0, len(s.listable))
	for id, name := range s.listable {
		files = append(files, map[string]string{"id": id, "name": name})
	}
	writeJSON(w, http.StatusOK, map[string]any{"files": files})
}

func (s *Server) bearerOK(r *http.Request) bool {
	auth := r.Header.Get("Authorization")
	tok, ok := strings.CutPrefix(auth, "Bearer ")
	if !ok {
		return false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	_, live := s.access[tok]
	return live
}

// --- wire shapes ------------------------------------------------------

// writeOAuthError writes the RFC 6749 error envelope carrying one of
// Google's documented code names.
//
// [RFC] The envelope. Google's page names the codes but never shows a
// body, so this shape is the RFC's and not transcribed. If a real
// exchange ever disagrees with a connector's parsing, suspect this.
func writeOAuthError(w http.ResponseWriter, status int, code, desc string) {
	writeJSON(w, status, map[string]any{
		"error":             code,
		"error_description": desc,
	})
}

// writeDriveError writes the Drive API error envelope.
//
// [GOOGLE, by observation of the API rather than from the OAuth2 page]
// Drive wraps errors as {"error": {"code", "message", "errors":[...]}}.
func writeDriveError(w http.ResponseWriter, status int, reason, message string) {
	writeJSON(w, status, map[string]any{
		"error": map[string]any{
			"code":    status,
			"message": message,
			"errors": []map[string]any{{
				"domain":  "global",
				"reason":  reason,
				"message": message,
			}},
		},
	})
}

func writeJSON(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", "application/json; charset=UTF-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(body)
}

func verifyPKCE(g *grant, verifier string) bool {
	if verifier == "" {
		return false
	}
	switch strings.ToUpper(g.method) {
	case "", "PLAIN":
		return verifier == g.codeChallenge
	case "S256":
		sum := sha256.Sum256([]byte(verifier))
		return base64.RawURLEncoding.EncodeToString(sum[:]) == g.codeChallenge
	}
	return false
}

// Deadline is a helper for tests that wait on the mock.
var Deadline = 5 * time.Second
