package httpserver

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	htcondor "github.com/bbockelm/golang-htcondor"
	"github.com/bbockelm/golang-htcondor/logging"
)

func credTestServer(t *testing.T) *Server {
	t.Helper()
	logger, err := logging.New(&logging.Config{OutputPath: "stderr"})
	if err != nil {
		t.Fatalf("failed to create logger: %v", err)
	}
	s, err := NewServer(Config{
		Logger:       logger,
		Credd:        htcondor.NewInMemoryCredd(),
		ScheddName:   "test-schedd",
		ScheddAddr:   "127.0.0.1:9618",
		OAuth2DBPath: t.TempDir() + "/sessions.db",
	})
	if err != nil {
		t.Fatalf("failed to create server: %v", err)
	}
	s.creddAvailable.Store(true)
	return s
}

// storeServiceCred POSTs a credential for one service and returns the recorder.
func storeServiceCred(t *testing.T, s *Server, service, credential string) *httptest.ResponseRecorder {
	t.Helper()
	body, err := json.Marshal(serviceCredentialRequest{CredType: "OAuth", Credential: credential})
	if err != nil {
		t.Fatalf("failed to marshal request: %v", err)
	}
	req := httptest.NewRequestWithContext(context.Background(), http.MethodPost,
		"/api/v1/creds/service/"+service, bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+createTestJWTToken(3600))
	w := httptest.NewRecorder()
	s.handleServiceCredentialItem(w, req)
	return w
}

// The REST store path had no JSON validation at all. The MCP tool grew one,
// but this path -- the one a browser or a script uses -- still accepted a bare
// token, and the credd still took it: it only parses the bytes when a request
// carries scopes or an audience. The store said 201, a list kept reporting the
// credential as present, and every query that named the service failed from
// then on. Nothing in the failure pointed back at the store.
func TestStoreServiceCredentialRESTRejectsNonJSON(t *testing.T) {
	s := credTestServer(t)

	w := storeServiceCred(t, s, "scitokens", "placeholder")
	if w.Code != http.StatusBadRequest {
		t.Fatalf("a bare token was accepted with status %d; it will break every later read", w.Code)
	}
	msg := w.Body.String()
	if !strings.Contains(msg, "not valid JSON") {
		t.Errorf("the error does not say what is wrong: %s", msg)
	}
	if !strings.Contains(msg, "access_token") {
		t.Errorf("the error does not show what a valid credential looks like: %s", msg)
	}

	// And it must not have reached the credd.
	creds, err := s.credd.ListServiceCreds(context.Background(), htcondor.CredTypeOAuth, "")
	if err != nil {
		t.Fatalf("failed to list credentials: %v", err)
	}
	if len(creds) != 0 {
		t.Errorf("the credential was stored anyway: %+v", creds)
	}
}

// base64 is decoded before storing, so the check has to run on the decoded
// bytes -- otherwise a perfectly good credential sent base64-encoded gets
// refused for not looking like JSON.
func TestStoreServiceCredentialRESTChecksDecodedBytes(t *testing.T) {
	s := credTestServer(t)

	encoded := base64.StdEncoding.EncodeToString([]byte(`{"access_token":"abc"}`))
	if w := storeServiceCred(t, s, "scitokens", encoded); w.Code != http.StatusCreated {
		t.Fatalf("a base64-encoded JSON credential was refused with status %d: %s", w.Code, w.Body.String())
	}
}

// An empty credential is a request, not a malformed credential: a credmon that
// mints tokens locally watches for the stored file and never reads what is in
// it. That is the documented path for services a job transform added, so the
// JSON rule must not swallow it.
func TestStoreServiceCredentialRESTAllowsEmpty(t *testing.T) {
	s := credTestServer(t)

	if w := storeServiceCred(t, s, "scitokens", ""); w.Code != http.StatusCreated {
		t.Fatalf("an empty credential was refused with status %d; that is how you ask a credmon to mint one: %s",
			w.Code, w.Body.String())
	}
}

// Only OAuth credentials are JSON. This endpoint's cred_type is not fixed --
// parseCredType accepts kerberos here too -- and a Kerberos credential is an
// opaque ticket that would fail a JSON check, so the gate has to be
// conditional on the type rather than applied to everything the handler
// stores.
func TestStoreServiceCredentialJSONRuleIsOAuthOnly(t *testing.T) {
	s := credTestServer(t)

	body, err := json.Marshal(serviceCredentialRequest{ //nolint:gosec // G101: test data
		CredType: "kerberos", Credential: "not-json-at-all"})
	if err != nil {
		t.Fatalf("failed to marshal request: %v", err)
	}
	req := httptest.NewRequestWithContext(context.Background(), http.MethodPost,
		"/api/v1/creds/service/krb", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+createTestJWTToken(3600))
	w := httptest.NewRecorder()
	s.handleServiceCredentialItem(w, req)

	if w.Code == http.StatusBadRequest {
		t.Fatalf("a Kerberos ticket was rejected for not being JSON: %s", w.Body.String())
	}
}
