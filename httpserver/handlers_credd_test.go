package httpserver

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	htcondor "github.com/bbockelm/golang-htcondor"
	"github.com/bbockelm/golang-htcondor/logging"
)

func TestHandlePasswordCredential_CreateAndQuery(t *testing.T) {
	logger, err := logging.New(&logging.Config{OutputPath: "stderr"})
	if err != nil {
		t.Fatalf("failed to create logger: %v", err)
	}

	s := &Server{
		logger:     logger,
		tokenCache: NewTokenCache(),
		credd:      htcondor.NewInMemoryCredd(),
	}

	token := createTestJWTToken(3600)

	// Add password
	body, _ := json.Marshal(passwordRequest{Password: "secret"})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/creds/password", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	s.handlePasswordCredential(w, req)

	if w.Result().StatusCode != http.StatusCreated {
		t.Fatalf("expected status 201, got %d", w.Result().StatusCode)
	}

	// Query password
	req = httptest.NewRequest(http.MethodGet, "/api/v1/creds/password", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	w = httptest.NewRecorder()
	s.handlePasswordCredential(w, req)

	if w.Result().StatusCode != http.StatusOK {
		t.Fatalf("expected status 200 on query, got %d", w.Result().StatusCode)
	}

	var status credentialStatusResponse
	if err := json.NewDecoder(w.Body).Decode(&status); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}
	if !status.Exists {
		t.Fatalf("expected credential to exist")
	}
}

func TestHandleServiceCredential_AddAndFetchToken(t *testing.T) {
	logger, err := logging.New(&logging.Config{OutputPath: "stderr"})
	if err != nil {
		t.Fatalf("failed to create logger: %v", err)
	}

	s := &Server{
		logger:     logger,
		tokenCache: NewTokenCache(),
		credd:      htcondor.NewInMemoryCredd(),
	}

	token := createTestJWTToken(3600)

	// Add service credential
	addReq := serviceCredentialRequest{
		CredType:   "OAuth",
		Credential: "oauth-token",
		Service:    "example",
	}
	body, _ := json.Marshal(addReq)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/creds/service", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	s.handleServiceCredential(w, req)

	if w.Result().StatusCode != http.StatusCreated {
		t.Fatalf("expected status 201, got %d", w.Result().StatusCode)
	}

	// Fetch credential token
	req = httptest.NewRequest(http.MethodGet, "/api/v1/creds/service/token?service=example", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	w = httptest.NewRecorder()
	s.handleServiceCredentialToken(w, req)

	if w.Result().StatusCode != http.StatusOK {
		t.Fatalf("expected status 200, got %d", w.Result().StatusCode)
	}

	var resp oauthCredentialResponse
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}
	if resp.Credential != "oauth-token" {
		t.Fatalf("unexpected credential: %s", resp.Credential)
	}
}
