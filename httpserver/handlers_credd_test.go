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
	}
	body, _ := json.Marshal(addReq)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/creds/service/example", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	s.handleServiceCredentialItem(w, req)

	if w.Result().StatusCode != http.StatusCreated {
		t.Fatalf("expected status 201, got %d", w.Result().StatusCode)
	}

	// Fetch credential token
	req = httptest.NewRequest(http.MethodGet, "/api/v1/creds/service/example/credential", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	w = httptest.NewRecorder()
	s.handleServiceCredentialItem(w, req)

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

	// List credentials
	req = httptest.NewRequest(http.MethodGet, "/api/v1/creds/service", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	w = httptest.NewRecorder()
	s.handleServiceCredentialCollection(w, req)

	if w.Result().StatusCode != http.StatusOK {
		t.Fatalf("expected status 200 on list, got %d", w.Result().StatusCode)
	}
	var listResp []serviceStatusResponse
	if err := json.NewDecoder(w.Body).Decode(&listResp); err != nil {
		t.Fatalf("failed to decode list response: %v", err)
	}
	if len(listResp) != 1 || listResp[0].Service != "example" {
		t.Fatalf("unexpected list response: %+v", listResp)
	}
}
