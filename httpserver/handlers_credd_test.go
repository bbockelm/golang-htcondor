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

	// Add first service credential (github)
	addReq := serviceCredentialRequest{
		CredType:   "OAuth",
		Credential: "github-oauth-token",
	}
	body, _ := json.Marshal(addReq)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/creds/service/github", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	s.handleServiceCredentialItem(w, req)

	if w.Result().StatusCode != http.StatusCreated {
		t.Fatalf("expected status 201, got %d", w.Result().StatusCode)
	}

	// List credentials - should show only one
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
	if len(listResp) != 1 || listResp[0].Service != "github" {
		t.Fatalf("unexpected list response after first add: %+v", listResp)
	}
	t.Logf("✓ List shows 1 credential: %s", listResp[0].Service)

	// Add second service credential (gitlab)
	addReq2 := serviceCredentialRequest{
		CredType:   "OAuth",
		Credential: "gitlab-oauth-token",
	}
	body2, _ := json.Marshal(addReq2)
	req = httptest.NewRequest(http.MethodPost, "/api/v1/creds/service/gitlab", bytes.NewReader(body2))
	req.Header.Set("Authorization", "Bearer "+token)
	w = httptest.NewRecorder()
	s.handleServiceCredentialItem(w, req)

	if w.Result().StatusCode != http.StatusCreated {
		t.Fatalf("expected status 201 for second credential, got %d", w.Result().StatusCode)
	}
	t.Logf("✓ Added second credential: gitlab")

	// List credentials - should now show two
	req = httptest.NewRequest(http.MethodGet, "/api/v1/creds/service", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	w = httptest.NewRecorder()
	s.handleServiceCredentialCollection(w, req)

	if w.Result().StatusCode != http.StatusOK {
		t.Fatalf("expected status 200 on second list, got %d", w.Result().StatusCode)
	}
	var listResp2 []serviceStatusResponse
	if err := json.NewDecoder(w.Body).Decode(&listResp2); err != nil {
		t.Fatalf("failed to decode second list response: %v", err)
	}
	if len(listResp2) != 2 {
		t.Fatalf("expected 2 credentials in list, got %d: %+v", len(listResp2), listResp2)
	}

	// Verify both services are present
	services := make(map[string]bool)
	for _, item := range listResp2 {
		services[item.Service] = true
	}
	if !services["github"] || !services["gitlab"] {
		t.Fatalf("expected both 'github' and 'gitlab' in list, got: %+v", listResp2)
	}
	t.Logf("✓ List shows 2 credentials: github and gitlab")

	// Fetch first credential token
	req = httptest.NewRequest(http.MethodGet, "/api/v1/creds/service/github/credential", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	w = httptest.NewRecorder()
	s.handleServiceCredentialItem(w, req)

	if w.Result().StatusCode != http.StatusOK {
		t.Fatalf("expected status 200 for github credential, got %d", w.Result().StatusCode)
	}

	var resp1 oauthCredentialResponse
	if err := json.NewDecoder(w.Body).Decode(&resp1); err != nil {
		t.Fatalf("failed to decode github response: %v", err)
	}
	if resp1.Credential != "github-oauth-token" {
		t.Fatalf("unexpected github credential: %s", resp1.Credential)
	}
	t.Logf("✓ Fetched github credential successfully")

	// Fetch second credential token
	req = httptest.NewRequest(http.MethodGet, "/api/v1/creds/service/gitlab/credential", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	w = httptest.NewRecorder()
	s.handleServiceCredentialItem(w, req)

	if w.Result().StatusCode != http.StatusOK {
		t.Fatalf("expected status 200 for gitlab credential, got %d", w.Result().StatusCode)
	}

	var resp2 oauthCredentialResponse
	if err := json.NewDecoder(w.Body).Decode(&resp2); err != nil {
		t.Fatalf("failed to decode gitlab response: %v", err)
	}
	if resp2.Credential != "gitlab-oauth-token" {
		t.Fatalf("unexpected gitlab credential: %s", resp2.Credential)
	}
	t.Logf("✓ Fetched gitlab credential successfully")
}
