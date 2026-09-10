package httpserver

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestValidateGrantTypes(t *testing.T) {
	ok := [][]string{
		{"authorization_code"},
		{"authorization_code", "refresh_token"},
		{"client_credentials"},
		{"authorization_code", "refresh_token", "client_credentials"},
	}
	for _, g := range ok {
		if err := validateGrantTypes(g, false); err != nil {
			t.Errorf("validateGrantTypes(%v, confidential) = %v, want nil", g, err)
		}
	}
	if err := validateGrantTypes(nil, false); err == nil {
		t.Error("empty grant set must be rejected")
	}
	if err := validateGrantTypes([]string{"password"}, false); err == nil {
		t.Error("unsupported grant must be rejected")
	}
	if err := validateGrantTypes([]string{"authorization_code", "authorization_code"}, false); err == nil {
		t.Error("duplicate grant must be rejected")
	}
	// A public client cannot hold client_credentials (no secret to authenticate it).
	if err := validateGrantTypes([]string{"client_credentials"}, true); err == nil {
		t.Error("client_credentials on a public client must be rejected")
	}
}

func TestPatchGrantTypesAndServiceSubject(t *testing.T) {
	server, req := newProvenanceServer(t)
	db := server.oauth2Provider.GetStorage().GetDB()
	insertClient(t, db, "svc") // confidential (public=0)

	patch := func(body string) int {
		rec := httptest.NewRecorder()
		server.handleAdminUpdateClient(rec, req("PATCH", "/api/v1/admin/oauth2/clients/svc", body))
		return rec.Code
	}

	// client_credentials without a service subject is refused.
	if code := patch(`{"grant_types":["client_credentials"]}`); code != http.StatusBadRequest {
		t.Errorf("client_credentials w/o subject: status %d, want 400", code)
	}

	// With a subject it succeeds and both are persisted.
	if code := patch(`{"grant_types":["client_credentials"],"service_subject":"pipeline-bot"}`); code != http.StatusOK {
		t.Fatalf("client_credentials w/ subject: status %d, want 200", code)
	}
	got := findClient(t, listClients(t, server, req), "svc")
	if len(got.GrantTypes) != 1 || got.GrantTypes[0] != "client_credentials" {
		t.Errorf("grant types = %v, want [client_credentials]", got.GrantTypes)
	}
	if got.ServiceSubject != "pipeline-bot" {
		t.Errorf("service subject = %q, want pipeline-bot", got.ServiceSubject)
	}

	// The stored subject is what the token handler will read.
	subj, err := server.oauth2Provider.GetStorage().clientServiceSubject(context.Background(), "svc")
	if err != nil || subj != "pipeline-bot" {
		t.Errorf("clientServiceSubject = %q,%v", subj, err)
	}

	// An unsupported grant is rejected without changing anything.
	if code := patch(`{"grant_types":["password"]}`); code != http.StatusBadRequest {
		t.Errorf("unsupported grant: status %d, want 400", code)
	}
}

func TestPatchClientCredentialsRejectedForPublicClient(t *testing.T) {
	server, req := newProvenanceServer(t)
	db := server.oauth2Provider.GetStorage().GetDB()
	// public=1
	if _, err := db.ExecContext(context.Background(), `INSERT INTO oauth2_clients
		(id, client_secret, redirect_uris, grant_types, response_types, scopes, public)
		VALUES ('pub', '', '[]', '[]', '[]', '[]', 1)`); err != nil {
		t.Fatal(err)
	}
	rec := httptest.NewRecorder()
	server.handleAdminUpdateClient(rec,
		req("PATCH", "/api/v1/admin/oauth2/clients/pub",
			`{"grant_types":["client_credentials"],"service_subject":"x"}`))
	if rec.Code != http.StatusBadRequest {
		t.Errorf("client_credentials on public client: status %d, want 400", rec.Code)
	}
}
