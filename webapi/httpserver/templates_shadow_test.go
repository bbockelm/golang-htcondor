package httpserver

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/bbockelm/golang-htcondor/webapi/templates"
)

// A user cannot save a shared template under a built-in's id, so another
// user fetching that id gets the built-in; a template under a free id is
// still saved and shared.
func TestSavedTemplateCannotTakeABuiltinID(t *testing.T) {
	cfg := newTestConfig(t)
	cfg.UserHeader = "X-Test-User"
	cfg.UserHeaderTrustAnyUnsafe = true // single-host test, no proxy in front
	cfg.SigningKeyPath = writeTestSigningKey(t)
	cfg.TrustDomain = "test.domain"
	cfg.UIDDomain = "test.domain"
	s, err := NewServer(cfg)
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	if s.templateLibrary == nil {
		t.Fatal("no template store: this test cannot exercise Save")
	}
	s.setupRoutes()

	do := func(method, path, user, body string) *httptest.ResponseRecorder {
		req := httptest.NewRequestWithContext(context.Background(), method, path, strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("X-Test-User", user)
		w := httptest.NewRecorder()
		s.ServeHTTP(w, req)
		return w
	}

	const shadow = `{"id":"hello-world","name":"Hello","contents":"executable = /bin/evil\nqueue\n","visibility":"shared"}`
	if w := do(http.MethodPost, "/api/v1/templates", "mallory", shadow); w.Code != http.StatusBadRequest {
		t.Errorf("saving under a built-in id: %d, want 400: %s", w.Code, w.Body.String())
	}
	w := do(http.MethodGet, "/api/v1/templates/hello-world", "alice", "")
	var got templates.Template
	if err := json.Unmarshal(w.Body.Bytes(), &got); err != nil || got.Source != templates.SourceBuiltin {
		t.Errorf("alice's hello-world: %d %s, want the built-in", w.Code, w.Body.String())
	}

	const free = `{"id":"mallory-pipeline","name":"Pipeline","contents":"# x\nqueue\n","visibility":"shared"}`
	if w := do(http.MethodPost, "/api/v1/templates", "mallory", free); w.Code != http.StatusCreated {
		t.Fatalf("saving under a free id: %d: %s", w.Code, w.Body.String())
	}
	if w := do(http.MethodGet, "/api/v1/templates/mallory-pipeline", "alice", ""); w.Code != http.StatusOK ||
		!strings.Contains(w.Body.String(), `"owner":"mallory"`) {
		t.Errorf("alice cannot load mallory's shared template: %d %s", w.Code, w.Body.String())
	}
}
