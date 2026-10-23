package httpserver

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// A submit file that sets, as a custom attribute, an attribute the site
// overrides control is refused with 400 before the schedd is contacted;
// the same file without that line goes on to the schedd.
func TestSubmitRefusesCustomAttributeAnOverrideControls(t *testing.T) {
	addr, accepted := fakeScheddListener(t)
	cfg := newTestConfig(t)
	cfg.ScheddAddr = addr
	cfg.UserHeader = "X-Test-User"
	cfg.UserHeaderTrustAnyUnsafe = true // single-host test, no proxy in front
	cfg.SigningKeyPath = writeTestSigningKey(t)
	cfg.TrustDomain = "test.domain"
	cfg.UIDDomain = "test.domain"
	cfg.SubmitFileOverrides = "accounting_group = grp_site"
	s, err := NewServer(cfg)
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	s.setupRoutes()

	post := func(submitFile string) *httptest.ResponseRecorder {
		body, err := json.Marshal(map[string]string{"submit_file": submitFile})
		if err != nil {
			t.Fatal(err)
		}
		req := httptest.NewRequestWithContext(context.Background(), http.MethodPost,
			"/api/v1/jobs", strings.NewReader(string(body)))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("X-Test-User", "alice")
		w := httptest.NewRecorder()
		s.ServeHTTP(w, req)
		return w
	}

	before := accepted.Load()
	w := post("executable = /bin/true\n+AccountingGroup = \"evil\"\nqueue\n")
	if w.Code != http.StatusBadRequest || !strings.Contains(w.Body.String(), "AccountingGroup") {
		t.Fatalf("submit setting +AccountingGroup was answered %d, want 400 naming it: %s", w.Code, w.Body.String())
	}
	if n := accepted.Load() - before; n != 0 {
		t.Errorf("the refused submit reached the schedd (%d connection(s))", n)
	}

	w = post("executable = /bin/true\n+ProjectName = \"mine\"\nqueue\n")
	if w.Code == http.StatusBadRequest {
		t.Fatalf("a submit with an unrelated custom attribute was refused: %s", w.Body.String())
	}
	if accepted.Load() == before {
		t.Errorf("an acceptable submit never reached the schedd (status %d: %s)", w.Code, w.Body.String())
	}
}
