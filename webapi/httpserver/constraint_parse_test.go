package httpserver

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
)

// An administrator's listing is not owner-scoped, so nothing in the
// handler re-parses its constraint; one that does not parse must still be
// a 400 before the schedd is contacted, not a query for every job.
func TestUnscopedListingRefusesUnparseableConstraint(t *testing.T) {
	addr, accepted := fakeScheddListener(t)
	cfg := newTestConfig(t)
	cfg.ScheddAddr = addr
	cfg.UserHeader = "X-Test-User"
	cfg.UserHeaderTrustAnyUnsafe = true // single-host test, no proxy in front
	cfg.SigningKeyPath = writeTestSigningKey(t)
	cfg.TrustDomain = "test.domain"
	cfg.UIDDomain = "test.domain"
	cfg.MCPAdminUsers = []string{"admin"}
	s, err := NewServer(cfg)
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	s.setupRoutes()

	list := func(constraint string) *httptest.ResponseRecorder {
		q := url.Values{"owned_by_me": {"false"}, "constraint": {constraint}}
		req := httptest.NewRequestWithContext(context.Background(), http.MethodGet,
			"/api/v1/jobs?"+q.Encode(), nil)
		req.Header.Set("X-Test-User", "admin")
		w := httptest.NewRecorder()
		s.ServeHTTP(w, req)
		return w
	}

	before := accepted.Load()
	if w := list("JobStatus = 1"); w.Code != http.StatusBadRequest {
		t.Errorf("an unparseable constraint was answered %d, want 400: %s", w.Code, w.Body.String())
	}
	if n := accepted.Load() - before; n != 0 {
		t.Errorf("an unparseable constraint reached the schedd (%d connection(s))", n)
	}

	_ = list("JobStatus == 1")
	if accepted.Load() == before {
		t.Error("a valid constraint never reached the schedd; the zero above proves nothing")
	}
}
