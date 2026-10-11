package httpserver

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	htcondor "github.com/bbockelm/golang-htcondor"
)

// The pool summary ANDs the caller's expression onto its dynamic-slot
// exclusion. An expression with unbalanced parentheses could reach past
// that exclusion when spliced as text; it is refused with 400 before the
// collector is asked, and a well-formed one still goes out.
func TestPoolSummaryRefusesUnbalancedConstraint(t *testing.T) {
	addr, accepted := fakeScheddListener(t)
	cfg := newTestConfig(t)
	cfg.Collector = htcondor.NewCollector(addr)
	cfg.UserHeader = "X-Test-User"
	cfg.UserHeaderTrustAnyUnsafe = true // single-host test, no proxy in front
	cfg.SigningKeyPath = writeTestSigningKey(t)
	cfg.TrustDomain = "test.domain"
	cfg.UIDDomain = "test.domain"
	s, err := NewServer(cfg)
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	s.setupRoutes()

	get := func(constraint string) *httptest.ResponseRecorder {
		req := httptest.NewRequestWithContext(context.Background(), http.MethodGet,
			"/api/v1/collector/pool-summary?"+url.Values{"constraint": {constraint}}.Encode(), nil)
		req.Header.Set("X-Test-User", "alice")
		w := httptest.NewRecorder()
		s.ServeHTTP(w, req)
		return w
	}

	before := accepted.Load()
	if w := get(`true) || (true`); w.Code != http.StatusBadRequest {
		t.Errorf("an unbalanced constraint was answered %d, want 400: %s", w.Code, w.Body.String())
	}
	if n := accepted.Load() - before; n != 0 {
		t.Errorf("an unbalanced constraint reached the collector (%d connection(s))", n)
	}

	_ = get(`Cpus > 1`)
	if accepted.Load() == before {
		t.Error("a well-formed constraint never reached the collector; the zero above proves nothing")
	}
}
