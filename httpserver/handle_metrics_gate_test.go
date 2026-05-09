package httpserver

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"

	"github.com/bbockelm/golang-htcondor/httpserver/apikey"
)

// metricsGateHandler is the smallest Handler that can serve
// /metrics: a logger, an apiKeyStore, and an httpMetricsState. Other
// fields stay nil — handleMetrics doesn't read them on the gate path.
func metricsGateHandler(t *testing.T, public bool) *Handler {
	t.Helper()
	db := newTestDB(t, filepath.Join(t.TempDir(), "metrics-ak.db"))
	return &Handler{
		logger:           testLogger(t),
		apiKeyStore:      &apiKeyStore{db: db},
		httpMetricsState: newHTTPMetrics(),
		metricsPublic:    public,
	}
}

// TestMetricsGateAllowsPublic verifies HTTP_API_METRICS_PUBLIC=true
// preserves the pre-API-key behavior: anyone can scrape, no auth.
// Returning anything other than 200 here would break operators who
// depend on the public mode being a true bypass.
func TestMetricsGateAllowsPublic(t *testing.T) {
	h := metricsGateHandler(t, true)
	w := httptest.NewRecorder()
	h.handleMetrics(w, httptest.NewRequest("GET", "/metrics", nil))
	if w.Code != http.StatusOK {
		t.Errorf("public /metrics returned %d, want 200; body=%s", w.Code, w.Body.String())
	}
}

// TestMetricsGateRejectsUnauthenticated checks that without the
// public flag, an unauthenticated request gets 401. This is the
// security-finding fix the user asked for.
func TestMetricsGateRejectsUnauthenticated(t *testing.T) {
	h := metricsGateHandler(t, false)
	w := httptest.NewRecorder()
	h.handleMetrics(w, httptest.NewRequest("GET", "/metrics", nil))
	if w.Code != http.StatusUnauthorized {
		t.Errorf("unauthenticated /metrics returned %d, want 401; body=%s", w.Code, w.Body.String())
	}
}

// TestMetricsGateRejectsBogusKey covers a presented API key that
// doesn't match any stored row. Should 401 — no info leak about
// whether the key_id existed.
func TestMetricsGateRejectsBogusKey(t *testing.T) {
	h := metricsGateHandler(t, false)
	bogus := apikey.Prefix + "ffffffffffff-ffffffffffffffffffffffffffffffff"
	r := httptest.NewRequest("GET", "/metrics", nil)
	r.Header.Set("Authorization", "Bearer "+bogus)
	w := httptest.NewRecorder()
	h.handleMetrics(w, r)
	if w.Code != http.StatusUnauthorized {
		t.Errorf("bogus-key /metrics returned %d, want 401; body=%s", w.Code, w.Body.String())
	}
}

// TestMetricsGateRejectsKeyWithoutScope covers the case where the
// admin minted a key for a different purpose and a Prometheus
// operator tries to use it. We deny with 403 (we know who you are,
// you just lack permission) — distinct from 401 (we don't know who
// you are at all).
func TestMetricsGateRejectsKeyWithoutScope(t *testing.T) {
	h := metricsGateHandler(t, false)
	minted, _ := apikey.Mint()
	// Use a fake scope that's not "metrics". The store doesn't
	// validate scope vocabulary at insert-time (the admin endpoint
	// does); we just want the key to authenticate but lack metrics.
	if _, err := h.apiKeyStore.Insert(context.Background(),
		minted.KeyID, minted.SecretHash, "wrong-scope-key", "alice",
		[]string{"some-other-scope"}, nil); err != nil {
		t.Fatalf("Insert: %v", err)
	}
	r := httptest.NewRequest("GET", "/metrics", nil)
	r.Header.Set("Authorization", "Bearer "+minted.Full)
	w := httptest.NewRecorder()
	h.handleMetrics(w, r)
	if w.Code != http.StatusForbidden {
		t.Errorf("scope-missing /metrics returned %d, want 403; body=%s", w.Code, w.Body.String())
	}
}

// TestMetricsGateAcceptsValidKey confirms the happy path: a valid
// API key with `metrics` scope returns 200 and the prom payload.
// Body content varies (depends on what's been registered), but it
// must not be empty.
func TestMetricsGateAcceptsValidKey(t *testing.T) {
	h := metricsGateHandler(t, false)
	minted, _ := apikey.Mint()
	if _, err := h.apiKeyStore.Insert(context.Background(),
		minted.KeyID, minted.SecretHash, "prom", "alice",
		[]string{"metrics"}, nil); err != nil {
		t.Fatalf("Insert: %v", err)
	}
	r := httptest.NewRequest("GET", "/metrics", nil)
	r.Header.Set("Authorization", "Bearer "+minted.Full)
	w := httptest.NewRecorder()
	h.handleMetrics(w, r)
	if w.Code != http.StatusOK {
		t.Errorf("valid-key /metrics returned %d, want 200; body=%s", w.Code, w.Body.String())
	}
	body, _ := io.ReadAll(w.Body)
	if len(body) == 0 {
		t.Errorf("valid-key /metrics returned empty body")
	}
}
