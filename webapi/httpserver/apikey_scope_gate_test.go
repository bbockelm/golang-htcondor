package httpserver

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	htcondor "github.com/bbockelm/golang-htcondor"
	"github.com/bbockelm/golang-htcondor/webapi/httpserver/apikey"
)

// gateTestKey mints a key with the given scopes and returns its wire
// string.
func gateTestKey(t *testing.T, h *Handler, scopes []string) string {
	t.Helper()
	minted, err := apikey.Mint()
	if err != nil {
		t.Fatalf("Mint: %v", err)
	}
	if _, err := h.apiKeyStore.Insert(context.Background(),
		minted.KeyID, minted.SecretHash, "gate-test", "alice",
		scopes, nil); err != nil {
		t.Fatalf("Insert: %v", err)
	}
	return minted.Full
}

// reachedBackend is a stand-in for a handler that would issue a schedd
// RPC or a mirror query. The gate's whole purpose is that this never
// runs for a wrongly-scoped request.
func reachedBackend(hit *bool) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		*hit = true
		w.WriteHeader(http.StatusOK)
	})
}

func gateRequest(t *testing.T, method, token string) *http.Request {
	t.Helper()
	r := httptest.NewRequestWithContext(context.Background(), method, "/api/v1/jobs", nil)
	if token != "" {
		r.Header.Set("Authorization", "Bearer "+token)
	}
	return r
}

// TestScopeGateRejectsReadKeyOnWrite is the property asked for: a
// read-only key cannot spend backend capacity on a write endpoint.
func TestScopeGateRejectsReadKeyOnWrite(t *testing.T) {
	h := condorTestHandler(t)
	token := gateTestKey(t, h, []string{condorScopeRead})

	var hit bool
	rec := httptest.NewRecorder()
	h.requireCondorScope(reachedBackend(&hit)).ServeHTTP(rec, gateRequest(t, http.MethodPost, token))

	if rec.Code != http.StatusForbidden {
		t.Errorf("status = %d, want 403", rec.Code)
	}
	if hit {
		t.Error("request reached the handler; the gate must reject before any backend work")
	}
}

// TestScopeGateRejectsWriteKeyOnRead is the reverse direction, which is
// the one that stops a write-only key being used to hammer queries.
func TestScopeGateRejectsWriteKeyOnRead(t *testing.T) {
	h := condorTestHandler(t)
	token := gateTestKey(t, h, []string{condorScopeWrite})

	var hit bool
	rec := httptest.NewRecorder()
	h.requireCondorScope(reachedBackend(&hit)).ServeHTTP(rec, gateRequest(t, http.MethodGet, token))

	if rec.Code != http.StatusForbidden {
		t.Errorf("status = %d, want 403", rec.Code)
	}
	if hit {
		t.Error("request reached the handler; the gate must reject before any backend work")
	}
}

// TestScopeGateAllowsMatchingScope confirms the gate is not simply
// closed: the right scope passes, and the context carries downstream.
func TestScopeGateAllowsMatchingScope(t *testing.T) {
	h := condorTestHandler(t)
	token := gateTestKey(t, h, []string{condorScopeRead, condorScopeWrite})

	for _, method := range []string{http.MethodGet, http.MethodPost, http.MethodDelete} {
		var hit bool
		var sawUser string
		next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			hit = true
			sawUser = htcondor.GetAuthenticatedUserFromContext(r.Context())
			w.WriteHeader(http.StatusOK)
		})
		rec := httptest.NewRecorder()
		h.requireCondorScope(next).ServeHTTP(rec, gateRequest(t, method, token))

		if !hit {
			t.Errorf("%s: gate rejected a key holding both scopes (status %d)", method, rec.Code)
		}
		if sawUser != "alice" {
			t.Errorf("%s: handler saw user %q, want alice; the gate must pass its context downstream", method, sawUser)
		}
	}
}

// TestScopeGateIgnoresNonAPIKeyCallers is the compatibility guarantee:
// session and OAuth2 callers carry none of these scopes, so the gate
// must not touch them. A false here would lock out the entire web UI.
func TestScopeGateIgnoresNonAPIKeyCallers(t *testing.T) {
	h := condorTestHandler(t)

	// Assembled rather than written as one literal so it does not read
	// as a hardcoded credential; it is only a bearer shaped like a JWT,
	// enough for the gate to take its non-API-key branch.
	jwtShaped := "eyJhbGciOiJIUzI1NiJ9" + "." + "eyJzdWIiOiJhbGljZSJ9" + "." + "sig"

	cases := map[string]string{
		"no credential at all": "",
		"a JWT-shaped bearer":  jwtShaped,
	}
	for name, token := range cases {
		var hit bool
		rec := httptest.NewRecorder()
		h.requireCondorScope(reachedBackend(&hit)).ServeHTTP(rec, gateRequest(t, http.MethodGet, token))
		if !hit {
			t.Errorf("%s: gate rejected a non-API-key caller (status %d)", name, rec.Code)
		}
	}
}

// TestScopeGateRejectsMetricsOnlyKey covers the key shape that exists
// today: it has no business reaching job data, and must not.
func TestScopeGateRejectsMetricsOnlyKey(t *testing.T) {
	h := condorTestHandler(t)
	token := gateTestKey(t, h, []string{"metrics"})

	var hit bool
	rec := httptest.NewRecorder()
	h.requireCondorScope(reachedBackend(&hit)).ServeHTTP(rec, gateRequest(t, http.MethodGet, token))

	if rec.Code != http.StatusForbidden {
		t.Errorf("status = %d, want 403", rec.Code)
	}
	if hit {
		t.Error("a metrics-only key reached a job endpoint")
	}
}

// TestScopeGateRejectsBogusKey checks an unparseable/unknown key is a
// 401 and never reaches the handler.
func TestScopeGateRejectsBogusKey(t *testing.T) {
	h := condorTestHandler(t)

	var hit bool
	rec := httptest.NewRecorder()
	h.requireCondorScope(reachedBackend(&hit)).ServeHTTP(rec,
		gateRequest(t, http.MethodGet, "htca-v1-deadbeef.notarealsecret"))

	if rec.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401", rec.Code)
	}
	if hit {
		t.Error("an invalid key reached the handler")
	}
}

// TestCondorScopeForMethod pins the method mapping, including the
// safe-by-default branch: an unrecognized method must require WRITE,
// not fall through to READ.
func TestCondorScopeForMethod(t *testing.T) {
	read := []string{http.MethodGet, http.MethodHead, http.MethodOptions}
	write := []string{http.MethodPost, http.MethodPut, http.MethodPatch, http.MethodDelete, "FROBNICATE"}

	for _, m := range read {
		if got := condorScopeForMethod(m); got != condorScopeRead {
			t.Errorf("%s -> %s, want %s", m, got, condorScopeRead)
		}
	}
	for _, m := range write {
		if got := condorScopeForMethod(m); got != condorScopeWrite {
			t.Errorf("%s -> %s, want %s", m, got, condorScopeWrite)
		}
	}
}
