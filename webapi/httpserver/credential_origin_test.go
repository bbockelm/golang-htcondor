package httpserver

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	htcondor "github.com/bbockelm/golang-htcondor"
)

// Every request, on every route, is marked as acting for somebody other than
// this daemon -- including routes registered after this test was written,
// which is the point of marking in ServeHTTP rather than per route.
//
// What it buys: a handler that reaches the schedd without attaching a
// credential is refused instead of authenticating as this daemon, which on an
// access point is a queue superuser.
func TestServeHTTPMarksEveryRequestAsTheCallers(t *testing.T) {
	server, err := NewServer(Config{
		Logger:       testLogger(t),
		ScheddName:   "test-schedd",
		ScheddAddr:   "127.0.0.1:9618",
		OAuth2DBPath: t.TempDir() + "/sessions.db",
	})
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}

	var (
		origin htcondor.CredentialOrigin
		reason string
	)
	server.SetupRoutes(func(mux *http.ServeMux) {
		mux.HandleFunc("/probe/credential-origin", func(w http.ResponseWriter, r *http.Request) {
			origin, reason = htcondor.CredentialOriginFromContext(r.Context())
			w.WriteHeader(http.StatusNoContent)
		})
	})

	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/probe/credential-origin", nil)
	server.ServeHTTP(httptest.NewRecorder(), req)

	if origin != htcondor.OriginUser {
		t.Fatalf("a request context is %s, not %s: a handler that reaches CEDAR without a "+
			"credential would authenticate as this daemon", origin, htcondor.OriginUser)
	}
	// The reason names the route, because the fix for a refusal is at the
	// route that produced the unauthenticated context.
	if reason == "" || !contains(reason, "/probe/credential-origin") {
		t.Errorf("the mark's reason %q does not identify the request", reason)
	}
}

// A refused daemon fallback is an authentication failure, and the handlers
// decide their status code through isAuthenticationError. Classified as
// anything else it becomes a 500, which tells the caller this server is
// broken rather than that their request was not authenticated.
func TestDaemonFallbackRefusalIsAnAuthenticationError(t *testing.T) {
	refusal := &htcondor.ErrDaemonFallbackRefused{
		Origin:   htcondor.OriginUser,
		Reason:   "HTTP request GET /api/v1/jobs",
		Command:  519,
		PeerName: "<127.0.0.1:9618>",
	}
	if !isAuthenticationError(refusal) {
		t.Fatal("a daemon-fallback refusal is not classified as an authentication error, so it is reported as 500")
	}
	// Wrapped, which is how it arrives: every schedd call adds context.
	wrapped := fmt.Errorf("failed to query jobs: %w", refusal)
	if !isAuthenticationError(wrapped) {
		t.Fatal("a wrapped refusal is not classified as an authentication error")
	}
	// And the classification is by type, not by what the message happens to
	// say -- otherwise wording changes would move the status code.
	if isAuthenticationError(errors.New("refusing to authenticate as this daemon")) {
		t.Error("isAuthenticationError matched the refusal's wording rather than its type")
	}
}

func contains(haystack, needle string) bool {
	for i := 0; i+len(needle) <= len(haystack); i++ {
		if haystack[i:i+len(needle)] == needle {
			return true
		}
	}
	return false
}
