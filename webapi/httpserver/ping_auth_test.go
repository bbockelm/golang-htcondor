package httpserver

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
)

// The ping endpoints must not answer an anonymous caller.
//
// They report an identity, an authentication method, a session id and the
// daemon's valid commands. Unauthenticated they answered for the service
// account, which on an access point is a queue superuser -- so anyone who
// could reach the port learned who the daemon is and what it may do.
//
// The tests that covered these handlers before could not catch this: they
// asserted `if w.Code != 200 && w.Code != 500 { t.Logf(...) }`, which
// fails for no status at all.
func TestPingEndpointsRefuseAnAnonymousCaller(t *testing.T) {
	cfg := newTestConfig(t)
	cfg.Logger = testLogger(t)
	server, err := NewServer(cfg)
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}

	for _, tc := range []struct {
		name    string
		path    string
		handler func(http.ResponseWriter, *http.Request)
	}{
		{"both", "/api/v1/ping", server.handlePing},
		{"schedd", "/api/v1/schedd/ping", server.handleScheddPing},
		{"collector", "/api/v1/collector/ping", server.handleCollectorPing},
	} {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, tc.path, nil)
			w := httptest.NewRecorder()
			tc.handler(w, req)

			if w.Code != http.StatusUnauthorized {
				t.Fatalf("%s answered an anonymous caller with %d: %s",
					tc.path, w.Code, w.Body.String())
			}
			// And it must not have leaked the answer alongside the refusal.
			for _, leak := range []string{"ValidCommands", "valid_commands", "session_id", "SessionID"} {
				if bodyContains(w.Body.String(), leak) {
					t.Errorf("%s returned %q in its refusal: %s", tc.path, leak, w.Body.String())
				}
			}
		})
	}
}

// An identified caller still gets an answer -- the gate is an
// authentication requirement, not a blanket refusal. The ping itself
// fails here because no schedd is running, which is a different status.
func TestPingEndpointsAnswerAnIdentifiedCaller(t *testing.T) {
	cfg := newTestConfig(t)
	cfg.Logger = testLogger(t)
	cfg.UserHeader = "X-Test-User"
	cfg.UserHeaderTrustAnyUnsafe = true // single-host test, no proxy in front
	cfg.SigningKeyPath = writeSigningKey(t)
	cfg.TrustDomain = "flock.example.org"
	cfg.UIDDomain = "example.org"
	server, err := NewServer(cfg)
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}

	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/api/v1/schedd/ping", nil)
	req.Header.Set("X-Test-User", "bbockelm")
	w := httptest.NewRecorder()
	server.handleScheddPing(w, req)

	if w.Code == http.StatusUnauthorized {
		t.Fatalf("an identified caller was refused: %s", w.Body.String())
	}
}

func bodyContains(body, needle string) bool {
	return len(needle) > 0 && len(body) >= len(needle) &&
		func() bool {
			for i := 0; i+len(needle) <= len(body); i++ {
				if body[i:i+len(needle)] == needle {
					return true
				}
			}
			return false
		}()
}
