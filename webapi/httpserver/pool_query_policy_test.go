package httpserver

import (
	"context"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	htcondor "github.com/bbockelm/golang-htcondor"
	"github.com/bbockelm/golang-htcondor/webapi/poolpolicy"
)

// newPoolPolicyServer is newCollectorReadServer with an attribute policy.
// The collector address has nothing listening on it, so a request the
// policy allows gets as far as the dial and fails there: "connection
// refused" is how an allowed request is told apart from a refused one,
// which never reaches the collector at all.
func newPoolPolicyServer(t *testing.T, p *poolpolicy.Policy) *Server {
	t.Helper()

	var lc net.ListenConfig
	l, err := lc.Listen(context.Background(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("reserving a port: %v", err)
	}
	collectorAddr := l.Addr().String()
	if err := l.Close(); err != nil {
		t.Fatalf("releasing the reserved port: %v", err)
	}

	signingKeyPath := filepath.Join(t.TempDir(), "POOL")
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i)
	}
	if err := os.WriteFile(signingKeyPath, key, 0600); err != nil {
		t.Fatalf("writing the signing key: %v", err)
	}

	server, err := NewServer(Config{
		Logger:                   testLogger(t),
		ScheddName:               "test-schedd",
		ScheddAddr:               "127.0.0.1:0",
		UserHeader:               "X-Test-User",
		UserHeaderTrustAnyUnsafe: true,
		SigningKeyPath:           signingKeyPath,
		TrustDomain:              "test.htcondor.org",
		UIDDomain:                "test.htcondor.org",
		Collector:                htcondor.NewCollector(collectorAddr),
		OAuth2DBPath:             filepath.Join(t.TempDir(), "sessions.db"),
		PoolQueryPolicy:          p,
	})
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	server.setupRoutes()
	return server
}

// get issues an authenticated GET as a user with no admin privilege.
func get(t *testing.T, server *Server, route string) (int, string) {
	t.Helper()
	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, route, nil)
	req.Header.Set("X-Test-User", "alice")
	rec := httptest.NewRecorder()
	server.ServeHTTP(rec, req)
	body, _ := io.ReadAll(rec.Body)
	return rec.Code, string(body)
}

// reached reports whether a request got past the policy to the collector.
func reached(code int, body string) bool {
	return code != http.StatusForbidden && strings.Contains(body, "connection refused")
}

func TestRestrictedPoolQueriesRefuseIdentity(t *testing.T) {
	server := newPoolPolicyServer(t, poolpolicy.New(poolpolicy.ModeRestricted, nil))

	refused := []struct{ name, route string }{
		{"projection names an owner", `/api/v1/collector/ads/startd?projection=Name,RemoteOwner`},
		{"projection asks for everything", `/api/v1/collector/ads/startd?projection=*`},
		{"constraint tests an owner", `/api/v1/collector/ads/startd?constraint=RemoteOwner%20%3D%3D%20%22bob%22`},
		{"constraint tests a project", `/api/v1/collector/ads/startd?constraint=RemoteProject%20%3D%3D%20%22chem%22`},
		{"submitter ads are all identity", `/api/v1/collector/ads/submitter`},
		{"the watch stream, by constraint", `/api/v1/collector/watch?type=StartdAd&constraint=RemoteOwner%20%3D%3D%20%22bob%22`},
		{"the watch stream, submitter ads", `/api/v1/collector/watch?type=SubmitterAd`},
	}
	for _, tc := range refused {
		t.Run(tc.name, func(t *testing.T) {
			code, body := get(t, server, tc.route)
			if code != http.StatusForbidden {
				t.Fatalf("got %d, want 403. Body: %s", code, body)
			}
			if strings.Contains(body, "connection refused") {
				t.Fatal("the request reached the collector before it was refused")
			}
		})
	}
}

func TestRestrictedPoolQueriesStillAnswerAboutMachines(t *testing.T) {
	server := newPoolPolicyServer(t, poolpolicy.New(poolpolicy.ModeRestricted, nil))

	allowed := []struct{ name, route string }{
		{"a safe projection", `/api/v1/collector/ads/startd?projection=Name,State,Cpus,GPUs`},
		{"no projection at all", `/api/v1/collector/ads/startd`},
		{"a safe constraint", `/api/v1/collector/ads/startd?constraint=GPUs%20%3E%200`},
		{"schedd ads", `/api/v1/collector/ads/schedd`},
		{"the pool summary", `/api/v1/collector/pool-summary`},
	}
	for _, tc := range allowed {
		t.Run(tc.name, func(t *testing.T) {
			code, body := get(t, server, tc.route)
			if !reached(code, body) {
				t.Fatalf("a request about machines was refused: got %d. Body: %s", code, body)
			}
		})
	}
}

func TestAdminOnlyPoolQueriesRefuseEveryone(t *testing.T) {
	server := newPoolPolicyServer(t, poolpolicy.New(poolpolicy.ModeAdmin, nil))

	for _, route := range []string{
		`/api/v1/collector/ads/startd?projection=Name,State`,
		`/api/v1/collector/ads/schedd`,
		`/api/v1/collector/pool-summary`,
		`/api/v1/collector/watch?type=StartdAd`,
	} {
		t.Run(route, func(t *testing.T) {
			code, body := get(t, server, route)
			if code != http.StatusForbidden {
				t.Fatalf("got %d, want 403. Body: %s", code, body)
			}
		})
	}
}

// The default has to leave an existing deployment answering exactly what it
// answered before, including the projections this change restricts.
func TestOpenIsTheDefaultAndChangesNothing(t *testing.T) {
	for _, name := range []string{"explicitly open", "no policy configured"} {
		t.Run(name, func(t *testing.T) {
			var p *poolpolicy.Policy
			if name == "explicitly open" {
				p = poolpolicy.New(poolpolicy.ModeOpen, nil)
			}
			server := newPoolPolicyServer(t, p)
			for _, route := range []string{
				`/api/v1/collector/ads/startd?projection=*`,
				`/api/v1/collector/ads/startd?constraint=RemoteOwner%20%3D%3D%20%22bob%22`,
				`/api/v1/collector/ads/submitter`,
			} {
				code, body := get(t, server, route)
				if !reached(code, body) {
					t.Errorf("%s was refused under the default policy: got %d. Body: %s",
						route, code, body)
				}
			}
		})
	}
}

func TestSiteExtraAttrsReachTheRESTPath(t *testing.T) {
	server := newPoolPolicyServer(t, poolpolicy.New(poolpolicy.ModeRestricted, []string{"GLIDEIN_Site"}))
	code, body := get(t, server, `/api/v1/collector/ads/startd?projection=Name,GLIDEIN_Site`)
	if !reached(code, body) {
		t.Fatalf("a site-added attribute was refused: got %d. Body: %s", code, body)
	}
}
