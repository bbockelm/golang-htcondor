package httpserver

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/bbockelm/cedar/security"

	htcondor "github.com/bbockelm/golang-htcondor"
	"github.com/bbockelm/golang-htcondor/webapi/interactive"
	"github.com/bbockelm/golang-htcondor/webapi/jobssh"
	"github.com/bbockelm/golang-htcondor/webapi/mcpserver"
	"github.com/bbockelm/golang-htcondor/webapi/sshgateway"
)

// forwardedBearer builds a JWT that the REST path treats as a forwarded
// IDTOKEN for alice: parseable, unexpired, never verified here. tag
// makes two such tokens distinct credentials.
func forwardedBearer(tag string) string {
	const subject = "alice@test.htcondor.org"
	enc := func(v any) string {
		b, err := json.Marshal(v)
		if err != nil {
			panic(err)
		}
		return base64.RawURLEncoding.EncodeToString(b)
	}
	header := enc(map[string]string{"alg": "HS256", "kid": "POOL"})
	claims := enc(map[string]any{
		"iss": "test.htcondor.org", "sub": subject,
		"exp": time.Now().Add(time.Hour).Unix(), "jti": tag,
	})
	return header + "." + claims + "." + base64.RawURLEncoding.EncodeToString([]byte("sig-"+tag))
}

// newBearerProxyTestHandler is a Handler with no user header, so every
// request authenticates by its bearer, and a transport cache whose
// dialer counts transports opened. Identities are seeded into the actor
// cache, standing in for the schedd's answer.
func newBearerProxyTestHandler(t *testing.T, backend string) (*Handler, *atomic.Int32, *fakeJobConn) {
	t.Helper()
	h := &Handler{
		logger:         testLogger(t),
		tokenCache:     NewTokenCache(),
		signingKeyPath: writeSigningKey(t),
		trustDomain:    "test.htcondor.org",
		uidDomain:      "test.htcondor.org",
	}
	var dials atomic.Int32
	conn := &fakeJobConn{backend: backend, done: make(chan struct{})}
	cache, err := jobssh.NewCache(jobssh.Options{
		Dial: func(context.Context, jobssh.Key) (jobssh.Conn, error) {
			dials.Add(1)
			return conn, nil
		},
	})
	if err != nil {
		t.Fatalf("NewCache: %v", err)
	}
	h.jobSSHCache = cache
	t.Cleanup(h.closeJobSSHCache)
	return h, &dials, conn
}

func proxyAs(h *Handler, bearer string) *httptest.ResponseRecorder {
	r := httptest.NewRequestWithContext(context.Background(), http.MethodGet,
		"/api/v1/jobs/12.0/proxy/8080/", nil)
	r.Header.Set("Authorization", "Bearer "+bearer)
	w := httptest.NewRecorder()
	h.handleJobProxy(w, r, 12, 0, jobProxyTarget{Port: 8080}, "/")
	return w
}

func okBackend(t *testing.T) string {
	t.Helper()
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = fmt.Fprint(w, "ok")
	}))
	t.Cleanup(backend.Close)
	return strings.TrimPrefix(backend.URL, "http://")
}

// A transport opened for one caller must not be reachable by a request
// whose identity could not be established. Such a request used to be
// keyed under an empty owner -- the same key as every other unidentified
// request -- and so found whatever transport an earlier one had opened.
func TestJobProxyRefusesEmptyIdentity(t *testing.T) {
	h, dials, conn := newBearerProxyTestHandler(t, okBackend(t))

	victim := forwardedBearer("victim")
	h.mcpActors.put(victim, "alice@test.htcondor.org", time.Minute)
	if w := proxyAs(h, victim); w.Code != http.StatusOK {
		t.Fatalf("the owner's own request: status %d (%s)", w.Code, w.Body.String())
	}
	if got := dials.Load(); got != 1 {
		t.Fatalf("precondition: %d transports opened, want 1", got)
	}
	forwardedBefore := conn.dials.Load()

	// A bearer the schedd would not accept resolves to no identity.
	unknown := forwardedBearer("unknown")
	h.mcpActors.put(unknown, "", time.Minute)
	w := proxyAs(h, unknown)
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("a request with no identity got status %d, want 401 (%s)", w.Code, w.Body.String())
	}
	if got := dials.Load(); got != 1 {
		t.Errorf("a request with no identity opened a transport (%d total)", got)
	}
	if got := conn.dials.Load(); got != forwardedBefore {
		t.Errorf("a request with no identity was forwarded into the job over the cached transport")
	}

	// And the owner still reuses their own.
	if w := proxyAs(h, victim); w.Code != http.StatusOK {
		t.Fatalf("the owner's second request: status %d", w.Code)
	}
	if got := dials.Load(); got != 1 {
		t.Errorf("the owner's second request opened a new transport (%d total), want reuse", got)
	}
}

// The same owner reached through a different forwarded credential gets
// a transport of its own: the identity is what the caller was resolved
// to, and only the credential that opened the transport has been shown
// to be good for it.
func TestJobProxyDoesNotShareTransportAcrossBearers(t *testing.T) {
	h, dials, _ := newBearerProxyTestHandler(t, okBackend(t))

	first := forwardedBearer("first")
	second := forwardedBearer("second")
	h.mcpActors.put(first, "alice@test.htcondor.org", time.Minute)
	h.mcpActors.put(second, "alice@test.htcondor.org", time.Minute)

	for _, b := range []string{first, second, first, second} {
		if w := proxyAs(h, b); w.Code != http.StatusOK {
			t.Fatalf("status %d (%s)", w.Code, w.Body.String())
		}
	}
	if got := dials.Load(); got != 2 {
		t.Errorf("opened %d transports for two credentials used twice each, want 2", got)
	}
}

// Warming is a way into the same cache, so it refuses the same request.
func TestJobWarmRefusesEmptyIdentity(t *testing.T) {
	h, dials, _ := newBearerProxyTestHandler(t, okBackend(t))

	unknown := forwardedBearer("unknown")
	h.mcpActors.put(unknown, "", time.Minute)
	r := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/api/v1/jobs/12.0/warm", nil)
	r.Header.Set("Authorization", "Bearer "+unknown)
	w := httptest.NewRecorder()
	h.handleJobWarm(w, r, "12.0")
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("status %d, want 401 (%s)", w.Code, w.Body.String())
	}
	if got := dials.Load(); got != 0 {
		t.Errorf("a request with no identity opened %d transports", got)
	}

	known := forwardedBearer("known")
	h.mcpActors.put(known, "alice@test.htcondor.org", time.Minute)
	r = httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/api/v1/jobs/12.0/warm", nil)
	r.Header.Set("Authorization", "Bearer "+known)
	w = httptest.NewRecorder()
	h.handleJobWarm(w, r, "12.0")
	if w.Code != http.StatusOK {
		t.Fatalf("the owner's warm: status %d (%s)", w.Code, w.Body.String())
	}
	if got := dials.Load(); got != 1 {
		t.Errorf("the owner's warm opened %d transports, want 1", got)
	}
}

// mintedContext is a request context carrying a credential this server
// minted for owner, with authz as its scope. nil mints the way session
// and user-header mode do, with no scope claim; anything else mints the
// way an OAuth2 grant, an API key or an impersonation does.
func mintedContext(t *testing.T, owner string, authz []string) context.Context {
	t.Helper()
	key := writeSigningKey(t)
	now := time.Now().Unix()
	var tok string
	var err error
	if authz == nil {
		tok, err = security.GenerateJWT(filepath.Dir(key), filepath.Base(key), owner, "test.htcondor.org", now, now+300, nil)
	} else {
		tok, err = generateMCPAccessJWT(filepath.Dir(key), filepath.Base(key), owner, "test.htcondor.org", now, now+300, authz)
	}
	if err != nil {
		t.Fatalf("minting: %v", err)
	}
	ctx := htcondor.WithAuthenticatedUser(context.Background(), owner)
	return htcondor.WithSecurityConfig(ctx, &security.SecurityConfig{Token: tok, SecurityTag: owner})
}

// A transport opened while superuser mode was armed is the
// impersonation's, and the same operator with the mode disarmed must
// not find it: their ordinary requests carry their own credential.
func TestJobTransportArmedIsNotReusedDisarmed(t *testing.T) {
	ctx := mintedContext(t, "admin@test.htcondor.org", superuserAuthz)
	imp := &Impersonation{
		Actor: "admin@test.htcondor.org", Target: "alice@test.htcondor.org",
		Identity: "condor@test.htcondor.org",
	}

	armed, err := jobTransportKey(ctx, "", imp, 12, 0)
	if err != nil {
		t.Fatalf("armed key: %v", err)
	}
	disarmed, err := jobTransportKey(ctx, "", nil, 12, 0)
	if err != nil {
		t.Fatalf("disarmed key: %v", err)
	}
	if armed == disarmed {
		t.Fatalf("armed and disarmed requests share a transport key: %+v", armed)
	}
	// The operator, not the job's owner, is the owner on both: a second
	// operator must not find the first one's impersonation either.
	if armed.Owner != "admin@test.htcondor.org" || disarmed.Owner != armed.Owner {
		t.Errorf("owners = %q, %q; want the operator on both", armed.Owner, disarmed.Owner)
	}

	var dials atomic.Int32
	cache, err := jobssh.NewCache(jobssh.Options{Dial: func(context.Context, jobssh.Key) (jobssh.Conn, error) {
		dials.Add(1)
		return &fakeJobConn{backend: okBackend(t), done: make(chan struct{})}, nil
	}})
	if err != nil {
		t.Fatalf("NewCache: %v", err)
	}
	t.Cleanup(cache.Close)
	for _, k := range []jobssh.Key{armed, disarmed} {
		if _, err := cache.Warm(ctx, k); err != nil {
			t.Fatalf("Warm: %v", err)
		}
	}
	if got := dials.Load(); got != 2 {
		t.Errorf("opened %d transports for an armed and a disarmed request, want 2", got)
	}
}

// Credentials this server mints are re-minted per request, so they are
// described by what they allow rather than by their bytes: two mints
// for the same owner and authority share a slot, and a credential
// without WRITE -- which could not open a transport -- does not share
// one that could.
func TestJobTransportCredentialForMintedCredentials(t *testing.T) {
	write1 := jobTransportCredential(mintedContext(t, "alice", []string{"READ", "WRITE"}), "")
	write2 := jobTransportCredential(mintedContext(t, "alice", []string{"READ", "WRITE"}), "")
	full := jobTransportCredential(mintedContext(t, "alice", nil), "")
	readOnly := jobTransportCredential(mintedContext(t, "alice", []string{"READ"}), "")

	if write1 == "" || write1 != write2 {
		t.Errorf("two mints of the same authority differ: %q, %q", write1, write2)
	}
	if write1 != full {
		t.Errorf("a WRITE credential (%q) and an unrestricted one (%q) differ; both could open the transport", write1, full)
	}
	if readOnly == write1 {
		t.Errorf("a READ-only credential shares the WRITE credential's slot (%q)", readOnly)
	}
	if got := jobTransportCredential(context.Background(), ""); got != "" {
		t.Errorf("a context with no credential described as %q, want \"\"", got)
	}
}

// A throttled identity resolution fails the request instead of letting
// it carry on with no identity.
func TestCreateAuthenticatedContextFailsWhenThrottled(t *testing.T) {
	h, _, _ := newBearerProxyTestHandler(t, okBackend(t))

	r := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/api/v1/jobs", nil)
	r.Header.Set("Authorization", "Bearer "+forwardedBearer("fresh"))
	exhaustResolveSource(&h.mcpActors, actorResolveSource(r, nil))

	_, err := h.createAuthenticatedContext(r)
	if !errors.Is(err, errActorResolveThrottled) {
		t.Fatalf("createAuthenticatedContext error = %v, want errActorResolveThrottled", err)
	}

	// A bearer already resolved is answered from the cache and is not
	// charged to the source at all.
	known := forwardedBearer("known")
	h.mcpActors.put(known, "alice@test.htcondor.org", time.Minute)
	r.Header.Set("Authorization", "Bearer "+known)
	ctx, err := h.createAuthenticatedContext(r)
	if err != nil {
		t.Fatalf("a resolved bearer was refused: %v", err)
	}
	if got := htcondor.GetAuthenticatedUserFromContext(ctx); got != "alice@test.htcondor.org" {
		t.Errorf("identity = %q", got)
	}
}

// The MCP path answers a throttled resolution with 429 rather than
// running the call with no identity.
func TestMCPForwardedTokenThrottledIs429(t *testing.T) {
	s := newMCPServer(t, "", "flock.example.org")

	req := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/mcp", strings.NewReader("{}"))
	req.Header.Set("Authorization", "Bearer "+poolIDToken("flock.example.org", "bbockelm"))
	req.Header.Set("Accept", mcpserver.AcceptHeader)
	exhaustResolveSource(&s.mcpActors, actorResolveSource(req, nil))

	rec := httptest.NewRecorder()
	if _, _, ok := s.mcpAuthContext(rec, req); ok {
		t.Fatal("a throttled resolution let the MCP call proceed")
	}
	if rec.Code != http.StatusTooManyRequests {
		t.Errorf("status %d, want 429", rec.Code)
	}
}

// exhaustResolveSource spends source's whole resolution budget.
func exhaustResolveSource(c *mcpActorCache, source string) {
	for i := 0; i < 1000; i++ {
		if !c.allowResolve(source) {
			return
		}
	}
}

// The gateway's keys carry the credential its channel was minted, so a
// gateway transport is the same slot as any other minted WRITE
// credential for that account -- which is what lets a warm request made
// over HTTP be found by the SSH connection that follows.
func TestSSHGatewayKeyCarriesTheCredential(t *testing.T) {
	h := &Handler{}
	ctx := mintedContext(t, "alice", []string{"READ", "WRITE"})
	key, err := h.sshGatewayResolve(ctx, "alice", sshgateway.Target{Cluster: 12, Proc: 0}, nil)
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if key.Credential != jobTransportMintedWrite {
		t.Errorf("job key credential = %q, want %q", key.Credential, jobTransportMintedWrite)
	}
	key, err = h.sshGatewayAwaitRunning(ctx, nil, interactive.Caller{Actor: "alice", Owner: "alice"}, "work",
		interactive.Info{Name: "work", JobID: "77.3", ClusterID: 77, ProcID: 3, JobStatus: 2}, nil)
	if err != nil {
		t.Fatalf("session resolve: %v", err)
	}
	if key.Credential != jobTransportMintedWrite {
		t.Errorf("session key credential = %q, want %q", key.Credential, jobTransportMintedWrite)
	}
}
