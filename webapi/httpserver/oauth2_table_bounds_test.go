package httpserver

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"runtime"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ory/fosite"
	"golang.org/x/time/rate"
)

// Tests for the bounds on state an unauthenticated caller can make this
// server keep: rate limits on the endpoints that write it, expiry for
// what they wrote, and caps on what is held in memory.

// idpBadLogin posts one login with a wrong password from addr
// ("ip:port") and returns the status.
func idpBadLogin(t *testing.T, server *Server, addr, username string) int {
	t.Helper()
	form := url.Values{"username": {username}, "password": {"wrong"}}
	req := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/idp/login", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.RemoteAddr = addr
	w := httptest.NewRecorder()
	server.handleIDPLogin(w, req)
	return w.Code
}

// freezeLimiters stops the limiters' buckets refilling, so a slow run
// cannot hand budget back partway through a test.
func freezeLimiters(ls ...*LoginRateLimiter) {
	now := time.Now()
	for _, l := range ls {
		l.now = func() time.Time { return now }
	}
}

func newIDPTestServer(t *testing.T) *Server {
	t.Helper()
	cfg := newTestConfig(t)
	cfg.EnableIDP = true
	cfg.IDPIssuer = "http://localhost:8080"
	server, err := NewServer(cfg)
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	t.Cleanup(func() { _ = server.idpProvider.Close() })
	if err := server.idpProvider.storage.CreateUser(context.Background(), "idpuser", "idppassword", "active"); err != nil {
		t.Fatalf("CreateUser: %v", err)
	}
	freezeLimiters(server.idpLoginLimiter, server.idpLoginByUser)
	return server
}

// idpGoodLogin posts one correct login from addr and returns the status.
func idpGoodLogin(t *testing.T, server *Server, addr string) int {
	t.Helper()
	form := url.Values{"username": {"idpuser"}, "password": {"idppassword"}}
	req := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/idp/login", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.RemoteAddr = addr
	w := httptest.NewRecorder()
	server.handleIDPLogin(w, req)
	return w.Code
}

// Only failures are charged: a site whose users all sign in from behind
// one address is not limited to a few logins a minute between them.
func TestIDPSuccessfulLoginsAreNotLimited(t *testing.T) {
	server := newIDPTestServer(t)
	for i := range 12 {
		if got := idpGoodLogin(t, server, fmt.Sprintf("192.0.2.8:%d", 40000+i)); got != http.StatusOK {
			t.Fatalf("successful login %d from one address: status %d, want 200", i+1, got)
		}
	}
}

// A new connection is a new source port, not a new client: the sixth
// failed login from one address is refused whatever port it came from,
// while another address is still let through.
func TestIDPLoginLimitedPerAddressNotPerConnection(t *testing.T) {
	server := newIDPTestServer(t)

	for i := 1; i <= 5; i++ {
		if got := idpBadLogin(t, server, fmt.Sprintf("192.0.2.7:%d", 40000+i), "idpuser"); got != http.StatusUnauthorized {
			t.Fatalf("attempt %d: status %d, want 401", i, got)
		}
	}
	if got := idpBadLogin(t, server, "192.0.2.7:40006", "idpuser"); got != http.StatusTooManyRequests {
		t.Fatalf("sixth attempt from the same address on a new port: status %d, want 429", got)
	}
	if got := idpBadLogin(t, server, "198.51.100.9:40001", "someoneelse"); got != http.StatusUnauthorized {
		t.Fatalf("a different address was refused too: status %d, want 401", got)
	}
}

// Spreading guesses across addresses meets the per-username limit.
func TestIDPLoginLimitedPerUsername(t *testing.T) {
	server := newIDPTestServer(t)

	for i := 1; i <= 10; i++ {
		if got := idpBadLogin(t, server, fmt.Sprintf("203.0.113.%d:1234", i), "idpuser"); got != http.StatusUnauthorized {
			t.Fatalf("attempt %d: status %d, want 401", i, got)
		}
	}
	if got := idpBadLogin(t, server, "203.0.113.11:1234", "IDPUSER"); got != http.StatusTooManyRequests {
		t.Fatalf("eleventh guess at one username from a fresh address: status %d, want 429", got)
	}
	if got := idpBadLogin(t, server, "203.0.113.12:1234", "otheruser"); got != http.StatusUnauthorized {
		t.Fatalf("a different username was refused too: status %d, want 401", got)
	}
}

// The limiter used to start a goroutine per key, sleeping for an hour.
func TestIDPLoginLimiterStartsNoGoroutinePerAttempt(t *testing.T) {
	server := newIDPTestServer(t)
	idpBadLogin(t, server, "192.0.2.1:1", "warmup")

	before := runtime.NumGoroutine()
	for i := range 300 {
		idpBadLogin(t, server, fmt.Sprintf("10.%d.%d.1:%d", i/250, i%250, 1000+i), fmt.Sprintf("u%d", i))
	}
	if grew := runtime.NumGoroutine() - before; grew > 20 {
		t.Fatalf("goroutines grew by %d over 300 login attempts", grew)
	}
}

// The limiter keeps at most maxKeys keys, forgets idle ones, and keeps
// the key in use when it has to drop one.
func TestLoginRateLimiterIsBounded(t *testing.T) {
	l := NewLoginRateLimiter(rate.Limit(1), 2) // refills in 2s
	l.maxKeys = 100
	now := time.Unix(1_700_000_000, 0)
	l.now = func() time.Time { return now }

	l.Allow("busy")
	l.Allow("busy")
	for i := range 1000 {
		l.Allow(fmt.Sprintf("k%d", i))
		if l.Allow("busy") {
			t.Fatalf("the busy key regained budget after %d other keys", i+1)
		}
		if l.size() > 100 {
			t.Fatalf("limiter tracks %d keys, cap is 100", l.size())
		}
	}

	now = now.Add(3 * time.Second)
	l.Allow("fresh")
	if got := l.size(); got != 1 {
		t.Fatalf("%d keys left after every other one sat idle past its refill, want 1", got)
	}
}

// postRegister posts a dynamic registration from addr through the
// router.
func postRegister(t *testing.T, srv *Server, addr string) *httptest.ResponseRecorder {
	t.Helper()
	body := `{"client_name":"bounds","redirect_uris":["http://127.0.0.1/callback"],"grant_types":["urn:ietf:params:oauth:grant-type:device_code"]}`
	req := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/mcp/oauth2/register", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.RemoteAddr = addr
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, req)
	return w
}

func TestDynamicRegistrationRateLimitedPerAddress(t *testing.T) {
	srv := startDeviceVerifyServer(t)
	freezeLimiters(srv.oauth2Limiters())

	created, refused := 0, 0
	for i := range 1000 {
		switch w := postRegister(t, srv, fmt.Sprintf("192.0.2.50:%d", 1024+i)); w.Code {
		case http.StatusCreated:
			created++
		case http.StatusTooManyRequests:
			refused++
		default:
			t.Fatalf("registration %d: status %d %s", i, w.Code, w.Body.String())
		}
	}
	if created != registrationBurst || refused != 1000-registrationBurst {
		t.Fatalf("created %d, refused %d; want %d created and the rest refused", created, refused, registrationBurst)
	}
	if w := postRegister(t, srv, "198.51.100.50:1024"); w.Code != http.StatusCreated {
		t.Fatalf("another address was refused too: %d %s", w.Code, w.Body.String())
	}
}

func TestDynamicClientIDsAreRandom(t *testing.T) {
	srv := startDeviceVerifyServer(t)
	shape := regexp.MustCompile(`^client_[0-9a-f]{32}$`)
	seen := map[string]bool{}
	for range 3 {
		id := registerDeviceVerifyClient(t, srv)
		if !shape.MatchString(id) {
			t.Fatalf("client id %q is not client_ plus 128 random bits", id)
		}
		if seen[id] {
			t.Fatalf("client id %q issued twice", id)
		}
		seen[id] = true
	}
}

func TestDynamicRegistrationCanBeDisabled(t *testing.T) {
	server, _ := newProvenanceServer(t)

	metadata := func() map[string]any {
		w := httptest.NewRecorder()
		server.handleOAuth2Metadata(w, httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/.well-known/oauth-authorization-server", nil))
		var m map[string]any
		if err := json.Unmarshal(w.Body.Bytes(), &m); err != nil {
			t.Fatalf("metadata: %v", err)
		}
		return m
	}

	if _, ok := metadata()["registration_endpoint"]; !ok {
		t.Fatal("registration_endpoint is not advertised while registration is on")
	}
	if status, body := registerClient(t, server, map[string]any{"redirect_uris": []string{"https://c.example/cb"}}); status != http.StatusCreated {
		t.Fatalf("registration while on: %d %v", status, body)
	}

	server.mcpDCRDisabled = true
	if _, ok := metadata()["registration_endpoint"]; ok {
		t.Error("registration_endpoint is advertised while registration is off")
	}
	if status, body := registerClient(t, server, map[string]any{"redirect_uris": []string{"https://c.example/cb"}}); status != http.StatusForbidden {
		t.Fatalf("registration while off: %d %v", status, body)
	}
}

// postDeviceAuthorize starts a device flow for clientID from addr
// through the router.
func postDeviceAuthorize(t *testing.T, srv *Server, addr, clientID string) *httptest.ResponseRecorder {
	t.Helper()
	form := url.Values{"client_id": {clientID}, "scope": {"openid"}}
	req := httptest.NewRequestWithContext(context.Background(), http.MethodPost,
		"/mcp/oauth2/device/authorize", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.RemoteAddr = addr
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, req)
	return w
}

func TestDeviceAuthorizeRequiresTheDeviceGrant(t *testing.T) {
	srv := startDeviceVerifyServer(t)

	browserOnly := postRegisterBody(t, srv, `{"redirect_uris":["https://c.example/cb"]}`)
	w := postDeviceAuthorize(t, srv, "192.0.2.60:1", browserOnly)
	if w.Code != http.StatusBadRequest || !strings.Contains(w.Body.String(), "unauthorized_client") {
		t.Fatalf("a client without the device grant started a device flow: %d %s", w.Code, w.Body.String())
	}

	device := registerDeviceVerifyClient(t, srv)
	if w := postDeviceAuthorize(t, srv, "192.0.2.60:2", device); w.Code != http.StatusOK {
		t.Fatalf("a device-grant client was refused: %d %s", w.Code, w.Body.String())
	}
}

func postRegisterBody(t *testing.T, srv *Server, body string) string {
	t.Helper()
	req := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/mcp/oauth2/register", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, req)
	var reg struct {
		ClientID string `json:"client_id"`
	}
	if w.Code != http.StatusCreated || json.Unmarshal(w.Body.Bytes(), &reg) != nil || reg.ClientID == "" {
		t.Fatalf("register: %d %s", w.Code, w.Body.String())
	}
	return reg.ClientID
}

func TestDeviceAuthorizeRateLimitedPerAddress(t *testing.T) {
	srv := startDeviceVerifyServer(t)
	client := registerDeviceVerifyClient(t, srv)
	freezeLimiters(srv.oauth2Limiters())

	for i := range deviceAuthorizationBurst {
		if w := postDeviceAuthorize(t, srv, fmt.Sprintf("192.0.2.61:%d", 1024+i), client); w.Code != http.StatusOK {
			t.Fatalf("authorization %d: %d %s", i, w.Code, w.Body.String())
		}
	}
	if w := postDeviceAuthorize(t, srv, "192.0.2.61:9999", client); w.Code != http.StatusTooManyRequests {
		t.Fatalf("authorization past the burst: %d, want 429", w.Code)
	}
	if w := postDeviceAuthorize(t, srv, "198.51.100.61:1024", client); w.Code != http.StatusOK {
		t.Fatalf("another address was refused too: %d %s", w.Code, w.Body.String())
	}
}

// pollDeviceToken polls the token endpoint once and returns the OAuth
// error, or "" for a token.
func pollDeviceToken(t *testing.T, srv *Server, clientID, deviceCode string) string {
	t.Helper()
	form := url.Values{"grant_type": {deviceCodeGrant}, "device_code": {deviceCode}, "client_id": {clientID}}
	req := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/mcp/oauth2/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, req)
	var body struct {
		Error       string `json:"error"`
		AccessToken string `json:"access_token"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatalf("token response: %d %s", w.Code, w.Body.String())
	}
	if body.Error == "" && body.AccessToken == "" {
		t.Fatalf("token response with neither error nor token: %d %s", w.Code, w.Body.String())
	}
	return body.Error
}

func TestDevicePollSoonerThanTheIntervalIsSlowDown(t *testing.T) {
	srv := startDeviceVerifyServer(t)
	client := registerDeviceVerifyClient(t, srv)
	w := postDeviceAuthorize(t, srv, "192.0.2.62:1", client)
	var auth DeviceAuthorizationResponse
	if err := json.Unmarshal(w.Body.Bytes(), &auth); err != nil || auth.DeviceCode == "" {
		t.Fatalf("device authorize: %d %s", w.Code, w.Body.String())
	}
	if auth.Interval != int(deviceCodePollInterval.Seconds()) {
		t.Errorf("advertised interval %d, enforced %s", auth.Interval, deviceCodePollInterval)
	}

	if got := pollDeviceToken(t, srv, client, auth.DeviceCode); got != "authorization_pending" {
		t.Fatalf("first poll: %q, want authorization_pending", got)
	}
	if got := pollDeviceToken(t, srv, client, auth.DeviceCode); got != "slow_down" {
		t.Fatalf("second poll straight after: %q, want slow_down", got)
	}

	// One interval later the client is answered normally again; the
	// refused poll did not restart the clock.
	db := srv.oauth2Provider.GetStorage().GetDB()
	if _, err := db.ExecContext(context.Background(),
		`UPDATE oauth2_device_codes SET last_polled_at = ? WHERE device_code = ?`,
		time.Now().UTC().Add(-deviceCodePollInterval), sessionKey(auth.DeviceCode)); err != nil {
		t.Fatalf("backdating the poll: %v", err)
	}
	if got := pollDeviceToken(t, srv, client, auth.DeviceCode); got != "authorization_pending" {
		t.Fatalf("poll one interval later: %q, want authorization_pending", got)
	}
}

// deviceVerifyAs makes one request to the server-rendered verification
// page as user, from addr.
func deviceVerifyAs(t *testing.T, srv *Server, method, addr, user, userCode string) *httptest.ResponseRecorder {
	t.Helper()
	var req *http.Request
	if method == http.MethodGet {
		req = httptest.NewRequestWithContext(context.Background(), method,
			"/mcp/oauth2/device/verify?user_code="+url.QueryEscape(userCode), nil)
	} else {
		form := url.Values{"user_code": {userCode}, "action": {"approve"}}
		req = httptest.NewRequestWithContext(context.Background(), method,
			"/mcp/oauth2/device/verify", strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}
	if user != "" {
		req.Header.Set("X-Test-User", user)
	}
	req.RemoteAddr = addr
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, req)
	return w
}

// Each lookup of a user code is a guess at one, so the verification page
// charges the same per-address budget as the SSH approval screen.
func TestDeviceVerifyLookupsRateLimitedPerAddress(t *testing.T) {
	for _, method := range []string{http.MethodGet, http.MethodPost} {
		t.Run(method, func(t *testing.T) {
			srv := startDeviceConsentServer(t)
			freezeLimiters(srv.sshConsentLimiters())
			for i := range sshConsentBurst {
				w := deviceVerifyAs(t, srv, method, "192.0.2.63:1", fmt.Sprintf("user%d", i), fmt.Sprintf("BAD%d-CODE", i))
				if w.Code == http.StatusTooManyRequests {
					t.Fatalf("lookup %d refused inside the budget", i)
				}
			}
			w := deviceVerifyAs(t, srv, method, "192.0.2.63:1", "another", "BADX-CODE")
			if w.Code != http.StatusTooManyRequests {
				t.Fatalf("lookup %d from one address: %d, want 429", sshConsentBurst+1, w.Code)
			}
			if w := deviceVerifyAs(t, srv, method, "198.51.100.63:1", "another", "BADX-CODE"); w.Code == http.StatusTooManyRequests {
				t.Fatal("another address was refused too")
			}
		})
	}
}

// Before signing in, a code that exists and one that does not get the
// same answer: the lookup happens only once the caller is known.
func TestDeviceVerifyDoesNotLookUpCodesBeforeSignIn(t *testing.T) {
	srv := startDeviceConsentServer(t)
	issued := issueDeviceCode(t, srv)

	answer := func(code string) string {
		w := deviceVerifyAs(t, srv, http.MethodPost, "192.0.2.64:1", "", code)
		b, _ := io.ReadAll(w.Result().Body)
		return fmt.Sprintf("%d %s", w.Code, b)
	}
	if a, b := answer(issued), answer("ZZZZ-ZZZZ"); a != b {
		t.Fatalf("an unauthenticated caller can tell a real code from a made-up one:\n%s\n---\n%s", a, b)
	}
	if a := answer(issued); !strings.Contains(a, "Authentication required") {
		t.Fatalf("unauthenticated verify: %s", a)
	}
}

// seedGrantState writes one row with the given expiry into a table that
// shares the token schema.
func seedGrantState(t *testing.T, f *reauthFixture, table, sig string, expiresAt time.Time) {
	t.Helper()
	db := f.server.oauth2Provider.GetStorage().GetDB()
	var err error
	if table == "oauth2_device_codes" {
		_, err = db.ExecContext(context.Background(), `INSERT INTO oauth2_device_codes
			(device_code, user_code, request_id, requested_at, client_id, scopes, granted_scopes, form_data, expires_at)
			VALUES (?, ?, 'r', ?, 'c', '[]', '[]', '{}', ?)`, sig, "UC-"+sig, expiresAt, expiresAt)
	} else {
		//nolint:gosec // G202: table comes from this test's own literals
		_, err = db.ExecContext(context.Background(), "INSERT INTO "+table+` (signature, request_id, requested_at, client_id, subject,
			scopes, granted_scopes, form_data, session_data, active, expires_at)
			VALUES (?, 'r', ?, 'c', 'alice', '[]', '[]', '{}', '{}', 1, ?)`, sig, expiresAt, expiresAt)
	}
	if err != nil {
		t.Fatalf("seeding %s: %v", table, err)
	}
}

func rowExists(t *testing.T, f *reauthFixture, table, keyCol, key string) bool {
	t.Helper()
	var n int
	//nolint:gosec // G202: table and column come from this test's own literals
	if err := f.server.oauth2Provider.GetStorage().GetDB().QueryRowContext(context.Background(),
		"SELECT COUNT(*) FROM "+table+" WHERE "+keyCol+" = ?", key).Scan(&n); err != nil {
		t.Fatalf("counting %s: %v", table, err)
	}
	return n > 0
}

// Expired in-flight authorization state goes; live state stays. The
// expired rows carry a zone other than UTC, as the device-code handler
// writes them, so a text comparison against a UTC cutoff would misjudge
// them.
func TestRetentionDeletesExpiredGrantState(t *testing.T) {
	f := newReauthFixture(t, Config{})
	elsewhere := time.FixedZone("UTC-10", -10*3600)
	expired := time.Now().Add(-2 * grantStateGrace).In(elsewhere)
	live := time.Now().Add(10 * time.Minute).In(elsewhere)

	// Listed here rather than read from grantStateTables, so a table
	// dropped from the sweep fails this test.
	tables := []string{"oauth2_device_codes", "oauth2_authorization_codes", "oauth2_pkce_requests", "oauth2_oidc_sessions"}
	keyCol := map[string]string{"oauth2_device_codes": "device_code"}
	for _, table := range tables {
		seedGrantState(t, f, table, "expired", expired)
		seedGrantState(t, f, table, "live", live)
	}

	if _, err := f.server.purgeExpiredGrantState(context.Background()); err != nil {
		t.Fatalf("purge: %v", err)
	}
	for _, table := range tables {
		col := keyCol[table]
		if col == "" {
			col = "signature"
		}
		if rowExists(t, f, table, col, "expired") {
			t.Errorf("%s: the expired row survived the sweep", table)
		}
		if !rowExists(t, f, table, col, "live") {
			t.Errorf("%s: a live row was deleted", table)
		}
	}
}

// A dynamically registered client that never obtained a token is deleted
// after the TTL; anything with a sign of use or of an operator is kept.
func TestRetentionDeletesUnusedDynamicClients(t *testing.T) {
	f := newReauthFixture(t, Config{})
	db := f.server.oauth2Provider.GetStorage().GetDB()
	ctx := context.Background()
	old := time.Now().UTC().Add(-unusedClientTTL - time.Hour).Format("2006-01-02 15:04:05")
	recent := time.Now().UTC().Add(-time.Hour).Format("2006-01-02 15:04:05")

	clients := []struct {
		id, origin, created, notes, grants string
		lastUsed                           any
		token                              bool
		keep                               bool
	}{
		{"unused-old", "dynamic", old, "", `["authorization_code"]`, nil, false, false},
		{"unused-recent", "dynamic", recent, "", `["authorization_code"]`, nil, false, true},
		{"used", "dynamic", old, "", `["authorization_code"]`, time.Now().UTC(), false, true},
		{"has-token", "dynamic", old, "", `["authorization_code"]`, nil, true, true},
		{"annotated", "dynamic", old, "ours", `["authorization_code"]`, nil, false, true},
		{"exchange", "dynamic", old, "", `["authorization_code","` + tokenExchangeGrantType + `"]`, nil, false, true},
		{"seeded", "seeded", old, "", `["authorization_code"]`, nil, false, true},
	}
	for _, c := range clients {
		if _, err := db.ExecContext(ctx, `INSERT INTO oauth2_clients
			(id, client_secret, redirect_uris, grant_types, response_types, scopes, public, created_at, origin, notes, last_used_at)
			VALUES (?, '', '[]', ?, '["code"]', '[]', 0, ?, ?, ?, ?)`,
			c.id, c.grants, c.created, c.origin, c.notes, c.lastUsed); err != nil {
			t.Fatalf("seeding %s: %v", c.id, err)
		}
		if c.token {
			if _, err := db.ExecContext(ctx, `INSERT INTO oauth2_refresh_tokens (signature, request_id, requested_at, client_id, subject,
				scopes, granted_scopes, form_data, session_data, active, expires_at)
				VALUES ('sig-'||?, 'r', ?, ?, 'alice', '[]', '[]', '{}', '{}', 0, NULL)`, c.id, time.Now().UTC(), c.id); err != nil {
				t.Fatalf("seeding token for %s: %v", c.id, err)
			}
		}
	}

	if _, err := f.server.purgeUnusedClients(ctx); err != nil {
		t.Fatalf("purge: %v", err)
	}
	for _, c := range clients {
		if got := rowExists(t, f, "oauth2_clients", "id", c.id); got != c.keep {
			t.Errorf("client %s: present=%v, want %v", c.id, got, c.keep)
		}
	}
}

// Every distinct client_id an unauthenticated caller names used to stay
// in the cache for good.
func TestCIMDCacheIsBounded(t *testing.T) {
	r := newCIMDResolver([]string{"only.example.org"}, http.DefaultClient)
	ctx := context.Background()
	for i := range 10000 {
		if _, err := r.resolve(ctx, fmt.Sprintf("https://h%d.attacker.example/m", i)); err == nil {
			t.Fatal("a disallowed host resolved")
		}
	}
	r.mu.Lock()
	n, l := len(r.cache), r.lru.Len()
	r.mu.Unlock()
	if n > cimdCacheMax || n != l {
		t.Fatalf("cache holds %d entries (%d in recency order), bound is %d", n, l, cimdCacheMax)
	}
}

// An expired entry is dropped when looked up, so it neither answers nor
// occupies a slot.
func TestCIMDCacheExpiresEntries(t *testing.T) {
	r := newCIMDResolver([]string{"only.example.org"}, http.DefaultClient)
	now := time.Unix(1_700_000_000, 0)
	r.now = func() time.Time { return now }
	ctx := context.Background()
	_, _ = r.resolve(ctx, "https://a.attacker.example/m")
	now = now.Add(cimdNegCacheTTL + time.Second)
	r.mu.Lock()
	_, ok := r.lookupLocked("https://a.attacker.example/m", now)
	n := len(r.cache)
	r.mu.Unlock()
	if ok || n != 0 {
		t.Fatalf("expired entry: found=%v, %d entries remain", ok, n)
	}
}

// startServer starts srv's routes on a loopback listener, as
// startDeviceVerifyServer does.
func startServer(t *testing.T, srv *Server) {
	t.Helper()
	ln, err := (&net.ListenConfig{}).Listen(context.Background(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	if err := srv.Handler.Start(t.Context(), ln, "http"); err != nil {
		t.Fatalf("Start: %v", err)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = srv.Shutdown(ctx)
	})
}

// countingTransport answers every request 404 and counts them.
type countingTransport struct{ n atomic.Int32 }

func (c *countingTransport) RoundTrip(*http.Request) (*http.Response, error) {
	c.n.Add(1)
	return &http.Response{StatusCode: http.StatusNotFound, Body: io.NopCloser(strings.NewReader("")), Header: http.Header{}}, nil
}

// Cache misses become outbound fetches, so each source address gets a
// budget of them. Driven through the authorize endpoint, which an
// unauthenticated caller reaches.
func TestCIMDFetchesLimitedPerSource(t *testing.T) {
	cfg := newTestConfig(t)
	cfg.Logger = testLogger(t)
	cfg.EnableMCP = true
	cfg.MCPCIMDEnabled = true
	cfg.OAuth2DBPath = t.TempDir() + "/oauth2.db"
	cfg.SigningKeyPath = writeSigningKey(t)
	srv, err := NewServer(cfg)
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	startServer(t, srv)
	transport := &countingTransport{}
	srv.oauth2Provider.GetStorage().cimd.client = &http.Client{Transport: transport}
	freezeLimiters(srv.oauth2Provider.GetStorage().cimd.bySource)

	authorize := func(addr string, i int) {
		q := url.Values{
			"client_id":     {fmt.Sprintf("https://h%d.example.org/client", i)},
			"response_type": {"code"},
			"redirect_uri":  {"http://127.0.0.1/cb"},
			"state":         {"0123456789abcdef"},
		}
		req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/mcp/oauth2/authorize?"+q.Encode(), nil)
		req.RemoteAddr = addr
		srv.ServeHTTP(httptest.NewRecorder(), req)
	}
	for i := range cimdFetchBurst + 10 {
		authorize("192.0.2.70:1", i)
	}
	if got := transport.n.Load(); got != cimdFetchBurst {
		t.Fatalf("%d fetches from one address, want %d", got, cimdFetchBurst)
	}
	authorize("198.51.100.70:1", 1000)
	if got := transport.n.Load(); got != cimdFetchBurst+1 {
		t.Fatalf("another address's miss was not fetched: %d fetches", got)
	}
}

// A context without a source -- a lookup for a token this server issued
// -- is not charged.
func TestCIMDUnattributedLookupsAreNotLimited(t *testing.T) {
	transport := &countingTransport{}
	r := newCIMDResolver(nil, &http.Client{Transport: transport})
	for i := range cimdFetchBurst + 5 {
		_, err := r.resolve(context.Background(), fmt.Sprintf("https://h%d.example.org/client", i))
		if err == nil || !strings.Contains(fosite.ErrorToRFC6749Error(err).HintField, "HTTP 404") {
			t.Fatalf("lookup %d: %v", i, err)
		}
	}
	if got := transport.n.Load(); got != cimdFetchBurst+5 {
		t.Fatalf("%d fetches, want %d", got, cimdFetchBurst+5)
	}
}
