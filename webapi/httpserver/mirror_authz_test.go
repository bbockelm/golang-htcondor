package httpserver

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/PelicanPlatform/classad/classad"
	"github.com/PelicanPlatform/classad/db"
	"github.com/PelicanPlatform/classad/dbrpc"
	"github.com/bbockelm/cedar/commands"
	"github.com/bbockelm/cedar/message"
	"github.com/bbockelm/cedar/security"
	cedarserver "github.com/bbockelm/cedar/server"

	htcondor "github.com/bbockelm/golang-htcondor"
	"github.com/bbockelm/golang-htcondor/config"
	"github.com/bbockelm/golang-htcondor/webapi/dbmirror"
)

const mirrorAuthzTrustDomain = "test.htcondor.org"

// tokenPoolConfig is a pool that authenticates with IDTOKENs signed by
// the key in keyDir, for both the fake daemons and the API server.
func tokenPoolConfig(keyDir string) *config.Config {
	cfg := config.NewEmpty()
	for k, v := range map[string]string{
		"SEC_DEFAULT_AUTHENTICATION":         "REQUIRED",
		"SEC_DEFAULT_AUTHENTICATION_METHODS": "TOKEN",
		"SEC_CLIENT_AUTHENTICATION_METHODS":  "TOKEN",
		"SEC_DEFAULT_CRYPTO_METHODS":         "AES",
		"SEC_CLIENT_CRYPTO_METHODS":          "AES",
		"SEC_PASSWORD_DIRECTORY":             keyDir,
		"TRUST_DOMAIN":                       mirrorAuthzTrustDomain,
		"UID_DOMAIN":                         mirrorAuthzTrustDomain,
	} {
		cfg.Set(k, v)
	}
	return cfg
}

// tokenDaemonSecurity is the server side of tokenPoolConfig, with a
// session cache of its own: the process-wide one belongs to the API
// server's client side, which runs in this same process.
//
// Authentication is OPTIONAL on the server side only. The client side
// still requires it, so every connection authenticates with a token; but
// cedar's server restores a resumed session without its authenticated
// flag, and at REQUIRED it then refuses the command -- so a second read
// of the mirror, which resumes the first one's session, would never be
// dispatched.
func tokenDaemonSecurity(t *testing.T, cfg *config.Config, command int) *security.SecurityConfig {
	t.Helper()
	sec, err := htcondor.GetServerSecurityConfig(cfg, command, "DEFAULT")
	if err != nil {
		t.Fatalf("server security config: %v", err)
	}
	sec.SessionCache = security.NewSessionCache()
	sec.Authentication = security.SecurityOptional
	return sec
}

// startTokenDaemon serves srv on a loopback port and returns its sinful
// string.
func startTokenDaemon(t *testing.T, srv *cedarserver.Server) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0") //nolint:noctx // test-only loopback listener
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	go func() { _ = srv.Serve(ctx, ln) }()
	t.Cleanup(func() { cancel(); _ = ln.Close() })
	return fmt.Sprintf("<%s>", ln.Addr().String())
}

// fakeReadSchedd stands in for a schedd whose READ authorization
// excludes the caller: it authenticates anyone holding a pool token and
// answers DC_NOP, which DaemonCore registers at ALLOW, but while
// refuseRead is set it refuses every READ-level command it is asked to
// run -- DC_NOP_READ and the queue and history queries alike. A real schedd says no
// after authenticating (post-auth DENIED); this one says it during
// negotiation, which reaches the client as the same kind of failure.
type fakeReadSchedd struct {
	addr       string
	refuseRead atomic.Bool
	readPings  atomic.Int32
}

func newFakeReadSchedd(t *testing.T, cfg *config.Config) *fakeReadSchedd {
	t.Helper()
	f := &fakeReadSchedd{}
	sec := tokenDaemonSecurity(t, cfg, int(commands.DC_NOP))
	refused := *sec
	refused.AuthMethods = []security.AuthMethod{security.AuthKerberos}
	srv := cedarserver.New(sec)
	srv.SecurityConfigForCommand = func(cmd int) *security.SecurityConfig {
		switch cmd {
		case int(commands.DC_NOP_READ):
			f.readPings.Add(1)
		case int(commands.QUERY_JOB_ADS), int(commands.QUERY_JOB_ADS_WITH_AUTH), int(commands.QUERY_SCHEDD_HISTORY):
		default:
			return nil
		}
		if f.refuseRead.Load() {
			return &refused
		}
		return nil
	}
	nop := func(context.Context, *cedarserver.Conn) error { return nil }
	srv.Handle(int(commands.DC_NOP), nop, "ALLOW")
	srv.Handle(int(commands.DC_NOP_READ), nop, "READ")
	f.addr = startTokenDaemon(t, srv)
	return f
}

// fakeMirror is an htcondordb with a caught-up jobs table and history
// archive, each holding one job for each of the given owners. sessions
// counts reads: every query the API server makes of it opens one.
type fakeMirror struct {
	addr     string
	sessions atomic.Int32
}

func newFakeMirror(t *testing.T, cfg *config.Config, owners ...string) *fakeMirror {
	t.Helper()
	cat, err := db.OpenCatalog(t.TempDir())
	if err != nil {
		t.Fatalf("open catalog: %v", err)
	}
	if _, err := cat.CreateTable("jobs"); err != nil {
		t.Fatalf("create jobs table: %v", err)
	}
	if _, err := cat.CreateArchiveTable("history", db.ArchiveConfig{ZoneAttrs: []string{"CompletionDate"}}); err != nil {
		t.Fatalf("create history archive: %v", err)
	}
	rpc := dbrpc.NewServerCatalog(cat)
	t.Cleanup(func() { rpc.Close(); _ = cat.Close() })

	// Seed over an in-process connection, the way a syncer would write.
	cconn, sconn := net.Pipe()
	go func() { _ = rpc.ServeConn(dbrpc.NewStreamConn(sconn)) }()
	seed := dbrpc.NewClient(dbrpc.NewStreamConn(cconn))
	ctx := context.Background()
	tx, err := seed.BeginTable(ctx, "jobs")
	if err != nil {
		t.Fatalf("begin: %v", err)
	}
	for i, owner := range owners {
		ad := fmt.Sprintf("ClusterId = %d\nProcId = 0\nOwner = %q\nJobStatus = 1", i+1, owner)
		if err := tx.NewClassAd(ctx, fmt.Sprintf("%d.0", i+1), ad); err != nil {
			t.Fatalf("insert: %v", err)
		}
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatalf("commit: %v", err)
	}
	for i, owner := range owners {
		ad := fmt.Sprintf("ClusterId = %d\nProcId = 0\nOwner = %q\nJobStatus = 4\nCompletionDate = %d",
			100+i, owner, time.Now().Unix()-60)
		if err := seed.ArchiveAppend(ctx, "history", ad); err != nil {
			t.Fatalf("append history: %v", err)
		}
	}
	_ = seed.Close()

	f := &fakeMirror{}
	srv := cedarserver.New(tokenDaemonSecurity(t, cfg, dbmirror.SessionCommand))
	srv.Handle(dbmirror.StatusCommand, func(ctx context.Context, c *cedarserver.Conn) error {
		if _, err := message.NewMessageFromStream(c.Stream).GetClassAd(ctx); err != nil {
			return err
		}
		now := time.Now().Unix()
		ad := classad.New()
		_ = ad.Set("MyType", dbmirror.AdType)
		_ = ad.Set("Name", "fake-htcondordb")
		_ = ad.Set("JobQueueCaughtUp", true)
		_ = ad.Set("JobQueueLastSyncTime", now)
		_ = ad.Set("JobQueueSecondsSinceSync", 0)
		_ = ad.Set("HistoryCaughtUp", true)
		_ = ad.Set("HistoryLastSyncTime", now)
		_ = ad.Set("HistorySecondsSinceSync", 0)
		out := message.NewMessageForStream(c.Stream)
		if err := out.PutClassAd(ctx, ad); err != nil {
			return err
		}
		return out.FinishMessage(ctx)
	}, "READ")
	srv.Handle(dbmirror.SessionCommand, func(ctx context.Context, c *cedarserver.Conn) error {
		f.sessions.Add(1)
		return rpc.ServeConnOpts(dbrpc.NewCedarConn(ctx, c.Stream), dbrpc.ServeOptions{ReadOnly: true})
	}, "READ")
	f.addr = startTokenDaemon(t, srv)
	return f
}

// jobsReply is the part of a /api/v1/jobs or /api/v1/jobs/archive
// response these tests read. The listing is under "jobs" or "ads".
type jobsReply struct {
	Jobs   []map[string]any `json:"jobs"`
	Ads    []map[string]any `json:"ads"`
	Source string           `json:"source"`
	Error  string           `json:"error"`
}

func (j jobsReply) rows() []map[string]any { return append(j.Jobs, j.Ads...) }

func (j jobsReply) owners() map[string]bool {
	out := map[string]bool{}
	for _, job := range j.rows() {
		if o, ok := job["Owner"].(string); ok {
			out[o] = true
		}
	}
	return out
}

// TestMirrorReadRequiresScheddReadAcceptance drives /api/v1/jobs through
// ServeHTTP with a mirror configured and current, against a schedd that
// authenticates every caller but refuses READ to some.
//
// A caller the schedd refuses at READ must get no rows, and the mirror
// must not be read on their behalf at all: it is dialed with this
// daemon's own credential, so a read there is one the schedd's ACL never
// sees. That holds however the caller was identified -- a forwarded
// IDTOKEN (identity resolved with the schedd), an opaque OAuth2 access
// token (identified by this server's authorization server), or a browser
// session (identified by its cookie). A caller the schedd accepts is
// still served from the mirror.
//
//nolint:gocyclo // One server shared by subtests for each kind of caller and page.
func TestMirrorReadRequiresScheddReadAcceptance(t *testing.T) {
	signingKey := writeSigningKey(t)
	keyDir := filepath.Dir(signingKey)
	cfg := tokenPoolConfig(keyDir)

	schedd := newFakeReadSchedd(t, cfg)
	mirror := newFakeMirror(t, cfg, "alice", "bob", "mallory")

	server, err := NewServer(Config{
		ListenAddr:     "127.0.0.1:0",
		ScheddName:     "fake-schedd",
		ScheddAddr:     schedd.addr,
		ClientConfig:   cfg,
		HTCondorConfig: cfg,
		SigningKeyPath: signingKey,
		TrustDomain:    mirrorAuthzTrustDomain,
		UIDDomain:      mirrorAuthzTrustDomain,
		SessionTTL:     time.Hour,
		OAuth2DBPath:   filepath.Join(t.TempDir(), "oauth2.db"),
		// For the authorization server that issues opaque access tokens.
		EnableMCP: true,
	})
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	// Start() would bind a listener and spawn background work; the routes
	// are all this needs.
	server.setupRoutes()
	// The pool has no collector to advertise to, so the mirror is pinned
	// by address, which discovery then asks directly for its status.
	server.dbMirror = dbmirror.NewLocatorWithOptions(htcondor.NewCollector("<127.0.0.1:1>"), cfg,
		dbmirror.Options{Address: mirror.addr})
	server.dbMirror.SetTokenSource(server.mirrorTokenSource())

	idtoken := func(t *testing.T, user string) string {
		t.Helper()
		now := time.Now().Unix()
		tok, err := security.GenerateJWT(keyDir, "POOL", user+"@"+mirrorAuthzTrustDomain,
			mirrorAuthzTrustDomain, now, now+600, nil)
		if err != nil {
			t.Fatalf("GenerateJWT(%s): %v", user, err)
		}
		return tok
	}
	bearer := func(tok string) func(*http.Request) {
		return func(r *http.Request) { r.Header.Set("Authorization", "Bearer "+tok) }
	}
	session := func(t *testing.T, user string) func(*http.Request) {
		t.Helper()
		sid, _, err := server.sessionStore.Create(user)
		if err != nil {
			t.Fatalf("session create: %v", err)
		}
		return func(r *http.Request) {
			r.AddCookie(&http.Cookie{Name: sessionCookieName, Value: sid}) //nolint:gosec // test cookie
		}
	}
	// Both mirror-routed listings: the live queue and the archive.
	routes := []string{"/api/v1/jobs", "/api/v1/jobs/archive"}
	list := func(t *testing.T, route string, as func(*http.Request)) (jobsReply, int) {
		t.Helper()
		req := httptest.NewRequestWithContext(context.Background(), http.MethodGet,
			route+"?owned_by_me=false&projection=ClusterId,ProcId,Owner", nil)
		as(req)
		rec := httptest.NewRecorder()
		server.ServeHTTP(rec, req)
		var reply jobsReply
		if rec.Code == http.StatusOK {
			if err := json.Unmarshal(rec.Body.Bytes(), &reply); err != nil {
				t.Fatalf("%s: decoding the response: %v (body %s)", route, err, rec.Body.String())
			}
		}
		t.Logf("%s: status %d, source %q, %d rows, error %q", route, rec.Code, reply.Source, len(reply.rows()), reply.Error)
		return reply, rec.Code
	}
	refused := func(t *testing.T, as func(*http.Request)) {
		t.Helper()
		schedd.refuseRead.Store(true)
		defer schedd.refuseRead.Store(false)
		pings, reads := schedd.readPings.Load(), mirror.sessions.Load()

		for _, route := range routes {
			reply, code := list(t, route, as)
			if len(reply.rows()) != 0 {
				t.Errorf("%s: a caller the schedd refuses at READ got %d rows: %v", route, len(reply.rows()), reply.owners())
			}
			if reply.Source == "htcondordb" {
				t.Errorf("%s: the response came from the mirror", route)
			}
			// Refused outright, or passed to the schedd, whose refusal the
			// streamed listing reports in its footer.
			switch {
			case code == http.StatusOK && reply.Error == "":
				t.Errorf("%s: the schedd's refusal was not reported", route)
			case code != http.StatusOK && code != http.StatusUnauthorized && code != http.StatusForbidden:
				t.Errorf("%s: status %d, want a refusal", route, code)
			}
		}
		if got := mirror.sessions.Load() - reads; got != 0 {
			t.Errorf("the mirror was read %d times on behalf of a caller the schedd refuses at READ", got)
		}
		if schedd.readPings.Load() == pings {
			t.Error("the schedd was never asked whether this caller may read")
		}
	}
	// accepted checks that the caller is served its own jobs from the
	// mirror. ownOnly additionally checks that no other user's job comes
	// back; it is false where owner scoping is not what is under test.
	accepted := func(t *testing.T, as func(*http.Request), ownOnly bool) {
		t.Helper()
		for _, route := range routes {
			reads := mirror.sessions.Load()
			reply, _ := list(t, route, as)
			if reply.Source != "htcondordb" {
				t.Fatalf("%s: source = %q, want htcondordb", route, reply.Source)
			}
			if mirror.sessions.Load() == reads {
				t.Errorf("%s: the mirror was not read", route)
			}
			owners := reply.owners()
			if !owners["alice"] {
				t.Errorf("%s: own job missing: %v", route, owners)
			}
			if ownOnly && (owners["bob"] || owners["mallory"]) {
				t.Errorf("%s: other users' jobs present: %v", route, owners)
			}
		}
	}

	t.Run("forwarded IDTOKEN refused at READ", func(t *testing.T) {
		tok := idtoken(t, "mallory")
		// What makes this caller dangerous: the schedd does authenticate
		// them. A DC_NOP ping -- what identity resolution used to send --
		// succeeds and names them.
		schedd.refuseRead.Store(true)
		sec, err := htcondor.NewClientSecurityConfigWithConfig(context.Background(), cfg, tok, "", 0, "CLIENT", nil)
		if err != nil {
			t.Fatalf("client security config: %v", err)
		}
		sec.SecurityTag = "dc-nop-probe"
		res, err := htcondor.NewSchedd("fake-schedd", schedd.addr).WithConfig(cfg).
			Ping(htcondor.WithSecurityConfig(context.Background(), sec))
		schedd.refuseRead.Store(false)
		if err != nil || res.User == "" {
			t.Fatalf("the fake schedd must accept DC_NOP for a READ-refused caller (result %v, err %v)", res, err)
		}

		refused(t, bearer(tok))
	})

	t.Run("opaque OAuth2 token refused at READ", func(t *testing.T) {
		refused(t, bearer(mintRESTAccessToken(t, server.Handler, "dave", []string{"condor:/READ"})))
	})

	t.Run("session refused at READ", func(t *testing.T) {
		refused(t, session(t, "carol"))
	})

	// Whether a bearer's owned_by_me=false listing also shows other users'
	// jobs is owner scoping's concern, not this test's; a non-admin
	// session's listing is owner-scoped. Either way it comes from the
	// mirror.
	t.Run("accepted bearer is served from the mirror", func(t *testing.T) {
		accepted(t, bearer(idtoken(t, "alice")), false)
	})

	t.Run("accepted opaque OAuth2 token is served from the mirror", func(t *testing.T) {
		accepted(t, bearer(mintRESTAccessToken(t, server.Handler, "alice", []string{"condor:/READ"})), false)
	})

	t.Run("accepted session is served its own jobs from the mirror", func(t *testing.T) {
		accepted(t, session(t, "alice"), true)
	})

	// The other pages that read the mirror on a caller's behalf. Only the
	// metrics query has no schedd to fall back to, so it is the only one
	// that refuses outright; the rest fall back as the listings do.
	pages := []string{"/api/v1/dashboard", "/api/v1/dashboard/activity", "/api/v1/issues", "/api/v1/metrics/job_metrics?group_by=Owner&agg=count:*"}
	get := func(t *testing.T, route string, as func(*http.Request)) int {
		t.Helper()
		req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, route, nil)
		as(req)
		rec := httptest.NewRecorder()
		server.ServeHTTP(rec, req)
		return rec.Code
	}

	t.Run("other pages do not read the mirror for a session refused at READ", func(t *testing.T) {
		schedd.refuseRead.Store(true)
		defer schedd.refuseRead.Store(false)
		as := session(t, "erin")
		for _, route := range pages {
			reads := mirror.sessions.Load()
			code := get(t, route, as)
			if got := mirror.sessions.Load() - reads; got != 0 {
				t.Errorf("%s: the mirror was read %d times on behalf of a caller the schedd refuses at READ", route, got)
			}
			if strings.HasPrefix(route, "/api/v1/metrics/") && code != http.StatusForbidden {
				t.Errorf("%s: status %d, want %d", route, code, http.StatusForbidden)
			}
		}
	})

	t.Run("other pages read the mirror for a session accepted at READ", func(t *testing.T) {
		as := session(t, "alice")
		for _, route := range pages {
			reads := mirror.sessions.Load()
			code := get(t, route, as)
			if mirror.sessions.Load() == reads {
				t.Errorf("%s: the mirror was not read (status %d)", route, code)
			}
		}
	})

	// Verification spends a schedd handshake, so it is charged to the
	// request's source like every other resolution; a source that has
	// used up its allowance is not verified, even for a credential the
	// schedd would accept. Last, because it exhausts the test source.
	t.Run("throttled resolution does not verify", func(t *testing.T) {
		probe := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/", nil)
		source := actorResolveSource(probe, server.trustedProxies)
		for server.mcpActors.allowResolve(source) {
		}
		as := bearer(mintRESTAccessToken(t, server.Handler, "frank", []string{"condor:/READ"}))
		for _, route := range routes {
			reads := mirror.sessions.Load()
			reply, _ := list(t, route, as)
			if reply.Source == "htcondordb" || mirror.sessions.Load() != reads {
				t.Errorf("%s: the mirror answered a caller whose verification was throttled", route)
			}
		}
	})
}
