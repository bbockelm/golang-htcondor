package httpserver

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/PelicanPlatform/classad/classad"

	htcondor "github.com/bbockelm/golang-htcondor"
	"github.com/bbockelm/golang-htcondor/webapi/ownerscope"
)

// The placementd account and the local user who shares its Owner.
const (
	placedAlice = "alice@course.example"
	localAlice  = "alice@" + mirrorAuthzTrustDomain
)

// placedAliceJobs are a job of the placementd account placedAlice and one
// of the local localAlice. Both have Owner "alice"; only User tells them
// apart.
func placedAliceJobs() (jobs, history []string) {
	done := time.Now().Unix() - 60
	for i, user := range []string{placedAlice, localAlice} {
		jobs = append(jobs, fmt.Sprintf("ClusterId = %d\nProcId = 0\nOwner = \"alice\"\nUser = %q\nJobStatus = 1", i+1, user))
		history = append(history, fmt.Sprintf("ClusterId = %d\nProcId = 0\nOwner = \"alice\"\nUser = %q\nJobStatus = 4\nCompletionDate = %d",
			100+i, user, done))
	}
	return jobs, history
}

// placementdSession creates a browser session for a placementd account.
func placementdSession(t *testing.T, s *Server, account string) string {
	t.Helper()
	sid, _, err := s.sessionStore.CreateSession(SessionData{
		Username:          account,
		PlacementIdentity: "alice@idp.example",
		IdentitySource:    identitySourcePlacementd,
		Placement: &PlacementAccountInfo{
			Account:        account,
			Authorizations: []string{"READ", "WRITE"},
			CheckedAt:      time.Now(),
		},
	})
	if err != nil {
		t.Fatalf("CreateSession: %v", err)
	}
	return sid
}

// TestPlacementdAccountReadsOnlyItsOwnUser: an account the placementd
// assigned outside UID_DOMAIN, alice@course.example, shares Owner "alice"
// with the local alice@UID_DOMAIN. Its reads are confined by User, so it
// sees its own jobs and not the local alice's -- from the mirror, by
// browser session and by an OAuth2 bearer alike, and in every owner scope
// the server builds for it. A local session keeps Owner scoping.
func TestPlacementdAccountReadsOnlyItsOwnUser(t *testing.T) {
	signingKey := writeSigningKey(t)
	cfg := tokenPoolConfig(filepath.Dir(signingKey))
	schedd := newFakeReadSchedd(t, cfg)
	jobs, history := placedAliceJobs()
	mirror := newFakeMirrorAds(t, cfg, jobs, history)

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
		EnableMCP:      true,
		// The pool has no collector to advertise to, so the mirror is
		// pinned by address. Set here rather than after construction so
		// the MCP tools, which share the server's locator, read it too.
		Collector:       htcondor.NewCollector("<127.0.0.1:1>"),
		DBMirrorAddress: mirror.addr,
	})
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	server.setupRoutes()

	placedSID := placementdSession(t, server, placedAlice)
	cookie := func(sid string) func(*http.Request) {
		return func(r *http.Request) {
			r.AddCookie(&http.Cookie{Name: sessionCookieName, Value: sid}) //nolint:gosec // test cookie
		}
	}
	// A bearer for the account, granted after a placementd session signed
	// in as it.
	if err := server.recordPlacementSubject(context.Background(), &SessionData{
		Username: placedAlice, PlacementIdentity: "alice@idp.example", IdentitySource: identitySourcePlacementd,
		Placement: &PlacementAccountInfo{Account: placedAlice, Authorizations: []string{"READ"}},
	}); err != nil {
		t.Fatalf("recordPlacementSubject: %v", err)
	}
	bearer := mintRESTAccessToken(t, server.Handler, placedAlice, []string{"condor:/READ"})
	mcpBearer := mintRESTAccessToken(t, server.Handler, placedAlice, []string{"mcp:read", "condor:/READ"})
	localSID, _, err := server.sessionStore.Create("alice")
	if err != nil {
		t.Fatalf("session create: %v", err)
	}

	users := func(t *testing.T, route string, as func(*http.Request)) map[string]bool {
		t.Helper()
		req := httptest.NewRequestWithContext(context.Background(), http.MethodGet,
			route+"?projection=ClusterId,ProcId,Owner,User", nil)
		as(req)
		rec := httptest.NewRecorder()
		server.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("%s: status %d: %s", route, rec.Code, rec.Body.String())
		}
		var reply jobsReply
		if err := json.Unmarshal(rec.Body.Bytes(), &reply); err != nil {
			t.Fatalf("%s: decoding: %v (%s)", route, err, rec.Body.String())
		}
		if reply.Source != "htcondordb" {
			t.Fatalf("%s: source %q, want the mirror", route, reply.Source)
		}
		out := map[string]bool{}
		for _, row := range reply.rows() {
			u, _ := row["User"].(string)
			out[u] = true
		}
		return out
	}

	for name, as := range map[string]func(*http.Request){
		"placementd session": cookie(placedSID),
		"placementd bearer": func(r *http.Request) {
			r.Header.Set("Authorization", "Bearer "+bearer)
		},
	} {
		t.Run(name, func(t *testing.T) {
			for _, route := range []string{"/api/v1/jobs", "/api/v1/jobs/archive"} {
				got := users(t, route, as)
				if got[localAlice] {
					t.Errorf("%s: %s read %s's job: %v", route, placedAlice, localAlice, got)
				}
				if !got[placedAlice] {
					t.Errorf("%s: %s's own job is missing: %v", route, placedAlice, got)
				}
			}
		})
	}

	// The MCP owner-scope injection, over the transport: query_jobs,
	// answered from the mirror.
	t.Run("placementd MCP bearer", func(t *testing.T) {
		req := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/mcp/message",
			strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":`+
				`{"name":"query_jobs","arguments":{"constraint":"true","projection":["ClusterId","ProcId","User"]}}}`))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Accept", "application/json, text/event-stream")
		req.Header.Set("Authorization", "Bearer "+mcpBearer)
		rec := httptest.NewRecorder()
		server.ServeHTTP(rec, req)
		body := rec.Body.String()
		if rec.Code != http.StatusOK || !strings.Contains(body, "htcondordb") {
			t.Fatalf("query_jobs: status %d, not answered from the mirror: %s", rec.Code, body)
		}
		if strings.Contains(body, localAlice) {
			t.Errorf("query_jobs as %s returned %s's job: %s", placedAlice, localAlice, body)
		}
		if !strings.Contains(body, placedAlice) {
			t.Errorf("query_jobs as %s did not return its own job: %s", placedAlice, body)
		}
	})

	t.Run("local session keeps Owner scoping", func(t *testing.T) {
		for _, route := range []string{"/api/v1/jobs", "/api/v1/jobs/archive"} {
			if got := users(t, route, cookie(localSID)); !got[localAlice] {
				t.Errorf("%s: the local alice's own job is missing: %v", route, got)
			}
		}
	})

	// Every scope the server builds for the placementd session's request,
	// evaluated against both jobs.
	t.Run("every owner scope", func(t *testing.T) {
		req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/api/v1/jobs", nil)
		cookie(placedSID)(req)
		ctx, err := server.createAuthenticatedContext(req)
		if err != nil {
			t.Fatalf("createAuthenticatedContext: %v", err)
		}
		// The local job given the placementd job's id, so a scope naming
		// one job cannot tell them apart by id.
		mine, local := parsedJobAd(t, jobs[0]), parsedJobAd(t, strings.Replace(jobs[1], "ClusterId = 2", "ClusterId = 1", 1))
		check := func(name, constraint string, err error) {
			t.Helper()
			if err != nil {
				t.Fatalf("%s: %v", name, err)
			}
			if !evalConstraint(t, constraint, mine) || evalConstraint(t, constraint, local) {
				t.Errorf("%s = %q: want only %s's job", name, constraint, placedAlice)
			}
		}
		c, err := server.jobsOwnerScope(ctx, req, "JobStatus == 1", jobScopeRead)
		check("jobsOwnerScope", c, err)
		c, err = server.jobReadScope(ctx, req, 1, 0)
		check("jobReadScope", c, err)
		c, err = localReadOwnerScope(ctx, "JobStatus == 1", false)
		check("localReadOwnerScope", c, err)
		c, _, err = server.historyOwnerScope(ctx, req, "JobStatus == 1")
		check("historyOwnerScope", c, err)
		c, err = chatJobScope(ctx, htcondor.GetAuthenticatedUserFromContext(ctx), "JobStatus == 1", jobScopeRead)
		check("chatJobScope", c, err)
	})
}

func parsedJobAd(t *testing.T, text string) *classad.ClassAd {
	t.Helper()
	ad, err := classad.ParseOld(text)
	if err != nil {
		t.Fatalf("ParseOld(%q): %v", text, err)
	}
	return ad
}

// TestPlacementOwnerScopeMarksOnlyPlacementdCallers: the MCP transport
// confines a bearer by User when, and only when, its subject is an account
// a placementd session signed in as.
func TestPlacementOwnerScopeMarksOnlyPlacementdCallers(t *testing.T) {
	s := placementSSOServer(t, map[string]any{"sub": "x"})
	if err := s.recordPlacementSubject(context.Background(), &SessionData{
		Username: placedAlice, PlacementIdentity: "alice@idp.example", IdentitySource: identitySourcePlacementd,
		Placement: &PlacementAccountInfo{Account: placedAlice, Authorizations: []string{"READ"}},
	}); err != nil {
		t.Fatalf("recordPlacementSubject: %v", err)
	}
	for actor, want := range map[string]bool{placedAlice: true, localAlice: false} {
		ctx := s.withPlacementOwnerScope(context.Background(), nil, actor)
		if got := ownerscope.UserScoped(ctx); got != want {
			t.Errorf("%s: user-scoped %v, want %v", actor, got, want)
		}
	}
}

// TestJobFeedRefusedToForeignPlacementdAccount: the job change feed files
// a job under its Owner, so a placementd account outside UID_DOMAIN is
// refused a stream of it rather than given the local same-named user's.
func TestJobFeedRefusedToForeignPlacementdAccount(t *testing.T) {
	h := &Handler{uidDomain: mirrorAuthzTrustDomain, logger: testLogger(t)}
	for _, tc := range []struct {
		actor  string
		placed bool
		want   bool
	}{
		{placedAlice, true, false},
		{"bob@" + mirrorAuthzTrustDomain, true, true},
		{localAlice, false, true},
		{placedAlice, false, true}, // not a placementd caller: Owner scoping, as before
	} {
		ctx := htcondor.WithAuthenticatedUser(context.Background(), tc.actor)
		if tc.placed {
			ctx = ownerscope.WithUserScope(ctx)
		}
		rec := httptest.NewRecorder()
		if got := h.streamCallerInDomain(ctx, rec); got != tc.want {
			t.Errorf("%s (placementd %v): allowed %v, want %v (%d %s)", tc.actor, tc.placed, got, tc.want, rec.Code, rec.Body.String())
		}
	}
}
