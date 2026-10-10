//go:build integration

package httpserver

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/PelicanPlatform/classad/db"
	htcondor "github.com/bbockelm/golang-htcondor"
	"github.com/bbockelm/golang-htcondor/config"
	"github.com/bbockelm/golang-htcondor/webapi/dbmirror"
)

// Reads answered from the htcondordb mirror are made with this daemon's
// credential, so the owner clause the handler adds is all that keeps one
// user's records from another's. These drive the endpoints through
// ServeHTTP against a real mirror holding two owners' rows, as a bearer
// whose identity is qualified the way a bearer's is ("alice@domain"
// where a job's Owner is "alice"), as a browser session, and as an
// administrator.

// twoOwnerMirror brings up a mirror whose jobs table holds seedJobs'
// ten jobs for alice and one held job for bob, and whose job_metrics
// archive holds samples for both, and returns a server reading it.
func twoOwnerMirror(ctx context.Context, t *testing.T) *Server {
	t.Helper()
	bin := htcondordbBinary(t)
	harness := htcondor.SetupCondorHarnessWithConfig(t, "DAEMON_LIST = MASTER, COLLECTOR\n")
	startMirror(t, harness, bin, t.TempDir())

	cfg := config.NewEmpty()
	cfg.Set("SEC_DEFAULT_AUTHENTICATION_METHODS", "FS")
	cfg.Set("SEC_CLIENT_AUTHENTICATION_METHODS", "FS")
	cfg.Set("UID_DOMAIN", harness.GetTrustDomain())
	cfg.Set("TRUST_DOMAIN", harness.GetTrustDomain())

	s := unidentifiedReadsServer(t)
	s.dbMirror = dbmirror.NewLocator(htcondor.NewCollector(harness.GetCollectorAddr()), cfg)

	waitFor(t, "the mirror to accept a connection", 45*time.Second, func() bool {
		dbc, closer, _, err := s.dbMirror.Client(ctx)
		if err != nil {
			return false
		}
		defer closer()
		cerr := dbc.CreateTable(ctx, "jobs")
		return cerr == nil || strings.Contains(cerr.Error(), "exists")
	})
	dbc, closer, _, err := s.dbMirror.Client(ctx)
	if err != nil {
		t.Fatalf("connecting to seed: %v", err)
	}
	defer closer()

	seedJobs(ctx, t, dbc, "alice")
	now := time.Now().Unix()
	tx, err := dbc.BeginTable(ctx, "jobs")
	if err != nil {
		t.Fatalf("begin: %v", err)
	}
	if err := tx.NewClassAd(ctx, "50.0", fmt.Sprintf(
		"ClusterId = 50\nProcId = 0\nOwner = \"bob\"\nJobStatus = 5\nCmd = \"/bin/sleep\"\nQDate = %d\n"+
			"HoldReasonCode = 13\nHoldReason = \"transfer output: /no/such/bob\"\nEnteredCurrentStatus = %d",
		now-300, now-45)); err != nil {
		t.Fatalf("insert bob's job: %v", err)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatalf("commit: %v", err)
	}

	if err := dbc.CreateArchiveTable(ctx, "job_metrics", db.ArchiveConfig{
		ZoneAttrs: []string{"SampleTime"},
	}); err != nil && !strings.Contains(err.Error(), "exists") {
		t.Fatalf("creating the job_metrics archive: %v", err)
	}
	for i, owner := range []string{"alice", "alice", "bob"} {
		ad := fmt.Sprintf("ClusterId = %d\nProcId = 0\nOwner = %q\nRunInstanceID = \"r%d\"\nSampleTime = %d\nMemoryUsage = 100",
			i+1, owner, i, now-60)
		if err := dbc.ArchiveAppend(ctx, "job_metrics", ad); err != nil {
			t.Fatalf("seeding a sample: %v", err)
		}
	}
	return s
}

// getJSON runs one GET through ServeHTTP and decodes a 200 into out.
func getJSON(ctx context.Context, t *testing.T, s *Server, path string, auth func(*http.Request), out any) {
	t.Helper()
	req := httptest.NewRequestWithContext(ctx, http.MethodGet, path, nil)
	auth(req)
	w := httptest.NewRecorder()
	s.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("GET %s: status = %d: %s", path, w.Code, w.Body.String())
	}
	if err := json.Unmarshal(w.Body.Bytes(), out); err != nil {
		t.Fatalf("GET %s: decoding %s: %v", path, w.Body.String(), err)
	}
}

func TestMirrorReadsAreOwnerScopedAgainstARealMirror(t *testing.T) {
	if testing.Short() {
		t.Skip("integration test (forks a real htcondordb)")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()
	s := twoOwnerMirror(ctx, t)

	asAliceBearer := func(r *http.Request) {
		r.Header.Set("Authorization", "Bearer "+identifiedBearer(t, s.Handler))
	}
	asAliceSession := func(r *http.Request) { withSession(t, s, r, "alice") }
	asAdmin := func(r *http.Request) { withSession(t, s, r, "root", "condor-admins") }

	t.Run("metrics", func(t *testing.T) {
		owners := func(t *testing.T, auth func(*http.Request)) map[string]bool {
			t.Helper()
			var resp metricsResponse
			getJSON(ctx, t, s, "/api/v1/metrics/job_metrics?group_by=Owner&agg=count:*", auth, &resp)
			if !resp.Enabled {
				t.Fatal("metrics reported disabled")
			}
			got := map[string]bool{}
			for _, row := range resp.Rows {
				if len(row) > 0 {
					got[strings.Trim(row[0], `"`)] = true
				}
			}
			return got
		}
		if got := owners(t, asAliceBearer); !got["alice"] || got["bob"] {
			t.Errorf("a bearer for alice read owners %v, want alice only", got)
		}
		if got := owners(t, asAdmin); !got["alice"] || !got["bob"] {
			t.Errorf("an administrator read owners %v, want both", got)
		}
	})

	t.Run("dashboard", func(t *testing.T) {
		total := func(t *testing.T, path string, auth func(*http.Request)) int {
			t.Helper()
			var resp DashboardResponse
			getJSON(ctx, t, s, path, auth, &resp)
			return resp.JobsTotal
		}
		if got := total(t, "/api/v1/dashboard", asAliceBearer); got != 10 {
			t.Errorf("a bearer for alice counts %d jobs, want her 10", got)
		}
		if got := total(t, "/api/v1/dashboard?owned_by_me=false", asAliceBearer); got != 10 {
			t.Errorf("a bearer for alice asking for everyone counts %d jobs, want her 10", got)
		}
		if got := total(t, "/api/v1/dashboard?owned_by_me=false", asAdmin); got != 11 {
			t.Errorf("an administrator asking for everyone counts %d jobs, want 11", got)
		}
	})

	t.Run("issues", func(t *testing.T) {
		holds := func(t *testing.T, path string, auth func(*http.Request)) int {
			t.Helper()
			var resp IssuesResponse
			getJSON(ctx, t, s, path, auth, &resp)
			if resp.Timings == nil {
				t.Fatal("no timings in the issues response")
			}
			return resp.Timings.Holds
		}
		session := holds(t, "/api/v1/issues?include_ended=false", asAliceSession)
		if session == 0 {
			t.Fatal("alice's session read none of her held jobs; the fixture is not exercising the scope")
		}
		if got := holds(t, "/api/v1/issues?include_ended=false", asAliceBearer); got != session {
			t.Errorf("a bearer for alice read %d holds, her session %d", got, session)
		}
		if got := holds(t, "/api/v1/issues?include_ended=false&owned_by_me=false", asAdmin); got != session+1 {
			t.Errorf("an administrator read %d holds, want alice's %d plus bob's", got, session)
		}
	})
}
