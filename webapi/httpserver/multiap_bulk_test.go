package httpserver

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/bbockelm/golang-htcondor/webapi/internal/fakeschedd"
	"github.com/bbockelm/golang-htcondor/webapi/multiap"
	"github.com/bbockelm/golang-htcondor/webapi/multiap/multiaptest"
)

// bulkAPs: alice has jobs on ap1 and ap2 (fresh) and nothing on ap3
// (fresh) or ap4 (stale); bob has a job on ap3.
func newBulkServer(t *testing.T, superusers map[string][]string) (*Server, *actionAPs, *bulkLegs) {
	t.Helper()
	aps := newActionAPs(t, ap1, ap2, "ap3.example.org", "ap4.example.org")
	hub := multiaptest.NewHub(t)
	hub.PutJob(ap1, "alice@d", 1, 0, "")
	hub.PutJob(ap2, "alice@d", 1, 0, "")
	hub.PutJob("ap3.example.org", "bob@d", 1, 0, "")
	hub.PutSource(ap1, multiap.StateFresh, 2)
	hub.PutSource(ap2, multiap.StateFresh, 2)
	hub.PutSource("ap3.example.org", multiap.StateFresh, 2)
	hub.PutSource("ap4.example.org", multiap.StateStale, 500)
	svc := multiAPService(t, hub, aps.reg)
	srv, err := NewServer(Config{
		MultiAP: MultiAPConfig{ScheddConstraint: `regexp("^ap", Name)`, service: svc, BulkFresh: time.Minute,
			queueSuperUser: func(ap, actor string) bool {
				for _, u := range superusers[strings.ToLower(ap)] {
					if sameIdentity(actor, u) {
						return true
					}
				}
				return false
			}},
		Logger:                   newTestLogger(t),
		OAuth2DBPath:             t.TempDir() + "/oauth2.db",
		UserHeader:               "X-Remote-User",
		UserHeaderTrustAnyUnsafe: true,
		SigningKeyPath:           writeTestSigningKey(t),
		TrustDomain:              "test.domain",
		UIDDomain:                "d",
		WebUIAdminGroup:          "admins",
	})
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	srv.setupRoutes()
	legs := &bulkLegs{constraints: map[string]string{}}
	srv.multi.observeBulkLeg = legs.observe
	return srv, aps, legs
}

type bulkLegs struct {
	mu          sync.Mutex
	constraints map[string]string
}

func (b *bulkLegs) observe(ap, c string) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.constraints[ap] = c
}

func (b *bulkLegs) get() map[string]string {
	b.mu.Lock()
	defer b.mu.Unlock()
	out := map[string]string{}
	for k, v := range b.constraints {
		out[k] = v
	}
	return out
}

// Every bulk route fans out: an AP the hub proves empty is skipped, a
// stale one is contacted whatever the hub says, and each AP's result is
// reported. Each contacted AP is sent the caller-scoped constraint.
func TestMultiAPBulkActionsFanOut(t *testing.T) {
	for _, c := range []struct{ method, path, body string }{
		{http.MethodPost, "/api/v1/jobs/hold", `{"constraint":"JobStatus == 1"}`},
		{http.MethodPost, "/api/v1/jobs/release", `{"constraint":"JobStatus == 1"}`},
		{http.MethodDelete, "/api/v1/jobs", `{"constraint":"JobStatus == 1"}`},
		{http.MethodPatch, "/api/v1/jobs", `{"constraint":"JobStatus == 1","attributes":{"Foo":1}}`},
	} {
		srv, aps, legs := newBulkServer(t, nil)
		rec := doAlice(t, srv, c.method, c.path, c.body)
		var body MultiAPBulkResponse
		if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
			t.Fatalf("%s %s: %d %s", c.method, c.path, rec.Code, rec.Body.String())
		}
		status := map[string]string{}
		for _, a := range body.APs {
			status[a.Schedd] = a.Status
		}
		// The fakes hang up, so a contacted AP fails; which ones were
		// contacted is the point.
		want := map[string]string{ap1: multiap.BulkFailed, ap2: multiap.BulkFailed,
			"ap3.example.org": multiap.BulkSkipped, "ap4.example.org": multiap.BulkFailed}
		for ap, st := range want {
			if status[ap] != st {
				t.Errorf("%s %s: %s = %q, want %q (%s)", c.method, c.path, ap, status[ap], st, rec.Body.String())
			}
		}
		counts := aps.counts()
		if counts["ap3.example.org"] != 0 || counts[ap1] == 0 || counts[ap2] == 0 || counts["ap4.example.org"] == 0 {
			t.Errorf("%s %s contacted %v", c.method, c.path, counts)
		}
		if body.Complete || rec.Code != http.StatusBadGateway {
			t.Errorf("%s %s with every contacted AP failing = %d complete=%v", c.method, c.path, rec.Code, body.Complete)
		}
		for ap, constraint := range legs.get() {
			if !strings.Contains(constraint, `User == "alice@d"`) {
				t.Errorf("%s %s sent %s an unscoped constraint: %s", c.method, c.path, ap, constraint)
			}
		}
	}
}

// A crafted constraint is refused or confined, never widened.
func TestMultiAPBulkScopeCannotWiden(t *testing.T) {
	srv, aps, legs := newBulkServer(t, nil)
	rec := doAlice(t, srv, http.MethodPost, "/api/v1/jobs/hold", `{"constraint":"true) || (true"}`)
	if rec.Code != http.StatusBadRequest {
		t.Errorf("unbalanced constraint = %d %s", rec.Code, rec.Body.String())
	}
	if c := aps.counts(); c[ap1]+c[ap2] != 0 {
		t.Errorf("a refused constraint reached a schedd: %v", c)
	}
	doAlice(t, srv, http.MethodPost, "/api/v1/jobs/hold", `{"constraint":"Owner == \"bob\" || true"}`)
	got := legs.get()
	if len(got) == 0 {
		t.Fatal("no leg ran")
	}
	for ap, constraint := range got {
		if !strings.HasPrefix(constraint, `(User == "alice@d") && (`) {
			t.Errorf("%s was sent %s", ap, constraint)
		}
	}
	// bob's job on ap3 does not make ap3 worth contacting for alice.
	if aps.counts()["ap3.example.org"] != 0 {
		t.Error("ap3 was contacted for alice on the strength of bob's job")
	}
}

// An administrator's exemption is per AP: unscoped where she is a queue
// superuser, her own jobs elsewhere -- and the hub check follows, so ap3
// (bob's job) is contacted only where she may act on it.
func TestMultiAPBulkSuperuserPerAP(t *testing.T) {
	srv, aps, legs := newBulkServer(t, map[string][]string{"ap3.example.org": {"alice@d"}})
	sid, _, err := srv.sessionStore.Create("alice", []string{"admins"})
	if err != nil {
		t.Fatal(err)
	}
	req := newCookieRequest(http.MethodPost, "/api/v1/jobs/hold", `{"constraint":"JobStatus == 1"}`, sid)
	rec := serve(srv, req)
	got := legs.get()
	if c := got["ap3.example.org"]; c == "" || strings.Contains(c, "User ==") {
		t.Errorf("ap3 (superuser there) was sent %q, want it unscoped (%d %s)", c, rec.Code, rec.Body.String())
	}
	if c := got[ap1]; !strings.Contains(c, `User == "alice@d"`) {
		t.Errorf("ap1 (not superuser) was sent %q", c)
	}
	if aps.counts()["ap3.example.org"] == 0 {
		t.Error("ap3 holds bob's job and alice may act on it there, but it was skipped")
	}
}

func newCookieRequest(method, target, body, sid string) *http.Request {
	req := httptest.NewRequestWithContext(context.Background(), method, target, strings.NewReader(body))
	req.Header.Set("Origin", "http://example.com")
	req.Header.Set("Content-Type", "application/json")
	req.AddCookie(&http.Cookie{Name: sessionCookieName, Value: sid, Secure: true, HttpOnly: true, SameSite: http.SameSiteLaxMode})
	return req
}

func serve(h http.Handler, req *http.Request) *httptest.ResponseRecorder {
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

// A single-job action this server just took on an AP voids the hub's
// "nothing there" for that AP: ap3 is fresh and holds none of alice's
// jobs, but after alice acts on ap3 a bulk action must contact it.
func TestMultiAPSingleActionVoidsTheBulkSkip(t *testing.T) {
	srv, aps, _ := newBulkServer(t, nil)
	doAlice(t, srv, http.MethodPost, "/api/v1/jobs/1.0@ap3.example.org/hold", "")
	before := aps.counts()["ap3.example.org"]
	rec := doAlice(t, srv, http.MethodPost, "/api/v1/jobs/hold", `{"constraint":"JobStatus == 1"}`)
	if aps.counts()["ap3.example.org"] == before {
		t.Errorf("ap3 was skipped on the hub's word right after this server acted there: %s", rec.Body.String())
	}
}

// No access point known yet is a 503, not "nothing matched anywhere".
func TestMultiAPBulkWithNoAPs(t *testing.T) {
	svc := multiAPService(t, multiAPHub(t), multiaptest.NewRegistry())
	srv := newMultiAPServer(t, svc)
	rec := doAlice(t, srv, http.MethodPost, "/api/v1/jobs/hold", `{"constraint":"true"}`)
	if rec.Code != http.StatusServiceUnavailable {
		t.Errorf("bulk hold with no APs = %d %s, want 503", rec.Code, rec.Body.String())
	}
}

// An AP that matched nothing did not act, even when its schedd -- one built
// between 2025-02-24 and 2026-04-14 -- sends an uninitialised
// result_total_6 (AR_LIMIT_EXCEEDED); a 25.8.0 schedd sent 1840092560.
// Read as a count, it made the AP "acted" with ~1.84e9 errors, turned the
// 404 into a 200 and noted a write that never happened.
func TestMultiAPBulkIgnoresLimitGarbage(t *testing.T) {
	keyFile := writeTestSigningKey(t)
	fs := fakeschedd.Start(t, keyFile, "test.domain")
	fs.SetActionReplyAttr("result_total_6", 1840092560)
	reg := multiaptest.NewRegistry(ap1).WithSchedds(func(string) string { return fs.Addr() })
	hub := multiaptest.NewHub(t)
	// Stale, so the AP is contacted whatever the hub holds.
	hub.PutSource(ap1, multiap.StateStale, 500)
	svc := multiAPService(t, hub, reg)
	srv, err := NewServer(Config{
		MultiAP:                  MultiAPConfig{ScheddConstraint: `regexp("^ap", Name)`, service: svc, BulkFresh: time.Minute},
		Logger:                   newTestLogger(t),
		OAuth2DBPath:             t.TempDir() + "/oauth2.db",
		UserHeader:               "X-Remote-User",
		UserHeaderTrustAnyUnsafe: true,
		SigningKeyPath:           keyFile,
		TrustDomain:              "test.domain",
		UIDDomain:                "d",
		WebUIAdminGroup:          "admins",
	})
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	srv.setupRoutes()

	for _, c := range []struct{ method, path string }{
		{http.MethodPost, "/api/v1/jobs/hold"},
		{http.MethodPost, "/api/v1/jobs/release"},
		{http.MethodDelete, "/api/v1/jobs"},
	} {
		rec := doAlice(t, srv, c.method, c.path, `{"constraint":"ClusterId == 99"}`)
		var body MultiAPBulkResponse
		if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
			t.Fatalf("%s %s: %d %s", c.method, c.path, rec.Code, rec.Body.String())
		}
		if len(body.APs) != 1 || body.APs[0].Status != multiap.BulkNoMatch {
			t.Errorf("%s %s: APs = %+v, want %s no_match", c.method, c.path, body.APs, ap1)
		}
		if rec.Code != http.StatusNotFound || body.Totals != (multiap.BulkCounts{}) {
			t.Errorf("%s %s matching nothing = %d totals %+v, want 404 and zero", c.method, c.path, rec.Code, body.Totals)
		}
	}
	if svc.WroteSince(ap1, time.Hour) {
		t.Error("a bulk action that matched nothing noted a write")
	}
	if acted := fs.ActedOn(); len(acted) != 0 {
		t.Errorf("acted on %v", acted)
	}
}
