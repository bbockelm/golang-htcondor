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
			if !strings.Contains(constraint, `Owner == "alice"`) {
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
		if !strings.HasPrefix(constraint, `(Owner == "alice") && (`) {
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
	if c := got["ap3.example.org"]; c == "" || strings.Contains(c, "Owner") {
		t.Errorf("ap3 (superuser there) was sent %q, want it unscoped (%d %s)", c, rec.Code, rec.Body.String())
	}
	if c := got[ap1]; !strings.Contains(c, `Owner == "alice"`) {
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
