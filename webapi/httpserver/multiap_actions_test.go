package httpserver

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/PelicanPlatform/classad/classad"

	htcondor "github.com/bbockelm/golang-htcondor"
	"github.com/bbockelm/golang-htcondor/jobid"
	"github.com/bbockelm/golang-htcondor/webapi/apregistry"
	"github.com/bbockelm/golang-htcondor/webapi/jobssh"
	"github.com/bbockelm/golang-htcondor/webapi/multiap"
	"github.com/bbockelm/golang-htcondor/webapi/multiap/multiaptest"
)

// actionAPs is a two-AP set whose schedds are listeners that count the
// connections made to them: an action routed to an AP shows up as a
// connection there, and on no other.
type actionAPs struct {
	reg      *multiaptest.Registry
	accepted map[string]*atomic.Int64
}

func newActionAPs(t *testing.T, names ...string) *actionAPs {
	t.Helper()
	a := &actionAPs{accepted: map[string]*atomic.Int64{}}
	addrs := map[string]string{}
	for _, n := range names {
		addr, n2 := fakeScheddListener(t)
		addrs[n], a.accepted[n] = "<"+addr+">", n2
	}
	a.reg = multiaptest.NewRegistry(names...).WithSchedds(func(n string) string { return addrs[n] })
	return a
}

func (a *actionAPs) counts() map[string]int64 {
	out := map[string]int64{}
	for n, c := range a.accepted {
		out[n] = c.Load()
	}
	return out
}

// newActionServer is newMultiAPServer over the standard hub population
// with aps as the AP set, and a fixed per-AP superuser table.
func newActionServer(t *testing.T, aps *actionAPs, superusers map[string][]string) *Server {
	t.Helper()
	svc := multiAPService(t, multiAPHub(t), aps.reg)
	srv, err := NewServer(Config{
		MultiAP: MultiAPConfig{
			ScheddConstraint: `regexp("^ap", Name)`, service: svc,
			queueSuperUser: func(ap, actor string) bool {
				for _, u := range superusers[strings.ToLower(ap)] {
					if sameIdentity(actor, u) {
						return true
					}
				}
				return false
			},
		},
		Logger:                   newTestLogger(t),
		EnableMCP:                true,
		OAuth2DBPath:             t.TempDir() + "/oauth2.db",
		OAuth2Issuer:             "http://localhost:8080",
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
	return srv
}

func doAlice(t *testing.T, h http.Handler, method, target, body string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequestWithContext(context.Background(), method, target, strings.NewReader(body))
	req.Header.Set("X-Remote-User", "alice")
	req.Header.Set("Origin", "http://example.com")
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

// singleJobActions is every single-job action multi-AP mode serves, as
// (method, sub-path, body). Each reaches its job's schedd.
var singleJobActions = []struct{ method, sub, body string }{
	{http.MethodDelete, "", ""},
	{http.MethodPatch, "", `{"attributes":{"Foo":1}}`},
	{http.MethodPost, "/hold", `{"reason":"test"}`},
	{http.MethodPost, "/release", ""},
	{http.MethodGet, "/stdout", ""},
	{http.MethodGet, "/stderr", ""},
	{http.MethodGet, "/log", ""},
	{http.MethodGet, "/peek", ""},
	{http.MethodGet, "/dag", ""},
	{http.MethodGet, "/files/out.txt", ""},
	{http.MethodGet, "/output", ""},
	{http.MethodPut, "/input", "not a tar"},
	{http.MethodPost, "/input/share", ""},
	{http.MethodPost, "/output/share", ""},
	{http.MethodGet, "/watch", ""},
	{http.MethodPost, "/warm", ""},
	{http.MethodGet, "/proxy/8080/", ""},
	{http.MethodGet, "/ssh", ""},
}

// Every single-job action on 1.0@ap2 reaches ap2's schedd and never
// ap1's -- though both have a 1.0, and alice owns both.
func TestMultiAPActionsRouteToTheJobsAP(t *testing.T) {
	aps := newActionAPs(t, ap1, ap2)
	srv := newActionServer(t, aps, nil)

	for _, a := range singleJobActions {
		for _, c := range []struct{ target, other string }{{ap2, ap1}, {ap1, ap2}} {
			before := aps.counts()
			path := "/api/v1/jobs/1.0@" + c.target + a.sub
			rec := doAlice(t, srv, a.method, path, a.body)
			after := aps.counts()
			if after[c.target] == before[c.target] {
				t.Errorf("%s %s = %d %s: never reached %s's schedd", a.method, path, rec.Code,
					clip(rec.Body.String(), 200), c.target)
			}
			if after[c.other] != before[c.other] {
				t.Errorf("%s %s reached %s's schedd (%d connections)", a.method, path, c.other,
					after[c.other]-before[c.other])
			}
			if rec.Code == http.StatusNotImplemented {
				t.Errorf("%s %s is still refused in multi-AP mode", a.method, path)
			}
		}
	}
	if n := srv.multi.scheddCalls.Load(); n != 0 {
		t.Errorf("the single-schedd accessor was called %d times", n)
	}
}

// A mutation naming only cluster.proc is a 400 that names the caller's
// candidates, and reaches no schedd.
func TestMultiAPActionsRefuseBareIDs(t *testing.T) {
	aps := newActionAPs(t, ap1, ap2)
	srv := newActionServer(t, aps, nil)
	before := aps.counts()
	for _, a := range singleJobActions {
		rec := doAlice(t, srv, a.method, "/api/v1/jobs/1.0"+a.sub, a.body)
		var body struct {
			Reason     string           `json:"reason"`
			Candidates []multiap.JobRef `json:"candidates"`
		}
		if rec.Code != http.StatusBadRequest || json.Unmarshal(rec.Body.Bytes(), &body) != nil {
			t.Errorf("%s 1.0%s = %d %s, want 400", a.method, a.sub, rec.Code, rec.Body.String())
			continue
		}
		if body.Reason != multiap.ReasonIncompleteID || len(body.Candidates) != 2 ||
			body.Candidates[0].JobID != "1.0@"+ap1 || body.Candidates[1].JobID != "1.0@"+ap2 {
			t.Errorf("%s 1.0%s: %s, want both of alice's 1.0 as candidates", a.method, a.sub, rec.Body.String())
		}
	}
	// bob's 5.0 is not alice's candidate; the refusal still stands.
	rec := doAlice(t, srv, http.MethodDelete, "/api/v1/jobs/5.0", "")
	var five struct {
		Candidates []multiap.JobRef `json:"candidates"`
	}
	if rec.Code != http.StatusBadRequest || json.Unmarshal(rec.Body.Bytes(), &five) != nil || len(five.Candidates) != 0 {
		t.Errorf("bare 5.0 for alice = %d %s, want 400 with no candidates", rec.Code, rec.Body.String())
	}
	if after := aps.counts(); after[ap1] != before[ap1] || after[ap2] != before[ap2] {
		t.Errorf("a bare id reached a schedd: %v -> %v", before, after)
	}
}

// An unknown, absent or untrusted AP is its own error, and fails fast:
// no connection is attempted.
func TestMultiAPActionsOnUnusableAPs(t *testing.T) {
	aps := newActionAPs(t, ap1, ap2, "ap3.example.org")
	aps.reg.Update(ap2, func(m *apregistry.Member) { m.Present = false })
	aps.reg.Update("ap3.example.org", func(m *apregistry.Member) {
		m.Trust = apregistry.Trust{State: apregistry.TrustUntrusted, Reason: "identified the probe as nobody@x"}
	})
	srv := newActionServer(t, aps, nil)
	before := aps.counts()
	for _, c := range []struct {
		ap     string
		status int
		reason string
		text   string
	}{
		{"ap9.example.org", http.StatusNotFound, multiap.ReasonUnknownAP, "not an access point this server serves"},
		{ap2, http.StatusServiceUnavailable, multiap.ReasonAPAbsent, "not advertised in the collector"},
		{"ap3.example.org", http.StatusServiceUnavailable, multiap.ReasonAPUntrusted, "this access point does not trust this API server's tokens"},
	} {
		rec := doAlice(t, srv, http.MethodPost, "/api/v1/jobs/1.0@"+c.ap+"/hold", "")
		var body struct {
			Reason  string `json:"reason"`
			Message string `json:"message"`
		}
		_ = json.Unmarshal(rec.Body.Bytes(), &body)
		if rec.Code != c.status || body.Reason != c.reason || !strings.Contains(body.Message, c.text) {
			t.Errorf("hold 1.0@%s = %d %s, want %d %s", c.ap, rec.Code, rec.Body.String(), c.status, c.reason)
		}
	}
	if after := aps.counts(); after[ap2] != before[ap2] || after["ap3.example.org"] != before["ap3.example.org"] {
		t.Errorf("an unusable AP was contacted: %v -> %v", before, after)
	}
}

// scheddFor answers from the routed AP only, and refuses a context that
// carries no caller credential rather than act as this daemon.
func TestScheddForFailsClosed(t *testing.T) {
	aps := newActionAPs(t, ap1, ap2)
	srv := newActionServer(t, aps, nil)
	m, _ := aps.reg.Get(ap2)
	ctx := multiap.WithTarget(context.Background(), multiap.Target{Member: m, ID: jobid.ID{Schedd: ap2, Cluster: 1}})

	if got := srv.scheddFor(ctx); got != multiap.NoSchedd {
		t.Errorf("scheddFor with no caller credential = %v, want the schedd that cannot connect", got)
	}
	sec, err := htcondor.NewClientSecurityConfigWithConfig(context.Background(), nil, "x.y.z", "", 0, "CLIENT", nil)
	if err != nil {
		t.Fatal(err)
	}
	if got := srv.scheddFor(htcondor.WithSecurityConfig(ctx, sec)); got != m.Schedd {
		t.Errorf("scheddFor(ap2 with a credential) = %v, want ap2's schedd", got)
	}
	before := srv.multi.scheddCalls.Load()
	if got := srv.scheddFor(htcondor.WithSecurityConfig(context.Background(), sec)); got != multiap.NoSchedd {
		t.Errorf("scheddFor with no routed AP = %v", got)
	}
	if srv.multi.scheddCalls.Load() != before+1 {
		t.Error("an unrouted scheddFor was not counted as a bug")
	}
}

// Cross-user power is per AP: alice, an administrator by this server's
// policy, is a queue superuser on ap1 only. She sees and acts on other
// users' jobs on ap1, and only her own on ap2.
func TestMultiAPSuperuserIsPerAP(t *testing.T) {
	aps := newActionAPs(t, ap1, ap2)
	srv := newActionServer(t, aps, map[string][]string{ap1: {"alice@d"}})
	sid, _, err := srv.sessionStore.Create("alice", []string{"admins"})
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/api/v1/jobs/5.0@x/hold", nil)
	req.AddCookie(&http.Cookie{Name: sessionCookieName, Value: sid, Secure: true, HttpOnly: true, SameSite: http.SameSiteLaxMode})
	base := htcondor.WithAuthenticatedUser(context.Background(), "alice")
	at := func(ap string) context.Context {
		m, _ := aps.reg.Get(ap)
		return multiap.WithTarget(base, multiap.Target{Member: m, ID: jobid.ID{Schedd: ap, Cluster: 5}})
	}
	if !srv.seesAllJobsByPolicy(base, req, jobScopeMutate) {
		t.Fatal("the test's administrator is not one by this server's policy")
	}
	for _, tier := range []jobScopeTier{jobScopeRead, jobScopeMutate} {
		if !srv.seesAllJobs(at(ap1), req, tier) {
			t.Errorf("tier %d: alice cannot reach other users' jobs on ap1, where she is a queue superuser", tier)
		}
		if srv.seesAllJobs(at(ap2), req, tier) {
			t.Errorf("tier %d: alice reaches other users' jobs on ap2, where she is not a queue superuser", tier)
		}
		if srv.seesAllJobs(base, req, tier) {
			t.Errorf("tier %d: a request routed to no AP sees other users' jobs", tier)
		}
	}
	// The constraint each AP is sent follows.
	c1, err := srv.jobOwnerScope(at(ap1), req, 5, 0, jobScopeMutate)
	if err != nil || strings.Contains(c1, "User ==") {
		t.Errorf("ap1 constraint = %q (%v), want it unscoped", c1, err)
	}
	c2, err := srv.jobOwnerScope(at(ap2), req, 5, 0, jobScopeMutate)
	if err != nil || !strings.Contains(c2, `User == "alice@d"`) {
		t.Errorf("ap2 constraint = %q (%v), want it confined to alice", c2, err)
	}
	// Superuser mode itself is off in multi-AP mode.
	if srv.superuserModeAvailable() {
		t.Error("superuser mode is available in multi-AP mode")
	}
}

// Two APs, the same cluster.proc, the same caller: every cache keyed on
// a job keeps them apart.
func TestMultiAPStateIsKeyedByAP(t *testing.T) {
	aps := newActionAPs(t, ap1, ap2)
	srv := newActionServer(t, aps, nil)
	sec, err := htcondor.NewClientSecurityConfigWithConfig(context.Background(), nil, "x.y.z", "", 0, "CLIENT", nil)
	if err != nil {
		t.Fatal(err)
	}
	sec.SecurityTag = "alice-tag"
	base := htcondor.WithAuthenticatedUser(htcondor.WithSecurityConfig(context.Background(), sec), "alice@d")
	at := func(ap string) context.Context {
		m, _ := aps.reg.Get(ap)
		return multiap.WithTarget(base, multiap.Target{Member: m, ID: jobid.ID{Schedd: ap, Cluster: 1}})
	}

	// Job transports.
	k1, err1 := jobTransportKey(at(ap1), "", nil, 1, 0)
	k2, err2 := jobTransportKey(at(ap2), "", nil, 1, 0)
	if err1 != nil || err2 != nil || k1 == k2 || k1.Schedd != ap1 || k2.Schedd != ap2 {
		t.Errorf("transport keys %+v (%v) and %+v (%v) must differ by AP", k1, err1, k2, err2)
	}
	if got := srv.scheddForTransport(k2); got == nil || got.Name() != ap2 {
		t.Errorf("a transport keyed to ap2 dials %v", got)
	}
	if got := srv.scheddForTransport(jobsshKeyNoAP(k2)); got != nil {
		t.Errorf("a transport keyed to no AP dials %v in multi-AP mode", got)
	}

	// DAG structures.
	if dagCacheKey(routedSchedd(at(ap1)), 1, 0, "w.dag") == dagCacheKey(routedSchedd(at(ap2)), 1, 0, "w.dag") {
		t.Error("the DAG cache does not tell 1.0@ap1 from 1.0@ap2")
	}

	// Per-job watch polls: two groups on two loops, each querying its own AP.
	hub := newJobPollHub(srv.jobPolls.interval, srv.logger, func(context.Context, string) (*classad.ClassAd, error) { return nil, nil })
	g1, _ := hub.keyFor(at(ap1), "ClusterId == 1 && ProcId == 0")
	g2, _ := hub.keyFor(at(ap2), "ClusterId == 1 && ProcId == 0")
	if g1 == g2 || g1.cred == g2.cred {
		t.Errorf("poll keys %+v and %+v share a group or a loop across APs", g1, g2)
	}
	_, pollCtx := hub.keyFor(at(ap2), "ClusterId == 1 && ProcId == 0")
	if routedSchedd(pollCtx) != ap2 {
		t.Errorf("the poll context lost its AP: %q", routedSchedd(pollCtx))
	}
	single, _ := hub.keyFor(base, "true")
	if single.cred != "alice-tag" {
		t.Errorf("an unrouted poll key changed: %q", single.cred)
	}
}

func clip(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}

func jobsshKeyNoAP(k jobssh.Key) jobssh.Key {
	k.Schedd = ""
	return k
}

// A long-lived routed context (a job watch's poll loop) follows the
// registry: a new address is used, and an AP that left the collector or
// failed its trust probe is no longer reached.
func TestScheddForFollowsTheRegistry(t *testing.T) {
	aps := newActionAPs(t, ap1, ap2)
	srv := newActionServer(t, aps, nil)
	stale, _ := aps.reg.Get(ap2)
	sec, err := htcondor.NewClientSecurityConfigWithConfig(context.Background(), nil, "e30.e30.c2ln", "", 0, "CLIENT", nil)
	if err != nil {
		t.Fatal(err)
	}
	ctx := multiap.WithTarget(htcondor.WithSecurityConfig(context.Background(), sec),
		multiap.Target{Member: stale, ID: jobid.ID{Schedd: ap2, Cluster: 1}})

	moved := htcondor.NewSchedd(ap2, "<127.0.0.1:2>")
	aps.reg.Update(ap2, func(m *apregistry.Member) { m.Address, m.Schedd = "<127.0.0.1:2>", moved })
	if got := srv.scheddFor(ctx); got != moved {
		t.Errorf("after an address change scheddFor = %v, want the new handle", got)
	}
	aps.reg.Update(ap2, func(m *apregistry.Member) { m.Present = false })
	if got := srv.scheddFor(ctx); got != multiap.NoSchedd {
		t.Errorf("for an AP gone from the collector scheddFor = %v", got)
	}
	aps.reg.Update(ap2, func(m *apregistry.Member) {
		m.Present, m.Trust = true, apregistry.Trust{State: apregistry.TrustUntrusted}
	})
	if got := srv.scheddFor(ctx); got != multiap.NoSchedd {
		t.Errorf("for an untrusted AP scheddFor = %v", got)
	}
}
