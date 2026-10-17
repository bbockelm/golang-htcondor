package httpserver

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/PelicanPlatform/classad/dbrpc"

	"github.com/bbockelm/golang-htcondor/webapi/jobwatch"
	"github.com/bbockelm/golang-htcondor/webapi/multiap"
	"github.com/bbockelm/golang-htcondor/webapi/multiap/multiaptest"
	"github.com/bbockelm/golang-htcondor/webapi/utilization"
)

// TestMultiAPTwoHubs: /api/v1/aps and /readyz name the active hub and
// its peer; reads report the hub they came from; when the active hub
// stops answering, reads, the AP view and readiness move to the other.
func TestMultiAPTwoHubs(t *testing.T) {
	a, b := multiAPHub(t), multiaptest.NewHub(t)
	b.PutJob(ap1, "alice@d", 1, 0, `Marker = "alice-ap1-1"`)
	b.PutJob(ap2, "alice@d", 1, 0, `Marker = "alice-ap2-1"`)
	b.PutSource(ap1, multiap.StateFresh, 2)
	b.PutSource(ap2, multiap.StateStale, 90)
	var aDown atomic.Bool
	hub := multiap.NewHubSet(multiap.HubOptions{Interval: time.Hour, Static: []multiap.HubSpec{
		{Name: "hub-a", Address: "<127.0.0.1:1>", Dial: func(ctx context.Context) (*dbrpc.Client, func(), error) {
			if aDown.Load() {
				return nil, nil, errors.New("connection refused")
			}
			return a.Dial(ctx)
		}},
		{Name: "hub-b", Address: "<127.0.0.1:2>", Dial: b.Dial},
	}})
	if err := hub.Refresh(context.Background()); err != nil {
		t.Fatal(err)
	}
	reg := multiaptest.NewRegistry(ap1, ap2)
	srv := newMultiAPServer(t, &multiap.Service{Registry: reg, Hub: hub, Stale: multiap.StaleInclude, UIDDomain: "d"})

	aps := func() APsResponse {
		t.Helper()
		rec := doAs(t, srv, "alice", http.MethodGet, "/api/v1/aps")
		var out APsResponse
		if rec.Code != http.StatusOK || json.Unmarshal(rec.Body.Bytes(), &out) != nil {
			t.Fatalf("/api/v1/aps: %d %s", rec.Code, rec.Body.String())
		}
		return out
	}
	got := aps()
	if got.Hub.Name != "hub-a" || !got.Hub.Active || got.Hub.FreshAPs != 2 || len(got.Hubs) != 2 ||
		!got.Hubs[0].Active || got.Hubs[1].Active || got.Hubs[1].Name != "hub-b" || got.Hubs[1].FreshAPs != 1 ||
		got.Sources.Hub != "hub-a" || got.HubSwitch != nil {
		t.Fatalf("aps with hub-a active: hub %+v hubs %+v sources %+v switch %+v", got.Hub, got.Hubs, got.Sources, got.HubSwitch)
	}
	if l := decodeList(t, doAs(t, srv, "alice", http.MethodGet, "/api/v1/jobs")); l.Sources.Hub != "hub-a" || len(l.Jobs) != 3 {
		t.Fatalf("jobs from hub-a: %d rows, sources %+v", len(l.Jobs), l.Sources)
	}

	aDown.Store(true)
	_ = hub.Refresh(context.Background())
	_ = hub.Refresh(context.Background())
	got = aps()
	if got.Hub.Name != "hub-b" || !got.Hub.Active || got.Hubs[0].Active || got.HubSwitch == nil ||
		got.HubSwitch.Reason != "unreachable" || got.HubSwitch.From != "hub-a" || got.HubSwitch.To != "hub-b" ||
		got.Sources.Hub != "hub-b" || got.Sources.Fresh != 0 || got.Sources.StateOf(ap1) != multiap.StateSettling {
		t.Fatalf("aps after hub-a stopped: hub %+v hubs %+v sources %+v switch %+v", got.Hub, got.Hubs, got.Sources, got.HubSwitch)
	}
	l := decodeList(t, doAs(t, srv, "alice", http.MethodGet, "/api/v1/jobs"))
	if l.Sources.Hub != "hub-b" || len(l.Jobs) != 2 || l.Sources.StateOf(ap2) != multiap.StateStale {
		t.Fatalf("jobs after the switch: %d rows, sources %+v; want hub-b's 2 with ap2 stale", len(l.Jobs), l.Sources)
	}

	checkTwoHubReadyz(t, srv)
}

// checkTwoHubReadyz: ready with hub-b answering for hub-a; the public
// answer counts the hubs without naming them, the detailed one names
// both and the switch.
func checkTwoHubReadyz(t *testing.T, srv *Server) {
	t.Helper()
	rec := doAs(t, srv, "", http.MethodGet, "/readyz")
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `"hubs_reachable":`) {
		t.Fatalf("readyz with one of two hubs answering: %d %s", rec.Code, rec.Body.String())
	}
	if strings.Contains(rec.Body.String(), "hub-") {
		t.Errorf("unauthenticated readyz names the hubs: %s", rec.Body.String())
	}
	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/readyz", nil)
	req.Header.Set("Authorization", "Bearer "+gateTestKey(t, srv.Handler, []string{"metrics"}))
	rec = serve(srv, req)
	var body struct {
		Hub       map[string]any `json:"hub"`
		Hubs      []APHubReach   `json:"hubs"`
		HubSwitch *APHubSwitch   `json:"hub_switch"`
	}
	if rec.Code != http.StatusOK || json.Unmarshal(rec.Body.Bytes(), &body) != nil {
		t.Fatalf("readyz with detail: %d %s", rec.Code, rec.Body.String())
	}
	if body.Hub["name"] != "hub-b" || len(body.Hubs) != 2 || body.Hubs[0].LastError == "" || !body.Hubs[1].Reachable ||
		body.HubSwitch == nil || body.HubSwitch.To != "hub-b" {
		t.Fatalf("readyz detail %s", rec.Body.String())
	}
}

// TestNewHubSetFromConfig: HTTP_API_HUB_NAME names one hub or several;
// an address goes with one; with neither, hubs are discovered.
func TestNewHubSetFromConfig(t *testing.T) {
	if got := splitHubNames(" hub-a@db, hub-b@db\thub-c@db ,"); len(got) != 3 || got[0] != "hub-a@db" || got[2] != "hub-c@db" {
		t.Fatalf("splitHubNames = %q", got)
	}
	logger := newTestLogger(t)
	for _, tc := range []struct {
		name  string
		mc    MultiAPConfig
		hubs  []string
		fails bool
	}{
		{"discovered", MultiAPConfig{}, nil, false},
		{"one named", MultiAPConfig{HubName: "hub-a@db"}, []string{"hub-a@db"}, false},
		{"one at an address", MultiAPConfig{HubAddress: "<10.0.0.1:9618>"}, []string{""}, false},
		{"two named", MultiAPConfig{HubName: "hub-b@db, hub-a@db"}, []string{"hub-a@db", "hub-b@db"}, false},
		{"two named, one address", MultiAPConfig{HubName: "hub-a@db hub-b@db", HubAddress: "<10.0.0.1:9618>"}, nil, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			hub, err := newHubSet(tc.mc, &hubLocators{}, logger)
			if tc.fails {
				if err == nil {
					t.Fatal("accepted")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			var names []string
			for _, st := range hub.Statuses() {
				names = append(names, st.Name)
			}
			if strings.Join(names, ",") != strings.Join(tc.hubs, ",") {
				t.Fatalf("hubs %q, want %q", names, tc.hubs)
			}
		})
	}
}

// TestMultiAPDashboardDeparturesFollowTheirHub: the dashboard counts the
// feed's departures only while the feed follows the hub the request
// reads. Between a switch and the feed reaching the new hub, the old
// hub's departures are not added to the new hub's counts.
func TestMultiAPDashboardDeparturesFollowTheirHub(t *testing.T) {
	a, b := dashboardHub(t), dashboardHub(t)
	var aDown atomic.Bool
	hub := multiap.NewHubSet(multiap.HubOptions{Interval: time.Hour, Static: []multiap.HubSpec{
		{Name: "hub-a", Dial: func(ctx context.Context) (*dbrpc.Client, func(), error) {
			if aDown.Load() {
				return nil, nil, errors.New("connection refused")
			}
			return a.Dial(ctx)
		}},
		{Name: "hub-b", Dial: b.Dial},
	}})
	if err := hub.Refresh(context.Background()); err != nil {
		t.Fatal(err)
	}
	srv := newMultiAPServer(t, &multiap.Service{Registry: multiaptest.NewRegistry(ap1, ap2), Hub: hub,
		Stale: multiap.StaleInclude, UIDDomain: "d"})
	// The feed follows hub A and has not moved yet: a dialer that does
	// not end its stream on a switch.
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	originA := hub.Origin(context.Background())
	go func() {
		_ = srv.jobWatchFeed.RunResumableFrom(ctx, func(ctx context.Context, _ jobwatch.Resume) (<-chan jobwatch.WatchEvent, func(), string, error) {
			dbc, closer, err := a.Dial(ctx)
			if err != nil {
				return nil, nil, "", err
			}
			head, err := dbc.WatchHead(ctx, multiap.TableJobs)
			if err != nil {
				closer()
				return nil, nil, "", err
			}
			raw, stop, err := dbc.WatchTable(ctx, multiap.TableJobs, head)
			if err != nil {
				closer()
				return nil, nil, "", err
			}
			out := make(chan jobwatch.WatchEvent, 64)
			go func() {
				defer close(out)
				for ev := range raw {
					out <- jobwatch.WatchEvent{Kind: ev.Kind, Key: ev.Key, AdText: ev.AdText, Cursor: ev.Cursor}
				}
			}()
			return out, func() { stop(); closer() }, originA, nil
		})
	}()
	waitCond(t, "the feed to follow hub A", srv.jobWatchFeed.Warm)
	a.PutJob(ap1, "alice@d", 30, 0, "JobStatus = 4")
	a.DeleteJob(ap1, 30, 0)
	waitCond(t, "A's departure", func() bool { return len(srv.jobWatchFeed.Departures("alice", time.Now().Add(-time.Hour))) == 1 })

	finished := func() int {
		t.Helper()
		rec := doAs(t, srv, "alice", http.MethodGet, "/api/v1/dashboard/activity")
		var act DashboardActivityResponse
		if rec.Code != http.StatusOK || json.Unmarshal(rec.Body.Bytes(), &act) != nil {
			t.Fatalf("activity: %d %s", rec.Code, rec.Body.String())
		}
		for _, ap := range act.APs {
			if ap.Schedd == ap1 {
				return ap.FinishedRecently
			}
		}
		t.Fatalf("no %s in %+v", ap1, act.APs)
		return 0
	}
	onA := finished()
	aDown.Store(true)
	_ = hub.Refresh(context.Background())
	_ = hub.Refresh(context.Background())
	if hub.Active().Name() != "hub-b" {
		t.Fatalf("active %q, want hub-b", hub.Active().Name())
	}
	if onB := finished(); onB != onA-1 {
		t.Fatalf("finished on %s: %d on hub-a with its departure, %d on hub-b; want one fewer, without hub-a's departure", ap1, onA, onB)
	}
}

// twoHubServer is a multi-AP server over hubs a and b, with a able to be
// stopped.
func twoHubServer(t *testing.T, a, b *multiaptest.DB) (*Server, *multiap.Hub, *atomic.Bool) {
	t.Helper()
	var aDown atomic.Bool
	hub := multiap.NewHubSet(multiap.HubOptions{Interval: time.Hour, Static: []multiap.HubSpec{
		{Name: "hub-a", Dial: func(ctx context.Context) (*dbrpc.Client, func(), error) {
			if aDown.Load() {
				return nil, nil, errors.New("connection refused")
			}
			return a.Dial(ctx)
		}},
		{Name: "hub-b", Dial: b.Dial},
	}})
	if err := hub.Refresh(context.Background()); err != nil {
		t.Fatal(err)
	}
	srv := newMultiAPServer(t, &multiap.Service{Registry: multiaptest.NewRegistry(ap1, ap2), Hub: hub,
		Stale: multiap.StaleInclude, UIDDomain: "d"})
	return srv, hub, &aDown
}

// TestMultiAPUtilizationCacheFollowsTheHub: an analysis of hub A's
// history is not served from the cache once reads move to hub B.
func TestMultiAPUtilizationCacheFollowsTheHub(t *testing.T) {
	a, b := multiaptest.NewHub(t), multiaptest.NewHub(t)
	putHubHistory(t, a, ap1, "alice@d", 10, "/home/alice/sim")
	putHubHistory(t, a, ap1, "alice@d", 11, "/home/alice/sim")
	putHubHistory(t, b, ap1, "alice@d", 10, "/home/alice/sim")
	for _, db := range []*multiaptest.DB{a, b} {
		db.PutSource(ap1, "fresh", 2)
		db.PutSource(ap2, "fresh", 2)
	}
	srv, hub, aDown := twoHubServer(t, a, b)
	jobs := func() int {
		t.Helper()
		rec := doAs(t, srv, "alice", http.MethodGet, "/api/v1/utilization")
		var resp utilization.Summary
		if rec.Code != http.StatusOK || json.Unmarshal(rec.Body.Bytes(), &resp) != nil {
			t.Fatalf("utilization: %d %s", rec.Code, rec.Body.String())
		}
		return resp.JobsConsidered
	}
	if n := jobs(); n != 2 {
		t.Fatalf("on hub-a: %d jobs, want 2", n)
	}
	aDown.Store(true)
	_ = hub.Refresh(context.Background())
	_ = hub.Refresh(context.Background())
	if n := jobs(); n != 1 {
		t.Fatalf("after the switch: %d jobs, want hub-b's 1 (hub-a's analysis was served from the cache)", n)
	}
}
