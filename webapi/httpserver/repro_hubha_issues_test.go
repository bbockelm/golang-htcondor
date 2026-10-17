package httpserver

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"sync/atomic"
	"testing"
	"time"

	"github.com/PelicanPlatform/classad/dbrpc"

	"github.com/bbockelm/golang-htcondor/webapi/multiap"
	"github.com/bbockelm/golang-htcondor/webapi/multiap/multiaptest"
)

// TestReproIssuesMixHubsAcrossSwitch: GET /api/v1/issues is not pinned
// (handleIssues authenticates with requireAuthentication, not
// multiAPCaller), and its set cache is keyed on the scope alone. A set
// collected on hub A is served after the switch with hub B's sources
// block -- holds from one hub presented under the other's name.
func TestReproIssuesMixHubsAcrossSwitch(t *testing.T) {
	now := time.Now().Unix()
	a := multiaptest.NewHub(t)
	held := func(n int) string {
		return fmt.Sprintf("JobStatus = 5\nHoldReasonCode = 13\nHoldReason = \"failure %d\"\nEnteredCurrentStatus = %d", n, now)
	}
	a.PutJob(ap1, "alice@d", 1, 0, held(1))
	a.PutJob(ap2, "alice@d", 1, 0, held(2))
	b := multiaptest.NewHub(t)
	b.PutJob(ap1, "alice@d", 1, 0, "JobStatus = 2") // released and running, as B already knows
	b.PutJob(ap2, "alice@d", 1, 0, "JobStatus = 2")
	for _, db := range []*multiaptest.DB{a, b} {
		for _, ap := range []string{ap1, ap2} {
			db.PutSourceAd(ap, fmt.Sprintf("ScheddName = %q\nState = \"fresh\"\nJobsConnected = true\nStalenessSeconds = 1\nHistoryConnected = true", ap))
		}
	}
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
	type body struct {
		Sections []struct {
			Kind  string `json:"kind"`
			Total int    `json:"total"`
		} `json:"sections"`
		Sources *multiap.Sources `json:"sources"`
	}
	get := func() (string, int) {
		rec := doAs(t, srv, "alice", http.MethodGet, "/api/v1/issues?include_ended=false")
		var out body
		if rec.Code != http.StatusOK || json.Unmarshal(rec.Body.Bytes(), &out) != nil || out.Sources == nil {
			t.Fatalf("issues: %d %s", rec.Code, rec.Body.String())
		}
		holds := 0
		for _, s := range out.Sections {
			if s.Kind == "hold" {
				holds += s.Total
			}
		}
		return out.Sources.Hub, holds
	}
	if h, n := get(); h != "hub-a" || n != 2 {
		t.Fatalf("on hub-a: sources from %q, %d holds; want hub-a's 2", h, n)
	}
	aDown.Store(true)
	_ = hub.Refresh(context.Background())
	_ = hub.Refresh(context.Background())
	if hub.Active().Name() != "hub-b" {
		t.Fatalf("active %q", hub.Active().Name())
	}
	if h, n := get(); h == "hub-b" && n != 0 {
		t.Fatalf("after the switch: sources say %q but the answer has %d holds, which are hub-a's (hub-b has none)", h, n)
	}
}
