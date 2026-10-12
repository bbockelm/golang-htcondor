package multiap

import (
	"context"
	"errors"
	"net/http"
	"sync/atomic"
	"testing"
	"time"

	"github.com/PelicanPlatform/classad/dbrpc"
	"github.com/bbockelm/golang-htcondor/jobid"
)

// Review gap in locate_test.go: a hub that cannot be reached is an
// error, never an empty answer -- the interactive manager reads "none"
// as "the name is free" and would create a second session of a name in
// use. Kills: FindOwn answering (nil, nil) when the hub is down.
func TestFindOwnRefusesWhenTheHubIsDown(t *testing.T) {
	hub := hubDB(t)
	hub.PutSource("ap1", StateFresh, 1)
	hub.PutJob("ap1", "alice@d", 7, 0, `JobBatchName = "htcondor-api-session-work"`)
	var down atomic.Bool
	h := NewHub(func(ctx context.Context) (*dbrpc.Client, func(), error) {
		if down.Load() {
			return nil, nil, errors.New("connection refused")
		}
		return hub.Dial(ctx)
	}, time.Hour)
	if err := h.Refresh(context.Background()); err != nil {
		t.Fatal(err)
	}
	s := &Service{Registry: newFakeRegistry("ap1"), Hub: h, Codec: jobid.Default(), Stale: StaleInclude, UIDDomain: "d"}
	if rows, _, err := s.FindOwn(context.Background(), "alice@d", "true", nil, 0); err != nil || len(rows) != 1 {
		t.Fatalf("FindOwn with the hub up = %d rows, %v", len(rows), err)
	}
	down.Store(true)
	rows, _, err := s.FindOwn(context.Background(), "alice@d", "true", nil, 0)
	if err == nil || StatusOf(err) != http.StatusServiceUnavailable {
		t.Errorf("FindOwn with the hub down = %d rows, %v; want a 503", len(rows), err)
	}
}
