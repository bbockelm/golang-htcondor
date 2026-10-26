package multiap

import (
	"context"
	"fmt"
	"net/http"
	"testing"

	"github.com/PelicanPlatform/classad/dbrpc"
)

// TestJobsTokenIsBoundToItsHub: a job list token names the hub that
// issued it. Another hub refuses it with a 400 asking the caller to
// restart; back on the issuing hub it resumes, and every job comes back
// exactly once. A token from before tokens named their hub is refused
// the same way.
func TestJobsTokenIsBoundToItsHub(t *testing.T) {
	a, b := memoryHub(t), memoryHub(t)
	for c := 100; c < 140; c++ {
		b.PutJob(ap1, "bob@d", c, 0, "")
	}
	for c := 1; c <= 6; c++ {
		a.PutJob(ap1, "alice@d", c, 0, "")
		b.PutJob(ap1, "alice@d", c, 0, "")
	}
	freshSources(a)
	freshSources(b)
	p := newHubPair(t, a, b, HubPolicy{})
	p.refresh()
	s := pairService(p)
	seen := map[string]int{}
	page := func(token string) (*ListResult, error) {
		return s.ListJobs(context.Background(), ListRequest{User: "alice@d", Limit: 2, PageToken: token}, func(r Row) bool {
			seen[fmt.Sprintf("%d.%d", r.ID.Cluster, r.ID.Proc)]++
			return true
		})
	}
	res, err := page("")
	if err != nil || !res.HasMore {
		t.Fatalf("page 1: %+v %v", res, err)
	}
	p.moveTo(t, hubB)
	if _, err := page(res.NextPageToken); StatusOf(err) != http.StatusBadRequest || ReasonOf(err) != ReasonRestartPaging {
		t.Fatalf("hub A's token on hub B: err %v, want a 400 asking to restart pagination", err)
	}
	if _, err := page("db1:eyJzIjowLCJ2IjoyLCJxIjoxLCJrIjoib3BhcXVlLTcifQ"); ReasonOf(err) != ReasonRestartPaging {
		t.Fatalf("a token naming no hub: err %v, want a 400 asking to restart pagination", err)
	}
	p.moveTo(t, hubA)
	for token := res.NextPageToken; token != ""; {
		res, err = page(token)
		if err != nil {
			t.Fatalf("hub A's token back on hub A: %v", err)
		}
		token = ""
		if res.HasMore {
			token = res.NextPageToken
		}
	}
	if len(seen) != 6 {
		t.Fatalf("saw %v, want alice's 6 jobs", seen)
	}
	for id, n := range seen {
		if n != 1 {
			t.Fatalf("%s returned %d times", id, n)
		}
	}
}

// TestExpiredJobsTokenAsksForRestart: a hub that can no longer resume a
// token's cursor answers before any row, and the list reports it as a
// 400 asking the caller to restart -- not a 503 that invites retrying a
// token that will fail the same way every time.
func TestExpiredJobsTokenAsksForRestart(t *testing.T) {
	expired := fmt.Errorf("reading: %w", &dbrpc.ServerError{Msg: "cursor expired: collections: the cursor's snapshot has been reclaimed"})
	if err := hubReadError(expired); err.Status != http.StatusBadRequest || err.Reason != ReasonRestartPaging {
		t.Fatalf("expired cursor: %d %q, want 400 %q", err.Status, err.Reason, ReasonRestartPaging)
	}
	if err := hubReadError(&dbrpc.ServerError{Msg: "no such table: jobs"}); err.Status != http.StatusServiceUnavailable || err.Reason != "" {
		t.Fatalf("another server error: %d %q, want a 503", err.Status, err.Reason)
	}
}
