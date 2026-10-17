package multiap

// Repro tests for defects found reviewing multi-ap-hub-ha. They FAIL on
// the branch as it stands (build tag hubharepro keeps the copy green).

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/bbockelm/golang-htcondor/jobid"
)

// TestReproPageTokenAcrossHubSwitch: a /api/v1/jobs page token is a
// commit-sequence cursor (dbrpc.SeqCursor) -- a position in ONE hub's
// store. Page 1 is served by hub A; the hub fails over; page 2 is
// served by hub B with A's cursor. B's sequences are unrelated to A's,
// so the walk silently skips or repeats rows. The caller must get every
// job exactly once, or a refusal (400) -- never a short list that looks
// complete.
func TestReproPageTokenAcrossHubSwitch(t *testing.T) {
	a, b := memoryHub(t), memoryHub(t)
	// B saw other traffic first, so its commit sequence is ahead of A's.
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
	s := &Service{Registry: newFakeRegistry(ap1, ap2), Hub: p.hub, Codec: jobid.Default(), Stale: StaleInclude, UIDDomain: "d"}

	seen := map[string]int{}
	page := func(token string) *ListResult {
		res, err := s.ListJobs(context.Background(), ListRequest{User: "alice@d", Limit: 2, PageToken: token}, func(r Row) bool {
			seen[fmt.Sprintf("%d.%d", r.ID.Cluster, r.ID.Proc)]++
			return true
		})
		if err != nil {
			if StatusOf(err) == 400 {
				return nil // refused: acceptable
			}
			t.Fatal(err)
		}
		return res
	}
	res := page("")
	if p.active() != hubA || res == nil || !res.HasMore {
		t.Fatalf("page 1: active %s, res %+v", p.active(), res)
	}
	p.a.down.Store(true)
	p.clock.advance(5 * time.Second)
	p.refresh()
	p.clock.advance(5 * time.Second)
	p.refresh()
	if p.active() != hubB {
		t.Fatalf("active %q, want %s", p.active(), hubB)
	}
	token := res.NextPageToken
	for i := 0; i < 20 && token != ""; i++ {
		res = page(token)
		if res == nil {
			t.Logf("hub B refused hub A's page token (acceptable)")
			return
		}
		token = ""
		if res.HasMore {
			token = res.NextPageToken
		}
	}
	if len(seen) != 6 {
		t.Fatalf("paged across the switch: saw %d of alice's 6 jobs (%v), with no error and no refusal", len(seen), seen)
	}
	for id, n := range seen {
		if n != 1 {
			t.Fatalf("%s returned %d times", id, n)
		}
	}
}
