package multiap

import (
	"testing"
	"time"
)

// TestReproNeverSeenOnNewHubIsNotGone (design hazard, FAILS on the
// branch): the watch tracked ap2's 1.0 on hub A. Reads fail over to hub
// B, which reports ap2 fresh (StalenessSeconds 2, jobs stream connected,
// JobsSynced with an unchanged JobsSyncedAt) -- but B's jobs table does
// not hold 1.0 yet. htcondordb measures staleness on the syncstatus
// stream only; a jobs stream that has caught up once (Synced) can still
// be backlogged behind it. With one hub this cannot produce a verdict:
// a job seen on the hub leaves it only when the hub applies the delete.
// After a switch the job was never on B, and two of B's reads later the
// watch fires "done" for a job that is still queued (hub A, back up,
// still shows it).
func TestReproNeverSeenOnNewHubIsNotGone(t *testing.T) {
	synced := []string{"JobsSynced = true", "JobsSyncedAt = 100"}
	r := newTwoHubWatchRig(t, HubPolicy{}, func(b *testDB) {
		b.PutJob(ap1, "alice@d", 1, 0, "") // ap2's 1.0 still in B's jobs-stream backlog
		b.PutSourceAd(ap1, sourceAd(ap1, StateFresh, synced...))
		b.PutSourceAd(ap2, sourceAd(ap2, StateFresh, synced...))
	})
	r.hub.PutSourceAd(ap1, sourceAd(ap1, StateFresh, synced...))
	r.hub.PutSourceAd(ap2, sourceAd(ap2, StateFresh, synced...))
	r.pair.refresh()
	r.pass()
	if got := r.watch().Tracked; len(got) != 2 {
		t.Fatalf("tracked %+v, want 1.0 on both APs", got)
	}
	r.pair.a.down.Store(true)
	r.pair.refresh()
	r.pair.refresh()
	if r.pair.active() != hubB {
		t.Fatalf("active %q", r.pair.active())
	}
	for i := 0; i < 3; i++ {
		r.pair.clock.advance(5 * time.Minute)
		r.pair.refresh()
		if st := r.pass(); st.Fired != 0 {
			t.Fatalf("pass %d on %s fired %+v for a job hub B never held (it is still queued on hub A)", i, hubB, r.watch().Matched)
		}
	}
}
