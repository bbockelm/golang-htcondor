package jobwatch

import (
	"fmt"
	"testing"
	"time"
)

func subUpsert(cluster, proc int, status int) WatchEvent {
	return WatchEvent{
		Kind:   WatchUpsert,
		Key:    fmt.Sprintf("%d.%d", cluster, proc),
		AdText: fmt.Sprintf("ClusterId = %d\nProcId = %d\nJobStatus = %d\n", cluster, proc, status),
	}
}

func recv(t *testing.T, ch <-chan KeyChange) KeyChange {
	t.Helper()
	select {
	case c := <-ch:
		return c
	case <-time.After(2 * time.Second):
		t.Fatal("expected a change, got none")
		return KeyChange{}
	}
}

func expectQuiet(t *testing.T, ch <-chan KeyChange) {
	t.Helper()
	select {
	case c := <-ch:
		t.Fatalf("expected no change, got %+v", c)
	case <-time.After(100 * time.Millisecond):
	}
}

func TestSubscribeDeliversOnlyTheSubscribedJob(t *testing.T) {
	f := NewFeed(nil)
	ch, cancel := f.Subscribe(7, 0)
	defer cancel()

	// A different job on the same stream must not wake this subscriber.
	// The feed sees every job in the table; the filtering is the point.
	f.Apply(subUpsert(8, 0, 2))
	expectQuiet(t, ch)

	f.Apply(subUpsert(7, 0, 2))
	got := recv(t, ch)
	if got.Ad == nil {
		t.Fatalf("expected an ad, got %+v", got)
	}
	if v, _ := got.Ad.EvaluateAttrInt("JobStatus"); v != 2 {
		t.Errorf("JobStatus = %d, want 2", v)
	}
}

func TestSubscribeReportsGoneOnDelete(t *testing.T) {
	f := NewFeed(nil)
	ch, cancel := f.Subscribe(7, 0)
	defer cancel()

	// The delete carries only the storage key, so the feed has to
	// recover the job's identity from the upsert it kept. Without that
	// prior upsert there is nothing to attribute the delete to.
	f.Apply(subUpsert(7, 0, 2))
	recv(t, ch)

	f.Apply(WatchEvent{Kind: WatchDelete, Key: "7.0"})
	got := recv(t, ch)
	if !got.Gone {
		t.Fatalf("expected Gone, got %+v", got)
	}
}

func TestSubscribeDistinguishesProcsOfOneCluster(t *testing.T) {
	f := NewFeed(nil)
	ch, cancel := f.Subscribe(7, 1)
	defer cancel()

	// Same cluster, different proc. An implementation that keyed identity
	// on ClusterId alone would pass every other test in this file, since
	// they all use proc 0 -- which is what the linter noticed about the
	// helper before this test existed.
	f.Apply(subUpsert(7, 0, 2))
	expectQuiet(t, ch)

	f.Apply(subUpsert(7, 1, 2))
	if got := recv(t, ch); got.Ad == nil {
		t.Fatalf("expected the ad for 7.1, got %+v", got)
	}
}

func TestSubscribeIgnoresDeleteOfAnotherJob(t *testing.T) {
	f := NewFeed(nil)
	ch, cancel := f.Subscribe(7, 0)
	defer cancel()

	f.Apply(subUpsert(7, 0, 2))
	recv(t, ch)
	f.Apply(subUpsert(8, 0, 2))
	f.Apply(WatchEvent{Kind: WatchDelete, Key: "8.0"})
	expectQuiet(t, ch)
}

func TestResetMarksSubscribersStale(t *testing.T) {
	f := NewFeed(nil)
	ch, cancel := f.Subscribe(7, 0)
	defer cancel()

	f.Apply(WatchEvent{Kind: WatchReset})
	if got := recv(t, ch); !got.Stale {
		t.Fatalf("a replay must mark the view stale, got %+v", got)
	}
}

func TestGoingColdMarksSubscribersStale(t *testing.T) {
	f := NewFeed(nil)
	f.setWarm(true)
	ch, cancel := f.Subscribe(7, 0)
	defer cancel()

	// The case this exists for: a subscriber cannot tell a disconnected
	// feed from a quiet one, and would otherwise wait forever on a job
	// that has long since changed.
	f.setWarm(false)
	if got := recv(t, ch); !got.Stale {
		t.Fatalf("losing the stream must mark the view stale, got %+v", got)
	}
}

func TestStaleSurvivesBeingSuperseded(t *testing.T) {
	f := NewFeed(nil)
	f.setWarm(true)
	ch, cancel := f.Subscribe(7, 0)
	defer cancel()

	// One slot, and nobody reading it. A later update replaces the
	// pending change, but it must not swallow the fact that the view
	// went stale: that is the one signal a newer ad does not answer,
	// because it says "go and re-read", not "here is the new state".
	f.setWarm(false)
	f.Apply(subUpsert(7, 0, 2))

	got := recv(t, ch)
	if !got.Stale {
		t.Fatalf("a superseding update must not drop the stale flag, got %+v", got)
	}
}

func TestCancelStopsDelivery(t *testing.T) {
	f := NewFeed(nil)
	ch, cancel := f.Subscribe(7, 0)
	cancel()
	// Cancel closes the channel; a second cancel must not panic.
	cancel()

	f.Apply(subUpsert(7, 0, 2))
	if _, open := <-ch; open {
		t.Fatal("expected the channel to be closed after cancel")
	}
}

func TestSubscribersDoNotStallTheFeed(t *testing.T) {
	f := NewFeed(nil)
	_, cancel := f.Subscribe(7, 0)
	defer cancel()

	// Nobody is reading. The feed is shared with the MCP evaluator, so
	// applying events must stay non-blocking however far behind a
	// subscriber falls.
	done := make(chan struct{})
	go func() {
		for i := 0; i < 1000; i++ {
			f.Apply(subUpsert(7, 0, 1))
		}
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("Apply blocked on an unread subscriber")
	}
}
