package httpserver

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/bbockelm/golang-htcondor/webapi/issues"
)

// The issues cache holds a SHARED answer: one collection is served to
// every viewer in that scope for the next minute. These pin the two
// things that made that sharing go wrong in production.

func TestACancelledWaiterDoesNotStopTheCollection(t *testing.T) {
	// The reported failure. A page load triggers the refresh; the person
	// reloads, or the SPA changes a query key, and that request's
	// context is cancelled. If the collection is running on it, the read
	// dies halfway -- and it is the long one, the run-attempt history,
	// that is still in flight when it does.
	c := newIssueCache()
	started := make(chan struct{})
	finished := make(chan *issues.Set, 1)

	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		_, _, _ = c.get(ctx, "k", func() (*issues.Set, error) {
			close(started)
			// Stand in for a slow read. The caller goes away during it.
			time.Sleep(150 * time.Millisecond)
			set := &issues.Set{ComputedAt: time.Now(), HoldCount: 7}
			finished <- set
			return set, nil
		})
	}()

	<-started
	cancel()

	select {
	case set := <-finished:
		if set.HoldCount != 7 {
			t.Fatalf("collection produced %+v", set)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("the collection did not finish after its requester went away")
	}

	// And it landed in the cache, so the next person to ask is served
	// rather than made to start again.
	got, cached, err := c.get(context.Background(), "k", func() (*issues.Set, error) {
		t.Error("recomputed instead of using the cached answer")
		return &issues.Set{ComputedAt: time.Now()}, nil
	})
	if err != nil || !cached || got.HoldCount != 7 {
		t.Fatalf("second caller got set=%+v cached=%v err=%v", got, cached, err)
	}
}

func TestAWaiterGivesUpWhenItsOwnCallerLeaves(t *testing.T) {
	// The other side of the same coin: a request queued behind a slow
	// collection should stop waiting when its own client goes, rather
	// than hold a connection open for a page nobody is looking at.
	c := newIssueCache()
	release := make(chan struct{})
	leaderIn := make(chan struct{})
	go func() {
		_, _, _ = c.get(context.Background(), "k", func() (*issues.Set, error) {
			close(leaderIn)
			<-release
			return &issues.Set{ComputedAt: time.Now()}, nil
		})
	}()
	<-leaderIn

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		_, _, err := c.get(ctx, "k", func() (*issues.Set, error) {
			t.Error("the waiter ran its own collection instead of waiting")
			return nil, nil
		})
		done <- err
	}()
	cancel()

	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("waiter returned %v, want the cancellation", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("the waiter blocked on a collection it no longer needed")
	}
	close(release)
}

func TestAnIncompleteAnswerIsNotKeptForTheFullMinute(t *testing.T) {
	// A set missing a section is a failure, and at the full lifetime one
	// bad read put a banner in front of everyone for a minute with no
	// way to ask again.
	c := newIssueCache()
	now := time.Unix(1000, 0)
	c.now = func() time.Time { return now }

	partial := &issues.Set{ComputedAt: now, Incomplete: true, Notes: []string{"no epoch history"}}
	if _, _, err := c.get(context.Background(), "k", func() (*issues.Set, error) {
		return partial, nil
	}); err != nil {
		t.Fatal(err)
	}

	now = now.Add(issueRefreshIncomplete + time.Second)
	retried := false
	set, cached, err := c.get(context.Background(), "k", func() (*issues.Set, error) {
		retried = true
		return &issues.Set{ComputedAt: now, HoldCount: 3}, nil
	})
	if err != nil || !retried || cached || set.Incomplete {
		t.Fatalf("a failed read was not retried: retried=%v cached=%v set=%+v err=%v", retried, cached, set, err)
	}

	// A whole answer is still kept for the full minute -- the short
	// lifetime is for failures, not a blanket reduction that would undo
	// the point of caching.
	now = now.Add(issueRefreshIncomplete + time.Second)
	if _, cached, _ := c.get(context.Background(), "k", func() (*issues.Set, error) {
		t.Error("recomputed a good answer well inside its lifetime")
		return nil, nil
	}); !cached {
		t.Error("a complete answer was discarded as early as a failed one")
	}
}

type issueCtxKey struct{}

func TestCollectionOutlivesTheRequestButKeepsItsIdentity(t *testing.T) {
	// The reported bug in one assertion. The collection is shared, so it
	// must not die with whichever request happened to trigger it -- but
	// it still authenticates to the schedd as that caller, so it has to
	// keep the request's values.
	req, cancelReq := context.WithCancel(context.WithValue(context.Background(), issueCtxKey{}, "alice"))
	collect, cancel := issueCollectContext(req)
	defer cancel()

	cancelReq()

	select {
	case <-collect.Done():
		t.Fatal("the collection was cancelled with the request that triggered it")
	default:
	}
	if got := collect.Value(issueCtxKey{}); got != "alice" {
		t.Errorf("identity = %v, want it carried over; the schedd handshake needs it", got)
	}
	// Nothing else bounds it now, so it has to bound itself.
	if _, ok := collect.Deadline(); !ok {
		t.Error("the collection has no deadline and nothing left to cancel it")
	}
}
