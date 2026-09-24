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
		_, _, _ = c.get(ctx, "k", func(context.Context) (*issues.Set, error) {
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
	got, cached, err := c.get(context.Background(), "k", func(context.Context) (*issues.Set, error) {
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
		_, _, _ = c.get(context.Background(), "k", func(context.Context) (*issues.Set, error) {
			close(leaderIn)
			<-release
			return &issues.Set{ComputedAt: time.Now()}, nil
		})
	}()
	<-leaderIn

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		_, _, err := c.get(ctx, "k", func(context.Context) (*issues.Set, error) {
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
	if _, _, err := c.get(context.Background(), "k", func(context.Context) (*issues.Set, error) {
		return partial, nil
	}); err != nil {
		t.Fatal(err)
	}

	now = now.Add(issueRefreshIncomplete + time.Second)
	retried := false
	set, cached, err := c.get(context.Background(), "k", func(context.Context) (*issues.Set, error) {
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
	if _, cached, _ := c.get(context.Background(), "k", func(context.Context) (*issues.Set, error) {
		t.Error("recomputed a good answer well inside its lifetime")
		return nil, nil
	}); !cached {
		t.Error("a complete answer was discarded as early as a failed one")
	}
}

type issueCtxKey struct{}

// computeContextOf runs one collection through a cache and returns the
// context the cache handed to it, after the caller's own context has
// been cancelled underneath.
//
// Asserted at the cache rather than at the call site on purpose. The
// first version of this fix left each call site to detach its own
// context, and a test written against the cache could not see whether
// the call site had -- so the mutation that put the walk back on the
// request context passed. The cache owns the sharing, so it owns the
// rule, and this is where it can be checked.
func TestTheIssuesCacheHandsComputeAContextThatOutlivesTheRequest(t *testing.T) {
	c := newIssueCache()
	req, cancelReq := context.WithCancel(context.WithValue(context.Background(), issueCtxKey{}, "alice"))
	var got context.Context
	started, done := make(chan struct{}), make(chan struct{})

	go func() {
		_, _, _ = c.get(req, "k", func(cctx context.Context) (*issues.Set, error) {
			got = cctx
			close(started)
			<-done
			return &issues.Set{ComputedAt: time.Now()}, nil
		})
	}()
	<-started
	cancelReq()
	defer close(done)

	assertOutlivesRequest(got, t)
}

func TestTheDashboardCacheHandsComputeAContextThatOutlivesTheRequest(t *testing.T) {
	c := newDashboardCache()
	req, cancelReq := context.WithCancel(context.WithValue(context.Background(), issueCtxKey{}, "alice"))
	var got context.Context
	started, done := make(chan struct{}), make(chan struct{})

	go func() {
		_, _ = c.get(req, "k", func(wctx context.Context) (*dashboardSnapshot, error) {
			got = wctx
			close(started)
			<-done
			return &dashboardSnapshot{}, nil
		})
	}()
	<-started
	cancelReq()
	defer close(done)

	assertOutlivesRequest(got, t)
}

// assertOutlivesRequest is the whole rule in three checks.
func assertOutlivesRequest(ctx context.Context, t *testing.T) {
	t.Helper()
	select {
	case <-ctx.Done():
		t.Error("the shared work was cancelled with the request that triggered it")
	default:
	}
	// Not context.Background(): the schedd handshake authenticates as the
	// caller, so the request's values have to survive even though its
	// cancellation does not.
	if v := ctx.Value(issueCtxKey{}); v != "alice" {
		t.Errorf("identity = %v, want it carried over", v)
	}
	// Nothing else bounds it now, so it has to bound itself.
	if _, ok := ctx.Deadline(); !ok {
		t.Error("no deadline, and nothing left to cancel it")
	}
}

func TestDashboardWalkOutlivesTheViewerThatTriggeredIt(t *testing.T) {
	// The same defect, in the cache that guards the more expensive read:
	// the dashboard's queue walk is tens of thousands of ads on a busy
	// access point, shared for three minutes. One viewer navigating away
	// must not kill a walk that everybody else is queued behind.
	c := newDashboardCache()
	started := make(chan struct{})
	finished := make(chan struct{})

	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		_, _ = c.get(ctx, "k", func(context.Context) (*dashboardSnapshot, error) {
			close(started)
			time.Sleep(150 * time.Millisecond)
			close(finished)
			return &dashboardSnapshot{Total: 12}, nil
		})
	}()
	<-started
	cancel()

	select {
	case <-finished:
	case <-time.After(2 * time.Second):
		t.Fatal("the queue walk died with the viewer that triggered it")
	}

	got, err := c.get(context.Background(), "k", func(context.Context) (*dashboardSnapshot, error) {
		t.Error("walked again instead of using the snapshot the first walk produced")
		return &dashboardSnapshot{}, nil
	})
	if err != nil || got.Total != 12 {
		t.Fatalf("second viewer got %+v, err=%v", got, err)
	}
}

func TestADashboardViewerGivesUpWhenItsOwnCallerLeaves(t *testing.T) {
	c := newDashboardCache()
	release := make(chan struct{})
	leaderIn := make(chan struct{})
	go func() {
		_, _ = c.get(context.Background(), "k", func(context.Context) (*dashboardSnapshot, error) {
			close(leaderIn)
			<-release
			return &dashboardSnapshot{}, nil
		})
	}()
	<-leaderIn

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		_, err := c.get(ctx, "k", func(context.Context) (*dashboardSnapshot, error) {
			t.Error("the viewer started its own walk instead of waiting")
			return nil, nil
		})
		done <- err
	}()
	cancel()

	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("viewer returned %v, want the cancellation", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("the viewer blocked on a walk it no longer needed")
	}
	close(release)
}
