package dbmirror

import (
	"context"
	"sync/atomic"
	"testing"
	"time"

	"github.com/PelicanPlatform/classad/classad"

	htcondor "github.com/bbockelm/golang-htcondor"
)

// deadLocator is a Locator whose collector refuses, so discovery falls
// back to the stubbed status query, and whose database address refuses
// too: port 1 on loopback.
func deadLocator(t *testing.T) *Locator {
	t.Helper()
	return NewLocatorWithOptions(htcondor.NewCollector("<127.0.0.1:1>"), testConfig(t, ""), Options{Address: "<127.0.0.1:1>"})
}

// A database that restarts comes back on a new address. The cached ad
// used to be handed out for the rest of InfoTTL regardless, so for up to
// thirty seconds every read dialled the address of a process that no
// longer existed. A failed connection now sends the next Discover back
// to the source of truth.
func TestClientFailureForcesRediscovery(t *testing.T) {
	var queries atomic.Int32
	withStatusQuery(t, func(*Locator, context.Context, string) (*classad.ClassAd, error) {
		queries.Add(1)
		return statusAd("db@example.org", ""), nil
	})
	prev := rediscoverAfterDialFailure
	rediscoverAfterDialFailure = 0
	t.Cleanup(func() { rediscoverAfterDialFailure = prev })

	l := deadLocator(t)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	if _, err := l.Discover(ctx); err != nil {
		t.Fatalf("Discover: %v", err)
	}
	if _, err := l.Discover(ctx); err != nil {
		t.Fatalf("Discover: %v", err)
	}
	if n := queries.Load(); n != 1 {
		t.Fatalf("a second Discover inside InfoTTL queried again (%d queries)", n)
	}

	if _, _, _, err := l.Client(ctx); err == nil {
		t.Fatal("connected to a port nothing listens on")
	}
	if n := queries.Load(); n != 1 {
		t.Fatalf("the failed Client queried %d times; it should dial the cached ad", n)
	}
	if _, err := l.Discover(ctx); err != nil {
		t.Fatalf("Discover after the failure: %v", err)
	}
	if n := queries.Load(); n != 2 {
		t.Errorf("Discover after a failed connection reused the cached ad (%d queries, want 2)", n)
	}
	// A fresh answer is cached again.
	if _, err := l.Discover(ctx); err != nil {
		t.Fatalf("Discover: %v", err)
	}
	if n := queries.Load(); n != 2 {
		t.Errorf("the rediscovered ad was not cached (%d queries, want 2)", n)
	}
}

// The floor: a database that stays down costs at most one discovery per
// RediscoverAfterDialFailure, not one per request.
func TestClientFailureRediscoveryIsRateLimited(t *testing.T) {
	var queries atomic.Int32
	withStatusQuery(t, func(*Locator, context.Context, string) (*classad.ClassAd, error) {
		queries.Add(1)
		return statusAd("db@example.org", ""), nil
	})
	prev := rediscoverAfterDialFailure
	rediscoverAfterDialFailure = time.Hour
	t.Cleanup(func() { rediscoverAfterDialFailure = prev })

	l := deadLocator(t)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	for i := 0; i < 3; i++ {
		if _, _, _, err := l.Client(ctx); err == nil {
			t.Fatal("connected to a port nothing listens on")
		}
	}
	if n := queries.Load(); n != 1 {
		t.Errorf("three failed connections inside the floor cost %d discoveries, want 1", n)
	}
}
