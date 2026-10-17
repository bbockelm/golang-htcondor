package htcondor

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"

	"github.com/PelicanPlatform/classad/classad"
)

// A placementd that moved (a restart under shared port changes its sinful
// string) is followed: the dial to the stale address fails, the resolver
// is asked again, and the command is retried once at the new address.
func TestPlacementdFollowsResolverAfterConnectFailure(t *testing.T) {
	f := newFakePlacementd(t, map[int][]*classad.ClassAd{
		PlacementQueryUsers: {
			mustAd(t, map[string]any{"UserName": "alice@example.edu", "Authorized": true}),
			summaryAd(t),
		},
	})

	var calls atomic.Int32
	p := NewPlacementd("<127.0.0.1:1>").WithResolver(func(context.Context) (string, error) {
		calls.Add(1)
		return f.addr, nil
	})
	users, err := p.QueryUsers(placementTestContext(t), "")
	if err != nil {
		t.Fatalf("QueryUsers: %v", err)
	}
	if len(users) != 1 || users[0].UserName != "alice@example.edu" {
		t.Errorf("users = %+v", users)
	}
	if calls.Load() != 1 {
		t.Errorf("resolver ran %d times, want 1", calls.Load())
	}
	if p.Address() != f.addr {
		t.Errorf("Address() = %q, want the resolved %q", p.Address(), f.addr)
	}
}

// A client created before any placementd was found resolves on first use.
func TestPlacementdResolvesWhenCreatedWithoutAddress(t *testing.T) {
	f := newFakePlacementd(t, map[int][]*classad.ClassAd{
		PlacementQueryAuthorizations: {summaryAd(t)},
	})
	p := NewPlacementd("").WithResolver(func(context.Context) (string, error) { return f.addr, nil })
	if _, err := p.QueryAuthorizations(placementTestContext(t), ""); err != nil {
		t.Fatalf("QueryAuthorizations: %v", err)
	}
}

// A daemon that stays down costs one discovery per interval, not one per
// call, and the original connection error is what the caller sees.
func TestPlacementdResolverIsThrottled(t *testing.T) {
	var calls atomic.Int32
	p := NewPlacementd("<127.0.0.1:1>").WithResolver(func(context.Context) (string, error) {
		calls.Add(1)
		return "", errors.New("not advertised")
	})
	ctx := placementTestContext(t)
	for range 3 {
		if _, err := p.QueryUsers(ctx, ""); err == nil {
			t.Fatal("QueryUsers against nothing succeeded")
		}
	}
	if calls.Load() != 1 {
		t.Errorf("resolver ran %d times in one interval, want 1", calls.Load())
	}
}
