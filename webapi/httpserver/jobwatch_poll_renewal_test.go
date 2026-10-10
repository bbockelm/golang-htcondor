package httpserver

import (
	"context"
	"testing"
	"time"

	"github.com/PelicanPlatform/classad/classad"
	"github.com/bbockelm/cedar/security"
	htcondor "github.com/bbockelm/golang-htcondor"
)

// A watch poll outlives the request that started it, and the token that
// request carried. Once that token has expired, a poll that only copied it
// fails -- and does not authenticate as this daemon instead. A poll that
// carried the credential's renewer mints it again and goes on as the
// caller.
func TestJobWatchPollRenewsTheCallersCredential(t *testing.T) {
	pool := newTokenPool(t)
	schedd := htcondor.NewSchedd("fake", pool.serve(t, nil)).WithConfig(pool.cfg)

	type result struct {
		user string
		err  error
	}
	results := make(chan result, 64)
	hub := newJobPollHub(20*time.Millisecond, nil, func(ctx context.Context, _ string) (*classad.ClassAd, error) {
		res, err := schedd.Ping(ctx)
		if err != nil {
			results <- result{err: err}
			return nil, err
		}
		results <- result{user: res.User}
		ad := classad.New()
		_ = ad.Set("User", res.User)
		return ad, nil
	})

	callerConfig := func(ttl time.Duration) *security.SecurityConfig {
		t.Helper()
		sc, err := configureSecurityForToken(pool.cfg, pool.mint(t, "alice@pool.example", ttl, nil), security.NewSessionCache(), false)
		if err != nil {
			t.Fatal(err)
		}
		sc.SecurityTag = "alice"
		return sc
	}
	request := func(sc *security.SecurityConfig, renew htcondor.SecurityConfigRenewer) context.Context {
		ctx := htcondor.WithUserRequest(context.Background(), "test request")
		ctx = htcondor.WithAuthenticatedUser(ctx, "alice@pool.example")
		return htcondor.WithRenewableSecurityConfig(ctx, sc, renew)
	}
	// poll subscribes and returns the first successful tick, or the last
	// failure if none succeeds within a few ticks.
	poll := func(ctx context.Context) result {
		t.Helper()
		src := hub.Subscribe(ctx, "ClusterId == 1")
		defer src.Close()
		var last result
		for i := 0; i < 5; i++ {
			select {
			case last = <-results:
				if last.err == nil {
					return last
				}
			case <-time.After(10 * time.Second):
				t.Fatal("the poll never ran")
			}
		}
		return last
	}

	// The token expired a second ago and nothing can renew it.
	r := poll(request(callerConfig(-time.Second), nil))
	if r.err == nil {
		t.Fatalf("a poll on an expired token succeeded as %q", r.user)
	}

	// The same expired token, carried with the renewer it was minted with.
	renew := func(context.Context) (*security.SecurityConfig, error) { return callerConfig(time.Minute), nil }
	r = poll(request(callerConfig(-time.Second), renew))
	if r.err != nil {
		t.Fatalf("a poll on a renewable credential failed: %v", r.err)
	}
	if r.user != "alice@pool.example" {
		t.Errorf("the renewed poll ran as %q, want alice@pool.example", r.user)
	}
}
