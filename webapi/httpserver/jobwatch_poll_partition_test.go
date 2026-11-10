package httpserver

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/PelicanPlatform/classad/classad"
	"github.com/bbockelm/cedar/security"
	htcondor "github.com/bbockelm/golang-htcondor"
)

// callerContext is a request context as the handlers build one: a
// credential tagged with who the caller is.
func callerContext(tag string) context.Context {
	ctx := htcondor.WithUserRequest(context.Background(), "test")
	if tag == "" {
		return ctx
	}
	ctx = htcondor.WithSecurityConfig(ctx, &security.SecurityConfig{SecurityTag: tag})
	return htcondor.WithAuthenticatedUser(ctx, tag)
}

// recordingHub counts polls and records the credential each one ran on.
func recordingHub(t *testing.T) (*jobPollHub, func() []string) {
	return recordingHubEvery(t, time.Hour)
}

func recordingHubEvery(t *testing.T, interval time.Duration) (*jobPollHub, func() []string) {
	t.Helper()
	var mu sync.Mutex
	var tags []string
	h := newJobPollHub(interval, testLogger(t),
		func(ctx context.Context, _ string) (*classad.ClassAd, error) {
			mu.Lock()
			defer mu.Unlock()
			cfg, ok := htcondor.GetSecurityConfigFromContext(ctx)
			if !ok {
				tags = append(tags, "<no credential>")
			} else {
				tags = append(tags, cfg.SecurityTag)
			}
			return nil, nil
		})
	return h, func() []string {
		mu.Lock()
		defer mu.Unlock()
		out := make([]string, len(tags))
		copy(out, tags)
		return out
	}
}

// Two different people watching the same job must not share a poll.
//
// They produce byte-identical constraints whenever the owner scope leaves
// the constraint unscoped -- which it does for every administrator -- so
// keying on the constraint alone put strangers on one subscription,
// running on whichever of them arrived first.
func TestTwoCallersDoNotShareAPoll(t *testing.T) {
	h, _ := recordingHub(t)

	const sameJob = "ClusterId == 5 && ProcId == 0"
	a := h.Subscribe(callerContext("alice"), sameJob)
	defer a.Close()
	b := h.Subscribe(callerContext("bob"), sameJob)
	defer b.Close()

	h.mu.Lock()
	n := len(h.groups)
	h.mu.Unlock()
	if n != 2 {
		t.Fatalf("%d poll groups for two different callers, want 2", n)
	}
}

// The same person in two browser tabs still shares one poll -- that is
// the sharing this hub exists for, and partitioning must not cost it.
func TestOneCallerInTwoTabsSharesAPoll(t *testing.T) {
	h, _ := recordingHub(t)

	const sameJob = "ClusterId == 5 && ProcId == 0"
	a := h.Subscribe(callerContext("alice"), sameJob)
	defer a.Close()
	b := h.Subscribe(callerContext("alice"), sameJob)
	defer b.Close()

	h.mu.Lock()
	n := len(h.groups)
	h.mu.Unlock()
	if n != 1 {
		t.Fatalf("%d poll groups for one caller in two tabs, want 1", n)
	}
}

// A caller with no credential to key on gets a group of its own rather
// than joining one. An empty tag is the absence of an identity; treating
// it as one would put every such caller on a single shared poll.
func TestUntaggedCallersEachGetTheirOwnPoll(t *testing.T) {
	h, _ := recordingHub(t)

	const sameJob = "ClusterId == 5 && ProcId == 0"
	a := h.Subscribe(callerContext(""), sameJob)
	defer a.Close()
	b := h.Subscribe(callerContext(""), sameJob)
	defer b.Close()

	h.mu.Lock()
	n := len(h.groups)
	h.mu.Unlock()
	if n != 2 {
		t.Fatalf("%d poll groups for two untagged callers, want 2", n)
	}
}

// The poll runs on the subscriber's credential, not on this daemon's.
//
// The query used to run on a bare context.Background(), which is not
// unauthenticated downstream -- GetSecurityConfigOrDefault falls through
// to the daemon's own configuration, a queue superuser on an access
// point. So the watch read the queue with more authority than the person
// watching had.
func TestThePollRunsOnTheSubscribersCredential(t *testing.T) {
	h, seen := recordingHub(t)

	sub := h.Subscribe(callerContext("alice"), "ClusterId == 5 && ProcId == 0")
	defer sub.Close()

	// run() polls once immediately, before the first tick.
	deadline := time.Now().Add(2 * time.Second)
	for len(seen()) == 0 && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	got := seen()
	if len(got) == 0 {
		t.Fatal("the group never polled")
	}
	if got[0] != "alice" {
		t.Fatalf("the poll ran as %q, want alice", got[0])
	}
}

// And the poll context is not the request's, or the poll would stop the
// moment the subscriber's HTTP request ended -- for every other
// subscriber sharing it too.
//
// Asserted by watching it KEEP polling after the request context is
// cancelled. An earlier version of this test only checked that the group
// was still in the map, which survives a cancelled context either way:
// the entry is removed by Close, not by the context ending. It passed
// against a deliberately broken build.
func TestThePollSurvivesItsSubscribersRequestEnding(t *testing.T) {
	h, seen := recordingHubEvery(t, 10*time.Millisecond)

	reqCtx, cancel := context.WithCancel(callerContext("alice"))
	sub := h.Subscribe(reqCtx, "ClusterId == 5 && ProcId == 0")
	defer sub.Close()
	cancel() // the HTTP request ends

	before := len(seen())
	deadline := time.Now().Add(2 * time.Second)
	for len(seen()) <= before+1 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if got := len(seen()); got <= before+1 {
		t.Fatalf("the poll stopped when its subscriber's request ended: %d polls, was %d", got, before)
	}
}

// Last one out drops the group, so an idle server runs no job queries.
func TestTheGroupGoesWhenItsLastSubscriberDoes(t *testing.T) {
	h, _ := recordingHub(t)

	const sameJob = "ClusterId == 5 && ProcId == 0"
	a := h.Subscribe(callerContext("alice"), sameJob)
	b := h.Subscribe(callerContext("alice"), sameJob)
	a.Close()

	h.mu.Lock()
	n := len(h.groups)
	h.mu.Unlock()
	if n != 1 {
		t.Fatalf("the group went away while a subscriber remained: %d groups", n)
	}

	b.Close()
	h.mu.Lock()
	n = len(h.groups)
	h.mu.Unlock()
	if n != 0 {
		t.Fatalf("%d groups left after the last subscriber closed, want 0", n)
	}
}
