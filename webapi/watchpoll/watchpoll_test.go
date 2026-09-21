package watchpoll

import (
	"testing"
	"time"

	"github.com/bbockelm/golang-htcondor/webapi/jobwatch"
)

func TestClampWait(t *testing.T) {
	for _, tc := range []struct {
		name string
		raw  string
		want time.Duration
	}{
		{"absent", "", DefaultWait},
		{"honoured", "90", 90 * time.Second},
		{"capped", "99999", MaxWait},
		{"zero means no block", "0", 0},
		{"negative falls back", "-5", DefaultWait},
		{"garbage falls back", "soon", DefaultWait},
		{"padded", "  90  ", 90 * time.Second},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := ClampWait(tc.raw); got != tc.want {
				t.Fatalf("ClampWait(%q) = %v, want %v", tc.raw, got, tc.want)
			}
		})
	}
}

// poll_again is the field a dumb poller acts on, so the mapping from
// state to poll_again is the contract worth pinning: exactly one state
// means "call again".
func TestOnlyWaitingAsksToBeCalledAgain(t *testing.T) {
	if a := Waiting("w1", 30); !a.PollAgain || a.State != StateWaiting {
		t.Fatalf("Waiting = %+v", a)
	}
	if a := Gone("w1", 30); a.PollAgain || a.State != StateGone {
		t.Fatalf("Gone = %+v, and a poller told to retry a gone watch never stops", a)
	}
	now := time.Now()
	fired := From(&jobwatch.Watch{
		ID: "w1", CreatedAt: now.Add(-time.Minute), FiredAt: now, MatchedTotal: 3,
	}, 12, now)
	if fired.PollAgain || fired.State != StateFired {
		t.Fatalf("a fired watch asked to be polled again: %+v", fired)
	}
	pending := From(&jobwatch.Watch{ID: "w1", CreatedAt: now.Add(-time.Minute)}, 12, now)
	if !pending.PollAgain || pending.State != StateWaiting {
		t.Fatalf("an unfired watch did not ask to be polled again: %+v", pending)
	}
}

// WaitedSeconds is about THIS call; OpenSeconds is about the watch. They
// are different numbers and conflating them would tell a poller its
// last call blocked for the whole life of the question.
func TestWaitedAndOpenSecondsAreDistinct(t *testing.T) {
	now := time.Now()
	a := From(&jobwatch.Watch{
		ID: "w1", CreatedAt: now.Add(-10 * time.Minute), FiredAt: now.Add(-time.Minute),
	}, 30, now)
	if a.WaitedSeconds != 30 {
		t.Fatalf("waited_seconds = %d, want the 30 this call blocked", a.WaitedSeconds)
	}
	if a.OpenSeconds != 540 {
		t.Fatalf("open_seconds = %d, want the 540 between registering and firing", a.OpenSeconds)
	}
}

// A fired watch carries its outcome; an unfired one must not imply one.
func TestFromCarriesTheOutcomeOnlyWhenFired(t *testing.T) {
	now := time.Now()
	refs := []jobwatch.JobRef{{JobID: jobwatch.JobID{Cluster: 42, Proc: 1}}}
	fired := From(&jobwatch.Watch{
		ID: "w1", CreatedAt: now, FiredAt: now, Matched: refs,
		Unsatisfiable: true, Undetermined: true,
	}, 1, now)
	if len(fired.Matched) != 1 || !fired.Unsatisfiable || !fired.Undetermined {
		t.Fatalf("a fired watch lost its outcome: %+v", fired)
	}
	pending := From(&jobwatch.Watch{
		ID: "w1", CreatedAt: now, Matched: refs, Unsatisfiable: true, Undetermined: true,
	}, 1, now)
	if len(pending.Matched) != 0 || pending.Unsatisfiable || pending.Undetermined {
		t.Fatalf("an unfired watch reported an outcome it does not have: %+v", pending)
	}
}
