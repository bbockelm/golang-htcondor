package jobwatch

import (
	"context"
	"testing"
)

// TestRegisterIsIdempotent guards against the ghost-watch leak: a blocking
// register holds the request open while it waits, so a client whose transport
// times out mid-wait is told the call failed even though the row was written,
// and its retry would otherwise create a duplicate. An identical live watch
// must coalesce.
func TestRegisterIsIdempotent(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()

	w1 := register(t, s, "alice", EventDone, ModeAll)

	// A second identical registration returns the same watch, not a new one.
	again, err := New("alice", "test", "ClusterId == 42", EventDone, "", ModeAll)
	if err != nil {
		t.Fatal(err)
	}
	got, err := s.Register(ctx, again, 0)
	if err != nil {
		t.Fatalf("Register: %v", err)
	}
	if got.ID != w1.ID {
		t.Errorf("second register returned a new watch %s; want the existing %s", got.ID, w1.ID)
	}

	live, err := s.Live(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(live) != 1 {
		t.Errorf("live watches = %d, want 1 (the retry must not leak a duplicate)", len(live))
	}
}

// A genuinely different watch (different event) is not coalesced.
func TestRegisterDistinctWatchesCoexist(t *testing.T) {
	s := testStore(t)
	register(t, s, "alice", EventDone, ModeAll)
	register(t, s, "alice", EventHeld, ModeAny)
	live, err := s.Live(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(live) != 2 {
		t.Errorf("live watches = %d, want 2 (different events are different watches)", len(live))
	}
}
