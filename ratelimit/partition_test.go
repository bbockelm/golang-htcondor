package ratelimit

import (
	"testing"
)

// A hot schedd exhausts its own budget, never another's: the global and
// the per-user limit are both per partition.
func TestSchedulerPartitionsAreIndependent(t *testing.T) {
	// Global 1/s (burst 2), per user 1/s (burst 2).
	m := NewManager(1, 1, 0, 0)

	// alice exhausts ap1's budget for her...
	for i := 0; i < 2; i++ {
		if err := m.AllowScheddFor("ap1", "alice"); err != nil {
			t.Fatalf("ap1 request %d: %v", i, err)
		}
	}
	if err := m.AllowScheddFor("ap1", "alice"); err == nil {
		t.Fatal("ap1's budget did not run out")
	}
	// ...and ap1's global budget with it: bob on ap1 is refused too.
	if err := m.AllowScheddFor("ap1", "bob"); err == nil {
		t.Fatal("ap1's global limit did not apply to another user")
	}
	// ap2 is untouched, for alice and for its own global budget.
	for i := 0; i < 2; i++ {
		if err := m.AllowScheddFor("ap2", "alice"); err != nil {
			t.Fatalf("ap2 request %d after ap1 ran dry: %v", i, err)
		}
	}
	// The shared (unkeyed) budget is separate from every partition.
	if err := m.AllowSchedd("alice"); err != nil {
		t.Fatalf("shared budget spent by keyed traffic: %v", err)
	}
}

// The empty key is the shared limiter, so a client without a key keeps
// today's behaviour exactly.
func TestSchedulerEmptyKeyIsShared(t *testing.T) {
	m := NewManager(0, 1, 0, 0) // per user 1/s, burst 2
	if err := m.AllowSchedd("alice"); err != nil {
		t.Fatal(err)
	}
	if err := m.AllowScheddFor("", "alice"); err != nil {
		t.Fatal(err)
	}
	if err := m.AllowScheddFor("", "alice"); err == nil {
		t.Fatal("the empty key drew on a budget other than the shared one")
	}
	if err := m.AllowSchedd("alice"); err == nil {
		t.Fatal("the shared budget was not spent by empty-key traffic")
	}
	m.ResetAll()
	if err := m.AllowScheddFor("ap1", "alice"); err != nil {
		t.Fatalf("after ResetAll: %v", err)
	}
}
