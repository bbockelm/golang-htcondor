package htcondor

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// --- splitCollectorList ------------------------------------------------

func TestSplitCollectorList(t *testing.T) {
	cases := []struct {
		in   string
		want []string
	}{
		{"", nil},
		{"a", []string{"a"}},
		{"a,b", []string{"a", "b"}},
		{" a , b ", []string{"a", "b"}},
		{"a,,b", []string{"a", "b"}},
		{",a,b,", []string{"a", "b"}},
		{
			"cm-1.ospool.osg-htc.org,cm-2.ospool.osg-htc.org",
			[]string{"cm-1.ospool.osg-htc.org", "cm-2.ospool.osg-htc.org"},
		},
		// Mixed bracketed sinful + bare hostname: the top-level
		// comma still separates them; nothing inside <…> is dissected.
		{
			"host:9618,<10.0.0.1:9618?sock=collector>",
			[]string{"host:9618", "<10.0.0.1:9618?sock=collector>"},
		},
		// Commas inside the angle brackets are part of the token,
		// not separators. Catches the case where a future sinful
		// attribute carries a comma-separated value.
		{
			"<10.0.0.1:9618?alias=a,b>,host:9618",
			[]string{"<10.0.0.1:9618?alias=a,b>", "host:9618"},
		},
		// Two sinful strings, each with embedded commas, separated
		// by the one top-level comma.
		{
			"<a:1?x=1,2>,<b:2?y=3,4>",
			[]string{"<a:1?x=1,2>", "<b:2?y=3,4>"},
		},
		// Unbalanced brackets: clamp depth at zero and keep parsing.
		// The stray ">" goes into the current token but doesn't open
		// a new context; the comma after still acts as a separator.
		{
			"a>,b",
			[]string{"a>", "b"},
		},
	}
	for _, c := range cases {
		got := splitCollectorList(c.in)
		if !slices.Equal(got, c.want) {
			t.Errorf("splitCollectorList(%q) = %v; want %v", c.in, got, c.want)
		}
	}
}

func TestNewCollector_ParsesList(t *testing.T) {
	c := NewCollector("a,b ,, c")
	// NewCollector shuffles, so we can't assert exact order — but
	// the SET must round-trip cleanly.
	want := map[string]bool{"a": true, "b": true, "c": true}
	got := c.Addresses()
	if len(got) != len(want) {
		t.Fatalf("Addresses() = %v; want a permutation of %v", got, want)
	}
	for _, a := range got {
		if !want[a] {
			t.Errorf("Addresses() contained unexpected entry %q (full: %v)", a, got)
		}
	}
	if c.Address() != "a,b ,, c" {
		t.Errorf("Address() should return raw user string; got %q", c.Address())
	}
}

// TestNewCollector_Shuffles probabilistically verifies that the
// construction-time shuffle actually permutes. With 10 entries
// and 8 trials the chance of the input order coming back every
// time is 1/10!^8 — astronomically below flake territory.
func TestNewCollector_Shuffles(t *testing.T) {
	in := "a,b,c,d,e,f,g,h,i,j"
	seenDifferent := false
	for i := 0; i < 8; i++ {
		c := NewCollector(in)
		got := c.Addresses()
		// Identity check against the original input order.
		original := []string{"a", "b", "c", "d", "e", "f", "g", "h", "i", "j"}
		if !slices.Equal(got, original) {
			seenDifferent = true
			break
		}
	}
	if !seenDifferent {
		t.Errorf("NewCollector did not shuffle across 8 trials — shuffle is missing or broken")
	}
}

// TestSticky_PreferredMovesToFront verifies that after a successful
// dial, the winning address is promoted to position 0 on the next
// call to Addresses() / orderedAddrs().
func TestSticky_PreferredMovesToFront(t *testing.T) {
	c := NewCollector("a,b,c")
	all := c.Addresses()
	if len(all) != 3 {
		t.Fatalf("expected 3 addresses; got %v", all)
	}
	// Pick the back-of-list entry from whatever shuffle landed us,
	// pretend it just won a dial, and confirm it migrates to slot 0.
	target := all[2]
	c.notePreferred(target)
	got := c.Addresses()
	if got[0] != target {
		t.Errorf("preferred %q should be first; got %v", target, got)
	}
	// The non-preferred entries should still all be present.
	rest := map[string]bool{got[1]: true, got[2]: true}
	for _, a := range all {
		if a == target {
			continue
		}
		if !rest[a] {
			t.Errorf("address %q lost from order after notePreferred; have %v", a, got)
		}
	}
}

// TestSticky_DialOrderUsesPreferred drives the race helper with a
// fake connect function and asserts that on a second dial the
// previous winner is the first attempt scheduled.
func TestSticky_DialOrderUsesPreferred(t *testing.T) {
	c := NewCollector("a,b,c")
	stagger := 5 * time.Millisecond

	// First dial: force a specific winner by failing every other
	// address and stalling them so the stagger ordering gives the
	// winner a free shot.
	pickWinner := func(forceWin string) func(ctx context.Context, addr string) (*fakeConn, error) {
		return func(ctx context.Context, addr string) (*fakeConn, error) {
			if addr == forceWin {
				return &fakeConn{id: addr}, nil
			}
			<-ctx.Done()
			return nil, ctx.Err()
		}
	}

	winnerR1 := c.Addresses()[1] // arbitrary non-first pick from the shuffled order
	_, addr, err := raceDial(context.Background(), c.Addresses(), stagger, pickWinner(winnerR1))
	if err != nil {
		t.Fatalf("dial 1: %v", err)
	}
	if addr != winnerR1 {
		t.Fatalf("dial 1 winner = %q; want forced %q", addr, winnerR1)
	}
	c.notePreferred(addr)

	// Second dial: record the order in which the connect callback
	// is invoked. The first invocation must be the previous winner.
	var firstCall string
	var once sync.Once
	connectR2 := func(ctx context.Context, addr string) (*fakeConn, error) {
		once.Do(func() { firstCall = addr })
		return &fakeConn{id: addr}, nil
	}
	_, addr2, err := raceDial(context.Background(), c.Addresses(), stagger, connectR2)
	if err != nil {
		t.Fatalf("dial 2: %v", err)
	}
	if firstCall != winnerR1 {
		t.Errorf("dial 2 first attempt = %q; want previous winner %q", firstCall, winnerR1)
	}
	if addr2 != winnerR1 {
		t.Errorf("dial 2 winner = %q; want %q (sticky)", addr2, winnerR1)
	}
}

// --- raceDial: a fake dialer for hermetic timing tests ----------------

type fakeConn struct {
	id     string
	closed atomic.Bool
}

func (f *fakeConn) Close() error {
	f.closed.Store(true)
	return nil
}

func TestRaceDial_FirstSuccessWins(t *testing.T) {
	// Three addresses; second one responds instantly, first stalls
	// past stagger so the second's attempt starts and beats it.
	const stagger = 30 * time.Millisecond
	addrs := []string{"slow", "fast", "neverStarted"}
	connect := func(ctx context.Context, addr string) (*fakeConn, error) {
		switch addr {
		case "slow":
			select {
			case <-time.After(5 * time.Second):
				return &fakeConn{id: addr}, nil
			case <-ctx.Done():
				return nil, ctx.Err()
			}
		case "fast":
			return &fakeConn{id: addr}, nil
		case "neverStarted":
			// Should be cancelled before its stagger elapses.
			select {
			case <-time.After(5 * time.Second):
				return &fakeConn{id: addr}, nil
			case <-ctx.Done():
				return nil, ctx.Err()
			}
		}
		return nil, errors.New("unknown")
	}
	got, addr, err := raceDial(context.Background(), addrs, stagger, connect)
	if err != nil {
		t.Fatalf("raceDial err: %v", err)
	}
	if addr != "fast" {
		t.Errorf("winner = %q; want fast", addr)
	}
	if got == nil || got.id != "fast" {
		t.Errorf("winner conn = %+v; want fast", got)
	}
}

func TestRaceDial_StaggerOrders(t *testing.T) {
	// Two addresses; both succeed eventually but the first is delayed
	// just past the stagger. The second's later start beats the
	// first's response → the second wins.
	const stagger = 30 * time.Millisecond
	addrs := []string{"slowA", "fastB"}
	connect := func(ctx context.Context, addr string) (*fakeConn, error) {
		switch addr {
		case "slowA":
			select {
			case <-time.After(100 * time.Millisecond):
				return &fakeConn{id: addr}, nil
			case <-ctx.Done():
				return nil, ctx.Err()
			}
		case "fastB":
			// Returns immediately once started — but it can't start
			// before `stagger` due to the race scheduling.
			return &fakeConn{id: addr}, nil
		}
		return nil, errors.New("unknown")
	}
	start := time.Now()
	_, addr, err := raceDial(context.Background(), addrs, stagger, connect)
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if addr != "fastB" {
		t.Errorf("winner = %q; want fastB", addr)
	}
	elapsed := time.Since(start)
	if elapsed < stagger {
		t.Errorf("returned before stagger elapsed: %v < %v", elapsed, stagger)
	}
	if elapsed > 90*time.Millisecond {
		t.Errorf("returned later than expected: %v", elapsed)
	}
}

func TestRaceDial_AllFail(t *testing.T) {
	addrs := []string{"a", "b"}
	connect := func(ctx context.Context, addr string) (*fakeConn, error) {
		return nil, fmt.Errorf("boom-%s", addr)
	}
	_, _, err := raceDial(context.Background(), addrs, 5*time.Millisecond, connect)
	if err == nil {
		t.Fatal("expected aggregate error; got nil")
	}
	for _, a := range addrs {
		if !strings.Contains(err.Error(), a) {
			t.Errorf("aggregate err should mention %q; got %v", a, err)
		}
	}
}

func TestRaceDial_LateSuccessIsClosed(t *testing.T) {
	// First address wins; second's connect starts before the winner
	// fires (stagger is small so the slow attempt clears its
	// staggered start gate immediately) and intentionally ignores
	// cancellation. The drain goroutine must Close() the late
	// success once it eventually arrives.
	const stagger = 1 * time.Millisecond
	addrs := []string{"fast", "slow"}
	var lateConn *fakeConn
	var mu sync.Mutex
	connect := func(ctx context.Context, addr string) (*fakeConn, error) {
		if addr == "fast" {
			// Win, but not instantly — give the slow attempt time
			// to pass its stagger gate and enter its sleep.
			time.Sleep(20 * time.Millisecond)
			return &fakeConn{id: addr}, nil
		}
		// slow path: ignores cancellation entirely.
		time.Sleep(80 * time.Millisecond)
		c := &fakeConn{id: addr}
		mu.Lock()
		lateConn = c
		mu.Unlock()
		return c, nil
	}
	_, addr, err := raceDial(context.Background(), addrs, stagger, connect)
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if addr != "fast" {
		t.Fatalf("winner = %q; want fast", addr)
	}
	// Give the drain goroutine a moment to observe the late success.
	deadline := time.Now().Add(500 * time.Millisecond)
	for time.Now().Before(deadline) {
		mu.Lock()
		c := lateConn
		mu.Unlock()
		if c != nil && c.closed.Load() {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Errorf("late-arriving connection was not Close()d")
}

func TestRaceDial_EmptyAddresses(t *testing.T) {
	connect := func(ctx context.Context, addr string) (*fakeConn, error) {
		return nil, nil
	}
	_, _, err := raceDial(context.Background(), nil, time.Millisecond, connect)
	if err == nil {
		t.Errorf("empty address list should error")
	}
}

func TestRaceDial_ContextCancellationStops(t *testing.T) {
	// Cancel before any attempt finishes; we should bail with the
	// parent context's error rather than waiting forever.
	addrs := []string{"slowA", "slowB"}
	connect := func(ctx context.Context, addr string) (*fakeConn, error) {
		<-ctx.Done()
		return nil, ctx.Err()
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		_, _, err := raceDial(ctx, addrs, 5*time.Millisecond, connect)
		if err == nil {
			t.Errorf("expected error from cancellation")
		}
		close(done)
	}()
	time.Sleep(20 * time.Millisecond)
	cancel()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("raceDial did not return after parent context cancel")
	}
}

