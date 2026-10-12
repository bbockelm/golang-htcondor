package apassign

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// fakeBackend answers from a function and counts its calls.
type fakeBackend struct {
	calls atomic.Int64
	fn    func(Request) (Assignment, error)
}

func (f *fakeBackend) Assign(_ context.Context, req Request) (Assignment, error) {
	f.calls.Add(1)
	return f.fn(req)
}

func answer(schedd string, alts ...string) *fakeBackend {
	return &fakeBackend{fn: func(Request) (Assignment, error) { return Assignment{Schedd: schedd, Alternates: alts}, nil }}
}

func failing(err error) *fakeBackend {
	return &fakeBackend{fn: func(Request) (Assignment, error) { return Assignment{}, err }}
}

// clock is a settable clock.
type clock struct {
	mu sync.Mutex
	t  time.Time
}

func newClock() *clock { return &clock{t: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)} }

func (c *clock) now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *clock) advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.t = c.t.Add(d)
}

// set is a fake AP set: ap1, ap2, ap3 (spelled in upper case to check
// canonicalisation), with unusable members by name.
type set struct {
	unusable map[string]error
}

func (s set) inSet(name string) (string, bool) {
	for _, n := range []string{"AP1", "AP2", "AP3"} {
		if strings.EqualFold(n, name) {
			return n, true
		}
	}
	return "", false
}

func (s set) usable(name string) error {
	if err, ok := s.unusable[strings.ToUpper(name)]; ok {
		return err
	}
	return nil
}

func newTestChain(t *testing.T, backends []Backend, opts Options) *Chain {
	t.Helper()
	c, err := NewChain(backends, opts)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

var alice = Request{User: "alice@example.org", Kind: KindJob}

func wantErr(t *testing.T, err error, status int, reason string) {
	t.Helper()
	if err == nil {
		t.Fatalf("got no error, want %d %s", status, reason)
	}
	if StatusOf(err) != status || ReasonOf(err) != reason {
		t.Fatalf("got %d %q (%v), want %d %q", StatusOf(err), ReasonOf(err), err, status, reason)
	}
}

func TestChainFirstAnswerWins(t *testing.T) {
	a, b, c := failing(ErrNoAnswer), answer("ap2"), answer("ap3")
	ch := newTestChain(t, []Backend{{Name: "a", Assigner: a}, {Name: "b", Assigner: b}, {Name: "c", Assigner: c}},
		Options{Default: "ap1"})
	got, err := ch.Resolve(context.Background(), alice)
	if err != nil {
		t.Fatal(err)
	}
	if got.Schedd != "ap2" || got.Source != "b" {
		t.Errorf("got %+v, want ap2 from b", got)
	}
	if a.calls.Load() != 1 || b.calls.Load() != 1 || c.calls.Load() != 0 {
		t.Errorf("calls a=%d b=%d c=%d, want 1 1 0", a.calls.Load(), b.calls.Load(), c.calls.Load())
	}
}

// A backend error is not "no answer": neither the next backend nor the
// default is consulted.
func TestChainErrorDoesNotFallThrough(t *testing.T) {
	broken, next := failing(errors.New("connection refused")), answer("ap2")
	ch := newTestChain(t, []Backend{{Name: "rest", Assigner: broken}, {Name: "mapfile", Assigner: next}},
		Options{Default: "ap1"})
	_, err := ch.Resolve(context.Background(), alice)
	wantErr(t, err, http.StatusServiceUnavailable, ReasonUnavailable)
	if next.calls.Load() != 0 {
		t.Errorf("the next backend was asked %d times after an error", next.calls.Load())
	}
}

func TestChainLastKnownGoodThen503(t *testing.T) {
	clk := newClock()
	var broken atomic.Bool
	b := &fakeBackend{fn: func(Request) (Assignment, error) {
		if broken.Load() {
			return Assignment{}, errors.New("500 Internal Server Error")
		}
		return Assignment{Schedd: "ap2", TTL: 10 * time.Second}, nil
	}}
	ch := newTestChain(t, []Backend{{Name: "rest", Assigner: b}}, Options{Now: clk.now, Stale: time.Hour, Default: "ap1"})
	if a, err := ch.Resolve(context.Background(), alice); err != nil || a.Schedd != "ap2" || a.Stale {
		t.Fatalf("first answer %+v %v", a, err)
	}
	broken.Store(true)
	clk.advance(20 * time.Second) // past the TTL
	a, err := ch.Resolve(context.Background(), alice)
	if err != nil || a.Schedd != "ap2" || !a.Stale {
		t.Fatalf("within the stale window: %+v %v, want the last known good ap2, marked stale", a, err)
	}
	// Another user has no last known good answer.
	_, err = ch.Resolve(context.Background(), Request{User: "bob@example.org", Kind: KindJob})
	wantErr(t, err, http.StatusServiceUnavailable, ReasonUnavailable)

	clk.advance(time.Hour) // past the window, measured from when ap2 was answered
	_, err = ch.Resolve(context.Background(), alice)
	wantErr(t, err, http.StatusServiceUnavailable, ReasonUnavailable)

	broken.Store(false)
	if a, err := ch.Resolve(context.Background(), alice); err != nil || a.Stale {
		t.Fatalf("after recovery: %+v %v", a, err)
	}
}

func TestChainStaleNegativeNeverCovers(t *testing.T) {
	clk := newClock()
	var broken atomic.Bool
	b := &fakeBackend{fn: func(Request) (Assignment, error) {
		if broken.Load() {
			return Assignment{}, errors.New("down")
		}
		return Assignment{Schedd: "ap2", TTL: time.Second}, nil
	}}
	ch := newTestChain(t, []Backend{{Name: "rest", Assigner: b}}, Options{Now: clk.now, Stale: -1})
	if _, err := ch.Resolve(context.Background(), alice); err != nil {
		t.Fatal(err)
	}
	broken.Store(true)
	clk.advance(2 * time.Second)
	_, err := ch.Resolve(context.Background(), alice)
	wantErr(t, err, http.StatusServiceUnavailable, ReasonUnavailable)
}

func TestChainDefaultOnlyWhenNobodyAnswers(t *testing.T) {
	ch := newTestChain(t, []Backend{{Name: "a", Assigner: failing(ErrNoAnswer)}, {Name: "b", Assigner: failing(ErrNoAnswer)}},
		Options{Default: "ap1"})
	a, err := ch.Resolve(context.Background(), alice)
	if err != nil || a.Schedd != "ap1" || a.Source != SourceDefault {
		t.Fatalf("got %+v %v, want ap1 from the default", a, err)
	}

	ch = newTestChain(t, []Backend{{Name: "a", Assigner: failing(ErrNoAnswer)}}, Options{})
	_, err = ch.Resolve(context.Background(), alice)
	wantErr(t, err, http.StatusForbidden, ReasonNoAssignment)
	if !strings.Contains(err.Error(), "no access point is assigned to you") {
		t.Errorf("message %q", err)
	}
}

func TestChainDeniedStops(t *testing.T) {
	next := answer("ap2")
	ch := newTestChain(t, []Backend{{Name: "rest", Assigner: failing(ErrDenied)}, {Name: "mapfile", Assigner: next}},
		Options{Default: "ap1"})
	_, err := ch.Resolve(context.Background(), alice)
	wantErr(t, err, http.StatusForbidden, ReasonDenied)
	if next.calls.Load() != 0 {
		t.Errorf("a backend after a denial was asked")
	}
}

func TestChainCachesForTTL(t *testing.T) {
	clk := newClock()
	b := &fakeBackend{fn: func(Request) (Assignment, error) { return Assignment{Schedd: "ap2", TTL: 30 * time.Second}, nil }}
	ch := newTestChain(t, []Backend{{Name: "rest", Assigner: b}}, Options{Now: clk.now})
	for range 3 {
		if _, err := ch.Resolve(context.Background(), alice); err != nil {
			t.Fatal(err)
		}
	}
	if b.calls.Load() != 1 {
		t.Fatalf("backend asked %d times within the TTL, want 1", b.calls.Load())
	}
	// The cache is per kind too: a DAG may be placed differently.
	if _, err := ch.Resolve(context.Background(), Request{User: alice.User, Kind: KindDAG}); err != nil {
		t.Fatal(err)
	}
	if b.calls.Load() != 2 {
		t.Fatalf("a different kind reused the job answer")
	}
	clk.advance(31 * time.Second)
	if _, err := ch.Resolve(context.Background(), alice); err != nil {
		t.Fatal(err)
	}
	if b.calls.Load() != 3 {
		t.Fatalf("backend asked %d times after the TTL, want 3", b.calls.Load())
	}
}

func TestChainTTLDefaultsAndCap(t *testing.T) {
	clk := newClock()
	b := &fakeBackend{fn: func(Request) (Assignment, error) { return Assignment{Schedd: "ap2"}, nil }}
	ch := newTestChain(t, []Backend{{Name: "rest", Assigner: b, DefaultTTL: 5 * time.Minute}}, Options{Now: clk.now})
	a, _ := ch.Resolve(context.Background(), alice)
	if a.TTL != 5*time.Minute {
		t.Errorf("TTL %v, want the backend default 5m", a.TTL)
	}
	clk.advance(4 * time.Minute)
	_, _ = ch.Resolve(context.Background(), alice)
	if b.calls.Load() != 1 {
		t.Errorf("re-asked within the backend default TTL")
	}

	forever := &fakeBackend{fn: func(Request) (Assignment, error) { return Assignment{Schedd: "ap2", TTL: 1000 * time.Hour}, nil }}
	ch = newTestChain(t, []Backend{{Name: "rest", Assigner: forever}}, Options{Now: clk.now})
	if a, _ := ch.Resolve(context.Background(), alice); a.TTL != MaxTTL {
		t.Errorf("TTL %v, want it capped at %v", a.TTL, MaxTTL)
	}
	clk.advance(MaxTTL + time.Second)
	_, _ = ch.Resolve(context.Background(), alice)
	if forever.calls.Load() != 2 {
		t.Errorf("an answer outlived MaxTTL")
	}
}

func TestChainCacheCap(t *testing.T) {
	ch := newTestChain(t, []Backend{{Name: "rest", Assigner: answer("ap2")}}, Options{CacheSize: 3})
	for i := range 10 {
		if _, err := ch.Resolve(context.Background(), Request{User: fmt.Sprintf("u%d@example.org", i), Kind: KindJob}); err != nil {
			t.Fatal(err)
		}
	}
	if n := ch.cached(); n != 3 {
		t.Errorf("%d cached answers, want the cap of 3", n)
	}
}

func TestChainTimeout(t *testing.T) {
	release := make(chan struct{})
	defer close(release)
	slow := &fakeBackend{fn: func(Request) (Assignment, error) {
		<-release // ignores its context, as a badly written backend might
		return Assignment{Schedd: "ap2"}, nil
	}}
	ch := newTestChain(t, []Backend{{Name: "rest", Assigner: slow}}, Options{Timeout: 50 * time.Millisecond, Default: "ap1"})
	start := time.Now()
	_, err := ch.Resolve(context.Background(), alice)
	wantErr(t, err, http.StatusServiceUnavailable, ReasonUnavailable)
	if el := time.Since(start); el > 2*time.Second {
		t.Errorf("took %v; the timeout is 50ms", el)
	}
}

func TestChainDefaultTimeoutIsTwoSeconds(t *testing.T) {
	ch := newTestChain(t, nil, Options{})
	if ch.opts.Timeout != 2*time.Second {
		t.Errorf("default timeout %v", ch.opts.Timeout)
	}
	if ch.opts.Stale != time.Hour {
		t.Errorf("default stale window %v", ch.opts.Stale)
	}
}

func TestChainValidation(t *testing.T) {
	s := set{}
	for _, tc := range []struct {
		name   string
		answer *fakeBackend
		want   string
		alts   []string
		status int
		reason string
	}{
		{name: "in the set, canonical spelling", answer: answer("ap2", "ap3"), want: "AP2", alts: []string{"AP3"}},
		{name: "home outside the set", answer: answer("evil.example.org"), status: http.StatusServiceUnavailable, reason: ReasonInvalid},
		{name: "alternate outside the set is dropped", answer: answer("ap2", "nowhere", "ap1", "AP2"), want: "AP2", alts: []string{"AP1"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ch := newTestChain(t, []Backend{{Name: "rest", Assigner: tc.answer}}, Options{InSet: s.inSet, Usable: s.usable})
			a, err := ch.Resolve(context.Background(), alice)
			if tc.status != 0 {
				wantErr(t, err, tc.status, tc.reason)
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if a.Schedd != tc.want || strings.Join(a.Alternates, ",") != strings.Join(tc.alts, ",") {
				t.Errorf("got %s %v, want %s %v", a.Schedd, a.Alternates, tc.want, tc.alts)
			}
		})
	}

	// The default is validated like any other answer.
	ch := newTestChain(t, nil, Options{Default: "elsewhere", InSet: s.inSet})
	_, err := ch.Resolve(context.Background(), alice)
	wantErr(t, err, http.StatusServiceUnavailable, ReasonInvalid)
}

func TestChainTarget(t *testing.T) {
	s := set{unusable: map[string]error{"AP1": errors.New("this access point does not trust this API server's tokens")}}
	ch := newTestChain(t, []Backend{{Name: "mapfile", Assigner: answer("ap2", "ap3")}},
		Options{InSet: s.inSet, Usable: s.usable})
	ctx := context.Background()

	if got, _, err := ch.Target(ctx, alice, ""); err != nil || got != "AP2" {
		t.Fatalf("home: %q %v", got, err)
	}
	if got, _, err := ch.Target(ctx, alice, "ap3"); err != nil || got != "AP3" {
		t.Fatalf("alternate: %q %v", got, err)
	}
	if got, _, err := ch.Target(ctx, alice, "Ap2"); err != nil || got != "AP2" {
		t.Fatalf("home named explicitly: %q %v", got, err)
	}
	_, _, err := ch.Target(ctx, alice, "ap1")
	wantErr(t, err, http.StatusForbidden, ReasonTargetNotAllowed)
	_, _, err = ch.Target(ctx, alice, "nowhere")
	wantErr(t, err, http.StatusForbidden, ReasonTargetNotAllowed)

	// An untrusted home AP is a 503; its alternate still takes work.
	s2 := set{unusable: map[string]error{"AP2": errors.New("not advertised")}}
	ch = newTestChain(t, []Backend{{Name: "mapfile", Assigner: answer("ap2", "ap3")}},
		Options{InSet: s2.inSet, Usable: s2.usable})
	_, _, err = ch.Target(ctx, alice, "")
	wantErr(t, err, http.StatusServiceUnavailable, ReasonTargetUnusable)
	if got, _, err := ch.Target(ctx, alice, "ap3"); err != nil || got != "AP3" {
		t.Fatalf("alternate while home is down: %q %v", got, err)
	}
}

// genBackend is a backend whose answers change with its generation, as a
// mapfile's do when edited.
type genBackend struct {
	gen    atomic.Uint64
	schedd atomic.Value
}

func (g *genBackend) Assign(context.Context, Request) (Assignment, error) {
	return Assignment{Schedd: g.schedd.Load().(string), TTL: time.Hour}, nil
}

func (g *genBackend) Generation() uint64 { return g.gen.Load() }

func TestChainNewGenerationIsNotServedFromCache(t *testing.T) {
	g := &genBackend{}
	g.schedd.Store("ap1")
	ch := newTestChain(t, []Backend{{Name: "mapfile", Assigner: g}}, Options{})
	if a, _ := ch.Resolve(context.Background(), alice); a.Schedd != "ap1" {
		t.Fatalf("got %s", a.Schedd)
	}
	g.schedd.Store("ap2")
	if a, _ := ch.Resolve(context.Background(), alice); a.Schedd != "ap1" {
		t.Fatalf("same generation, within the TTL: got %s, want the cached ap1", a.Schedd)
	}
	g.gen.Add(1)
	if a, _ := ch.Resolve(context.Background(), alice); a.Schedd != "ap2" {
		t.Fatalf("new generation: got %s, want ap2", a.Schedd)
	}
}

func TestChainRefusesUnreachableBackends(t *testing.T) {
	if _, err := NewChain([]Backend{{Name: "static", Assigner: &Static{Schedd: "ap1"}}, {Name: "mapfile", Assigner: answer("x")}},
		Options{}); err == nil || !strings.Contains(err.Error(), "never be asked") {
		t.Errorf("static before another backend: %v", err)
	}
	if _, err := NewChain([]Backend{{Name: "rest", Assigner: answer("x")}, {Name: "rest", Assigner: answer("y")}},
		Options{}); err == nil {
		t.Errorf("a backend listed twice was accepted")
	}
}

func TestChainNoUser(t *testing.T) {
	ch := newTestChain(t, []Backend{{Name: "rest", Assigner: answer("ap1")}}, Options{})
	_, err := ch.Resolve(context.Background(), Request{Kind: KindJob})
	if StatusOf(err) != http.StatusUnauthorized {
		t.Fatalf("anonymous request: %v", err)
	}
}

func TestChainBackendPanicIsAnError(t *testing.T) {
	p := &fakeBackend{fn: func(Request) (Assignment, error) { panic("boom") }}
	ch := newTestChain(t, []Backend{{Name: "rest", Assigner: p}}, Options{Default: "ap1"})
	_, err := ch.Resolve(context.Background(), alice)
	wantErr(t, err, http.StatusServiceUnavailable, ReasonUnavailable)
}

func TestStaticBackend(t *testing.T) {
	ch := newTestChain(t, []Backend{{Name: "static", Assigner: &Static{}}}, Options{})
	_, err := ch.Resolve(context.Background(), alice)
	wantErr(t, err, http.StatusForbidden, ReasonNoAssignment)

	ch = newTestChain(t, []Backend{{Name: "static", Assigner: &Static{Schedd: "ap1"}}}, Options{})
	if a, err := ch.Resolve(context.Background(), alice); err != nil || a.Schedd != "ap1" || a.Source != "static" {
		t.Fatalf("%+v %v", a, err)
	}
}

func TestParseBackends(t *testing.T) {
	got, err := ParseBackends(" Mapfile, rest  static")
	if err != nil || strings.Join(got, ",") != "mapfile,rest,static" {
		t.Fatalf("%v %v", got, err)
	}
	if _, err := ParseBackends("mapfile, ldap"); err == nil || !strings.Contains(err.Error(), `"ldap"`) {
		t.Fatalf("unknown backend: %v", err)
	}
}

func TestBuild(t *testing.T) {
	if _, err := Build(Config{Backends: []string{"mapfile"}}, Options{}); err == nil {
		t.Error("mapfile with no path was accepted")
	}
	if _, err := Build(Config{Backends: []string{"rest"}}, Options{}); err == nil {
		t.Error("rest with no URL was accepted")
	}
	if _, err := Build(Config{Backends: []string{"nis"}}, Options{}); err == nil {
		t.Error("unknown backend was accepted")
	}
	ch, err := Build(Config{Default: "ap1", Stale: 5 * time.Minute}, Options{})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Join(ch.Backends(), ",") != "static" || ch.Default() != "ap1" || ch.opts.Stale != 5*time.Minute {
		t.Errorf("built %v default %q stale %v", ch.Backends(), ch.Default(), ch.opts.Stale)
	}
}
