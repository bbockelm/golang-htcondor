package httpserver

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/PelicanPlatform/classad/classad"
	htcondor "github.com/bbockelm/golang-htcondor"
	"github.com/bbockelm/golang-htcondor/webapi/jobwatch"
)

// openStream starts a GET of path on srv and returns its status and
// headers once they arrive; the body stays open until cancel.
func openStream(t *testing.T, srv *httptest.Server, path string, auth func(*http.Request)) (int, http.Header, context.CancelFunc) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, srv.URL+path, nil)
	if err != nil {
		cancel()
		t.Fatal(err)
	}
	auth(req)
	resp, err := srv.Client().Do(req) //nolint:bodyclose // closed by the returned cancel, once the stream is done with
	if err != nil {
		cancel()
		t.Fatalf("GET %s: %v", path, err)
	}
	return resp.StatusCode, resp.Header, func() {
		cancel()
		_ = resp.Body.Close()
	}
}

// One identity holds at most defaultMaxStreamsPerUser streams. Past
// that, opening another is refused with 429 -- and refused before it
// costs the schedd a query. Another identity is unaffected, and a stream
// that ends gives its slot back.
func TestJobWatchStreamsAreCappedPerIdentity(t *testing.T) {
	f := twoOwnerScheddServer(t)
	srv := httptest.NewServer(f.s)
	defer srv.Close()
	alice, bob := f.bearer(t, "alice"), f.bearer(t, "bob")

	var cancels []context.CancelFunc
	defer func() {
		for _, c := range cancels {
			c()
		}
	}()
	refused := 0
	for i := 0; i < 50; i++ {
		status, header, cancel := openStream(t, srv, "/api/v1/jobs/1.0/watch", alice)
		cancels = append(cancels, cancel)
		switch {
		case i < defaultMaxStreamsPerUser && status != http.StatusOK:
			t.Fatalf("watch %d as alice: status %d, want 200", i+1, status)
		case i >= defaultMaxStreamsPerUser && status != http.StatusTooManyRequests:
			t.Fatalf("watch %d as alice: status %d, want 429", i+1, status)
		case status == http.StatusTooManyRequests:
			refused++
			if header.Get("Retry-After") == "" {
				t.Errorf("a refused stream carries no Retry-After")
			}
		}
	}
	if refused != 50-defaultMaxStreamsPerUser {
		t.Fatalf("%d watches refused, want %d", refused, 50-defaultMaxStreamsPerUser)
	}
	queries, _ := f.schedd.JobQueries()

	// Bob has his own budget.
	status, _, cancel := openStream(t, srv, "/api/v1/jobs/2.0/watch", bob)
	cancels = append(cancels, cancel)
	if status != http.StatusOK {
		t.Fatalf("bob's watch: status %d, want 200 -- alice's streams spent his budget", status)
	}
	if after, _ := f.schedd.JobQueries(); after == queries {
		t.Fatalf("bob's admitted watch did not reach the schedd; the refusal count above proves nothing")
	}

	// Ending one of alice's streams frees its slot. The handler notices
	// the hang-up asynchronously, so retry until it has.
	cancels[0]()
	deadline := time.Now().Add(10 * time.Second)
	for {
		status, _, cancel := openStream(t, srv, "/api/v1/jobs/1.0/watch", alice)
		cancels = append(cancels, cancel)
		if status == http.StatusOK {
			break
		}
		cancel()
		if time.Now().After(deadline) {
			t.Fatalf("a closed stream never gave its slot back: status %d", status)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// The limiter's own arithmetic: the global cap binds across identities,
// and releasing is idempotent and leaves no entry behind.
func TestStreamLimiterCaps(t *testing.T) {
	l := newStreamLimiter(2, 3)
	a1, ok1 := l.acquire("a")
	_, ok2 := l.acquire("a")
	_, ok3 := l.acquire("a")
	if !ok1 || !ok2 || ok3 {
		t.Fatalf("per-identity cap: got %v %v %v, want true true false", ok1, ok2, ok3)
	}
	_, okb := l.acquire("b")
	_, okc := l.acquire("c")
	if !okb || okc {
		t.Fatalf("global cap: b=%v c=%v, want true false", okb, okc)
	}
	a1()
	a1()
	if _, ok := l.acquire("c"); !ok {
		t.Fatal("a released slot was not reusable")
	}
	l.mu.Lock()
	total, perA := l.total, l.perUser["a"]
	l.mu.Unlock()
	if total != 3 || perA != 1 {
		t.Fatalf("after a double release: total=%d a=%d, want 3 and 1", total, perA)
	}
}

// coalescingHub records every query it is asked, single or coalesced,
// and answers from ads.
func coalescingHub(t *testing.T, ads []*classad.ClassAd) (*jobPollHub, func() []string) {
	t.Helper()
	var mu sync.Mutex
	var seen []string
	match := func(constraint string) []*classad.ClassAd {
		expr, err := classad.ParseExpr(constraint)
		if err != nil {
			t.Errorf("unparseable constraint %q: %v", constraint, err)
			return nil
		}
		var out []*classad.ClassAd
		for _, ad := range ads {
			if ok, _ := expr.Eval(ad).BoolValue(); ok {
				out = append(out, ad)
			}
		}
		return out
	}
	record := func(ctx context.Context, kind, constraint string) {
		mu.Lock()
		defer mu.Unlock()
		cfg, _ := htcondor.GetSecurityConfigFromContext(ctx)
		seen = append(seen, kind+" "+cfg.SecurityTag+" "+constraint)
	}
	h := newJobPollHub(time.Hour, testLogger(t),
		func(ctx context.Context, constraint string) (*classad.ClassAd, error) {
			record(ctx, "one", constraint)
			if m := match(constraint); len(m) > 0 {
				return m[0], nil
			}
			return nil, nil
		})
	h.queryMany = func(ctx context.Context, constraint string, limit int) ([]*classad.ClassAd, error) {
		record(ctx, "many", constraint)
		m := match(constraint)
		if len(m) > limit {
			m = m[:limit]
		}
		return m, nil
	}
	return h, func() []string {
		mu.Lock()
		defer mu.Unlock()
		return slices.Clone(seen)
	}
}

// One caller watching sixteen jobs costs one query per tick, not
// sixteen, and each watch still gets its own job's ad -- or, for a job
// that has left the queue, none. Another caller's watch is not folded
// into that query: it runs on their credential, separately.
func TestOneCallersWatchesShareOneQueryPerTick(t *testing.T) {
	const n = defaultMaxStreamsPerUser
	var ads []*classad.ClassAd
	for i := 1; i < n; i++ { // job n is gone
		ads = append(ads, mustAd(t, fmt.Sprintf("[ClusterId = %d; ProcId = 0; Owner = \"alice\"]", i)))
	}
	ads = append(ads, mustAd(t, "[ClusterId = 99; ProcId = 0; Owner = \"bob\"]"))
	h, seen := coalescingHub(t, ads)

	job := func(c int) string { return fmt.Sprintf("ClusterId == %d && ProcId == 0", c) }
	subs := []jobWatchSource{h.Subscribe(callerContext("alice"), job(1))}
	defer func() {
		for _, s := range subs {
			s.Close()
		}
	}()
	// The loop's first poll is immediate; let it land before the rest
	// subscribe, so the tick below is the only one counted.
	deadline := time.Now().Add(5 * time.Second)
	for len(seen()) == 0 {
		if time.Now().After(deadline) {
			t.Fatal("the first poll never ran")
		}
		time.Sleep(time.Millisecond)
	}
	<-subs[0].Updates()
	for c := 2; c <= n; c++ {
		subs = append(subs, h.Subscribe(callerContext("alice"), job(c)))
	}
	bobSub := h.Subscribe(callerContext("bob"), job(99))
	defer bobSub.Close()

	before := len(seen())
	h.mu.Lock()
	cp := h.groups[pollKey{cred: "alice", constraint: job(1)}].poll
	h.mu.Unlock()
	cp.pollOnce(context.Background())

	// Bob's own loop polls on its own schedule; only alice's count.
	var got []string
	for _, q := range seen()[before:] {
		if strings.Contains(q, " alice ") {
			got = append(got, q)
		}
	}
	if len(got) != 1 || !strings.HasPrefix(got[0], "many alice ") {
		t.Fatalf("one tick of alice's %d watches ran %d queries: %q", n, len(got), got)
	}
	for c := 1; c <= n; c++ {
		if !strings.Contains(got[0], "("+job(c)+")") {
			t.Errorf("the coalesced query leaves out job %d", c)
		}
	}
	if strings.Contains(got[0], "99") {
		t.Errorf("bob's watch was folded into alice's query: %s", got[0])
	}

	for i, s := range subs {
		c := i + 1
		select {
		case u := <-s.Updates():
			if c == n {
				if u.Ad != nil {
					t.Errorf("job %d is gone, but its watch got an ad", c)
				}
				continue
			}
			if u.Ad == nil {
				t.Errorf("job %d's watch was told it is gone", c)
				continue
			}
			if got, _ := u.Ad.EvaluateAttrInt("ClusterId"); got != int64(c) {
				t.Errorf("job %d's watch got job %d's ad", c, got)
			}
		default:
			t.Errorf("job %d's watch got no update from the tick", c)
		}
	}
}

// Every long-lived stream draws on the same per-identity budget: with
// alice's spent, each refuses her with 429 -- and none refuses bob,
// whatever else it then tells him on a server without a collector,
// mirror or Jupyter instance.
func TestEveryStreamEndpointIsCapped(t *testing.T) {
	f := twoOwnerScheddServer(t)
	alice, bob := f.bearer(t, "alice"), f.bearer(t, "bob")
	limits := f.s.streamLimits()
	for i := 0; i < defaultMaxStreamsPerUser; i++ {
		release, ok := limits.acquire("alice@test.domain")
		if !ok {
			t.Fatalf("filling alice's budget: slot %d refused", i+1)
		}
		defer release()
	}

	for _, path := range []string{
		"/api/v1/collector/watch",
		"/api/v1/jobs/watch",
		"/api/v1/jobs/1.0/watch",
		"/api/v1/dashboard/activity/stream",
		"/api/v1/jupyter/instances/jl-0001/events",
	} {
		t.Run(path, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			defer cancel()
			if w := f.doCtx(ctx, t, path, alice); w.Code != http.StatusTooManyRequests {
				t.Errorf("alice over her budget: status %d, want 429: %.200s", w.Code, w.Body.String())
			}
			ctx, cancel = context.WithTimeout(context.Background(), 200*time.Millisecond)
			defer cancel()
			if w := f.doCtx(ctx, t, path, bob); w.Code == http.StatusTooManyRequests {
				t.Errorf("bob was refused on alice's budget: %.200s", w.Body.String())
			}
		})
	}
}

// The share-URL wait holds a connection for its whole wait too, and is
// counted against the watch's owner apart from their own sessions: a
// spent share budget refuses the URL, and leaves the owner's sessions
// alone.
func TestSharedWatchIsCapped(t *testing.T) {
	h, store := watchShareHandler(t)
	w := registerWatch(t, store)
	if err := store.Fire(context.Background(), w.ID, jobwatch.Outcome{Fires: true, Satisfied: 1}, time.Now()); err != nil {
		t.Fatalf("Fire: %v", err)
	}
	tok := watchToken(t, h, "alice", w.ID, time.Now().Add(time.Hour))
	for i := 0; i < defaultMaxStreamsPerUser; i++ {
		release, ok := h.streamLimits().acquire("share:alice")
		if !ok {
			t.Fatalf("filling the share budget: slot %d refused", i+1)
		}
		defer release()
	}

	rec := httptest.NewRecorder()
	h.handleSharedWatch(rec, httptest.NewRequestWithContext(context.Background(), http.MethodGet,
		"/api/v1/share/watch?t="+tok+"&wait=1", nil))
	if rec.Code != http.StatusTooManyRequests {
		t.Fatalf("a share URL over its owner's budget: status %d, want 429", rec.Code)
	}
	if _, ok := h.streamLimits().acquire("alice"); !ok {
		t.Fatal("share URLs spent their owner's own session budget")
	}
}
