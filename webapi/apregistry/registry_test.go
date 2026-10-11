package apregistry

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/PelicanPlatform/classad/classad"

	htcondor "github.com/bbockelm/golang-htcondor"
)

type fakeCollector struct {
	mu       sync.Mutex
	ads      []*classad.ClassAd
	err      error
	calls    int
	lastType string
	lastCons string
	lastOpts *htcondor.QueryOptions
}

func (f *fakeCollector) QueryAdsWithOptions(_ context.Context, adType, constraint string, opts *htcondor.QueryOptions) ([]*classad.ClassAd, *htcondor.PageInfo, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls++
	f.lastType, f.lastCons, f.lastOpts = adType, constraint, opts
	if f.err != nil {
		return nil, nil, f.err
	}
	return f.ads, &htcondor.PageInfo{TotalReturned: len(f.ads)}, nil
}

func (f *fakeCollector) set(ads []*classad.ClassAd, err error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.ads, f.err = ads, err
}

func scheddAd(t *testing.T, name, addr string) *classad.ClassAd {
	t.Helper()
	ad, err := classad.ParseOld(fmt.Sprintf("MyType = \"Scheduler\"\nName = %q\nMyAddress = %q", name, addr))
	if err != nil {
		t.Fatal(err)
	}
	return ad
}

func TestNewRejectsEmptyConstraint(t *testing.T) {
	if _, err := New(&fakeCollector{}, " ", Options{}); err == nil {
		t.Fatal("an empty constraint must be refused: it matches every schedd")
	}
	if _, err := New(nil, "true", Options{}); err == nil {
		t.Fatal("a nil querier must be refused")
	}
}

// TestRefreshAsksForEveryAd: a zero Limit is capped at 50 by the
// collector client, which silently truncates a large AP set.
func TestRefreshAsksForEveryAd(t *testing.T) {
	fc := &fakeCollector{}
	r, err := New(fc, `regexp("^ap", Name)`, Options{})
	if err != nil {
		t.Fatal(err)
	}
	var ads []*classad.ClassAd
	for i := range 120 {
		ads = append(ads, scheddAd(t, fmt.Sprintf("ap%03d.example.org", i), fmt.Sprintf("<10.0.0.%d:9618>", i%250)))
	}
	fc.set(ads, nil)
	if err := r.Refresh(context.Background()); err != nil {
		t.Fatal(err)
	}
	if fc.lastOpts == nil || fc.lastOpts.Limit != -1 {
		t.Fatalf("Limit = %+v, want -1", fc.lastOpts)
	}
	if fc.lastType != "ScheddAd" || fc.lastCons != `regexp("^ap", Name)` {
		t.Errorf("queried %q %q", fc.lastType, fc.lastCons)
	}
	hasName, hasAddr := false, false
	for _, a := range fc.lastOpts.Projection {
		hasName = hasName || a == "Name"
		hasAddr = hasAddr || a == "MyAddress"
	}
	if !hasName || !hasAddr {
		t.Errorf("projection %v lacks Name/MyAddress", fc.lastOpts.Projection)
	}
	if got := len(r.Members()); got != 120 {
		t.Errorf("members = %d, want 120", got)
	}
}

// TestMembershipIsSticky: an AP missing from a poll keeps its address
// and is reported absent; it is never dropped.
func TestMembershipIsSticky(t *testing.T) {
	clock := time.Unix(1000, 0)
	fc := &fakeCollector{}
	r, _ := New(fc, "true", Options{Now: func() time.Time { return clock }})
	fc.set([]*classad.ClassAd{scheddAd(t, "ap1", "<1.1.1.1:1>"), scheddAd(t, "ap2", "<2.2.2.2:2>")}, nil)
	if err := r.Refresh(context.Background()); err != nil {
		t.Fatal(err)
	}

	clock = clock.Add(time.Minute)
	fc.set([]*classad.ClassAd{scheddAd(t, "ap1", "<1.1.1.9:1>")}, nil)
	if err := r.Refresh(context.Background()); err != nil {
		t.Fatal(err)
	}
	ms := r.Members()
	if len(ms) != 2 {
		t.Fatalf("members = %d, want 2 (an absent AP must not be dropped)", len(ms))
	}
	ap1, _ := r.Get("AP1")
	if !ap1.Present || ap1.Address != "<1.1.1.9:1>" || ap1.Schedd.Address() != "<1.1.1.9:1>" {
		t.Errorf("ap1 = %+v, want present at the new address", ap1)
	}
	if !ap1.AddressSince.Equal(clock) || !ap1.FirstSeen.Equal(time.Unix(1000, 0)) {
		t.Errorf("ap1 times = %+v", ap1)
	}
	ap2, ok := r.Get("ap2")
	if !ok || ap2.Present || ap2.Address != "<2.2.2.2:2>" || ap2.Schedd == nil {
		t.Errorf("ap2 = %+v, want absent with its last address kept", ap2)
	}
	if !ap2.LastSeen.Equal(time.Unix(1000, 0)) {
		t.Errorf("ap2 LastSeen = %v, want the last poll that saw it", ap2.LastSeen)
	}

	// An empty but successful poll: everything absent, nothing removed.
	fc.set(nil, nil)
	if err := r.Refresh(context.Background()); err != nil {
		t.Fatal(err)
	}
	st := r.Status()
	if st.Members != 2 || st.Present != 0 {
		t.Errorf("status after empty poll = %+v, want 2 members, 0 present", st)
	}

	// Back again.
	fc.set([]*classad.ClassAd{scheddAd(t, "ap2", "<2.2.2.2:2>")}, nil)
	_ = r.Refresh(context.Background())
	if ap2, _ := r.Get("ap2"); !ap2.Present {
		t.Error("ap2 should be present again")
	}
}

// TestQuerierErrorKeepsState: a failed poll changes nothing.
func TestQuerierErrorKeepsState(t *testing.T) {
	clock := time.Unix(1000, 0)
	fc := &fakeCollector{}
	r, _ := New(fc, "true", Options{Now: func() time.Time { return clock }})
	fc.set([]*classad.ClassAd{scheddAd(t, "ap1", "<1.1.1.1:1>")}, nil)
	_ = r.Refresh(context.Background())

	clock = clock.Add(time.Minute)
	fc.set(nil, errors.New("collector down"))
	if err := r.Refresh(context.Background()); err == nil {
		t.Fatal("want the query error")
	}
	ap1, ok := r.Get("ap1")
	if !ok || !ap1.Present || ap1.Address != "<1.1.1.1:1>" {
		t.Errorf("ap1 after a failed poll = %+v, ok=%v; want unchanged", ap1, ok)
	}
	st := r.Status()
	if st.LastError == "" || !st.LastSuccess.Equal(time.Unix(1000, 0)) || !st.LastAttempt.Equal(clock) {
		t.Errorf("status = %+v", st)
	}
}

func TestHealthyPrefersPresent(t *testing.T) {
	fc := &fakeCollector{}
	r, _ := New(fc, "true", Options{})
	fc.set([]*classad.ClassAd{scheddAd(t, "a", "<1:1>"), scheddAd(t, "b", "<2:2>"), scheddAd(t, "c", "<3:3>")}, nil)
	_ = r.Refresh(context.Background())
	fc.set([]*classad.ClassAd{scheddAd(t, "c", "<3:3>")}, nil)
	_ = r.Refresh(context.Background())

	got := r.Healthy(2)
	if len(got) != 2 || got[0].Name != "c" || got[1].Name != "a" {
		t.Errorf("Healthy(2) = %v, want [c a]", names(got))
	}
	if got := r.Healthy(5); len(got) != 3 {
		t.Errorf("Healthy(5) = %v", names(got))
	}
}

func names(ms []Member) []string {
	out := make([]string, len(ms))
	for i, m := range ms {
		out[i] = m.Name
	}
	return out
}

func TestRunPollsUntilCancelled(t *testing.T) {
	fc := &fakeCollector{}
	r, _ := New(fc, "true", Options{Interval: 5 * time.Millisecond})
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	var n int
	var mu sync.Mutex
	go func() {
		r.Run(ctx, func(error) {
			mu.Lock()
			n++
			c := n
			mu.Unlock()
			if c == 3 {
				cancel()
			}
		})
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("Run did not stop")
	}
}
