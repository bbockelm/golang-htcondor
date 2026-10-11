package apregistry

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/PelicanPlatform/classad/classad"

	htcondor "github.com/bbockelm/golang-htcondor"
	"github.com/bbockelm/golang-htcondor/config"
)

// probeRecorder answers trust probes from a per-name table.
type probeRecorder struct {
	mu     sync.Mutex
	result map[string]error
	calls  map[string]int
}

func (p *probeRecorder) probe(_ context.Context, m Member) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.calls == nil {
		p.calls = map[string]int{}
	}
	p.calls[m.Name]++
	return p.result[m.Name]
}

func (p *probeRecorder) count(name string) int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.calls[name]
}

func newProbedRegistry(t *testing.T, pr *probeRecorder, now func() time.Time, ads ...*classad.ClassAd) (*Registry, *fakeCollector) {
	t.Helper()
	fc := &fakeCollector{}
	fc.set(ads, nil)
	r, err := New(fc, "true", Options{Probe: pr.probe, Now: now})
	if err != nil {
		t.Fatal(err)
	}
	if err := r.Refresh(context.Background()); err != nil {
		t.Fatal(err)
	}
	return r, fc
}

func trustOf(t *testing.T, r *Registry, name string) Trust {
	t.Helper()
	m, ok := r.Get(name)
	if !ok {
		t.Fatalf("%s not in the registry", name)
	}
	return m.Trust
}

func TestTrustProbeMarksMembers(t *testing.T) {
	pr := &probeRecorder{result: map[string]error{
		"ap2": errors.New("the access point reported the probe as nobody@elsewhere"),
	}}
	r, _ := newProbedRegistry(t, pr, nil, scheddAd(t, "ap1", "<10.0.0.1:9618>"), scheddAd(t, "ap2", "<10.0.0.2:9618>"))

	if got := trustOf(t, r, "ap1"); got.State != TrustUnknown {
		t.Fatalf("before any probe: %+v", got)
	}
	r.ProbeAll(context.Background())
	if got := trustOf(t, r, "ap1"); got.State != TrustTrusted || got.Address != "<10.0.0.1:9618>" {
		t.Errorf("ap1 = %+v, want trusted", got)
	}
	got := trustOf(t, r, "ap2")
	if got.State != TrustUntrusted || !strings.Contains(got.Reason, "nobody@elsewhere") {
		t.Errorf("ap2 = %+v, want untrusted with the probe's reason", got)
	}
	// An untrusted member is never offered to identify a caller.
	for _, m := range r.Healthy(5) {
		if m.Name == "ap2" {
			t.Errorf("Healthy offered the untrusted member %s", m.Name)
		}
	}
}

func TestTrustProbeInconclusiveKeepsState(t *testing.T) {
	pr := &probeRecorder{result: map[string]error{
		"ap1": fmt.Errorf("dial: connection refused: %w", ErrInconclusive),
	}}
	r, _ := newProbedRegistry(t, pr, nil, scheddAd(t, "ap1", "<10.0.0.1:9618>"))
	r.ProbeAll(context.Background())
	if got := trustOf(t, r, "ap1"); got.State != TrustUnknown {
		t.Errorf("unreachable member = %+v, want unknown, not untrusted", got)
	}
	// Once trusted, an unreachable probe leaves it trusted.
	pr.mu.Lock()
	pr.result["ap1"] = nil
	pr.mu.Unlock()
	r.ProbeAll(context.Background())
	pr.mu.Lock()
	pr.result["ap1"] = fmt.Errorf("timeout: %w", ErrInconclusive)
	pr.mu.Unlock()
	r.ProbeAll(context.Background())
	if got := trustOf(t, r, "ap1"); got.State != TrustTrusted {
		t.Errorf("trusted member after an inconclusive probe = %+v", got)
	}
}

// A new address is a new daemon: its trust is unknown until probed, and
// a probe result for the old address is discarded.
func TestTrustResetsOnAddressChange(t *testing.T) {
	pr := &probeRecorder{result: map[string]error{}}
	r, fc := newProbedRegistry(t, pr, nil, scheddAd(t, "ap1", "<10.0.0.1:9618>"))
	r.ProbeAll(context.Background())
	if trustOf(t, r, "ap1").State != TrustTrusted {
		t.Fatal("not trusted after a passing probe")
	}
	old, _ := r.Get("ap1")
	fc.set([]*classad.ClassAd{scheddAd(t, "ap1", "<10.0.0.9:9618>")}, nil)
	if err := r.Refresh(context.Background()); err != nil {
		t.Fatal(err)
	}
	if got := trustOf(t, r, "ap1"); got.State != TrustUnknown {
		t.Fatalf("after an address change: %+v", got)
	}
	// A late result about the old daemon must not land on the new one.
	r.finishProbe(old, errors.New("stale"), true)
	if got := trustOf(t, r, "ap1"); got.State != TrustUnknown {
		t.Errorf("a result for the old address was recorded: %+v", got)
	}
}

// Run probes members as they join and re-probes when due, without
// waiting on a probe that hangs.
func TestRunProbesInTheBackground(t *testing.T) {
	var now atomic.Int64
	now.Store(time.Unix(1000, 0).UnixNano())
	clock := func() time.Time { return time.Unix(0, now.Load()) }
	block := make(chan struct{})
	var hung atomic.Int32
	pr := &probeRecorder{result: map[string]error{}}
	probe := func(ctx context.Context, m Member) error {
		if m.Name == "hang" {
			hung.Add(1)
			select {
			case <-block:
			case <-ctx.Done():
			}
			return fmt.Errorf("hung: %w", ErrInconclusive)
		}
		return pr.probe(ctx, m)
	}
	fc := &fakeCollector{}
	fc.set([]*classad.ClassAd{scheddAd(t, "ap1", "<10.0.0.1:9618>"), scheddAd(t, "hang", "<10.0.0.3:9618>")}, nil)
	r, err := New(fc, "true", Options{Probe: probe, Now: clock, Interval: 10 * time.Millisecond, ProbeInterval: time.Hour})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	defer close(block)
	go r.Run(ctx, nil)

	deadline := time.Now().Add(5 * time.Second)
	for trustOf2(r, "ap1") != TrustTrusted {
		if time.Now().After(deadline) {
			t.Fatal("ap1 was never probed while another probe hung")
		}
		time.Sleep(5 * time.Millisecond)
	}
	// Not re-probed before ProbeInterval, however often the registry polls.
	time.Sleep(50 * time.Millisecond)
	if n := pr.count("ap1"); n != 1 {
		t.Errorf("ap1 probed %d times within its interval", n)
	}
	if n := hung.Load(); n != 1 {
		t.Errorf("the hung probe was started %d times; one in flight must not be duplicated", n)
	}
	now.Add(int64(2 * time.Hour))
	deadline = time.Now().Add(5 * time.Second)
	for pr.count("ap1") < 2 {
		if time.Now().After(deadline) {
			t.Fatal("ap1 was not re-probed once its interval passed")
		}
		time.Sleep(5 * time.Millisecond)
	}
}

func trustOf2(r *Registry, name string) string {
	m, _ := r.Get(name)
	return m.Trust.State
}

// Each member's schedd client draws on its own rate-limit budget: a
// member that spent its budget does not spend another's.
func TestMembersHaveTheirOwnRateLimitBudgets(t *testing.T) {
	cfg := config.NewEmpty()
	cfg.Set("SCHEDD_QUERY_PER_USER_RATE_LIMIT", "0.001") // one query, then refused
	fc := &fakeCollector{}
	fc.set([]*classad.ClassAd{scheddAd(t, "ap1", "<127.0.0.1:1>"), scheddAd(t, "ap2", "<127.0.0.1:1>")}, nil)
	r, err := New(fc, "true", Options{ClientConfig: cfg})
	if err != nil {
		t.Fatal(err)
	}
	if err := r.Refresh(context.Background()); err != nil {
		t.Fatal(err)
	}
	ctx := htcondor.WithAuthenticatedUser(htcondor.WithDaemonCredential(context.Background(), "test"), "alice")
	limited := func(name string) bool {
		m, _ := r.Get(name)
		_, _, err := m.Schedd.QueryWithOptions(ctx, "true", &htcondor.QueryOptions{Limit: 1})
		return err != nil && strings.Contains(err.Error(), "rate limit")
	}
	if limited("ap1") || !limited("ap1") {
		t.Fatal("ap1's budget did not run out after one query")
	}
	if limited("ap2") {
		t.Error("ap2 was refused on ap1's budget")
	}
}
