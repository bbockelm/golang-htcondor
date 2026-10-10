// Package apregistry tracks the access points a multi-AP htcondor-api
// serves: the schedds whose collector ads match HTTP_API_SCHEDD_CONSTRAINT.
//
// Membership is sticky. A schedd ad missing from one collector poll is a
// restart, a network blip or a collector failover far more often than a
// decommissioning, so a member that drops out of a poll keeps its last
// address and is reported as not present -- it is never removed. A failed
// poll changes nothing at all: "the collector did not answer" is not
// "there are no access points".
package apregistry

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/PelicanPlatform/classad/classad"

	htcondor "github.com/bbockelm/golang-htcondor"
	"github.com/bbockelm/golang-htcondor/config"
)

// DefaultInterval is how often Run re-queries the collector.
const DefaultInterval = 60 * time.Second

// pollTimeout bounds one collector query.
const pollTimeout = 20 * time.Second

// Querier is the collector query the registry needs. *htcondor.Collector
// satisfies it; tests substitute a fake.
type Querier interface {
	QueryAdsWithOptions(ctx context.Context, adType string, constraint string, opts *htcondor.QueryOptions) ([]*classad.ClassAd, *htcondor.PageInfo, error)
}

// Member is one access point.
type Member struct {
	// Name is the schedd's Name attribute, the AP's identity everywhere.
	Name string
	// Address is the last address the collector advertised for it.
	Address string
	// Schedd is a handle on Address. Replaced (not mutated) when the
	// address changes, so a caller holding one keeps a consistent handle.
	Schedd *htcondor.Schedd
	// Present is whether the AP's ad was in the last successful poll.
	Present bool
	// FirstSeen is when the AP first appeared.
	FirstSeen time.Time
	// LastSeen is the last successful poll that included the AP.
	LastSeen time.Time
	// LastConfirmed is when the collector last vouched for Address: the
	// same as LastSeen, kept separately so a reader does not have to know
	// that.
	LastConfirmed time.Time
	// AddressSince is when Address last changed.
	AddressSince time.Time
	// Trust is the outcome of the last trust probe; see Options.Probe.
	Trust Trust
}

// Trust states.
const (
	// TrustUnknown: not probed yet (or no probe is configured). Actions
	// are attempted; the schedd decides.
	TrustUnknown = "unknown"
	// TrustTrusted: the AP accepted this server's token and reported
	// the identity it was minted for.
	TrustTrusted = "trusted"
	// TrustUntrusted: the AP refused this server's token, or mapped it
	// to some other identity. Actions on it fail fast.
	TrustUntrusted = "untrusted"
)

// Trust is what the last probe of a member found.
type Trust struct {
	State     string
	Reason    string
	CheckedAt time.Time
	// Address is the address that was probed. A result for an address
	// the member no longer has is discarded.
	Address string
}

// Untrusted reports whether the member failed its last probe.
func (m Member) Untrusted() bool { return m.Trust.State == TrustUntrusted }

// Status describes the registry's own polling.
type Status struct {
	Constraint  string
	Members     int
	Present     int
	LastAttempt time.Time
	LastSuccess time.Time
	LastError   string
}

// DefaultProbeInterval is how often a member's trust is re-probed.
const DefaultProbeInterval = 10 * time.Minute

// probeTimeout bounds one trust probe.
const probeTimeout = 20 * time.Second

// maxConcurrentProbes bounds the probes in flight, so fifty members
// joining at once (the first poll) do not open fifty handshakes.
const maxConcurrentProbes = 8

// ProbeFunc checks that a member trusts this server's tokens. A nil
// error marks it trusted; an error marks it untrusted with the error's
// text as the reason -- unless it wraps ErrInconclusive.
type ProbeFunc func(ctx context.Context, m Member) error

// ErrInconclusive is wrapped by a probe error that says nothing about
// trust: the member did not answer at all. An unreachable AP is not an
// AP that refuses this server's tokens, and calling it untrusted would
// put a misleading reason on every action until the next probe. The
// member keeps its previous state and is probed again at the next poll.
var ErrInconclusive = errors.New("trust probe inconclusive")

// Registry is the AP set. Safe for concurrent use.
type Registry struct {
	q          Querier
	constraint string
	interval   time.Duration
	now        func() time.Time
	clientCfg  *config.Config

	probe         ProbeFunc
	probeInterval time.Duration
	probeSlots    chan struct{}
	probing       map[string]bool // lower-cased names with a probe in flight; under mu

	mu          sync.RWMutex
	members     map[string]*Member // keyed by lower-cased name
	lastAttempt time.Time
	lastSuccess time.Time
	lastErr     string
}

// newSchedd builds a member's schedd client from the registry's client
// config. Each member gets its own partition of the query rate limiter,
// so one busy AP cannot spend the others' budget.
func (r *Registry) newSchedd(name, addr string) *htcondor.Schedd {
	return htcondor.NewSchedd(name, addr).WithConfig(r.clientCfg).WithRateLimitKey(strings.ToLower(name))
}

// Options tunes a Registry. The zero value is the default.
type Options struct {
	// Interval between polls; zero means DefaultInterval.
	Interval time.Duration
	// Now replaces the clock, for tests.
	Now func() time.Time
	// ClientConfig is the configuration each member's schedd client is built
	// from (see htcondor.Schedd.WithConfig); nil uses the process default.
	ClientConfig *config.Config
	// Probe checks a member's trust when it joins, when its address
	// changes, and every ProbeInterval after. Nil leaves every member
	// TrustUnknown.
	Probe ProbeFunc
	// ProbeInterval between re-probes; zero means DefaultProbeInterval.
	ProbeInterval time.Duration
}

// New returns a registry of the schedds matching constraint. It holds no
// members until the first Refresh.
func New(q Querier, constraint string, opts Options) (*Registry, error) {
	if q == nil {
		return nil, errors.New("apregistry: a collector is required")
	}
	if strings.TrimSpace(constraint) == "" {
		return nil, errors.New("apregistry: an empty schedd constraint would match every schedd in the pool")
	}
	r := &Registry{
		q:          q,
		constraint: constraint,
		interval:   opts.Interval,
		now:        opts.Now,
		clientCfg:  opts.ClientConfig,
		members:    map[string]*Member{},

		probe:         opts.Probe,
		probeInterval: opts.ProbeInterval,
		probeSlots:    make(chan struct{}, maxConcurrentProbes),
		probing:       map[string]bool{},
	}
	if r.interval <= 0 {
		r.interval = DefaultInterval
	}
	if r.probeInterval <= 0 {
		r.probeInterval = DefaultProbeInterval
	}
	if r.now == nil {
		r.now = time.Now
	}
	return r, nil
}

// Constraint is the ScheddAd constraint defining the set.
func (r *Registry) Constraint() string { return r.constraint }

// queryOptions asks for every matching ad. Limit -1, not 0: a zero limit
// is silently capped at 50 by the collector client, which would cut a
// large AP set short with no error.
func queryOptions() *htcondor.QueryOptions {
	return &htcondor.QueryOptions{Limit: -1, Projection: []string{"Name", "MyAddress"}}
}

// Refresh polls the collector once. On error the registry is unchanged.
func (r *Registry) Refresh(ctx context.Context) error {
	ctx, cancel := context.WithTimeout(ctx, pollTimeout)
	defer cancel()
	ads, _, err := r.q.QueryAdsWithOptions(ctx, "ScheddAd", r.constraint, queryOptions())
	now := r.now()

	r.mu.Lock()
	defer r.mu.Unlock()
	r.lastAttempt = now
	if err != nil {
		r.lastErr = err.Error()
		return fmt.Errorf("querying the collector for access points: %w", err)
	}
	r.lastErr = ""
	r.lastSuccess = now

	seen := map[string]bool{}
	for _, ad := range ads {
		name, _ := ad.EvaluateAttrString("Name")
		addr, _ := ad.EvaluateAttrString("MyAddress")
		if name == "" || addr == "" {
			continue
		}
		key := strings.ToLower(name)
		seen[key] = true
		m, ok := r.members[key]
		if !ok {
			r.members[key] = &Member{
				Name: name, Address: addr, Schedd: r.newSchedd(name, addr),
				Present: true, FirstSeen: now, LastSeen: now, LastConfirmed: now, AddressSince: now,
				Trust: Trust{State: TrustUnknown},
			}
			continue
		}
		next := *m
		next.Present, next.LastSeen, next.LastConfirmed = true, now, now
		if addr != m.Address {
			next.Address, next.Schedd, next.AddressSince = addr, r.newSchedd(name, addr), now
			// A new address is a new daemon, possibly configured
			// differently: what the old one trusted says nothing.
			next.Trust = Trust{State: TrustUnknown}
		}
		r.members[key] = &next
	}
	for key, m := range r.members {
		if !seen[key] && m.Present {
			next := *m
			next.Present = false
			r.members[key] = &next
		}
	}
	return nil
}

// Run polls until ctx is done, starting immediately. After each poll
// it starts the trust probes that are due, without waiting for them: a
// member that hangs a handshake must not stall discovery.
func (r *Registry) Run(ctx context.Context, onResult func(error)) {
	poll := func() {
		err := r.Refresh(ctx)
		if onResult != nil {
			onResult(err)
		}
		r.startProbes(ctx)
	}
	poll()
	t := time.NewTicker(r.interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			poll()
		}
	}
}

// Members returns a snapshot of every member, sorted by name.
func (r *Registry) Members() []Member {
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := make([]Member, 0, len(r.members))
	for _, m := range r.members {
		out = append(out, *m)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

// Get returns the member named name (case-insensitive).
func (r *Registry) Get(name string) (Member, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	m, ok := r.members[strings.ToLower(name)]
	if !ok {
		return Member{}, false
	}
	return *m, true
}

// Status reports the registry's polling state.
func (r *Registry) Status() Status {
	r.mu.RLock()
	defer r.mu.RUnlock()
	st := Status{
		Constraint: r.constraint, Members: len(r.members),
		LastAttempt: r.lastAttempt, LastSuccess: r.lastSuccess, LastError: r.lastErr,
	}
	for _, m := range r.members {
		if m.Present {
			st.Present++
		}
	}
	return st
}

// Healthy returns up to n members to try for a call any member can
// answer (resolving a caller's identity: every member trusts the same
// signing key in v1). Present members come first, in name order, then
// absent ones with an address. A member that failed its trust probe is
// never offered: it would refuse the caller's token whoever the caller
// is.
func (r *Registry) Healthy(n int) []Member {
	all := r.Members()
	out := make([]Member, 0, n)
	for _, pass := range []bool{true, false} {
		for _, m := range all {
			if len(out) == n {
				return out
			}
			if m.Present == pass && m.Schedd != nil && !m.Untrusted() {
				out = append(out, m)
			}
		}
	}
	return out
}

// due reports whether m's trust should be (re)probed at now.
func (r *Registry) due(m *Member, now time.Time) bool {
	if m.Schedd == nil || m.Address == "" {
		return false
	}
	if m.Trust.State == TrustUnknown || m.Trust.Address != m.Address {
		return true
	}
	return now.Sub(m.Trust.CheckedAt) >= r.probeInterval
}

// startProbes launches the probes that are due, at most
// maxConcurrentProbes at a time, and returns without waiting.
func (r *Registry) startProbes(ctx context.Context) {
	if r.probe == nil {
		return
	}
	now := r.now()
	var todo []Member
	r.mu.Lock()
	for key, m := range r.members {
		if r.probing[key] || !r.due(m, now) {
			continue
		}
		r.probing[key] = true
		todo = append(todo, *m)
	}
	r.mu.Unlock()
	for _, m := range todo {
		go func(m Member) {
			select {
			case r.probeSlots <- struct{}{}:
			case <-ctx.Done():
				r.finishProbe(m, ctx.Err(), false)
				return
			}
			defer func() { <-r.probeSlots }()
			r.finishProbe(m, r.runProbe(ctx, m), true)
		}(m)
	}
}

// ProbeAll probes every member now and waits for the results. For tests
// and for an operator-triggered recheck.
func (r *Registry) ProbeAll(ctx context.Context) {
	if r.probe == nil {
		return
	}
	var wg sync.WaitGroup
	for _, m := range r.Members() {
		if m.Schedd == nil || m.Address == "" {
			continue
		}
		key := strings.ToLower(m.Name)
		r.mu.Lock()
		busy := r.probing[key]
		if !busy {
			r.probing[key] = true
		}
		r.mu.Unlock()
		if busy {
			continue
		}
		wg.Add(1)
		go func(m Member) {
			defer wg.Done()
			r.finishProbe(m, r.runProbe(ctx, m), true)
		}(m)
	}
	wg.Wait()
}

func (r *Registry) runProbe(ctx context.Context, m Member) (err error) {
	ctx, cancel := context.WithTimeout(ctx, probeTimeout)
	defer cancel()
	defer func() {
		// A probe is network code against a remote daemon; a panic in it
		// must not take the server down, and is not "trusted".
		if p := recover(); p != nil {
			err = fmt.Errorf("trust probe panicked: %v", p)
		}
	}()
	return r.probe(ctx, m)
}

// finishProbe records a probe's outcome, unless the member's address
// changed while it ran (the result is about a daemon that is gone).
// record is false when the probe never ran.
func (r *Registry) finishProbe(m Member, err error, record bool) {
	key := strings.ToLower(m.Name)
	r.mu.Lock()
	defer r.mu.Unlock()
	delete(r.probing, key)
	if !record {
		return
	}
	cur, ok := r.members[key]
	if !ok || cur.Address != m.Address {
		return
	}
	next := *cur
	switch {
	case errors.Is(err, ErrInconclusive):
		if next.Trust.State != TrustUnknown {
			// Keep the last conclusive answer; it is re-probed when due.
			return
		}
		next.Trust = Trust{State: TrustUnknown, Reason: err.Error()}
	case err != nil:
		next.Trust = Trust{State: TrustUntrusted, Reason: err.Error(), CheckedAt: r.now(), Address: m.Address}
	default:
		next.Trust = Trust{State: TrustTrusted, CheckedAt: r.now(), Address: m.Address}
	}
	r.members[key] = &next
}
