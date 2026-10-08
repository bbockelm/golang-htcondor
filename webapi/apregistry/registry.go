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
}

// Status describes the registry's own polling.
type Status struct {
	Constraint  string
	Members     int
	Present     int
	LastAttempt time.Time
	LastSuccess time.Time
	LastError   string
}

// Registry is the AP set. Safe for concurrent use.
type Registry struct {
	q          Querier
	constraint string
	interval   time.Duration
	now        func() time.Time

	mu          sync.RWMutex
	members     map[string]*Member // keyed by lower-cased name
	lastAttempt time.Time
	lastSuccess time.Time
	lastErr     string
}

// Options tunes a Registry. The zero value is the default.
type Options struct {
	// Interval between polls; zero means DefaultInterval.
	Interval time.Duration
	// Now replaces the clock, for tests.
	Now func() time.Time
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
		members:    map[string]*Member{},
	}
	if r.interval <= 0 {
		r.interval = DefaultInterval
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
				Name: name, Address: addr, Schedd: htcondor.NewSchedd(name, addr),
				Present: true, FirstSeen: now, LastSeen: now, LastConfirmed: now, AddressSince: now,
			}
			continue
		}
		next := *m
		next.Present, next.LastSeen, next.LastConfirmed = true, now, now
		if addr != m.Address {
			next.Address, next.Schedd, next.AddressSince = addr, htcondor.NewSchedd(name, addr), now
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

// Run polls until ctx is done, starting immediately.
func (r *Registry) Run(ctx context.Context, onResult func(error)) {
	poll := func() {
		err := r.Refresh(ctx)
		if onResult != nil {
			onResult(err)
		}
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
// absent ones with an address.
func (r *Registry) Healthy(n int) []Member {
	all := r.Members()
	out := make([]Member, 0, n)
	for _, pass := range []bool{true, false} {
		for _, m := range all {
			if len(out) == n {
				return out
			}
			if m.Present == pass && m.Schedd != nil {
				out = append(out, m)
			}
		}
	}
	return out
}
