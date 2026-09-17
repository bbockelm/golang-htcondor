// Copyright 2026 Morgridge Institute for Research
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package droppriv

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"
)

// groupChain merges the answers of several group lookups, the way glibc
// merges NSS services for a group query.
//
// The group database is a union, not a first-match: getgrouplist walks
// every service and combines what they return, because an account can
// hold local groups AND directory groups at once. Stopping at the first
// source that answers would drop half of somebody's membership.
type groupChain struct{ sources []GroupLookup }

// Name lists the chained sources, so a log line says what was consulted.
func (c *groupChain) Name() string {
	names := make([]string, 0, len(c.sources))
	for _, s := range c.sources {
		names = append(names, s.Name())
	}
	return "chain(" + strings.Join(names, ",") + ")"
}

// LookupGroups returns the union of every source's answer.
func (c *groupChain) LookupGroups(ctx context.Context, username string) ([]string, error) {
	var (
		merged   []string
		known    bool
		degraded *DegradedError
	)
	for _, s := range c.sources {
		groups, err := s.LookupGroups(ctx, username)
		if err != nil {
			if errors.Is(err, ErrUnknownUser) {
				// This service simply has no record of the account.
				continue
			}
			// Unavailable. Keep going, as glibc does, but remember.
			if degraded == nil {
				degraded = &DegradedError{Source: s.Name(), Err: err}
			}
			continue
		}
		known = true
		merged = append(merged, groups...)
	}

	if !known {
		if degraded != nil {
			// Nothing answered AND something was broken: an outage, not an
			// unknown account. Returning an empty list here would read
			// downstream as "belongs to nothing", which is what an
			// authorization decision misreads.
			return nil, fmt.Errorf("no source could answer for %q: %w", username, degraded)
		}
		return nil, fmt.Errorf("%w: no configured source knows %q", ErrUnknownUser, username)
	}

	merged = NormalizeGroups(merged)
	if degraded != nil {
		degraded.Groups = merged
		return merged, degraded
	}
	return merged, nil
}

// unsupportedMethod stands in for an nsswitch method this package cannot
// speak, so its absence is recorded rather than ignored.
//
// It returns a plain error rather than ErrUnknownUser, and the difference
// is the point: ErrUnknownUser means "this source knows the population and
// your account is not in it", which contributes nothing and is normal.
// This means "a service the administrator configured was not consulted at
// all", which makes the list possibly short.
//
// Note this can only arise without cgo. A cgo build resolves groups through
// getgrouplist(3), which speaks every method itself.
type unsupportedMethod struct {
	method string
	reason string
}

// Name identifies the method in logs.
func (u *unsupportedMethod) Name() string { return "unsupported:" + u.method }

// LookupGroups always fails, which marks the chain's read degraded.
func (u *unsupportedMethod) LookupGroups(context.Context, string) ([]string, error) {
	return nil, fmt.Errorf("%s is not implemented here, so its groups are missing from this answer (%s)",
		u.method, u.reason)
}

// CachedGroupLookup wraps a GroupLookup with a short positive cache.
//
// There is deliberately NO negative caching: a directory blip would
// otherwise become minutes of denied access for a user who is in fact a
// member. Degraded answers are not cached either, for the same reason.
type CachedGroupLookup struct {
	source GroupLookup
	ttl    time.Duration

	mu     sync.RWMutex
	groups map[string]cachedGroups
}

type cachedGroups struct {
	groups    []string
	expiresAt time.Time
}

// NewCachedGroupLookup wraps source, reusing answers for ttl.
func NewCachedGroupLookup(source GroupLookup, ttl time.Duration) *CachedGroupLookup {
	return &CachedGroupLookup{source: source, ttl: ttl, groups: make(map[string]cachedGroups)}
}

// Name returns the underlying lookup's name.
func (c *CachedGroupLookup) Name() string { return "cached(" + c.source.Name() + ")" }

// LookupGroups returns the account's groups, using the cache if fresh.
func (c *CachedGroupLookup) LookupGroups(ctx context.Context, username string) ([]string, error) {
	c.mu.RLock()
	if e, ok := c.groups[username]; ok && time.Now().Before(e.expiresAt) {
		c.mu.RUnlock()
		return e.groups, nil
	}
	c.mu.RUnlock()

	groups, err := c.source.LookupGroups(ctx, username)
	if err != nil {
		// Includes the degraded case: not cached, so the next call gets a
		// fresh chance at the source that was down.
		return groups, err
	}

	c.mu.Lock()
	c.groups[username] = cachedGroups{groups: groups, expiresAt: time.Now().Add(c.ttl)}
	c.mu.Unlock()
	return groups, nil
}

// Forget drops any cached answer for username.
func (c *CachedGroupLookup) Forget(username string) {
	c.mu.Lock()
	delete(c.groups, username)
	c.mu.Unlock()
}

var (
	defaultGroupLookupMu   sync.Mutex
	defaultGroupLookup     GroupLookup
	defaultGroupLookupOnce sync.Once
)

// DefaultGroupLookup returns the best group lookup for this system,
// chosen the same way DefaultLookup chooses a user lookup.
func DefaultGroupLookup() GroupLookup {
	defaultGroupLookupMu.Lock()
	defer defaultGroupLookupMu.Unlock()
	defaultGroupLookupOnce.Do(func() {
		defaultGroupLookup = NewCachedGroupLookup(selectBestGroupLookup(), time.Minute)
	})
	return defaultGroupLookup
}

// resetDefaultGroupLookup forces the next DefaultGroupLookup call to
// re-select. Intended for testing, via SetNSSSwitchPath.
func resetDefaultGroupLookup() {
	defaultGroupLookupMu.Lock()
	defer defaultGroupLookupMu.Unlock()
	defaultGroupLookupOnce = sync.Once{}
	defaultGroupLookup = nil
}

// NewSystemGroupLookup returns the best group lookup for this system,
// caching answers for ttl.
//
// Prefer DefaultGroupLookup unless the caller has its own TTL policy;
// this exists so a daemon can tie group freshness to its own
// configuration rather than to this package's default.
func NewSystemGroupLookup(ttl time.Duration) GroupLookup {
	if ttl <= 0 {
		ttl = time.Minute
	}
	return NewCachedGroupLookup(selectBestGroupLookup(), ttl)
}

// LookupGroups is a convenience wrapper over the default group lookup.
func LookupGroups(ctx context.Context, username string) ([]string, error) {
	return DefaultGroupLookup().LookupGroups(ctx, username)
}
