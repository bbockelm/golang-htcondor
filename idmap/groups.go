package idmap

import (
	"context"
	"errors"
	"sort"
	"strings"
	"sync"
	"time"
)

// ErrUnknownUser means a source does not know this account at all --
// which is NOT a failure. nsswitch.conf lists several services precisely
// because each knows a different part of the population: on a
// "group: files sss" host, every directory user is unknown to files and
// every local user is unknown to sss. Only a source that is BROKEN
// returns some other error, and that distinction decides whether a group
// list is complete enough to make an authorization decision from.
var ErrUnknownUser = errors.New("this source does not know the account")

// GroupSource reports the groups a local account belongs to.
//
// This exists because a site's authorization can live in its Unix groups
// rather than in the token. When it does, the token says who somebody is
// and the account database says what they may do, and the two are
// combined only after the subject has been mapped to an account.
type GroupSource interface {
	GroupsFor(ctx context.Context, username string) ([]string, error)
	Name() string
}

// There is no `id -Gn` group source and no os/user one.
//
// The first forks, which a privilege-manipulating daemon should not do.
// The second reads /etc/group ALONE when built without cgo, reporting a
// directory-backed account as a member of nothing -- which reads as "no
// permissions" rather than as the failure it is. Membership comes from
// GroupFiles and SSSDGroups, composed in the order nsswitch.conf gives.

// CachedGroups memoises a GroupSource. Group membership changes rarely
// and is consulted on every authorization, so the uncached cost would be
// a process spawn per request.
//
// There is no negative caching: a lookup that failed is not an answer,
// and remembering it would turn a transient directory outage into
// minutes of denied access.
type CachedGroups struct {
	src GroupSource
	ttl time.Duration
	now func() time.Time

	mu      sync.RWMutex
	entries map[string]groupEntry
}

type groupEntry struct {
	groups  []string
	expires time.Time
}

// NewCachedGroups wraps src with a TTL cache.
func NewCachedGroups(src GroupSource, ttl time.Duration) *CachedGroups {
	return &CachedGroups{src: src, ttl: ttl, now: time.Now, entries: map[string]groupEntry{}}
}

// Name identifies the wrapped source in logs.
func (c *CachedGroups) Name() string { return "cached(" + c.src.Name() + ")" }

// GroupsFor returns the cached membership, refreshing past the TTL.
func (c *CachedGroups) GroupsFor(ctx context.Context, username string) ([]string, error) {
	c.mu.RLock()
	e, ok := c.entries[username]
	c.mu.RUnlock()
	if ok && c.now().Before(e.expires) {
		return append([]string(nil), e.groups...), nil
	}

	groups, err := c.src.GroupsFor(ctx, username)
	if err != nil {
		return nil, err
	}

	c.mu.Lock()
	c.entries[username] = groupEntry{groups: groups, expires: c.now().Add(c.ttl)}
	c.mu.Unlock()
	return append([]string(nil), groups...), nil
}

// Forget drops a cached entry, so an operator who has just changed a
// user's groups does not have to wait out the TTL.
func (c *CachedGroups) Forget(username string) {
	c.mu.Lock()
	delete(c.entries, username)
	c.mu.Unlock()
}

// normalizeGroups sorts and de-duplicates, so that membership compares
// equal regardless of the order a source happened to return.
func normalizeGroups(in []string) []string {
	if len(in) == 0 {
		return nil
	}
	seen := make(map[string]bool, len(in))
	out := make([]string, 0, len(in))
	for _, g := range in {
		g = strings.TrimSpace(g)
		if g == "" || seen[g] {
			continue
		}
		seen[g] = true
		out = append(out, g)
	}
	sort.Strings(out)
	return out
}
