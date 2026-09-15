package idmap

import (
	"bytes"
	"context"
	"fmt"
	"os/exec"
	"os/user"
	"sort"
	"strings"
	"sync"
	"time"
)

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

// IDCommand reads group membership by running `id -Gn <user>`.
//
// It resolves through NSS, so it sees directory groups the same way the
// rest of the system does. That matters more than it looks: Go's
// os/user, built without cgo, reads /etc/group ALONE and would silently
// report a directory-backed user as a member of nothing -- which reads
// as "no permissions" rather than as an error.
type IDCommand struct {
	// Path to id. Empty means look it up on PATH.
	Path string
}

// Name identifies this source in logs.
func (c *IDCommand) Name() string { return "id -Gn" }

// GroupsFor returns every group the account belongs to, primary included.
func (c *IDCommand) GroupsFor(ctx context.Context, username string) ([]string, error) {
	if username == "" {
		return nil, fmt.Errorf("no username to look up groups for")
	}
	bin := c.Path
	if bin == "" {
		var err error
		if bin, err = exec.LookPath("id"); err != nil {
			return nil, fmt.Errorf("id is not available: %w", err)
		}
	}
	// -Gn is "all group names, including the primary one". The username
	// comes from the account database, never straight from a token, but
	// it is passed as an argument rather than through a shell regardless.
	cmd := exec.CommandContext(ctx, bin, "-Gn", "--", username) //nolint:gosec // bin is from PATH or operator config; username is an argv element
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("running %s -Gn %s: %w: %s", bin, username, err, strings.TrimSpace(stderr.String()))
	}
	return normalizeGroups(strings.Fields(stdout.String())), nil
}

// OSUser reads group membership through os/user. Complete only when the
// binary was built with cgo and NSS is configured; see IDCommand.
type OSUser struct{}

// Name identifies this source in logs.
func (OSUser) Name() string { return "os/user" }

// GroupsFor returns the account's groups as os/user reports them.
func (OSUser) GroupsFor(_ context.Context, username string) ([]string, error) {
	u, err := user.Lookup(username)
	if err != nil {
		return nil, err
	}
	gids, err := u.GroupIds()
	if err != nil {
		return nil, err
	}
	names := make([]string, 0, len(gids))
	for _, gid := range gids {
		g, err := user.LookupGroupId(gid)
		if err != nil {
			// A gid with no group entry is still a membership; report the
			// number rather than dropping the fact.
			names = append(names, gid)
			continue
		}
		names = append(names, g.Name)
	}
	return normalizeGroups(names), nil
}

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
