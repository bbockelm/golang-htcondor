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
	"os/user"
	"sort"
	"strings"
	"sync"
	"time"
)

// ErrUnknownUser means a source has no record of the account -- which is
// NOT a failure. nsswitch.conf lists several services precisely because
// each knows a different part of the population: on a "group: files sss"
// host, every directory user is unknown to files and every local user is
// unknown to sss. Only a source that is BROKEN returns some other error,
// and that distinction decides whether a group list is complete enough
// to make an authorization decision from.
var ErrUnknownUser = errors.New("this source does not know the account")

// GroupLookup resolves a user's complete group membership.
//
// It is the group half of LookupStrategy, kept as its own interface so
// that a strategy which cannot answer group questions is not forced to
// pretend it can.
type GroupLookup interface {
	// LookupGroups returns every group the account belongs to, by name,
	// sorted and deduplicated.
	LookupGroups(ctx context.Context, username string) ([]string, error)

	// Name returns the name of this lookup, for logs.
	Name() string
}

// DegradedError reports that a source was unavailable, so the group list
// may be short.
//
// glibc continues past an unavailable NSS service rather than failing
// the whole lookup, and so does groupChain: refusing outright would deny
// every login whenever a directory blinked, while the rest of the machine
// carried on. But "short because a source was down" and "short because
// the user really was removed" are indistinguishable from the list alone,
// and one caller -- the refresh-time membership re-check -- must not act
// on the difference. The partial list travels with the error so that
// caller can decline while a login still proceeds.
type DegradedError struct {
	Groups []string
	Source string
	Err    error
}

func (e *DegradedError) Error() string {
	return fmt.Sprintf("group lookup degraded: %s unavailable: %v", e.Source, e.Err)
}

func (e *DegradedError) Unwrap() error { return e.Err }

// groupNameCache memoises gid -> group name.
//
// Resolving a user in thirty groups means thirty getgrgid_r calls, each
// of which may reach a directory. The gid -> name mapping is the same for
// every account on the host, so it is looked up once and shared, rather
// than repeated per login.
type groupNameCache struct {
	mu    sync.RWMutex
	ttl   time.Duration
	names map[string]groupNameEntry

	// lookup is user.LookupGroupId, replaceable so a test can count how
	// often the cache actually goes to the system.
	lookup func(gid string) (*user.Group, error)
}

type groupNameEntry struct {
	name      string
	expiresAt time.Time
}

func newGroupNameCache(ttl time.Duration) *groupNameCache {
	return &groupNameCache{
		ttl:    ttl,
		names:  make(map[string]groupNameEntry),
		lookup: user.LookupGroupId,
	}
}

// name returns the group name for a gid, consulting the cache first.
func (c *groupNameCache) name(gid string) (string, error) {
	c.mu.RLock()
	if e, ok := c.names[gid]; ok && time.Now().Before(e.expiresAt) {
		c.mu.RUnlock()
		return e.name, nil
	}
	c.mu.RUnlock()

	g, err := c.lookup(gid)
	if err != nil {
		return "", err
	}

	c.mu.Lock()
	c.names[gid] = groupNameEntry{name: g.Name, expiresAt: time.Now().Add(c.ttl)}
	c.mu.Unlock()
	return g.Name, nil
}

// StdlibGroups reads membership through os/user.
//
// GroupIds() is the whole point: it returns the primary group from the
// passwd gid AND the supplementary ones, so nothing here has to parse
// /etc/group. With cgo it runs getgrouplist(3), which walks every service
// in nsswitch.conf -- files, sss, ldap, winbind -- and is therefore
// complete on its own. Without cgo the same call reads /etc/group
// directly, which covers "files" and nothing else; see
// selectBestGroupLookup for how the remaining services are added back.
type StdlibGroups struct {
	names *groupNameCache
}

// NewStdlibGroups returns a group lookup backed by os/user, caching the
// gid -> name mapping for ttl.
func NewStdlibGroups(ttl time.Duration) *StdlibGroups {
	return &StdlibGroups{names: newGroupNameCache(ttl)}
}

// Name returns the lookup name.
func (s *StdlibGroups) Name() string { return "stdlib" }

// LookupGroups returns the account's groups by name.
func (s *StdlibGroups) LookupGroups(_ context.Context, username string) ([]string, error) {
	if username == "" {
		return nil, fmt.Errorf("no username to look up groups for")
	}

	u, err := user.Lookup(username)
	if err != nil {
		var unknown user.UnknownUserError
		if errors.As(err, &unknown) {
			return nil, fmt.Errorf("%w: %q", ErrUnknownUser, username)
		}
		return nil, fmt.Errorf("looking up %q: %w", username, err)
	}

	gids, err := u.GroupIds()
	if err != nil {
		return nil, fmt.Errorf("reading group ids for %q: %w", username, err)
	}
	if len(gids) == 0 {
		// No real account is in zero groups -- it is in at least its
		// primary one. An empty list here means something is wrong, and
		// reporting it as "belongs to nothing" would read downstream as a
		// deliberate lack of permissions.
		return nil, fmt.Errorf("%q resolved to no groups at all", username)
	}

	names := make([]string, 0, len(gids))
	for _, gid := range gids {
		name, err := s.names.name(gid)
		if err != nil {
			// A gid with no group entry is real (the group was deleted, or
			// lives in a service that is down). Keep the number rather than
			// dropping it: silently shortening the list is the one outcome
			// an authorization decision must never see.
			name = gid
		}
		names = append(names, name)
	}
	return NormalizeGroups(names), nil
}

// NormalizeGroups sorts and deduplicates a group list, so that callers
// comparing two results are not defeated by ordering.
func NormalizeGroups(in []string) []string {
	if len(in) == 0 {
		return nil
	}
	seen := make(map[string]struct{}, len(in))
	out := make([]string, 0, len(in))
	for _, g := range in {
		g = strings.TrimSpace(g)
		if g == "" {
			continue
		}
		if _, dup := seen[g]; dup {
			continue
		}
		seen[g] = struct{}{}
		out = append(out, g)
	}
	sort.Strings(out)
	return out
}
