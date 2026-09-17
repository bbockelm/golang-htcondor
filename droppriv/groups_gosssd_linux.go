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

//go:build linux && !cgo

package droppriv

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/bbockelm/gosssd"
)

// SSSDGroups reads group membership over the SSSD socket protocol.
//
// It exists only for builds without cgo. With cgo, getgrouplist(3) already
// consults sss along with every other service in nsswitch.conf, and asking
// SSSD separately would duplicate or contradict that.
//
// The lookup is SSS_NSS_INITGR, the same request initgroups(3) makes, so
// it returns the full membership rather than only the groups that happen
// to name the user in /etc/group.
type SSSDGroups struct {
	// SocketPath overrides the SSSD NSS socket. Empty uses the default.
	SocketPath string

	mu     sync.Mutex
	client *gosssd.Client

	names *sssdGroupNames
}

// sssdGroupNames caches gid -> name for SSSD, for the same reason the
// stdlib lookup caches it: a user in thirty groups would otherwise cost
// thirty round trips to the directory on every login.
type sssdGroupNames struct {
	mu    sync.RWMutex
	ttl   time.Duration
	names map[uint32]sssdGroupNameEntry
}

type sssdGroupNameEntry struct {
	name      string
	expiresAt time.Time
}

// Name identifies this lookup in logs.
func (s *SSSDGroups) Name() string { return "sssd" }

// connect returns a connected client, dialling on first use.
func (s *SSSDGroups) connect(ctx context.Context) (*gosssd.Client, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.client != nil {
		return s.client, nil
	}

	opts := []gosssd.ClientOption{gosssd.WithContext(ctx)}
	if s.SocketPath != "" {
		opts = append(opts, gosssd.WithSocketPath(s.SocketPath))
	}
	client := gosssd.NewClient(opts...)
	if err := client.ConnectContext(ctx); err != nil {
		return nil, fmt.Errorf("SSSD not available: %w", err)
	}
	s.client = client
	return client, nil
}

// groupName resolves a gid to a name, consulting the cache first.
func (s *SSSDGroups) groupName(client *gosssd.Client, gid uint32) string {
	if s.names == nil {
		s.names = &sssdGroupNames{ttl: time.Minute, names: make(map[uint32]sssdGroupNameEntry)}
	}

	s.names.mu.RLock()
	if e, ok := s.names.names[gid]; ok && time.Now().Before(e.expiresAt) {
		s.names.mu.RUnlock()
		return e.name
	}
	s.names.mu.RUnlock()

	g, err := client.GetGroupByGID(gid)
	if err != nil || g == nil {
		// Keep the number rather than dropping the entry: a silently
		// shortened membership list is the one outcome an authorization
		// decision must never be handed.
		return fmt.Sprintf("%d", gid)
	}

	s.names.mu.Lock()
	s.names.names[gid] = sssdGroupNameEntry{name: g.Name, expiresAt: time.Now().Add(s.names.ttl)}
	s.names.mu.Unlock()
	return g.Name
}

// LookupGroups returns the account's groups by name.
func (s *SSSDGroups) LookupGroups(ctx context.Context, username string) ([]string, error) {
	if username == "" {
		return nil, fmt.Errorf("no username to look up groups for")
	}

	client, err := s.connect(ctx)
	if err != nil {
		return nil, err
	}

	gids, err := client.GetGroupsForUser(username)
	if err != nil {
		if strings.Contains(err.Error(), "not found") || strings.Contains(err.Error(), "No such") {
			return nil, fmt.Errorf("%w: SSSD has no account %q", ErrUnknownUser, username)
		}
		return nil, fmt.Errorf("SSSD group lookup for %q: %w", username, err)
	}
	if len(gids) == 0 {
		return nil, fmt.Errorf("%w: SSSD returned no groups for %q", ErrUnknownUser, username)
	}

	names := make([]string, 0, len(gids))
	for _, gid := range gids {
		names = append(names, s.groupName(client, gid))
	}
	return NormalizeGroups(names), nil
}

// sssdGroupLookup returns an SSSD group lookup for the nsswitch chain.
func sssdGroupLookup() GroupLookup { return &SSSDGroups{} }
