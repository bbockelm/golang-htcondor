package idmap

import (
	"context"
	"fmt"
	"strconv"
	"sync"

	"github.com/bbockelm/gosssd"
)

// SSSDGroups reads group membership straight from SSSD, over the same
// socket protocol droppriv already uses for uid lookups.
//
// This is the native answer to the question, and it is preferred over
// IDCommand: it asks SSS_NSS_INITGR directly instead of spawning a
// process, and it needs neither cgo nor the directory's permission to
// enumerate. It speaks only to SSSD, so a site whose groups are in
// /etc/group alone will get nothing here and should fall through --
// which is what GroupChain is for.
type SSSDGroups struct {
	// SocketPath overrides the SSSD NSS socket. Empty uses gosssd's
	// default. Exposed so this can be pointed at a test double: the one
	// bug that made this source unusable -- a client that reported a
	// successful connection and then failed every request -- was
	// invisible precisely because nothing could exercise it without a
	// live SSSD.
	SocketPath string

	mu     sync.Mutex
	client *gosssd.Client
}

// Name identifies this source in logs.
func (s *SSSDGroups) Name() string { return "sssd" }

// connect lazily dials SSSD. The client is kept because reconnecting per
// lookup would cost more than the lookup.
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
	c := gosssd.NewClient(opts...)
	if err := c.ConnectContext(ctx); err != nil {
		return nil, fmt.Errorf("SSSD not available: %w", err)
	}
	s.client = c
	return c, nil
}

// Close releases the SSSD connection.
func (s *SSSDGroups) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.client == nil {
		return nil
	}
	err := s.client.Close()
	s.client = nil
	return err
}

// GroupsFor returns the account's groups by name.
//
// SSSD answers with gids, so each is resolved to a name. A gid that will
// not resolve is reported as its number rather than dropped: it is still
// a membership, and silently shortening the list would quietly narrow
// what its owner may do.
func (s *SSSDGroups) GroupsFor(ctx context.Context, username string) ([]string, error) {
	if username == "" {
		return nil, fmt.Errorf("no username to look up groups for")
	}
	client, err := s.connect(ctx)
	if err != nil {
		return nil, err
	}

	gids, err := client.GetGroupsForUser(username)
	if err != nil {
		// A dead socket must not persist as a cached client.
		_ = s.Close()
		return nil, fmt.Errorf("SSSD group lookup for %q: %w", username, err)
	}
	if len(gids) == 0 {
		// Every account is in at least its primary group, so an empty
		// answer means SSSD does not know this user -- not that the user
		// has no permissions.
		return nil, fmt.Errorf("SSSD returned no groups for %q", username)
	}

	names := make([]string, 0, len(gids))
	for _, gid := range gids {
		if g, err := client.GetGroupByGID(gid); err == nil && g.Name != "" {
			names = append(names, g.Name)
			continue
		}
		names = append(names, strconv.FormatUint(uint64(gid), 10))
	}
	return normalizeGroups(names), nil
}
