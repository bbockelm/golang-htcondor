//go:build linux && !cgo

package droppriv

import (
	"context"
	"fmt"
	"strings"

	"github.com/bbockelm/gosssd"
)

// SSSDLookupStrategy uses SSSD via the gosssd library.
type SSSDLookupStrategy struct {
	client *gosssd.Client
}

// NewSSSDLookup creates a new SSSD lookup strategy using gosssd.
//
// The caller's context bounds construction and nothing more, so it is
// deliberately not handed to the client. gosssd closes the socket when
// the context it was built with is done and then refuses to redial
// through it, so a client built on a context that ends -- a request's, or
// the five-second construction deadline this is called with -- is dead
// from the moment that context expires, and stays dead for the life of
// the process. The symptom is every lookup failing with "context
// canceled" while `id` on the same host answers normally. The dial is
// bounded by the client's own timeout instead.
func NewSSSDLookup(ctx context.Context) (*SSSDLookupStrategy, error) {
	return newSSSDLookupAt(ctx, "")
}

// newSSSDLookupAt is NewSSSDLookup against a given socket, so a test can
// point it somewhere other than the system's. An empty path is the
// default socket.
func newSSSDLookupAt(_ context.Context, socketPath string) (*SSSDLookupStrategy, error) {
	var opts []gosssd.ClientOption
	if socketPath == "" {
		socketPath = gosssd.DefaultNSSSocketPath
	} else {
		opts = append(opts, gosssd.WithSocketPath(socketPath))
	}
	client := gosssd.NewClient(opts...)

	// Test connectivity by connecting
	if err := client.Connect(); err != nil {
		return nil, fmt.Errorf("SSSD not available at %s: %w", socketPath, err)
	}

	return &SSSDLookupStrategy{client: client}, nil
}

// LookupUser looks up a user using SSSD via gosssd.
//
// The context is unused: gosssd's request calls take none, and the
// client deliberately carries none either (see NewSSSDLookup). Named _
// so that is visible rather than looking like an oversight.
func (s *SSSDLookupStrategy) LookupUser(_ context.Context, username string) (*UserInfo, error) {
	user, err := s.client.GetUserByName(username)
	if err != nil {
		// Check if it's a "not found" error by examining the error message
		if strings.Contains(err.Error(), "not found") || strings.Contains(err.Error(), "No such") {
			return nil, &ErrUserNotFound{Username: username}
		}
		return nil, fmt.Errorf("SSSD lookup failed: %w", err)
	}

	// Try to get group name
	var groupname string
	if group, err := s.client.GetGroupByGID(user.GID); err == nil {
		groupname = group.Name
	} else {
		groupname = fmt.Sprintf("%d", user.GID)
	}

	return &UserInfo{
		UID:       user.UID,
		GID:       user.GID,
		Username:  user.Name,
		Groupname: groupname,
		HomeDir:   user.HomeDir,
		Shell:     user.Shell,
	}, nil
}

// Name returns the strategy name.
func (s *SSSDLookupStrategy) Name() string {
	return "sssd-gosssd"
}

// trySSSD attempts to create an SSSD lookup strategy using gosssd.
func trySSSD(ctx context.Context) (LookupStrategy, error) {
	// The conversion is explicit so that a failure yields a nil INTERFACE.
	// Returning the constructor's result directly would wrap a nil *T in a
	// non-nil interface, which is why callers' "strategy != nil" guards were
	// always true and could never have caught anything.
	s, err := NewSSSDLookup(ctx)
	if err != nil || s == nil {
		return nil, err
	}
	return s, nil
}
