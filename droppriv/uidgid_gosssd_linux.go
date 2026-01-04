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
func NewSSSDLookup(ctx context.Context) (*SSSDLookupStrategy, error) {
	client := gosssd.NewClient(gosssd.WithContext(ctx))

	// Test connectivity by connecting
	err := client.ConnectContext(ctx)
	if err != nil {
		return nil, fmt.Errorf("SSSD not available: %w", err)
	}

	return &SSSDLookupStrategy{client: client}, nil
}

// LookupUser looks up a user using SSSD via gosssd.
func (s *SSSDLookupStrategy) LookupUser(ctx context.Context, username string) (*UserInfo, error) {
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
	return NewSSSDLookup(ctx)
}
