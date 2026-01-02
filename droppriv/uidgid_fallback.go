package droppriv

import (
	"context"
	"errors"
	"fmt"
	"os/user"
	"strconv"
)

// GoLookupStrategy uses Go's built-in user lookup.
// When CGO is enabled, this automatically uses getpwnam_r and the best
// available C library functions for maximum compatibility.
// When CGO is disabled, it falls back to parsing /etc/passwd.
type GoLookupStrategy struct{}

// NewGoLookup creates a new Go lookup strategy.
func NewGoLookup() (*GoLookupStrategy, error) {
	return &GoLookupStrategy{}, nil
}

// LookupUser looks up a user using Go's os/user package.
func (s *GoLookupStrategy) LookupUser(ctx context.Context, username string) (*UserInfo, error) {
	// Note: os/user package does not support context yet
	_ = ctx
	u, err := user.Lookup(username)
	if err != nil {
		var unknownUserErr user.UnknownUserError
		if errors.As(err, &unknownUserErr) {
			return nil, &ErrUserNotFound{Username: username}
		}
		return nil, fmt.Errorf("user lookup failed: %w", err)
	}

	uid, err := strconv.ParseUint(u.Uid, 10, 32)
	if err != nil {
		return nil, fmt.Errorf("invalid UID: %w", err)
	}

	gid, err := strconv.ParseUint(u.Gid, 10, 32)
	if err != nil {
		return nil, fmt.Errorf("invalid GID: %w", err)
	}

	// Try to look up group name
	var groupname string
	if g, err := user.LookupGroupId(u.Gid); err == nil {
		groupname = g.Name
	} else {
		groupname = u.Gid
	}

	return &UserInfo{
		UID:       uint32(uid),
		GID:       uint32(gid),
		Username:  u.Username,
		Groupname: groupname,
		HomeDir:   u.HomeDir,
		Shell:     "", // Not available in Go's user package
	}, nil
}

// Name returns the strategy name.
func (s *GoLookupStrategy) Name() string {
	return "go-os-user"
}

// tryGoFallback attempts to create a Go lookup strategy.
// This always succeeds as it's the ultimate fallback.
func tryGoFallback() (LookupStrategy, error) {
	return NewGoLookup()
}
