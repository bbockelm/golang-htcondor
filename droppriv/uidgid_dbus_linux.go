//go:build linux

package droppriv

import (
	"context"
	"fmt"
	"strings"

	"github.com/godbus/dbus/v5"
)

// SSSDIfpLookupStrategy uses SSSD's InfoPipe (ifp) over D-Bus.
type SSSDIfpLookupStrategy struct {
	conn *dbus.Conn
}

// NewSSSDIfpLookup creates a new SSSD InfoPipe lookup strategy.
func NewSSSDIfpLookup(ctx context.Context) (*SSSDIfpLookupStrategy, error) {
	conn, err := dbus.SystemBus()
	if err != nil {
		return nil, fmt.Errorf("failed to connect to system bus: %w", err)
	}

	// Check if SSSD InfoPipe is available
	obj := conn.Object("org.freedesktop.sssd.infopipe", "/org/freedesktop/sssd/infopipe")
	call := obj.CallWithContext(ctx, "org.freedesktop.DBus.Introspectable.Introspect", 0)
	if call.Err != nil {
		_ = conn.Close() // Ignore error during cleanup on failure path
		return nil, fmt.Errorf("SSSD InfoPipe not available: %w", call.Err)
	}

	return &SSSDIfpLookupStrategy{conn: conn}, nil
}

// LookupUser looks up a user using SSSD InfoPipe.
func (s *SSSDIfpLookupStrategy) LookupUser(ctx context.Context, username string) (*UserInfo, error) {
	obj := s.conn.Object("org.freedesktop.sssd.infopipe", "/org/freedesktop/sssd/infopipe/Users")

	var userPath dbus.ObjectPath
	call := obj.CallWithContext(ctx, "org.freedesktop.sssd.infopipe.Users.FindByName", 0, username)
	if call.Err != nil {
		if strings.Contains(call.Err.Error(), "not found") {
			return nil, &ErrUserNotFound{Username: username}
		}
		return nil, fmt.Errorf("SSSD lookup failed: %w", call.Err)
	}

	if err := call.Store(&userPath); err != nil {
		return nil, fmt.Errorf("failed to get user path: %w", err)
	}

	// Get user properties
	userObj := s.conn.Object("org.freedesktop.sssd.infopipe", userPath)

	var uid, gid uint32
	var homeDir, shell string

	// Get UID
	variant, err := userObj.GetProperty("org.freedesktop.sssd.infopipe.Users.User.uidNumber")
	if err == nil {
		uid = variant.Value().(uint32)
	}

	// Get GID
	variant, err = userObj.GetProperty("org.freedesktop.sssd.infopipe.Users.User.gidNumber")
	if err == nil {
		gid = variant.Value().(uint32)
	}

	// Get home directory
	variant, err = userObj.GetProperty("org.freedesktop.sssd.infopipe.Users.User.homeDirectory")
	if err == nil {
		homeDir = variant.Value().(string)
	}

	// Get shell
	variant, err = userObj.GetProperty("org.freedesktop.sssd.infopipe.Users.User.loginShell")
	if err == nil {
		shell = variant.Value().(string)
	}

	// Try to get group name (may not be available via InfoPipe)
	groupname := fmt.Sprintf("%d", gid)

	return &UserInfo{
		UID:       uid,
		GID:       gid,
		Username:  username,
		Groupname: groupname,
		HomeDir:   homeDir,
		Shell:     shell,
	}, nil
}

// Name returns the strategy name.
func (s *SSSDIfpLookupStrategy) Name() string {
	return "sssd-infopipe"
}

// Close closes the D-Bus connection.
func (s *SSSDIfpLookupStrategy) Close() error {
	if s.conn != nil {
		return s.conn.Close()
	}
	return nil
}

// trySSSDIfp attempts to create an SSSD InfoPipe lookup strategy.
// It checks for availability by attempting to introspect the D-Bus service.
//
//nolint:unused // Used on non-CGO builds, false positive by linter
func trySSSDIfp() (LookupStrategy, error) {
	return NewSSSDIfpLookup(context.Background())
}
