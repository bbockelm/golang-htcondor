//go:build linux

// Package droppriv provides privilege dropping functionality for Unix-like systems.
package droppriv

import (
	"fmt"
	"syscall"
)

// dropPrivileges drops process effective privileges to the target identity.
// This only changes the effective UID/GID, leaving real/saved UIDs unchanged
// so privileges can be restored later.
func dropPrivileges(target Identity) error {
	// Drop effective GID first (must be done before dropping UID)
	if err := syscall.Setegid(int(target.GID)); err != nil {
		return fmt.Errorf("failed to drop effective GID to %d: %w", target.GID, err)
	}

	// Drop effective UID
	if err := syscall.Seteuid(int(target.UID)); err != nil {
		return fmt.Errorf("failed to drop effective UID to %d: %w", target.UID, err)
	}

	return nil
}

// restorePrivileges restores process effective privileges to the original identity.
func restorePrivileges(original Identity) error {
	// Restore effective UID first
	if err := syscall.Seteuid(int(original.UID)); err != nil {
		return fmt.Errorf("failed to restore effective UID to %d: %w", original.UID, err)
	}

	// Restore effective GID
	if err := syscall.Setegid(int(original.GID)); err != nil {
		return fmt.Errorf("failed to restore effective GID to %d: %w", original.GID, err)
	}

	return nil
}
