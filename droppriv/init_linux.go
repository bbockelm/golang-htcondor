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
//
// The supplementary groups are replaced with the target's primary group
// first, while the process is still root. Changing only the effective
// IDs leaves root's supplementary list in place -- disk, adm, wheel and
// whatever else root belongs to -- so the dropped process would keep
// every one of those groups' file access.
func dropPrivileges(target Identity) error {
	if err := syscall.Setgroups([]int{int(target.GID)}); err != nil {
		return fmt.Errorf("failed to set supplementary groups to %d: %w", target.GID, err)
	}

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

// restorePrivileges restores process effective privileges to the original
// identity and supplementary groups.
func restorePrivileges(original Identity, groups []int) error {
	// Restore effective UID first
	if err := syscall.Seteuid(int(original.UID)); err != nil {
		return fmt.Errorf("failed to restore effective UID to %d: %w", original.UID, err)
	}

	// Restore effective GID
	if err := syscall.Setegid(int(original.GID)); err != nil {
		return fmt.Errorf("failed to restore effective GID to %d: %w", original.GID, err)
	}

	if err := syscall.Setgroups(groups); err != nil {
		return fmt.Errorf("failed to restore supplementary groups: %w", err)
	}

	return nil
}
