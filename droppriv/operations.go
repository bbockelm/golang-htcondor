package droppriv

import (
	"errors"
	"fmt"
	"os"
	"regexp"
	"strings"
)

// ErrInvalidUsername is returned when a username fails validation.
var ErrInvalidUsername = errors.New("invalid username")

// Username validation rules:
// - Cannot be empty
// - Cannot be "root" (use separate root functions instead)
// - Cannot be "condor" (condor user is managed by the Manager)
// - Must match Linux username conventions (alphanumeric, dash, underscore, @, dot, $)
// - Must start with alphanumeric or underscore
// - Must be between 1 and 32 characters
var validUsernameRegex = regexp.MustCompile(`^[a-zA-Z0-9_][a-zA-Z0-9_@.$-]{0,31}$`)

// validateUsername checks if a username is valid for use with droppriv operations.
func validateUsername(userName string) error {
	userName = strings.TrimSpace(userName)

	// Empty string is allowed as a special case - means "no privilege drop"
	if userName == "" {
		return nil
	}

	if userName == "root" {
		return fmt.Errorf("%w: use separate root-specific functions instead of passing 'root'", ErrInvalidUsername)
	}

	if userName == "condor" {
		return fmt.Errorf("%w: 'condor' user is managed by the droppriv manager", ErrInvalidUsername)
	}

	if !validUsernameRegex.MatchString(userName) {
		return fmt.Errorf("%w: %q does not match valid username pattern", ErrInvalidUsername, userName)
	}

	return nil
}

func (m *Manager) withUser(userName string, fn func() error) error {
	if err := validateUsername(userName); err != nil {
		return err
	}

	// Empty username means "no privilege drop, run as current user"
	if strings.TrimSpace(userName) == "" {
		return fn()
	}

	identity, err := m.resolveUser(userName)
	if err != nil {
		return err
	}

	if !m.enabled {
		return fn()
	}

	if err := runAsUser(identity, fn); err != nil {
		if errors.Is(err, ErrUnsupported) {
			return fmt.Errorf("drop privileges requested but unsupported: %w", err)
		}
		return err
	}

	return nil
}

// Open wraps os.Open under the target user context.
// If userName is empty, the operation runs as the current user without privilege drop.
// userName cannot be "root" or "condor" - use OpenAsRoot for root operations.
func (m *Manager) Open(userName, path string) (*os.File, error) {
	var file *os.File
	err := m.withUser(userName, func() error {
		var err error
		//nolint:gosec // G304 - path is validated by caller, file access is controlled by privilege drop
		file, err = os.Open(path)
		return err
	})
	return file, err
}

// OpenFile wraps os.OpenFile under the target user context.
// If userName is empty, the operation runs as the current user without privilege drop.
// userName cannot be "root" or "condor" - use OpenFileAsRoot for root operations.
func (m *Manager) OpenFile(userName, path string, flag int, perm os.FileMode) (*os.File, error) {
	var file *os.File
	err := m.withUser(userName, func() error {
		var err error
		//nolint:gosec // G304 - path is validated by caller, file access is controlled by privilege drop
		file, err = os.OpenFile(path, flag, perm)
		return err
	})
	return file, err
}

// MkdirAll wraps os.MkdirAll under the target user context.
// If userName is empty, the operation runs as the current user without privilege drop.
// userName cannot be "root" or "condor" - use MkdirAllAsRoot for root operations.
func (m *Manager) MkdirAll(userName, path string, perm os.FileMode) error {
	return m.withUser(userName, func() error {
		return os.MkdirAll(path, perm)
	})
}

// Chown wraps os.Chown under the target user context.
// If userName is empty, the operation runs as the current user without privilege drop.
// userName cannot be "root" or "condor" - use ChownAsRoot for root operations.
func (m *Manager) Chown(userName, path string, uid, gid int) error {
	return m.withUser(userName, func() error {
		return os.Chown(path, uid, gid)
	})
}

// Open provides a package-level helper using the default manager.
func Open(userName, path string) (*os.File, error) {
	return DefaultManager().Open(userName, path)
}

// OpenFile provides a package-level helper using the default manager.
func OpenFile(userName, path string, flag int, perm os.FileMode) (*os.File, error) {
	return DefaultManager().OpenFile(userName, path, flag, perm)
}

// MkdirAll provides a package-level helper using the default manager.
func MkdirAll(userName, path string, perm os.FileMode) error {
	return DefaultManager().MkdirAll(userName, path, perm)
}

// Chown provides a package-level helper using the default manager.
func Chown(userName, path string, uid, gid int) error {
	return DefaultManager().Chown(userName, path, uid, gid)
}

// Root-specific operations
// These functions operate as root without user validation.
// Use these sparingly and only when root access is explicitly required.
// Prefer regular operations with proper user context whenever possible.

// OpenAsRoot opens a file as root user.
// WARNING: This bypasses all user validation. Use only when root access is required.
func (m *Manager) OpenAsRoot(path string) (*os.File, error) {
	//nolint:gosec // G304 - intentionally allows root file access, path validation is caller's responsibility
	return os.Open(path)
}

// OpenFileAsRoot opens a file as root user with specified flags and permissions.
// WARNING: This bypasses all user validation. Use only when root access is required.
func (m *Manager) OpenFileAsRoot(path string, flag int, perm os.FileMode) (*os.File, error) {
	//nolint:gosec // G304 - intentionally allows root file access, path validation is caller's responsibility
	return os.OpenFile(path, flag, perm)
}

// MkdirAllAsRoot creates directories as root user.
// WARNING: This bypasses all user validation. Use only when root access is required.
func (m *Manager) MkdirAllAsRoot(path string, perm os.FileMode) error {
	return os.MkdirAll(path, perm)
}

// ChownAsRoot changes ownership as root user.
// WARNING: This bypasses all user validation. Use only when root access is required.
func (m *Manager) ChownAsRoot(path string, uid, gid int) error {
	return os.Chown(path, uid, gid)
}

// Package-level root functions

// OpenAsRoot opens a file as root using the default manager.
// WARNING: This bypasses all user validation. Use only when root access is required.
func OpenAsRoot(path string) (*os.File, error) {
	return DefaultManager().OpenAsRoot(path)
}

// OpenFileAsRoot opens a file as root with specified flags and permissions using the default manager.
// WARNING: This bypasses all user validation. Use only when root access is required.
func OpenFileAsRoot(path string, flag int, perm os.FileMode) (*os.File, error) {
	return DefaultManager().OpenFileAsRoot(path, flag, perm)
}

// MkdirAllAsRoot creates directories as root using the default manager.
// WARNING: This bypasses all user validation. Use only when root access is required.
func MkdirAllAsRoot(path string, perm os.FileMode) error {
	return DefaultManager().MkdirAllAsRoot(path, perm)
}

// ChownAsRoot changes ownership as root using the default manager.
// WARNING: This bypasses all user validation. Use only when root access is required.
func ChownAsRoot(path string, uid, gid int) error {
	return DefaultManager().ChownAsRoot(path, uid, gid)
}
