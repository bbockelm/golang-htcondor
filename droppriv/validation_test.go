package droppriv

import (
	"errors"
	"testing"
)

func TestValidateUsername(t *testing.T) {
	tests := []struct {
		name      string
		username  string
		wantError bool
		errorType error
	}{
		{
			name:      "valid simple username",
			username:  "alice",
			wantError: false,
		},
		{
			name:      "valid username with underscore",
			username:  "user_name",
			wantError: false,
		},
		{
			name:      "valid username with dash",
			username:  "user-name",
			wantError: false,
		},
		{
			name:      "valid username with @",
			username:  "user@domain",
			wantError: false,
		},
		{
			name:      "valid username with dot",
			username:  "user.name",
			wantError: false,
		},
		{
			name:      "valid username with $",
			username:  "user$",
			wantError: false,
		},
		{
			name:      "valid username starting with number",
			username:  "1user",
			wantError: false,
		},
		{
			name:      "valid username all valid chars",
			username:  "user_name-123@domain.com$",
			wantError: false,
		},
		{
			name:      "empty username allowed",
			username:  "",
			wantError: false,
		},
		{
			name:      "whitespace only treated as empty",
			username:  "   ",
			wantError: false,
		},
		{
			name:      "root username",
			username:  "root",
			wantError: true,
			errorType: ErrInvalidUsername,
		},
		{
			name:      "condor username",
			username:  "condor",
			wantError: true,
			errorType: ErrInvalidUsername,
		},
		{
			name:      "username with space",
			username:  "user name",
			wantError: true,
			errorType: ErrInvalidUsername,
		},
		{
			name:      "username starting with dash",
			username:  "-username",
			wantError: true,
			errorType: ErrInvalidUsername,
		},
		{
			name:      "username starting with dot",
			username:  ".username",
			wantError: true,
			errorType: ErrInvalidUsername,
		},
		{
			name:      "username with slash",
			username:  "user/name",
			wantError: true,
			errorType: ErrInvalidUsername,
		},
		{
			name:      "username with colon",
			username:  "user:name",
			wantError: true,
			errorType: ErrInvalidUsername,
		},
		{
			name:      "username too long",
			username:  "a123456789012345678901234567890123",
			wantError: true,
			errorType: ErrInvalidUsername,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateUsername(tt.username)

			if tt.wantError {
				if err == nil {
					t.Errorf("validateUsername(%q) expected error, got nil", tt.username)
					return
				}
				if tt.errorType != nil && !errors.Is(err, tt.errorType) {
					t.Errorf("validateUsername(%q) error = %v, want error type %v", tt.username, err, tt.errorType)
				}
			} else if err != nil {
				t.Errorf("validateUsername(%q) unexpected error: %v", tt.username, err)
			}
		})
	}
}

func TestManagerOperationsWithInvalidUsername(t *testing.T) {
	mgr := &Manager{
		enabled:          false,
		cachedIdentities: make(map[string]Identity),
	}

	// Test Open with invalid usernames (not including empty, which is now allowed)
	invalidUsernames := []string{"root", "condor", "user name", "-invalid"}

	for _, username := range invalidUsernames {
		t.Run("Open_"+username, func(t *testing.T) {
			_, err := mgr.Open(username, "/tmp/test")
			if err == nil {
				t.Errorf("Open(%q, ...) expected error, got nil", username)
			}
			if !errors.Is(err, ErrInvalidUsername) {
				t.Errorf("Open(%q, ...) error = %v, want ErrInvalidUsername", username, err)
			}
		})
	}
}

func TestRootOperations(t *testing.T) {
	// These tests just verify the functions exist and have the right signatures
	// Actual functionality is just direct os.* calls
	mgr := &Manager{
		enabled:          false,
		cachedIdentities: make(map[string]Identity),
	}

	t.Run("OpenAsRoot_exists", func(_ *testing.T) {
		// Test that the function exists and can be called
		// Don't actually open a file
		_ = mgr.OpenAsRoot
	})

	t.Run("OpenFileAsRoot_exists", func(_ *testing.T) {
		_ = mgr.OpenFileAsRoot
	})

	t.Run("MkdirAllAsRoot_exists", func(_ *testing.T) {
		_ = mgr.MkdirAllAsRoot
	})

	t.Run("ChownAsRoot_exists", func(_ *testing.T) {
		_ = mgr.ChownAsRoot
	})
}
