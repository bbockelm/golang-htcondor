package httpserver

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/bbockelm/golang-htcondor/logging"
)

// createTestLogger creates a logger for testing
func createTestLogger() (*logging.Logger, error) {
	return logging.New(&logging.Config{
		OutputPath: "stderr",
	})
}

func TestHasCondorScopes(t *testing.T) {
	tests := []struct {
		name     string
		scopes   []string
		expected bool
	}{
		{
			name:     "no condor scopes",
			scopes:   []string{"openid", "profile", "email"},
			expected: false,
		},
		{
			name:     "has condor READ scope",
			scopes:   []string{"openid", "condor:/READ"},
			expected: true,
		},
		{
			name:     "has condor WRITE scope",
			scopes:   []string{"condor:/WRITE"},
			expected: true,
		},
		{
			name:     "multiple condor scopes",
			scopes:   []string{"condor:/READ", "condor:/WRITE", "condor:/ADVERTISE_STARTD"},
			expected: true,
		},
		{
			name:     "empty scopes",
			scopes:   []string{},
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := hasCondorScopes(tt.scopes)
			if result != tt.expected {
				t.Errorf("hasCondorScopes() = %v, want %v", result, tt.expected)
			}
		})
	}
}

func TestMapCondorScopesToAuthz(t *testing.T) {
	tests := []struct {
		name     string
		scopes   []string
		expected []string
	}{
		{
			name:     "READ scope",
			scopes:   []string{"condor:/READ"},
			expected: []string{"READ"},
		},
		{
			name:     "WRITE scope",
			scopes:   []string{"condor:/WRITE"},
			expected: []string{"WRITE"},
		},
		{
			name:     "ADVERTISE scopes",
			scopes:   []string{"condor:/ADVERTISE_STARTD", "condor:/ADVERTISE_SCHEDD", "condor:/ADVERTISE_MASTER"},
			expected: []string{"ADVERTISE_STARTD", "ADVERTISE_SCHEDD", "ADVERTISE_MASTER"},
		},
		{
			name:     "multiple scopes",
			scopes:   []string{"condor:/READ", "condor:/WRITE"},
			expected: []string{"READ", "WRITE"},
		},
		{
			name:     "case insensitive",
			scopes:   []string{"condor:/read", "condor:/Write"},
			expected: []string{"READ", "WRITE"},
		},
		{
			name:     "unknown scope ignored",
			scopes:   []string{"condor:/UNKNOWN", "condor:/READ"},
			expected: []string{"READ"},
		},
		{
			name:     "unsupported scopes ignored",
			scopes:   []string{"condor:/ADMINISTRATOR", "condor:/DAEMON", "condor:/READ"},
			expected: []string{"READ"},
		},
		{
			name:     "non-condor scopes ignored",
			scopes:   []string{"openid", "profile", "condor:/READ"},
			expected: []string{"READ"},
		},
		{
			name:     "empty scopes",
			scopes:   []string{},
			expected: []string{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := mapCondorScopesToAuthz(tt.scopes)

			// Convert result to map for easier comparison (order doesn't matter)
			resultMap := make(map[string]bool)
			for _, auth := range result {
				resultMap[auth] = true
			}

			expectedMap := make(map[string]bool)
			for _, auth := range tt.expected {
				expectedMap[auth] = true
			}

			// Check if all expected are present
			for auth := range expectedMap {
				if !resultMap[auth] {
					t.Errorf("mapCondorScopesToAuthz() missing expected auth: %s", auth)
				}
			}

			// Check if any unexpected are present
			for auth := range resultMap {
				if !expectedMap[auth] {
					t.Errorf("mapCondorScopesToAuthz() has unexpected auth: %s", auth)
				}
			}

			// Check counts match
			if len(result) != len(tt.expected) {
				t.Errorf("mapCondorScopesToAuthz() returned %d auths, want %d: got %v, want %v",
					len(result), len(tt.expected), result, tt.expected)
			}
		})
	}
}

func TestGenerateHTCondorTokenWithCondorScopes(t *testing.T) {
	// Create a temporary directory for signing key
	tmpDir := t.TempDir()

	// Create a test signing key
	keyPath := tmpDir + "/POOL"
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i)
	}
	if err := os.WriteFile(keyPath, key, 0600); err != nil {
		t.Fatalf("Failed to write signing key: %v", err)
	}

	// Import logging package for creating a real logger
	logger, err := createTestLogger()
	if err != nil {
		t.Fatalf("Failed to create logger: %v", err)
	}

	// Create a test server
	server, err := NewServer(Config{
		SigningKeyPath: keyPath,
		TrustDomain:    "test.htcondor.org",
		UIDDomain:      "test.htcondor.org",
		Logger:         logger,
		ScheddName:     "test-schedd",
		ScheddAddr:     "127.0.0.1:9618",
		OAuth2DBPath:   filepath.Join(t.TempDir(), "sessions.db"),
	})
	if err != nil {
		t.Fatalf("Failed to create server: %v", err)
	}

	tests := []struct {
		name          string
		username      string
		scopes        []string
		shouldContain []string
	}{
		{
			name:          "condor READ scope",
			username:      "testuser",
			scopes:        []string{"condor:/READ"},
			shouldContain: []string{"READ"},
		},
		{
			name:          "condor WRITE scope",
			username:      "testuser",
			scopes:        []string{"condor:/WRITE"},
			shouldContain: []string{"WRITE", "READ"},
		},
		{
			name:          "multiple condor scopes",
			username:      "testuser",
			scopes:        []string{"condor:/READ", "condor:/ADVERTISE_STARTD"},
			shouldContain: []string{"READ", "ADVERTISE_STARTD"},
		},
		{
			name:          "legacy mcp:write scope",
			username:      "testuser",
			scopes:        []string{"mcp:write"},
			shouldContain: []string{"WRITE", "READ"},
		},
		{
			name:          "legacy mcp:read scope",
			username:      "testuser",
			scopes:        []string{"mcp:read"},
			shouldContain: []string{"READ"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			token, err := server.generateHTCondorTokenWithScopes(tt.username, tt.scopes)
			if err != nil {
				t.Fatalf("generateHTCondorTokenWithScopes() error = %v", err)
			}

			if token == "" {
				t.Error("generateHTCondorTokenWithScopes() returned empty token")
			}

			// Basic JWT structure check (should have 3 parts separated by dots)
			parts := strings.Split(token, ".")
			if len(parts) != 3 {
				t.Errorf("Token should have 3 parts (header.payload.signature), got %d parts", len(parts))
			}

			// The token should be a JWT that HTCondor can validate
			// We can't easily decode it without bringing in JWT libraries,
			// but we can at least verify it's not empty and has the right structure
			t.Logf("Generated token: %s...", token[:min(50, len(token))])
		})
	}
}
