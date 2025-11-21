package httpserver

import (
	"path/filepath"
	"testing"

	"github.com/bbockelm/golang-htcondor/config"
)

func TestGetDefaultDBPath(t *testing.T) {
	tests := []struct {
		name        string
		cfg         *config.Config
		filename    string
		expected    string
		description string
	}{
		{
			name:        "nil config",
			cfg:         nil,
			filename:    "test.db",
			expected:    filepath.Join("/var/lib/condor", "test.db"),
			description: "should fallback to /var/lib/condor when config is nil",
		},
		{
			name:        "empty config",
			cfg:         config.NewEmpty(),
			filename:    "oauth2.db",
			expected:    filepath.Join("/var/lib/condor", "oauth2.db"),
			description: "should fallback to /var/lib/condor when LOCAL_DIR is not set",
		},
		{
			name: "config with LOCAL_DIR",
			cfg: func() *config.Config {
				cfg := config.NewEmpty()
				cfg.Set("LOCAL_DIR", "/tmp/condor")
				return cfg
			}(),
			filename:    "sessions.db",
			expected:    filepath.Join("/tmp/condor", "sessions.db"),
			description: "should use LOCAL_DIR from config",
		},
		{
			name: "config with empty LOCAL_DIR",
			cfg: func() *config.Config {
				cfg := config.NewEmpty()
				cfg.Set("LOCAL_DIR", "")
				return cfg
			}(),
			filename:    "test.db",
			expected:    filepath.Join("/var/lib/condor", "test.db"),
			description: "should fallback to /var/lib/condor when LOCAL_DIR is empty string",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := getDefaultDBPath(tt.cfg, tt.filename)
			if result != tt.expected {
				t.Errorf("%s: expected %s, got %s", tt.description, tt.expected, result)
			}
		})
	}
}
