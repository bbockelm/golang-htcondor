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
			name:     "empty config",
			cfg:      config.NewEmpty(),
			filename: "oauth2.db",
			// LOCAL_DIR's param default is "$(TILDE)" which expands
			// to the condor user's home directory; on the test
			// host that's /var/lib/condor. From there our default
			// adds the lib/condor sub-dir, mirroring stock RPM
			// layout where SPOOL / EXECUTE live under
			// $(LOCAL_DIR)/lib/condor on hosts whose LOCAL_DIR is
			// /var (rather than /var/lib/condor).
			expected:    filepath.Join("/var/lib/condor", "lib", "condor", "oauth2.db"),
			description: "should derive LOCAL_DIR from $(TILDE) and append lib/condor",
		},
		{
			name: "config with LOCAL_DIR",
			cfg: func() *config.Config {
				cfg := config.NewEmpty()
				cfg.Set("LOCAL_DIR", "/tmp/condor")
				return cfg
			}(),
			filename: "sessions.db",
			// Path lives under LOCAL_DIR/lib/condor — same parent
			// dir as EXECUTE / SPOOL / job_queue.log on a stock
			// HTCondor install, so existing backup and quota
			// policies for that tree apply to us automatically.
			expected:    filepath.Join("/tmp/condor", "lib", "condor", "sessions.db"),
			description: "should use LOCAL_DIR/lib/condor from config",
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
