package logging

import (
	"strings"
	"testing"

	"github.com/bbockelm/golang-htcondor/config"
)

func TestParseVerbosity(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected Verbosity
	}{
		// Simple verbosity levels
		{"error lowercase", "error", VerbosityError},
		{"ERROR uppercase", "ERROR", VerbosityError},
		{"warn lowercase", "warn", VerbosityWarn},
		{"WARN uppercase", "WARN", VerbosityWarn},
		{"WARNING", "WARNING", VerbosityWarn},
		{"info lowercase", "info", VerbosityInfo},
		{"INFO uppercase", "INFO", VerbosityInfo},
		{"debug lowercase", "debug", VerbosityDebug},
		{"DEBUG uppercase", "DEBUG", VerbosityDebug},
		{"whitespace", "  INFO  ", VerbosityInfo},

		// HTCondor debug levels - single flags
		{"D_ALWAYS", "D_ALWAYS", VerbosityError},
		{"D_ERROR", "D_ERROR", VerbosityError},
		{"D_STATUS", "D_STATUS", VerbosityInfo},
		{"D_GENERAL", "D_GENERAL", VerbosityInfo},
		{"D_FULLDEBUG", "D_FULLDEBUG", VerbosityDebug},
		{"D_SECURITY", "D_SECURITY", VerbosityDebug},
		{"D_COMMAND", "D_COMMAND", VerbosityDebug},
		{"D_PROTOCOL", "D_PROTOCOL", VerbosityDebug},
		{"D_NETWORK", "D_NETWORK", VerbosityDebug},

		// HTCondor debug levels - multiple flags (should use most verbose)
		{"D_FULLDEBUG D_SECURITY", "D_FULLDEBUG D_SECURITY", VerbosityDebug},
		{"D_STATUS D_FULLDEBUG", "D_STATUS D_FULLDEBUG", VerbosityDebug},
		{"D_ALWAYS D_STATUS", "D_ALWAYS D_STATUS", VerbosityInfo},
		{"D_ERROR D_ALWAYS", "D_ERROR D_ALWAYS", VerbosityError},

		// Unknown/default
		{"unknown", "UNKNOWN_LEVEL", VerbosityInfo},
		{"empty", "", VerbosityInfo},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := parseVerbosity(tt.input)
			if result != tt.expected {
				t.Errorf("parseVerbosity(%q) = %v, expected %v", tt.input, result, tt.expected)
			}
		})
	}
}

func TestFromConfig_Verbosity(t *testing.T) {
	tests := []struct {
		name              string
		configText        string
		expectedVerbosity Verbosity
	}{
		{
			name:              "default verbosity",
			configText:        "LOG = stdout\n",
			expectedVerbosity: VerbosityInfo,
		},
		{
			name: "ERROR level",
			configText: `
LOG = stdout
LOG_VERBOSITY = ERROR
`,
			expectedVerbosity: VerbosityError,
		},
		{
			name: "WARN level",
			configText: `
LOG = stdout
LOG_VERBOSITY = WARN
`,
			expectedVerbosity: VerbosityWarn,
		},
		{
			name: "INFO level",
			configText: `
LOG = stdout
LOG_VERBOSITY = INFO
`,
			expectedVerbosity: VerbosityInfo,
		},
		{
			name: "DEBUG level",
			configText: `
LOG = stdout
LOG_VERBOSITY = DEBUG
`,
			expectedVerbosity: VerbosityDebug,
		},
		{
			name: "D_ALWAYS",
			configText: `
LOG = stdout
LOG_VERBOSITY = D_ALWAYS
`,
			expectedVerbosity: VerbosityError,
		},
		{
			name: "D_ERROR",
			configText: `
LOG = stdout
LOG_VERBOSITY = D_ERROR
`,
			expectedVerbosity: VerbosityError,
		},
		{
			name: "D_STATUS",
			configText: `
LOG = stdout
LOG_VERBOSITY = D_STATUS
`,
			expectedVerbosity: VerbosityInfo,
		},
		{
			name: "D_FULLDEBUG",
			configText: `
LOG = stdout
LOG_VERBOSITY = D_FULLDEBUG
`,
			expectedVerbosity: VerbosityDebug,
		},
		{
			name: "D_FULLDEBUG D_SECURITY (multiple flags)",
			configText: `
LOG = stdout
LOG_VERBOSITY = D_FULLDEBUG D_SECURITY
`,
			expectedVerbosity: VerbosityDebug,
		},
		{
			name: "D_STATUS D_SECURITY (mixed levels)",
			configText: `
LOG = stdout
LOG_VERBOSITY = D_STATUS D_SECURITY
`,
			expectedVerbosity: VerbosityDebug,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg, err := config.NewFromReader(strings.NewReader(tt.configText))
			if err != nil {
				t.Fatalf("Failed to create config: %v", err)
			}

			logger, err := FromConfig(cfg)
			if err != nil {
				t.Fatalf("FromConfig() error = %v", err)
			}

			if logger.config.MinVerbosity != tt.expectedVerbosity {
				t.Errorf("FromConfig() verbosity = %v, expected %v", logger.config.MinVerbosity, tt.expectedVerbosity)
			}
		})
	}
}

func TestFromConfig_OutputPath(t *testing.T) {
	tests := []struct {
		name         string
		configText   string
		expectedPath string
	}{
		{
			name:         "stdout",
			configText:   "LOG = stdout\n",
			expectedPath: "stdout",
		},
		{
			name:         "stderr",
			configText:   "LOG = stderr\n",
			expectedPath: "stderr",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg, err := config.NewFromReader(strings.NewReader(tt.configText))
			if err != nil {
				t.Fatalf("Failed to create config: %v", err)
			}

			logger, err := FromConfig(cfg)
			if err != nil {
				t.Fatalf("FromConfig() error = %v", err)
			}

			if logger.config.OutputPath != tt.expectedPath {
				t.Errorf("FromConfig() output path = %v, expected %v", logger.config.OutputPath, tt.expectedPath)
			}
		})
	}
}

func TestFromConfig_Destinations(t *testing.T) {
	tests := []struct {
		name                 string
		configText           string
		expectedDestinations map[Destination]bool
	}{
		{
			name:                 "default (all enabled)",
			configText:           "LOG = stdout\n",
			expectedDestinations: nil, // nil means all enabled
		},
		{
			name: "specific destinations",
			configText: `
LOG = stdout
LOG_DESTINATIONS = HTTP, SCHEDD, SECURITY
`,
			expectedDestinations: map[Destination]bool{
				DestinationHTTP:     true,
				DestinationSchedd:   true,
				DestinationSecurity: true,
			},
		},
		{
			name: "single destination",
			configText: `
LOG = stdout
LOG_DESTINATIONS = HTTP
`,
			expectedDestinations: map[Destination]bool{
				DestinationHTTP: true,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg, err := config.NewFromReader(strings.NewReader(tt.configText))
			if err != nil {
				t.Fatalf("Failed to create config: %v", err)
			}

			logger, err := FromConfig(cfg)
			if err != nil {
				t.Fatalf("FromConfig() error = %v", err)
			}

			// Check if the maps match
			if tt.expectedDestinations == nil {
				if len(logger.config.EnabledDestinations) != 0 {
					t.Errorf("FromConfig() destinations = %v, expected nil/empty", logger.config.EnabledDestinations)
				}
			} else {
				if len(logger.config.EnabledDestinations) != len(tt.expectedDestinations) {
					t.Errorf("FromConfig() destinations count = %d, expected %d",
						len(logger.config.EnabledDestinations), len(tt.expectedDestinations))
				}
				for dest, expected := range tt.expectedDestinations {
					if logger.config.EnabledDestinations[dest] != expected {
						t.Errorf("FromConfig() destination %v = %v, expected %v",
							dest, logger.config.EnabledDestinations[dest], expected)
					}
				}
			}
		})
	}
}

func TestFromConfig_Nil(t *testing.T) {
	logger, err := FromConfig(nil)
	if err != nil {
		t.Fatalf("FromConfig(nil) error = %v", err)
	}
	if logger == nil {
		t.Fatal("FromConfig(nil) returned nil logger")
	}
	if logger.config.MinVerbosity != VerbosityInfo {
		t.Errorf("FromConfig(nil) verbosity = %v, expected VerbosityInfo", logger.config.MinVerbosity)
	}
}
