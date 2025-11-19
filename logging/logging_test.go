package logging

import (
	"strings"
	"testing"

	"github.com/bbockelm/golang-htcondor/config"
)

func TestParseLevel(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected Verbosity
	}{
		// String levels (case insensitive)
		{"error lowercase", "error", VerbosityError},
		{"ERROR uppercase", "ERROR", VerbosityError},
		{"warn lowercase", "warn", VerbosityWarn},
		{"WARN uppercase", "WARN", VerbosityWarn},
		{"WARNING", "warning", VerbosityWarn},
		{"info lowercase", "info", VerbosityInfo},
		{"INFO uppercase", "INFO", VerbosityInfo},
		{"debug lowercase", "debug", VerbosityDebug},
		{"DEBUG uppercase", "DEBUG", VerbosityDebug},
		{"whitespace", "  info  ", VerbosityInfo},

		// Integer levels
		{"0 (off/error)", "0", VerbosityError},
		{"1 (info)", "1", VerbosityInfo},
		{"2 (debug)", "2", VerbosityDebug},

		// Unknown/default
		{"unknown", "unknown_level", VerbosityWarn},
		{"empty", "", VerbosityWarn},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := parseLevel(tt.input)
			if result != tt.expected {
				t.Errorf("parseLevel(%q) = %v, expected %v", tt.input, result, tt.expected)
			}
		})
	}
}

func TestParseDestination(t *testing.T) {
	tests := []struct {
		name        string
		input       string
		expectedDst Destination
		expectedOk  bool
	}{
		{"general", "general", DestinationGeneral, true},
		{"http", "http", DestinationHTTP, true},
		{"HTTP uppercase", "HTTP", DestinationHTTP, true},
		{"schedd", "schedd", DestinationSchedd, true},
		{"collector", "collector", DestinationCollector, true},
		{"metrics", "metrics", DestinationMetrics, true},
		{"security", "security", DestinationSecurity, true},
		{"cedar", "cedar", DestinationCedar, true},
		{"CEDAR uppercase", "CEDAR", DestinationCedar, true},
		{"unknown", "unknown", DestinationGeneral, false},
		{"empty", "", DestinationGeneral, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dst, ok := parseDestination(tt.input)
			if dst != tt.expectedDst || ok != tt.expectedOk {
				t.Errorf("parseDestination(%q) = (%v, %v), expected (%v, %v)",
					tt.input, dst, ok, tt.expectedDst, tt.expectedOk)
			}
		})
	}
}

func TestFromConfigWithDaemon(t *testing.T) {
	tests := []struct {
		name               string
		daemonName         string
		configText         string
		expectedLevels     map[Destination]Verbosity
		expectedOutputPath string
	}{
		{
			name:       "HTTP_API_DEBUG with cedar:debug",
			daemonName: "HTTP_API",
			configText: `
LOG = stdout
HTTP_API_DEBUG = cedar:debug
`,
			expectedLevels: map[Destination]Verbosity{
				DestinationCedar: VerbosityDebug,
			},
			expectedOutputPath: "stdout",
		},
		{
			name:       "HTTP_API_DEBUG with multiple destinations",
			daemonName: "HTTP_API",
			configText: `
LOG = stderr
HTTP_API_DEBUG = cedar:debug, http:info, schedd:warn
`,
			expectedLevels: map[Destination]Verbosity{
				DestinationCedar:  VerbosityDebug,
				DestinationHTTP:   VerbosityInfo,
				DestinationSchedd: VerbosityWarn,
			},
			expectedOutputPath: "stderr",
		},
		{
			name:       "SCHEDD_DEBUG with numeric levels",
			daemonName: "SCHEDD",
			configText: `
LOG = stdout
SCHEDD_DEBUG = cedar:2 schedd:1
`,
			expectedLevels: map[Destination]Verbosity{
				DestinationCedar:  VerbosityDebug,
				DestinationSchedd: VerbosityInfo,
			},
			expectedOutputPath: "stdout",
		},
		{
			name:       "Mixed case destinations and levels",
			daemonName: "HTTP_API",
			configText: `
LOG = stdout
HTTP_API_DEBUG = CEDAR:DEBUG HTTP:INFO
`,
			expectedLevels: map[Destination]Verbosity{
				DestinationCedar: VerbosityDebug,
				DestinationHTTP:  VerbosityInfo,
			},
			expectedOutputPath: "stdout",
		},
		{
			name:               "No debug config (defaults to warn)",
			daemonName:         "HTTP_API",
			configText:         "LOG = stdout\n",
			expectedLevels:     map[Destination]Verbosity{},
			expectedOutputPath: "stdout",
		},
		{
			name:       "Malformed pairs are skipped",
			daemonName: "HTTP_API",
			configText: `
LOG = stdout
HTTP_API_DEBUG = cedar:debug, invalid, http:info
`,
			expectedLevels: map[Destination]Verbosity{
				DestinationCedar: VerbosityDebug,
				DestinationHTTP:  VerbosityInfo,
			},
			expectedOutputPath: "stdout",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg, err := config.NewFromReader(strings.NewReader(tt.configText))
			if err != nil {
				t.Fatalf("Failed to create config: %v", err)
			}

			logger, err := FromConfigWithDaemon(tt.daemonName, cfg)
			if err != nil {
				t.Fatalf("FromConfigWithDaemon() error = %v", err)
			}

			// Check output path
			if logger.config.OutputPath != tt.expectedOutputPath {
				t.Errorf("OutputPath = %v, expected %v", logger.config.OutputPath, tt.expectedOutputPath)
			}

			// Check destination levels
			if len(logger.config.DestinationLevels) != len(tt.expectedLevels) {
				t.Errorf("DestinationLevels count = %d, expected %d",
					len(logger.config.DestinationLevels), len(tt.expectedLevels))
			}
			for dest, expectedLevel := range tt.expectedLevels {
				if logger.config.DestinationLevels[dest] != expectedLevel {
					t.Errorf("DestinationLevels[%v] = %v, expected %v",
						dest, logger.config.DestinationLevels[dest], expectedLevel)
				}
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

func TestShouldLog(t *testing.T) {
	tests := []struct {
		name           string
		destLevels     map[Destination]Verbosity
		dest           Destination
		msgLevel       Verbosity
		expectedResult bool
	}{
		{
			name: "debug message allowed when dest is debug",
			destLevels: map[Destination]Verbosity{
				DestinationCedar: VerbosityDebug,
			},
			dest:           DestinationCedar,
			msgLevel:       VerbosityDebug,
			expectedResult: true,
		},
		{
			name: "debug message blocked when dest is info",
			destLevels: map[Destination]Verbosity{
				DestinationCedar: VerbosityInfo,
			},
			dest:           DestinationCedar,
			msgLevel:       VerbosityDebug,
			expectedResult: false,
		},
		{
			name: "info message allowed when dest is info",
			destLevels: map[Destination]Verbosity{
				DestinationHTTP: VerbosityInfo,
			},
			dest:           DestinationHTTP,
			msgLevel:       VerbosityInfo,
			expectedResult: true,
		},
		{
			name: "warn message allowed when dest is info",
			destLevels: map[Destination]Verbosity{
				DestinationHTTP: VerbosityInfo,
			},
			dest:           DestinationHTTP,
			msgLevel:       VerbosityWarn,
			expectedResult: true,
		},
		{
			name: "error message always allowed",
			destLevels: map[Destination]Verbosity{
				DestinationHTTP: VerbosityError,
			},
			dest:           DestinationHTTP,
			msgLevel:       VerbosityError,
			expectedResult: true,
		},
		{
			name:           "default to warn when dest not configured",
			destLevels:     map[Destination]Verbosity{},
			dest:           DestinationHTTP,
			msgLevel:       VerbosityWarn,
			expectedResult: true,
		},
		{
			name:           "default blocks debug when dest not configured",
			destLevels:     map[Destination]Verbosity{},
			dest:           DestinationHTTP,
			msgLevel:       VerbosityDebug,
			expectedResult: false,
		},
		{
			name:           "nil destLevels defaults to warn",
			destLevels:     nil,
			dest:           DestinationHTTP,
			msgLevel:       VerbosityWarn,
			expectedResult: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			logger := &Logger{
				config: &Config{
					DestinationLevels: tt.destLevels,
				},
			}

			result := logger.shouldLog(tt.dest, tt.msgLevel)
			if result != tt.expectedResult {
				t.Errorf("shouldLog(%v, %v) = %v, expected %v",
					tt.dest, tt.msgLevel, result, tt.expectedResult)
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
}

func TestFromConfigWithDaemon_Nil(t *testing.T) {
	logger, err := FromConfigWithDaemon("HTTP_API", nil)
	if err != nil {
		t.Fatalf("FromConfigWithDaemon(nil) error = %v", err)
	}
	if logger == nil {
		t.Fatal("FromConfigWithDaemon(nil) returned nil logger")
	}
}
