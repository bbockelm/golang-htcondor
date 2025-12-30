package logging

import (
	"fmt"
	"os"
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

// Test log rotation functionality
func TestLogRotation(t *testing.T) {
	// Create temp directory for test logs
	tmpDir := t.TempDir()
	logPath := tmpDir + "/test.log"

	// Create logger with small max size for testing
	logger, err := New(&Config{
		OutputPath: logPath,
		MaxLogSize: 200, // Very small for testing
		MaxNumLogs: 3,
		DestinationLevels: map[Destination]Verbosity{
			DestinationGeneral: VerbosityDebug,
		},
	})
	if err != nil {
		t.Fatalf("Failed to create logger: %v", err)
	}

	// Write messages to trigger rotation
	for i := 0; i < 5; i++ {
		logger.Info(DestinationGeneral, "Test message that is long enough to trigger rotation", "iteration", i)
	}

	// Check that rotated log files exist
	if _, err := os.Stat(logPath + ".old"); os.IsNotExist(err) {
		t.Error("Expected .old log file to exist")
	}
}

func TestLogRotation_MultipleRotations(t *testing.T) {
	tmpDir := t.TempDir()
	logPath := tmpDir + "/test.log"

	// Create logger with very small max size and multiple logs to keep
	logger, err := New(&Config{
		OutputPath: logPath,
		MaxLogSize: 150,
		MaxNumLogs: 3,
		DestinationLevels: map[Destination]Verbosity{
			DestinationGeneral: VerbosityDebug,
		},
	})
	if err != nil {
		t.Fatalf("Failed to create logger: %v", err)
	}

	// Write enough messages to trigger multiple rotations
	for i := 0; i < 10; i++ {
		logger.Info(DestinationGeneral, "Test message iteration", "i", i, "data", "some additional data here")
	}

	// Check that current log exists
	if _, err := os.Stat(logPath); os.IsNotExist(err) {
		t.Error("Expected current log file to exist")
	}

	// Check that .old exists
	if _, err := os.Stat(logPath + ".old"); os.IsNotExist(err) {
		t.Error("Expected .old log file to exist")
	}

	// Check that we don't have more than MaxNumLogs rotated logs
	// We should have at most .old, .old.1, .old.2
	oldestLog := logPath + ".old.3"
	if _, err := os.Stat(oldestLog); !os.IsNotExist(err) {
		t.Errorf("Expected oldest log %s to not exist (should have been deleted)", oldestLog)
	}
}

func TestLogRotation_TruncateOnOpen(t *testing.T) {
	tmpDir := t.TempDir()
	logPath := tmpDir + "/test.log"

	// Create a log file with existing content
	err := os.WriteFile(logPath, []byte("existing content\n"), 0600)
	if err != nil {
		t.Fatalf("Failed to create initial log file: %v", err)
	}

	// Create logger with TruncateOnOpen = true
	logger, err := New(&Config{
		OutputPath:     logPath,
		TruncateOnOpen: true,
		DestinationLevels: map[Destination]Verbosity{
			DestinationGeneral: VerbosityDebug,
		},
	})
	if err != nil {
		t.Fatalf("Failed to create logger: %v", err)
	}

	// Write a message
	logger.Info(DestinationGeneral, "New message after truncate")

	// Read the log file
	content, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatalf("Failed to read log file: %v", err)
	}

	// The old content should not be present
	if strings.Contains(string(content), "existing content") {
		t.Error("Expected old content to be truncated")
	}

	// New message should be present
	if !strings.Contains(string(content), "New message after truncate") {
		t.Error("Expected new message to be in log file")
	}
}

func TestLogRotation_NoTruncateOnOpen(t *testing.T) {
	tmpDir := t.TempDir()
	logPath := tmpDir + "/test.log"

	// Create a log file with existing content
	existingContent := "existing content line 1\n"
	err := os.WriteFile(logPath, []byte(existingContent), 0600)
	if err != nil {
		t.Fatalf("Failed to create initial log file: %v", err)
	}

	// Create logger with TruncateOnOpen = false (default)
	logger, err := New(&Config{
		OutputPath:     logPath,
		TruncateOnOpen: false,
		DestinationLevels: map[Destination]Verbosity{
			DestinationGeneral: VerbosityDebug,
		},
	})
	if err != nil {
		t.Fatalf("Failed to create logger: %v", err)
	}

	// Write a message
	logger.Info(DestinationGeneral, "New message after opening")

	// Read the log file
	content, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatalf("Failed to read log file: %v", err)
	}

	// Both old and new content should be present
	if !strings.Contains(string(content), "existing content") {
		t.Error("Expected old content to be preserved")
	}

	if !strings.Contains(string(content), "New message after opening") {
		t.Error("Expected new message to be in log file")
	}
}

func TestFromConfigWithDaemon_RotationParams(t *testing.T) {
	tests := []struct {
		name             string
		configText       string
		daemonName       string
		expectedMaxSize  int64
		expectedMaxNum   int
		expectedTruncate bool
	}{
		{
			name:       "Custom rotation parameters",
			daemonName: "HTTP_API",
			configText: `
HTTP_API_LOG = /tmp/http_api.log
MAX_HTTP_API_LOG = 5242880
MAX_NUM_HTTP_API_LOG = 5
TRUNC_HTTP_API_LOG_ON_OPEN = true
`,
			expectedMaxSize:  5242880,
			expectedMaxNum:   5,
			expectedTruncate: true,
		},
		{
			name:       "Default rotation parameters",
			daemonName: "SCHEDD",
			configText: `
SCHEDD_LOG = /tmp/schedd.log
`,
			expectedMaxSize:  DefaultMaxLogSize,
			expectedMaxNum:   DefaultMaxNumLogs,
			expectedTruncate: false,
		},
		{
			name:       "Partial rotation parameters",
			daemonName: "COLLECTOR",
			configText: `
COLLECTOR_LOG = /tmp/collector.log
MAX_COLLECTOR_LOG = 1048576
`,
			expectedMaxSize:  1048576,
			expectedMaxNum:   DefaultMaxNumLogs,
			expectedTruncate: false,
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

			if logger.config.MaxLogSize != tt.expectedMaxSize {
				t.Errorf("MaxLogSize = %v, expected %v", logger.config.MaxLogSize, tt.expectedMaxSize)
			}

			if logger.config.MaxNumLogs != tt.expectedMaxNum {
				t.Errorf("MaxNumLogs = %v, expected %v", logger.config.MaxNumLogs, tt.expectedMaxNum)
			}

			if logger.config.TruncateOnOpen != tt.expectedTruncate {
				t.Errorf("TruncateOnOpen = %v, expected %v", logger.config.TruncateOnOpen, tt.expectedTruncate)
			}
		})
	}
}

func TestLogRotation_StdoutStderr(t *testing.T) {
	// Test that rotation is skipped for stdout/stderr
	logger, err := New(&Config{
		OutputPath: "stdout",
		MaxLogSize: 100, // Small size
		DestinationLevels: map[Destination]Verbosity{
			DestinationGeneral: VerbosityDebug,
		},
	})
	if err != nil {
		t.Fatalf("Failed to create logger: %v", err)
	}

	// Should not panic or error even though we write more than MaxLogSize
	for i := 0; i < 10; i++ {
		logger.Info(DestinationGeneral, "Test message to stdout that should not cause rotation issues")
	}

	// No errors expected - test passes if we get here
}

func TestLogRotation_FileNaming(t *testing.T) {
	tmpDir := t.TempDir()
	logPath := tmpDir + "/daemon.log"

	// Create logger
	logger, err := New(&Config{
		OutputPath: logPath,
		MaxLogSize: 150,
		MaxNumLogs: 4,
		DestinationLevels: map[Destination]Verbosity{
			DestinationGeneral: VerbosityDebug,
		},
	})
	if err != nil {
		t.Fatalf("Failed to create logger: %v", err)
	}

	// Write enough to trigger several rotations
	for i := 0; i < 15; i++ {
		logger.Info(DestinationGeneral, "Message to trigger rotation with some extra data", "iteration", i)
	}

	// Check that current log exists
	if _, err := os.Stat(logPath); os.IsNotExist(err) {
		t.Errorf("Expected current log file %s to exist", logPath)
	}

	// Check that at least .old exists (we definitely triggered at least one rotation)
	if _, err := os.Stat(logPath + ".old"); os.IsNotExist(err) {
		t.Errorf("Expected file %s to exist", logPath+".old")
	}

	// Optional: Check if numbered old files exist (may or may not, depending on rotation count)
	// This is just informational, not a failure
	for i := 1; i < 4; i++ {
		numberedFile := fmt.Sprintf("%s.old.%d", logPath, i)
		if _, err := os.Stat(numberedFile); err == nil {
			t.Logf("Found numbered log file: %s", numberedFile)
		}
	}
}
