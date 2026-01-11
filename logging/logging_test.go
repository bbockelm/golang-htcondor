package logging

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
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

func TestDefaultLogPath(t *testing.T) {
	expectedDaemon := filepath.Join(defaultSystemLogDir, "HttpApiLog")
	if path := defaultLogPath("HTTP_API"); path != expectedDaemon {
		t.Fatalf("defaultLogPath(HTTP_API) = %s, expected %s", path, expectedDaemon)
	}

	expectedGeneric := filepath.Join(defaultSystemLogDir, "DaemonLog")
	if path := defaultLogPath(""); path != expectedGeneric {
		t.Fatalf("defaultLogPath(\"\") = %s, expected %s", path, expectedGeneric)
	}
}

func TestDaemonNameToCamelCase(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"", "DaemonLog"},
		{"HTTP_API", "HttpApiLog"},
		{"SCHEDD", "ScheddLog"},
		{"FOO_BAR", "FooBarLog"},
		{"A", "ALog"},
		{"A_B_C", "ABCLog"},
		{"HTTP_API_SERVER", "HttpApiServerLog"},
	}

	for _, tt := range tests {
		if result := daemonNameToCamelCase(tt.input); result != tt.expected {
			t.Errorf("daemonNameToCamelCase(%q) = %q, expected %q", tt.input, result, tt.expected)
		}
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

func TestFromConfigWithDaemon_DefaultPathAndOwnership(t *testing.T) {
	cfg, err := config.NewFromReader(strings.NewReader(""))
	if err != nil {
		t.Fatalf("Failed to create config: %v", err)
	}

	expectedPath := sanitizeOutputPath(defaultLogPath("HTTP_API"))
	logger, err := FromConfigWithDaemon("HTTP_API", cfg)
	if err != nil {
		t.Fatalf("FromConfigWithDaemon() error = %v", err)
	}

	if logger.config.OutputPath != expectedPath {
		t.Fatalf("OutputPath = %v, expected %v", logger.config.OutputPath, expectedPath)
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

func TestFromConfigWithDaemon_LogDirectory(t *testing.T) {
	// Create a writable temporary directory for file path tests
	tmpDir := t.TempDir()
	customPath := filepath.Join(tmpDir, "custom", "path.log")
	// Ensure custom path parent directory exists
	if err := os.MkdirAll(filepath.Dir(customPath), 0750); err != nil {
		t.Fatalf("Failed to create custom path directory: %v", err)
	}

	tests := []struct {
		name               string
		daemonName         string
		configText         string
		expectedOutputPath string
	}{
		{
			name:               "CUSTOM_DAEMON with LOG directory, no CUSTOM_DAEMON_LOG",
			daemonName:         "CUSTOM_DAEMON",
			configText:         "LOG = " + tmpDir + "\n",
			expectedOutputPath: filepath.Join(tmpDir, "CustomDaemonLog"),
		},
		{
			name:               "MY_SERVICE with LOG directory, no MY_SERVICE_LOG",
			daemonName:         "MY_SERVICE",
			configText:         "LOG = " + tmpDir + "\n",
			expectedOutputPath: filepath.Join(tmpDir, "MyServiceLog"),
		},
		{
			name:               "FOO_BAR with LOG directory, no FOO_BAR_LOG",
			daemonName:         "FOO_BAR",
			configText:         "LOG = " + tmpDir + "\n",
			expectedOutputPath: filepath.Join(tmpDir, "FooBarLog"),
		},
		{
			name:               "CUSTOM_DAEMON_LOG takes precedence over LOG",
			daemonName:         "CUSTOM_DAEMON",
			configText:         "LOG = " + tmpDir + "\nCUSTOM_DAEMON_LOG = " + customPath + "\n",
			expectedOutputPath: customPath,
		},
		{
			name:               "LOG stdout with daemon",
			daemonName:         "CUSTOM_DAEMON",
			configText:         "LOG = stdout\n",
			expectedOutputPath: "stdout",
		},
		{
			name:               "LOG stderr with daemon",
			daemonName:         "MY_SERVICE",
			configText:         "LOG = stderr\n",
			expectedOutputPath: "stderr",
		},
		{
			name:               "LOG STDOUT (uppercase) with daemon",
			daemonName:         "FOO_BAR",
			configText:         "LOG = STDOUT\n",
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

			if logger.config.OutputPath != tt.expectedOutputPath {
				t.Errorf("OutputPath = %v, expected %v", logger.config.OutputPath, tt.expectedOutputPath)
			}
		})
	}
}

func TestSanitizeOutputPath_FallsBackToStdoutWhenNotOwner(t *testing.T) {
	uid := os.Getuid()
	if uid == 0 {
		t.Skip("running as root; ownership fallback does not apply")
	}

	if condorUID, ok := condorUID(); ok && condorUID == uid {
		t.Skip("running as condor user; ownership fallback does not apply")
	}

	if path := sanitizeOutputPath("/etc/hosts"); path != "stdout" {
		t.Fatalf("sanitizeOutputPath(/etc/hosts) = %s, expected stdout fallback", path)
	}
}

func TestShouldLog(t *testing.T) {
	tests := []struct {
		name           string
		destLevels     map[Destination]Verbosity
		defaultLevel   Verbosity
		dest           Destination
		msgLevel       Verbosity
		expectedResult bool
	}{
		{
			name: "debug message allowed when dest is debug",
			destLevels: map[Destination]Verbosity{
				DestinationCedar: VerbosityDebug,
			},
			defaultLevel:   VerbosityWarn,
			dest:           DestinationCedar,
			msgLevel:       VerbosityDebug,
			expectedResult: true,
		},
		{
			name: "debug message blocked when dest is info",
			destLevels: map[Destination]Verbosity{
				DestinationCedar: VerbosityInfo,
			},
			defaultLevel:   VerbosityWarn,
			dest:           DestinationCedar,
			msgLevel:       VerbosityDebug,
			expectedResult: false,
		},
		{
			name: "info message allowed when dest is info",
			destLevels: map[Destination]Verbosity{
				DestinationHTTP: VerbosityInfo,
			},
			defaultLevel:   VerbosityWarn,
			dest:           DestinationHTTP,
			msgLevel:       VerbosityInfo,
			expectedResult: true,
		},
		{
			name: "warn message allowed when dest is info",
			destLevels: map[Destination]Verbosity{
				DestinationHTTP: VerbosityInfo,
			},
			defaultLevel:   VerbosityWarn,
			dest:           DestinationHTTP,
			msgLevel:       VerbosityWarn,
			expectedResult: true,
		},
		{
			name: "error message always allowed",
			destLevels: map[Destination]Verbosity{
				DestinationHTTP: VerbosityError,
			},
			defaultLevel:   VerbosityWarn,
			dest:           DestinationHTTP,
			msgLevel:       VerbosityError,
			expectedResult: true,
		},
		{
			name:           "uses default level when dest not configured",
			destLevels:     map[Destination]Verbosity{},
			defaultLevel:   VerbosityWarn,
			dest:           DestinationHTTP,
			msgLevel:       VerbosityWarn,
			expectedResult: true,
		},
		{
			name:           "default blocks debug when dest not configured",
			destLevels:     map[Destination]Verbosity{},
			defaultLevel:   VerbosityWarn,
			dest:           DestinationHTTP,
			msgLevel:       VerbosityDebug,
			expectedResult: false,
		},
		{
			name:           "nil destLevels uses default level",
			destLevels:     nil,
			defaultLevel:   VerbosityInfo,
			dest:           DestinationHTTP,
			msgLevel:       VerbosityInfo,
			expectedResult: true,
		},
		{
			name:           "default level of Error blocks Info",
			destLevels:     nil,
			defaultLevel:   VerbosityError,
			dest:           DestinationHTTP,
			msgLevel:       VerbosityInfo,
			expectedResult: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			logger := &Logger{
				config: &Config{
					DestinationLevels: tt.destLevels,
					DefaultLevel:      tt.defaultLevel,
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
	//nolint:gosec // G304 - logPath is test directory temp file, not user-controlled
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
	//nolint:gosec // G304 - logPath is test directory temp file, not user-controlled
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

func TestPerformMaintenance_ExternalRotation(t *testing.T) {
	tmpDir := t.TempDir()
	logPath := tmpDir + "/test.log"

	// Create logger
	logger, err := New(&Config{
		OutputPath: logPath,
		MaxLogSize: 1000000,
		DestinationLevels: map[Destination]Verbosity{
			DestinationGeneral: VerbosityDebug,
		},
	})
	if err != nil {
		t.Fatalf("Failed to create logger: %v", err)
	}

	// Write a message
	logger.Info(DestinationGeneral, "Test message before rotation")

	// Simulate external rotation by moving the log file
	if err := os.Rename(logPath, logPath+".rotated"); err != nil {
		t.Fatalf("Failed to simulate external rotation: %v", err)
	}

	// Perform maintenance - should detect the rotation and reopen
	if err := logger.PerformMaintenance(); err != nil {
		t.Fatalf("PerformMaintenance failed: %v", err)
	}

	// Write another message - should work with the new file
	logger.Info(DestinationGeneral, "Test message after rotation")

	// Verify the new file exists
	if _, err := os.Stat(logPath); os.IsNotExist(err) {
		t.Error("Expected log file to be recreated after external rotation")
	}

	// Verify the rotated file still exists
	if _, err := os.Stat(logPath + ".rotated"); os.IsNotExist(err) {
		t.Error("Expected rotated file to still exist")
	}
}

func TestPerformMaintenance_ExternalDeletion(t *testing.T) {
	tmpDir := t.TempDir()
	logPath := tmpDir + "/test.log"

	// Create logger
	logger, err := New(&Config{
		OutputPath: logPath,
		MaxLogSize: 1000000,
		DestinationLevels: map[Destination]Verbosity{
			DestinationGeneral: VerbosityDebug,
		},
	})
	if err != nil {
		t.Fatalf("Failed to create logger: %v", err)
	}

	// Write a message
	logger.Info(DestinationGeneral, "Test message before deletion")

	// Simulate external deletion
	if err := os.Remove(logPath); err != nil {
		t.Fatalf("Failed to simulate external deletion: %v", err)
	}

	// Perform maintenance - should detect the deletion and reopen
	if err := logger.PerformMaintenance(); err != nil {
		t.Fatalf("PerformMaintenance failed: %v", err)
	}

	// Write another message - should work with the new file
	logger.Info(DestinationGeneral, "Test message after deletion")

	// Verify the new file exists
	if _, err := os.Stat(logPath); os.IsNotExist(err) {
		t.Error("Expected log file to be recreated after external deletion")
	}
}

func TestStartMaintenance(t *testing.T) {
	tmpDir := t.TempDir()
	logPath := tmpDir + "/test.log"

	// Create logger with short touch interval for testing
	logger, err := New(&Config{
		OutputPath:       logPath,
		TouchLogInterval: 1, // 1 second
		DestinationLevels: map[Destination]Verbosity{
			DestinationGeneral: VerbosityDebug,
		},
	})
	if err != nil {
		t.Fatalf("Failed to create logger: %v", err)
	}

	// Create context for maintenance
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Start maintenance
	if err := logger.StartMaintenance(ctx); err != nil {
		t.Fatalf("StartMaintenance failed: %v", err)
	}

	// Verify maintenance is running
	if !logger.maintRunning.Load() {
		t.Error("Expected maintenance to be running")
	}

	// Write a message
	logger.Info(DestinationGeneral, "Test message")

	// Cancel context to stop maintenance
	cancel()

	// Stop maintenance (wait for goroutine)
	logger.StopMaintenance()

	// Verify maintenance stopped
	if logger.maintRunning.Load() {
		t.Error("Expected maintenance to be stopped")
	}
}

func TestFromConfigWithDaemon_TouchLogInterval(t *testing.T) {
	tests := []struct {
		name             string
		configText       string
		daemonName       string
		expectedInterval int
	}{
		{
			name:       "Custom touch interval",
			daemonName: "HTTP_API",
			configText: `
HTTP_API_LOG = /tmp/http_api.log
TOUCH_LOG_INTERVAL = 120
`,
			expectedInterval: 120,
		},
		{
			name:       "Default touch interval",
			daemonName: "SCHEDD",
			configText: `
SCHEDD_LOG = /tmp/schedd.log
`,
			expectedInterval: DefaultTouchLogInterval,
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

			if logger.config.TouchLogInterval != tt.expectedInterval {
				t.Errorf("TouchLogInterval = %v, expected %v", logger.config.TouchLogInterval, tt.expectedInterval)
			}
		})
	}
}

func TestAtomicRotation(t *testing.T) {
	tmpDir := t.TempDir()
	logPath := tmpDir + "/test.log"

	// Create logger with small max size
	logger, err := New(&Config{
		OutputPath: logPath,
		MaxLogSize: 200,
		MaxNumLogs: 2,
		DestinationLevels: map[Destination]Verbosity{
			DestinationGeneral: VerbosityDebug,
		},
	})
	if err != nil {
		t.Fatalf("Failed to create logger: %v", err)
	}

	// Write enough messages to trigger rotation
	// The atomic logic should ensure only one goroutine rotates
	for i := 0; i < 10; i++ {
		logger.Info(DestinationGeneral, "Test message that may trigger rotation", "iteration", i)
	}

	// Verify rotation happened
	if _, err := os.Stat(logPath + ".old"); os.IsNotExist(err) {
		t.Error("Expected .old log file to exist after rotation")
	}
}

// TestFilteringHandlerWithDirectSlogCalls tests that the filteringHandler
// properly filters direct slog calls (like those from Cedar) based on destination
func TestFilteringHandlerWithDirectSlogCalls(t *testing.T) {
	tmpDir := t.TempDir()
	logPath := tmpDir + "/test.log"

	// Create logger with specific destination levels
	logger, err := New(&Config{
		OutputPath: logPath,
		DestinationLevels: map[Destination]Verbosity{
			DestinationCedar:  VerbosityWarn,  // Cedar should only see WARN and above
			DestinationHTTP:   VerbosityInfo,  // HTTP should see INFO and above
			DestinationSchedd: VerbosityDebug, // Schedd should see everything
		},
	})
	if err != nil {
		t.Fatalf("Failed to create logger: %v", err)
	}

	// Test direct slog calls with different levels and destinations
	// These should be filtered by the filteringHandler

	// Cedar INFO should be filtered out (Cedar is WARN level)
	logger.Info(DestinationCedar, "Cedar INFO - should be filtered")

	// Cedar WARN should appear
	logger.Warn(DestinationCedar, "Cedar WARN - should appear")

	// HTTP DEBUG should be filtered out (HTTP is INFO level)
	logger.Debug(DestinationHTTP, "HTTP DEBUG - should be filtered")

	// HTTP INFO should appear
	logger.Info(DestinationHTTP, "HTTP INFO - should appear")

	// Schedd DEBUG should appear (Schedd is DEBUG level)
	logger.Debug(DestinationSchedd, "Schedd DEBUG - should appear")

	// Read log file
	//nolint:gosec // G304 - logPath is test directory temp file, not user-controlled
	content, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatalf("Failed to read log file: %v", err)
	}

	logContent := string(content)

	// Verify filtered messages don't appear
	if strings.Contains(logContent, "Cedar INFO - should be filtered") {
		t.Error("Cedar INFO message should have been filtered out")
	}
	if strings.Contains(logContent, "HTTP DEBUG - should be filtered") {
		t.Error("HTTP DEBUG message should have been filtered out")
	}

	// Verify allowed messages appear
	if !strings.Contains(logContent, "Cedar WARN - should appear") {
		t.Error("Cedar WARN message should appear in log")
	}
	if !strings.Contains(logContent, "HTTP INFO - should appear") {
		t.Error("HTTP INFO message should appear in log")
	}
	if !strings.Contains(logContent, "Schedd DEBUG - should appear") {
		t.Error("Schedd DEBUG message should appear in log")
	}
}

// TestDefaultLevel tests that the DefaultLevel setting works for unhandled destinations
func TestDefaultLevel(t *testing.T) {
	tempDir := t.TempDir()
	logPath := filepath.Join(tempDir, "test.log")

	// Create logger with DefaultLevel=VerbosityError (only errors)
	// Only configure HTTP destination explicitly, leave others to use default
	cfg := &Config{
		OutputPath: logPath,
		DestinationLevels: map[Destination]Verbosity{
			DestinationHTTP: VerbosityInfo, // HTTP allows INFO and above
		},
		DefaultLevel:      VerbosityError, // Default for unconfigured destinations: ERROR only
		SkipGlobalInstall: true,           // Don't affect global logger
	}

	logger, err := New(cfg)
	if err != nil {
		t.Fatalf("Failed to create logger: %v", err)
	}

	// HTTP (configured): INFO should appear
	logger.Info(DestinationHTTP, "HTTP INFO - should appear")

	// Schedd (not configured, uses DefaultLevel=Error): INFO should be filtered
	logger.Info(DestinationSchedd, "Schedd INFO - should be filtered")

	// Schedd (not configured, uses DefaultLevel=Error): ERROR should appear
	logger.Error(DestinationSchedd, "Schedd ERROR - should appear")

	// Cedar (not configured, uses DefaultLevel=Error): WARN should be filtered
	logger.Warn(DestinationCedar, "Cedar WARN - should be filtered")

	// Cedar (not configured, uses DefaultLevel=Error): ERROR should appear
	logger.Error(DestinationCedar, "Cedar ERROR - should appear")

	// Read log file
	//nolint:gosec // G304 - logPath is test directory temp file, not user-controlled
	content, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatalf("Failed to read log file: %v", err)
	}

	logContent := string(content)

	// Verify filtered messages (below default level)
	if strings.Contains(logContent, "Schedd INFO - should be filtered") {
		t.Error("Schedd INFO should be filtered (DefaultLevel=Error)")
	}
	if strings.Contains(logContent, "Cedar WARN - should be filtered") {
		t.Error("Cedar WARN should be filtered (DefaultLevel=Error)")
	}

	// Verify allowed messages
	if !strings.Contains(logContent, "HTTP INFO - should appear") {
		t.Error("HTTP INFO should appear (explicitly configured)")
	}
	if !strings.Contains(logContent, "Schedd ERROR - should appear") {
		t.Error("Schedd ERROR should appear (matches DefaultLevel)")
	}
	if !strings.Contains(logContent, "Cedar ERROR - should appear") {
		t.Error("Cedar ERROR should appear (matches DefaultLevel)")
	}
}

// TestSkipGlobalInstall tests that SkipGlobalInstall controls global slog installation
func TestSkipGlobalInstall(t *testing.T) {
	tempDir := t.TempDir()
	logPath := filepath.Join(tempDir, "test.log")

	t.Run("SkipGlobalInstall=false (default, installs globally)", func(t *testing.T) {
		// Create logger that installs globally (default behavior)
		cfg := &Config{
			OutputPath: logPath,
			DestinationLevels: map[Destination]Verbosity{
				DestinationCedar: VerbosityWarn, // Cedar at WARN level
			},
			DefaultLevel: VerbosityInfo,
			// SkipGlobalInstall defaults to false, so logger installs globally
		}

		_, err := New(cfg)
		if err != nil {
			t.Fatalf("Failed to create logger: %v", err)
		}

		// Direct slog call should use our logger
		// This simulates what Cedar library does
		ctx := context.Background()
		slog.InfoContext(ctx, "Direct slog INFO", "destination", "cedar")

		// Read log file
		//nolint:gosec // G304 - logPath is test directory temp file, not user-controlled
		content, err := os.ReadFile(logPath)
		if err != nil {
			t.Fatalf("Failed to read log file: %v", err)
		}

		logContent := string(content)

		// Cedar INFO should be filtered (Cedar configured at WARN)
		if strings.Contains(logContent, "Direct slog INFO") {
			t.Error("Direct slog INFO to Cedar should be filtered (Cedar at WARN level)")
		}
	})

	// Clear log file for next test
	//nolint:gosec // G304 - logPath is test directory temp file, not user-controlled
	if err := os.Remove(logPath); err != nil && !os.IsNotExist(err) {
		t.Fatalf("Failed to clear log file: %v", err)
	}

	t.Run("SkipGlobalInstall=true (skips global install)", func(t *testing.T) {
		// Create logger that does NOT install globally
		cfg := &Config{
			OutputPath: logPath,
			DestinationLevels: map[Destination]Verbosity{
				DestinationCedar: VerbosityError, // Cedar at ERROR level
			},
			DefaultLevel:      VerbosityInfo,
			SkipGlobalInstall: true, // Should NOT set global logger
		}

		_, err := New(cfg)
		if err != nil {
			t.Fatalf("Failed to create logger: %v", err)
		}

		// Direct slog calls should NOT use our logger (uses default slog)
		// So they won't be written to our log file
		ctx := context.Background()
		slog.InfoContext(ctx, "Direct slog INFO", "destination", "cedar")

		// Read log file
		//nolint:gosec // G304 - logPath is test directory temp file, not user-controlled
		content, err := os.ReadFile(logPath)
		if err != nil && !os.IsNotExist(err) {
			t.Fatalf("Failed to read log file: %v", err)
		}

		logContent := string(content)

		// Since SkipGlobalInstall=true, direct slog calls should NOT go to our file
		// (They would go to stderr or wherever the default slog is configured)
		if strings.Contains(logContent, "Direct slog INFO") {
			t.Error("Direct slog call should NOT appear when SkipGlobalInstall=true")
		}
	})
}
