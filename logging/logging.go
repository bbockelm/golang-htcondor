// Package logging provides structured logging functionality for HTCondor applications.
//
// It wraps Go's standard log/slog package with additional features:
//   - Destination-based filtering (HTTP, Schedd, Collector, etc.)
//   - Verbosity levels (Error, Warn, Info, Debug)
//   - Configuration from HTCondor config files
//   - Support for both structured and printf-style logging
package logging

import (
	"fmt"
	"io"
	"log/slog"
	"os"
	"strings"

	"github.com/bbockelm/golang-htcondor/config"
)

// Verbosity levels for logging
type Verbosity int

// Verbosity levels for logging.
const (
	// VerbosityError logs only error messages
	VerbosityError Verbosity = iota
	// VerbosityWarn logs warnings and errors
	VerbosityWarn
	// VerbosityInfo logs informational messages, warnings, and errors
	VerbosityInfo
	// VerbosityDebug logs all messages including debug information
	VerbosityDebug
)

// Destination represents where logs should be written
type Destination int

// Destination categories for log filtering.
const (
	DestinationGeneral   Destination = iota // General application logs
	DestinationHTTP                         // HTTP server logs
	DestinationSchedd                       // Schedd interaction logs
	DestinationCollector                    // Collector interaction logs
	DestinationMetrics                      // Metrics collection logs
	DestinationSecurity                     // Security/auth logs
)

// Config holds logging configuration
type Config struct {
	// OutputPath is where logs are written ("stdout", "stderr", or file path)
	OutputPath string
	// MinVerbosity is the minimum verbosity level to log
	MinVerbosity Verbosity
	// EnabledDestinations specifies which destinations are enabled
	// If nil or empty, all destinations are enabled
	EnabledDestinations map[Destination]bool
}

// Logger wraps slog.Logger with destination and verbosity filtering
type Logger struct {
	config *Config
	logger *slog.Logger
}

// New creates a new Logger with the given configuration
func New(config *Config) (*Logger, error) {
	if config == nil {
		config = &Config{
			OutputPath:   "stderr",
			MinVerbosity: VerbosityInfo,
		}
	}

	// Determine output writer
	var writer io.Writer
	switch config.OutputPath {
	case "stdout", "":
		writer = os.Stdout
	case "stderr":
		writer = os.Stderr
	default:
		// File path
		f, err := os.OpenFile(config.OutputPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0600)
		if err != nil {
			return nil, err
		}
		writer = f
	}

	// Convert our verbosity to slog level
	var slogLevel slog.Level
	switch config.MinVerbosity {
	case VerbosityError:
		slogLevel = slog.LevelError
	case VerbosityWarn:
		slogLevel = slog.LevelWarn
	case VerbosityInfo:
		slogLevel = slog.LevelInfo
	case VerbosityDebug:
		slogLevel = slog.LevelDebug
	default:
		slogLevel = slog.LevelInfo
	}

	// Create slog handler with options
	opts := &slog.HandlerOptions{
		Level: slogLevel,
	}

	handler := slog.NewTextHandler(writer, opts)
	logger := slog.New(handler)

	return &Logger{
		config: config,
		logger: logger,
	}, nil
}

// parseVerbosity converts a verbosity string to a Verbosity level.
// Supports both simple levels (ERROR, WARN, INFO, DEBUG) and HTCondor-style
// debug levels (D_ALWAYS, D_ERROR, D_STATUS, D_FULLDEBUG, etc.).
func parseVerbosity(level string) Verbosity {
	level = strings.ToUpper(strings.TrimSpace(level))

	// Handle simple verbosity levels
	switch level {
	case "ERROR":
		return VerbosityError
	case "WARN", "WARNING":
		return VerbosityWarn
	case "INFO":
		return VerbosityInfo
	case "DEBUG":
		return VerbosityDebug
	}

	// Handle HTCondor-style debug levels
	// HTCondor debug levels can be space-separated (e.g., "D_FULLDEBUG D_SECURITY")
	// We'll use the most verbose (highest) level specified
	hasMatch := false
	verbosity := VerbosityError // Start with least verbose
	parts := strings.Fields(level)

	for _, part := range parts {
		switch part {
		case "D_ALWAYS":
			// D_ALWAYS is for critical messages, map to Error
			hasMatch = true
			if verbosity < VerbosityError {
				verbosity = VerbosityError
			}
		case "D_ERROR":
			// D_ERROR maps to Error level
			hasMatch = true
			if verbosity < VerbosityError {
				verbosity = VerbosityError
			}
		case "D_STATUS", "D_GENERAL":
			// D_STATUS maps to Info level
			hasMatch = true
			if verbosity < VerbosityInfo {
				verbosity = VerbosityInfo
			}
		case "D_FULLDEBUG", "D_SECURITY", "D_COMMAND", "D_PROTOCOL", "D_NETWORK":
			// D_FULLDEBUG and other specific debug categories map to Debug level
			hasMatch = true
			if verbosity < VerbosityDebug {
				verbosity = VerbosityDebug
			}
		}
	}

	// If we didn't match any D_ flags, return default
	if !hasMatch {
		return VerbosityInfo
	}

	return verbosity
}

// FromConfig creates a new Logger from HTCondor configuration.
// It reads the following configuration parameters:
//   - LOG: Output path (stdout, stderr, or file path). Defaults to stderr.
//   - LOG_VERBOSITY: Minimum verbosity level. Defaults to INFO.
//     Supports both simple levels (ERROR, WARN, INFO, DEBUG) and HTCondor-style
//     debug levels (D_ALWAYS, D_ERROR, D_STATUS, D_FULLDEBUG, etc.).
//   - LOG_DESTINATIONS: Comma-separated list of enabled destinations (GENERAL, HTTP, SCHEDD, COLLECTOR, METRICS, SECURITY). Defaults to all enabled.
//
// Example configuration:
//
//	LOG = /var/log/htcondor/api.log
//	LOG_VERBOSITY = DEBUG
//	# or using HTCondor-style debug levels:
//	LOG_VERBOSITY = D_FULLDEBUG D_SECURITY
//	LOG_DESTINATIONS = HTTP, SCHEDD, SECURITY
func FromConfig(cfg *config.Config) (*Logger, error) {
	if cfg == nil {
		return New(nil)
	}

	// Parse output path
	outputPath := "stderr"
	if logPath, ok := cfg.Get("LOG"); ok && logPath != "" {
		outputPath = logPath
	}

	// Parse verbosity
	verbosity := VerbosityInfo
	if logVerbosity, ok := cfg.Get("LOG_VERBOSITY"); ok {
		verbosity = parseVerbosity(logVerbosity)
	}

	// Parse enabled destinations
	var enabledDestinations map[Destination]bool
	if logDestinations, ok := cfg.Get("LOG_DESTINATIONS"); ok && logDestinations != "" {
		enabledDestinations = make(map[Destination]bool)
		parts := strings.Split(logDestinations, ",")
		for _, part := range parts {
			part = strings.ToUpper(strings.TrimSpace(part))
			switch part {
			case "GENERAL":
				enabledDestinations[DestinationGeneral] = true
			case "HTTP":
				enabledDestinations[DestinationHTTP] = true
			case "SCHEDD":
				enabledDestinations[DestinationSchedd] = true
			case "COLLECTOR":
				enabledDestinations[DestinationCollector] = true
			case "METRICS":
				enabledDestinations[DestinationMetrics] = true
			case "SECURITY":
				enabledDestinations[DestinationSecurity] = true
			}
		}
	}

	return New(&Config{
		OutputPath:          outputPath,
		MinVerbosity:        verbosity,
		EnabledDestinations: enabledDestinations,
	})
}

// shouldLog checks if a log should be written based on destination filtering
func (l *Logger) shouldLog(dest Destination) bool {
	// If no destinations are configured, allow all
	if len(l.config.EnabledDestinations) == 0 {
		return true
	}
	return l.config.EnabledDestinations[dest]
}

// destinationString returns a string representation of the destination
func destinationString(dest Destination) string {
	switch dest {
	case DestinationGeneral:
		return "general"
	case DestinationHTTP:
		return "http"
	case DestinationSchedd:
		return "schedd"
	case DestinationCollector:
		return "collector"
	case DestinationMetrics:
		return "metrics"
	case DestinationSecurity:
		return "security"
	default:
		return "unknown"
	}
}

// Error logs an error message
func (l *Logger) Error(dest Destination, msg string, args ...any) {
	if !l.shouldLog(dest) {
		return
	}
	l.logger.Error(msg, append([]any{"destination", destinationString(dest)}, args...)...)
}

// Warn logs a warning message
func (l *Logger) Warn(dest Destination, msg string, args ...any) {
	if !l.shouldLog(dest) {
		return
	}
	l.logger.Warn(msg, append([]any{"destination", destinationString(dest)}, args...)...)
}

// Info logs an info message
func (l *Logger) Info(dest Destination, msg string, args ...any) {
	if !l.shouldLog(dest) {
		return
	}
	l.logger.Info(msg, append([]any{"destination", destinationString(dest)}, args...)...)
}

// Debug logs a debug message
func (l *Logger) Debug(dest Destination, msg string, args ...any) {
	if !l.shouldLog(dest) {
		return
	}
	l.logger.Debug(msg, append([]any{"destination", destinationString(dest)}, args...)...)
}

// Errorf logs an error message with Printf-style formatting
func (l *Logger) Errorf(dest Destination, format string, args ...any) {
	if !l.shouldLog(dest) {
		return
	}
	l.logger.Error(formatMessage(format, args...), "destination", destinationString(dest))
}

// Warnf logs a warning message with Printf-style formatting
func (l *Logger) Warnf(dest Destination, format string, args ...any) {
	if !l.shouldLog(dest) {
		return
	}
	l.logger.Warn(formatMessage(format, args...), "destination", destinationString(dest))
}

// Infof logs an info message with Printf-style formatting
func (l *Logger) Infof(dest Destination, format string, args ...any) {
	if !l.shouldLog(dest) {
		return
	}
	l.logger.Info(formatMessage(format, args...), "destination", destinationString(dest))
}

// Debugf logs a debug message with Printf-style formatting
func (l *Logger) Debugf(dest Destination, format string, args ...any) {
	if !l.shouldLog(dest) {
		return
	}
	l.logger.Debug(formatMessage(format, args...), "destination", destinationString(dest))
}

// formatMessage is a helper to format Printf-style messages
func formatMessage(format string, args ...any) string {
	if len(args) == 0 {
		return format
	}
	return fmt.Sprintf(format, args...)
}
