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
	DestinationCedar                        // Cedar protocol logs
)

// Config holds logging configuration
type Config struct {
	// OutputPath is where logs are written ("stdout", "stderr", or file path)
	OutputPath string
	// DestinationLevels specifies verbosity level for each destination
	// If a destination is not in the map, it defaults to VerbosityWarn
	DestinationLevels map[Destination]Verbosity
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
			OutputPath:        "stderr",
			DestinationLevels: nil, // Will default to VerbosityWarn for all
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

	// Find the most verbose level across all destinations to set slog level
	// This ensures slog doesn't filter out messages we might want for specific destinations
	minVerbosity := VerbosityWarn // Default
	for _, level := range config.DestinationLevels {
		if level > minVerbosity {
			minVerbosity = level
		}
	}

	// Convert our verbosity to slog level
	var slogLevel slog.Level
	switch minVerbosity {
	case VerbosityError:
		slogLevel = slog.LevelError
	case VerbosityWarn:
		slogLevel = slog.LevelWarn
	case VerbosityInfo:
		slogLevel = slog.LevelInfo
	case VerbosityDebug:
		slogLevel = slog.LevelDebug
	default:
		slogLevel = slog.LevelWarn
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

// parseLevel converts a level string to a Verbosity level.
// Supports: "error", "warn", "info", "debug" (case insensitive)
// Also supports integers: 0=off (error), 1=info, 2=debug
func parseLevel(level string) Verbosity {
	level = strings.ToLower(strings.TrimSpace(level))

	// Handle string levels
	switch level {
	case "error":
		return VerbosityError
	case "warn", "warning":
		return VerbosityWarn
	case "info":
		return VerbosityInfo
	case "debug":
		return VerbosityDebug
	case "0": // off
		return VerbosityError
	case "1": // info
		return VerbosityInfo
	case "2": // debug
		return VerbosityDebug
	}

	// Default to warn
	return VerbosityWarn
}

// parseDestination converts a destination string to a Destination constant.
func parseDestination(dest string) (Destination, bool) {
	dest = strings.ToLower(strings.TrimSpace(dest))
	switch dest {
	case "general":
		return DestinationGeneral, true
	case "http":
		return DestinationHTTP, true
	case "schedd":
		return DestinationSchedd, true
	case "collector":
		return DestinationCollector, true
	case "metrics":
		return DestinationMetrics, true
	case "security":
		return DestinationSecurity, true
	case "cedar":
		return DestinationCedar, true
	default:
		return DestinationGeneral, false
	}
}

// FromConfigWithDaemon creates a new Logger from HTCondor configuration for a specific daemon.
// It reads the following configuration parameters:
//   - LOG: Output path (stdout, stderr, or file path). Defaults to stderr.
//   - <DAEMON>_DEBUG: Space or comma-separated list of destination:level pairs.
//     Example: "cedar:debug, http:info" or "cedar:2 http:1"
//     Levels: error, warn, info, debug (or integers: 0=off, 1=info, 2=debug)
//     Default level for all destinations is warn if not specified.
//
// Example configuration:
//
//	LOG = /var/log/htcondor/api.log
//	HTTP_API_DEBUG = cedar:debug, http:info, schedd:warn
//	# or using integers:
//	HTTP_API_DEBUG = cedar:2 http:1
func FromConfigWithDaemon(daemonName string, cfg *config.Config) (*Logger, error) {
	if cfg == nil {
		return New(nil)
	}

	// Parse output path
	outputPath := "stderr"
	if logPath, ok := cfg.Get("LOG"); ok && logPath != "" {
		outputPath = logPath
	}

	// Parse destination levels from <DAEMON>_DEBUG
	destinationLevels := make(map[Destination]Verbosity)
	debugParam := strings.ToUpper(daemonName) + "_DEBUG"
	if debugConfig, ok := cfg.Get(debugParam); ok && debugConfig != "" {
		// Split by comma or whitespace
		debugConfig = strings.ReplaceAll(debugConfig, ",", " ")
		pairs := strings.Fields(debugConfig)

		for _, pair := range pairs {
			// Split by colon
			parts := strings.SplitN(pair, ":", 2)
			if len(parts) != 2 {
				continue // Skip malformed pairs
			}

			dest, ok := parseDestination(parts[0])
			if !ok {
				continue // Skip unknown destinations
			}

			level := parseLevel(parts[1])
			destinationLevels[dest] = level
		}
	}

	return New(&Config{
		OutputPath:        outputPath,
		DestinationLevels: destinationLevels,
	})
}

// FromConfig creates a new Logger from HTCondor configuration with default settings.
// For daemon-specific logging, use FromConfigWithDaemon instead.
// It only reads the LOG parameter for output path.
func FromConfig(cfg *config.Config) (*Logger, error) {
	if cfg == nil {
		return New(nil)
	}

	// Parse output path only
	outputPath := "stderr"
	if logPath, ok := cfg.Get("LOG"); ok && logPath != "" {
		outputPath = logPath
	}

	return New(&Config{
		OutputPath:        outputPath,
		DestinationLevels: nil, // All destinations default to warn
	})
}

// shouldLog checks if a log should be written based on destination-specific verbosity level
func (l *Logger) shouldLog(dest Destination, msgLevel Verbosity) bool {
	// Get the configured level for this destination (default to warn)
	configuredLevel := VerbosityWarn
	if l.config.DestinationLevels != nil {
		if level, ok := l.config.DestinationLevels[dest]; ok {
			configuredLevel = level
		}
	}

	// Only log if message level is at or below configured level
	return msgLevel <= configuredLevel
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
	case DestinationCedar:
		return "cedar"
	default:
		return "unknown"
	}
}

// Error logs an error message
func (l *Logger) Error(dest Destination, msg string, args ...any) {
	if !l.shouldLog(dest, VerbosityError) {
		return
	}
	l.logger.Error(msg, append([]any{"destination", destinationString(dest)}, args...)...)
}

// Warn logs a warning message
func (l *Logger) Warn(dest Destination, msg string, args ...any) {
	if !l.shouldLog(dest, VerbosityWarn) {
		return
	}
	l.logger.Warn(msg, append([]any{"destination", destinationString(dest)}, args...)...)
}

// Info logs an info message
func (l *Logger) Info(dest Destination, msg string, args ...any) {
	if !l.shouldLog(dest, VerbosityInfo) {
		return
	}
	l.logger.Info(msg, append([]any{"destination", destinationString(dest)}, args...)...)
}

// Debug logs a debug message
func (l *Logger) Debug(dest Destination, msg string, args ...any) {
	if !l.shouldLog(dest, VerbosityDebug) {
		return
	}
	l.logger.Debug(msg, append([]any{"destination", destinationString(dest)}, args...)...)
}

// Errorf logs an error message with Printf-style formatting
func (l *Logger) Errorf(dest Destination, format string, args ...any) {
	if !l.shouldLog(dest, VerbosityError) {
		return
	}
	l.logger.Error(formatMessage(format, args...), "destination", destinationString(dest))
}

// Warnf logs a warning message with Printf-style formatting
func (l *Logger) Warnf(dest Destination, format string, args ...any) {
	if !l.shouldLog(dest, VerbosityWarn) {
		return
	}
	l.logger.Warn(formatMessage(format, args...), "destination", destinationString(dest))
}

// Infof logs an info message with Printf-style formatting
func (l *Logger) Infof(dest Destination, format string, args ...any) {
	if !l.shouldLog(dest, VerbosityInfo) {
		return
	}
	l.logger.Info(formatMessage(format, args...), "destination", destinationString(dest))
}

// Debugf logs a debug message with Printf-style formatting
func (l *Logger) Debugf(dest Destination, format string, args ...any) {
	if !l.shouldLog(dest, VerbosityDebug) {
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
