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

const (
	VerbosityError Verbosity = iota
	VerbosityWarn
	VerbosityInfo
	VerbosityDebug
)

// Destination represents where logs should be written
type Destination int

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
		f, err := os.OpenFile(config.OutputPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0640)
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

// FromConfig creates a new Logger from HTCondor configuration.
// It reads the following configuration parameters:
//   - LOG: Output path (stdout, stderr, or file path). Defaults to stderr.
//   - LOG_VERBOSITY: Minimum verbosity level (ERROR, WARN, INFO, DEBUG). Defaults to INFO.
//   - LOG_DESTINATIONS: Comma-separated list of enabled destinations (GENERAL, HTTP, SCHEDD, COLLECTOR, METRICS, SECURITY). Defaults to all enabled.
//
// Example configuration:
//
//	LOG = /var/log/htcondor/api.log
//	LOG_VERBOSITY = DEBUG
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
		switch strings.ToUpper(strings.TrimSpace(logVerbosity)) {
		case "ERROR":
			verbosity = VerbosityError
		case "WARN", "WARNING":
			verbosity = VerbosityWarn
		case "INFO":
			verbosity = VerbosityInfo
		case "DEBUG":
			verbosity = VerbosityDebug
		}
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
