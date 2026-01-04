// Package logging provides structured logging functionality for HTCondor applications.
//
// It wraps Go's standard log/slog package with additional features:
//   - Destination-based filtering (HTTP, Schedd, Collector, etc.)
//   - Verbosity levels (Error, Warn, Info, Debug)
//   - Configuration from HTCondor config files
//   - Support for both structured and printf-style logging
//   - Log rotation based on HTCondor daemon log rotation logic
package logging

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

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
	// MaxLogSize is the maximum size of the log file in bytes before rotation
	// Default: 10 MB (10485760 bytes). Set to 0 to disable rotation.
	MaxLogSize int64
	// MaxNumLogs is the number of rotated log files to keep
	// Old logs are named: <logfile>.old, <logfile>.old.1, <logfile>.old.2, etc.
	// Default: 1
	MaxNumLogs int
	// TruncateOnOpen determines if the log file should be truncated on open
	// If true, the log file is truncated (cleared) when the logger is created
	// If false (default), logs are appended to the existing file
	TruncateOnOpen bool
	// TouchLogInterval is the time interval between log file touches (in seconds)
	// This updates the modification time and allows detection of external rotation.
	// Default: 60 seconds. Set to 0 to disable.
	TouchLogInterval int
}

// Logger wraps slog.Logger with destination and verbosity filtering
type Logger struct {
	config       *Config
	logger       atomic.Pointer[slog.Logger] // Atomic pointer to allow handler updates
	logFile      atomic.Pointer[os.File]     // Atomic pointer to current log file (nil for stdout/stderr)
	currentSize  atomic.Int64                // Current size of log file
	rotating     atomic.Int32                // Flag to indicate rotation in progress (0 or 1)
	maintWg      sync.WaitGroup              // WaitGroup for maintenance goroutine
	maintRunning atomic.Bool                 // Indicates if maintenance is running
}

// Default configuration values
const (
	// DefaultMaxLogSize is the default maximum log file size (10 MB)
	DefaultMaxLogSize = 10 * 1024 * 1024 // 10 MB
	// DefaultMaxNumLogs is the default number of rotated logs to keep
	DefaultMaxNumLogs = 1
	// DefaultTouchLogInterval is the default interval for touching log files (60 seconds)
	DefaultTouchLogInterval = 60
	// defaultSystemLogDir matches the OS-packaged HTCondor layout and avoids
	// relying on the condor user's home directory (which may not exist).
	defaultSystemLogDir   = "/var/log/condor"
	defaultGenericLogFile = "DaemonLog"
)

// daemonNameToCamelCase converts a daemon name from UPPER_CASE to CamelCaseLog.
// For example: FOO_BAR -> FooBarLog, HTTP_API -> HttpApiLog, SCHEDD -> ScheddLog
func daemonNameToCamelCase(daemonName string) string {
	if daemonName == "" {
		return defaultGenericLogFile
	}

	// Split by underscore
	parts := strings.Split(daemonName, "_")

	// Capitalize each part
	for i, part := range parts {
		if len(part) > 0 {
			parts[i] = strings.ToUpper(part[:1]) + strings.ToLower(part[1:])
		}
	}

	// Join and append "Log"
	return strings.Join(parts, "") + "Log"
}

func defaultLogPath(daemonName string) string {
	fileName := defaultGenericLogFile
	if daemonName != "" {
		fileName = daemonNameToCamelCase(daemonName)
	}
	return filepath.Join(defaultSystemLogDir, fileName)
}

func condorUID() (int, bool) {
	u, err := user.Lookup("condor")
	if err != nil {
		return 0, false
	}

	uid, err := strconv.Atoi(u.Uid)
	if err != nil {
		return 0, false
	}

	return uid, true
}

func pathOwnerUID(path string) (int, error) {
	info, err := os.Stat(path)
	if err != nil {
		return 0, err
	}

	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return 0, fmt.Errorf("stat information unavailable for %s", path)
	}

	return int(stat.Uid), nil
}

func shouldFallbackToStdout(outputPath string) bool {
	uid := os.Getuid()
	if uid == 0 { // root can always use the path
		return false
	}

	condorUIDVal, isCondorUser := condorUID()
	if isCondorUser && uid == condorUIDVal {
		// Current user is condor, can use condor-owned paths
		return false
	}

	ownerUID, err := pathOwnerUID(outputPath)
	if err != nil {
		switch {
		case os.IsNotExist(err):
			// File doesn't exist, check parent directory
			parentUID, parentErr := pathOwnerUID(filepath.Dir(outputPath))
			if parentErr != nil {
				// Can't determine parent ownership, assume we can't write
				return true
			}
			// If parent is owned by current user, we can likely create the file
			if parentUID == uid {
				return false
			}
			// If parent is owned by condor and we're condor user, we can write
			// (already checked above, so if we're here, we're not condor user)
			// Therefore, we should fall back to stdout
			return true
		case errors.Is(err, os.ErrPermission):
			return true
		default:
			return false
		}
	}

	// File exists, check if we own it or can write to it
	if ownerUID == uid {
		return false
	}

	// File is owned by someone else - we should fall back to stdout
	return true
}

func sanitizeOutputPath(outputPath string) string {
	if outputPath == "" {
		return outputPath
	}

	// Check for stdout/stderr (case-insensitive)
	lowerPath := strings.ToLower(outputPath)
	if lowerPath == "stdout" || lowerPath == "stderr" {
		return lowerPath
	}

	if shouldFallbackToStdout(outputPath) {
		return "stdout"
	}

	return outputPath
}

// New creates a new Logger with the given configuration
func New(config *Config) (*Logger, error) {
	if config == nil {
		config = &Config{
			OutputPath:        "stderr",
			DestinationLevels: nil, // Will default to VerbosityWarn for all
			MaxLogSize:        DefaultMaxLogSize,
			MaxNumLogs:        DefaultMaxNumLogs,
			TruncateOnOpen:    false,
			TouchLogInterval:  DefaultTouchLogInterval,
		}
	}

	// Set defaults for rotation parameters if not specified
	if config.MaxLogSize == 0 {
		config.MaxLogSize = DefaultMaxLogSize
	}
	if config.MaxNumLogs == 0 {
		config.MaxNumLogs = DefaultMaxNumLogs
	}
	if config.TouchLogInterval == 0 {
		config.TouchLogInterval = DefaultTouchLogInterval
	}

	config.OutputPath = sanitizeOutputPath(config.OutputPath)

	// Determine output writer
	var writer io.Writer
	var logFile *os.File
	var currentSize int64

	switch config.OutputPath {
	case "stdout", "":
		writer = os.Stdout
	case "stderr":
		writer = os.Stderr
	default:
		// File path - handle truncation and get current size
		flags := os.O_CREATE | os.O_WRONLY
		if config.TruncateOnOpen {
			flags |= os.O_TRUNC
		} else {
			flags |= os.O_APPEND
		}

		f, err := os.OpenFile(config.OutputPath, flags, 0600)
		if err != nil {
			// If we can't open the log file (permission denied, etc.), fall back to stdout
			// This can happen if the directory doesn't exist or we don't have write permission
			if errors.Is(err, os.ErrPermission) || os.IsNotExist(err) || os.IsPermission(err) {
				config.OutputPath = "stdout"
				writer = os.Stdout
			} else {
				return nil, err
			}
		} else {
			logFile = f
			writer = f

			// Get current file size for rotation tracking
			if !config.TruncateOnOpen {
				stat, err := f.Stat()
				if err != nil {
					_ = f.Close() // Ignore error, we're already handling failure
					return nil, err
				}
				currentSize = stat.Size()
			}
		}
	}

	// Set slog handler to capture all log levels (Debug)
	// Per-destination filtering happens in shouldLog() method
	// This ensures slog doesn't filter out messages before we can apply destination-specific levels
	slogLevel := slog.LevelDebug

	// Create slog handler with options
	opts := &slog.HandlerOptions{
		Level: slogLevel,
	}

	handler := slog.NewTextHandler(writer, opts)
	logger := slog.New(handler)

	l := &Logger{
		config: config,
	}
	l.logger.Store(logger)
	l.logFile.Store(logFile)
	l.currentSize.Store(currentSize)

	return l, nil
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
//   - MAX_<DAEMON>_LOG: Maximum log file size in bytes before rotation. Default: 10 MB
//   - MAX_NUM_<DAEMON>_LOG: Number of rotated logs to keep. Default: 1
//   - TRUNC_<DAEMON>_LOG_ON_OPEN: If true, truncate log on startup. Default: false
//   - TOUCH_LOG_INTERVAL: Time interval in seconds between log file touches. Default: 60
//
// Example configuration:
//
//	LOG = /var/log/htcondor/api.log
//	HTTP_API_DEBUG = cedar:debug, http:info, schedd:warn
//	# or using integers:
//	HTTP_API_DEBUG = cedar:2 http:1
//	MAX_HTTP_API_LOG = 5242880
//	MAX_NUM_HTTP_API_LOG = 3
//	TRUNC_HTTP_API_LOG_ON_OPEN = false
//	TOUCH_LOG_INTERVAL = 60
func FromConfigWithDaemon(daemonName string, cfg *config.Config) (*Logger, error) {
	if cfg == nil {
		return New(nil)
	}

	// Parse output path
	// First try daemon-specific log path (e.g., HTTP_API_LOG)
	// Then construct from LOG directory + daemon log filename
	outputPath := ""
	daemonLogParam := strings.ToUpper(daemonName) + "_LOG"
	if logPath, ok := cfg.Get(daemonLogParam); ok && logPath != "" {
		outputPath = logPath
	} else if logDir, ok := cfg.Get("LOG"); ok && logDir != "" {
		// LOG is a directory, not a file path
		// Construct full path: LOG directory + daemon-specific filename
		lowerLogDir := strings.ToLower(logDir)
		if lowerLogDir == "stdout" || lowerLogDir == "stderr" {
			outputPath = lowerLogDir
		} else {
			// Construct log filename from daemon name (e.g., FOO_BAR -> FooBarLog)
			fileName := defaultGenericLogFile
			if daemonName != "" {
				fileName = daemonNameToCamelCase(daemonName)
			}
			outputPath = filepath.Join(logDir, fileName)
		}
	}

	if outputPath == "" {
		outputPath = defaultLogPath(daemonName)
	}

	outputPath = sanitizeOutputPath(outputPath)

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

	// Parse rotation parameters
	maxLogSize := int64(DefaultMaxLogSize)
	maxLogParam := "MAX_" + strings.ToUpper(daemonName) + "_LOG"
	if maxLogStr, ok := cfg.Get(maxLogParam); ok && maxLogStr != "" {
		if size, err := strconv.ParseInt(maxLogStr, 10, 64); err == nil && size > 0 {
			maxLogSize = size
		}
	}

	maxNumLogs := DefaultMaxNumLogs
	maxNumParam := "MAX_NUM_" + strings.ToUpper(daemonName) + "_LOG"
	if maxNumStr, ok := cfg.Get(maxNumParam); ok && maxNumStr != "" {
		if num, err := strconv.Atoi(maxNumStr); err == nil && num > 0 {
			maxNumLogs = num
		}
	}

	truncateOnOpen := false
	truncParam := "TRUNC_" + strings.ToUpper(daemonName) + "_LOG_ON_OPEN"
	if truncStr, ok := cfg.Get(truncParam); ok && truncStr != "" {
		truncateOnOpen = strings.ToLower(truncStr) == "true"
	}

	touchLogInterval := DefaultTouchLogInterval
	touchParam := "TOUCH_LOG_INTERVAL"
	if touchStr, ok := cfg.Get(touchParam); ok && touchStr != "" {
		if interval, err := strconv.Atoi(touchStr); err == nil && interval > 0 {
			touchLogInterval = interval
		}
	}

	return New(&Config{
		OutputPath:        outputPath,
		DestinationLevels: destinationLevels,
		MaxLogSize:        maxLogSize,
		MaxNumLogs:        maxNumLogs,
		TruncateOnOpen:    truncateOnOpen,
		TouchLogInterval:  touchLogInterval,
	})
}

// FromConfig creates a new Logger from HTCondor configuration with default settings.
// For daemon-specific logging, use FromConfigWithDaemon instead.
// It only reads the LOG parameter for output path.
func FromConfig(cfg *config.Config) (*Logger, error) {
	if cfg == nil {
		return New(nil)
	}

	// Parse output path
	// First try TOOL_LOG (for non-daemon tools)
	// Then construct from LOG directory
	outputPath := ""
	if toolLog, ok := cfg.Get("TOOL_LOG"); ok && toolLog != "" {
		outputPath = toolLog
	} else if logDir, ok := cfg.Get("LOG"); ok && logDir != "" {
		// LOG is a directory, not a file path
		lowerLogDir := strings.ToLower(logDir)
		if lowerLogDir == "stdout" || lowerLogDir == "stderr" {
			outputPath = lowerLogDir
		} else {
			// Construct generic log path
			outputPath = filepath.Join(logDir, defaultGenericLogFile)
		}
	}

	if outputPath == "" {
		outputPath = defaultLogPath("")
	}

	outputPath = sanitizeOutputPath(outputPath)

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

// rotateLogIfNeeded checks if log rotation is needed and performs it if necessary.
// Uses compare-and-swap to determine which goroutine performs the rotation.
// It's OK to go one line over the limit.
func (l *Logger) rotateLogIfNeeded() error {
	// Only rotate if we have a log file (not stdout/stderr)
	logFile := l.logFile.Load()
	if logFile == nil {
		return nil
	}

	// Check if we exceed the max log size
	currentSize := l.currentSize.Load()
	if currentSize <= l.config.MaxLogSize {
		return nil
	}

	// Use compare-and-swap to determine if this goroutine should rotate
	// If rotating flag is 0, set it to 1 and this goroutine wins
	if !l.rotating.CompareAndSwap(0, 1) {
		// Another goroutine is rotating, skip
		return nil
	}
	defer l.rotating.Store(0)

	// Perform rotation
	logPath := l.config.OutputPath

	// Close current log file
	oldFile := l.logFile.Load()
	if oldFile != nil {
		if err := oldFile.Close(); err != nil {
			return fmt.Errorf("failed to close log file: %w", err)
		}
	}

	// Rotate existing log files
	// Delete oldest log if we're at the limit
	oldestLog := fmt.Sprintf("%s.old.%d", logPath, l.config.MaxNumLogs-1)
	if _, err := os.Stat(oldestLog); err == nil {
		if err := os.Remove(oldestLog); err != nil {
			return fmt.Errorf("failed to remove oldest log: %w", err)
		}
	}

	// Shift existing rotated logs (rename .old.N-1 to .old.N)
	for i := l.config.MaxNumLogs - 1; i > 0; i-- {
		oldName := fmt.Sprintf("%s.old.%d", logPath, i-1)
		newName := fmt.Sprintf("%s.old.%d", logPath, i)

		// Skip if source doesn't exist
		if _, err := os.Stat(oldName); os.IsNotExist(err) {
			continue
		}

		if err := os.Rename(oldName, newName); err != nil {
			return fmt.Errorf("failed to rotate log %s to %s: %w", oldName, newName, err)
		}
	}

	// Rename current log to .old
	oldLog := logPath + ".old"
	if err := os.Rename(logPath, oldLog); err != nil {
		return fmt.Errorf("failed to rename current log to .old: %w", err)
	}

	// Create new log file
	//nolint:gosec // G304 - logPath is internal to logger, not user-controlled
	f, err := os.OpenFile(logPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0600)
	if err != nil {
		return fmt.Errorf("failed to create new log file: %w", err)
	}

	// Update file handle and reset size atomically
	l.logFile.Store(f)
	l.currentSize.Store(0)

	// Create new handler and logger with the new file
	// Set slog handler to capture all log levels (Debug)
	// Per-destination filtering happens in shouldLog() method
	slogLevel := slog.LevelDebug

	opts := &slog.HandlerOptions{
		Level: slogLevel,
	}
	handler := slog.NewTextHandler(f, opts)
	newLogger := slog.New(handler)
	l.logger.Store(newLogger)

	return nil
}

// PerformMaintenance performs maintenance on the log file.
// It checks if the log file has been externally rotated or deleted by comparing
// the file handle's inode with the file path's inode. If different, it reopens the file.
// This method is safe to call from multiple goroutines.
func (l *Logger) PerformMaintenance() error {
	logFile := l.logFile.Load()
	if logFile == nil {
		// No file to maintain (stdout/stderr)
		return nil
	}

	logPath := l.config.OutputPath

	// fstat the current file handle
	fileStat, err := logFile.Stat()
	if err != nil {
		// File handle is no longer valid, reopen
		return l.reopenLogFile()
	}

	// Update current size from actual file size
	l.currentSize.Store(fileStat.Size())

	// stat the file path
	pathStat, err := os.Stat(logPath)
	if err != nil {
		if os.IsNotExist(err) {
			// File was deleted externally, reopen
			return l.reopenLogFile()
		}
		return fmt.Errorf("failed to stat log path: %w", err)
	}

	// Compare inode and device ID
	fileSys := fileStat.Sys().(*syscall.Stat_t)
	pathSys := pathStat.Sys().(*syscall.Stat_t)

	if fileSys.Ino != pathSys.Ino || fileSys.Dev != pathSys.Dev {
		// File was rotated externally, reopen
		return l.reopenLogFile()
	}

	// After updating size, check if we need to rotate
	if err := l.rotateLogIfNeeded(); err != nil {
		return fmt.Errorf("failed to rotate during maintenance: %w", err)
	}

	// Touch the log file by updating its access and modification times
	now := time.Now()
	if err := os.Chtimes(logPath, now, now); err != nil {
		return fmt.Errorf("failed to touch log file: %w", err)
	}

	return nil
}

// reopenLogFile reopens the log file after external rotation or deletion.
func (l *Logger) reopenLogFile() error {
	logPath := l.config.OutputPath

	// Open new file
	//nolint:gosec // G304 - logPath is internal to logger, not user-controlled
	f, err := os.OpenFile(logPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0600)
	if err != nil {
		return fmt.Errorf("failed to reopen log file: %w", err)
	}

	// Get current file size
	stat, err := f.Stat()
	if err != nil {
		_ = f.Close() // Ignore error, we're already handling failure
		return fmt.Errorf("failed to stat reopened log file: %w", err)
	}

	// Swap file handle using compare-and-swap
	oldFile := l.logFile.Swap(f)
	if oldFile != nil {
		_ = oldFile.Close() // Ignore error, old file is being replaced
	}

	// Reset size to current file size
	l.currentSize.Store(stat.Size())

	// Create new handler and logger with the new file
	// Set slog handler to capture all log levels (Debug)
	// Per-destination filtering happens in shouldLog() method
	slogLevel := slog.LevelDebug

	opts := &slog.HandlerOptions{
		Level: slogLevel,
	}
	handler := slog.NewTextHandler(f, opts)
	newLogger := slog.New(handler)
	l.logger.Store(newLogger)

	return nil
}

// StartMaintenance starts a goroutine that periodically performs maintenance
// on the log file at the configured TouchLogInterval.
// The goroutine will stop when the context is cancelled.
// Returns an error if maintenance is already running.
func (l *Logger) StartMaintenance(ctx context.Context) error {
	if l.maintRunning.Load() {
		return fmt.Errorf("maintenance already running")
	}

	if l.config.TouchLogInterval <= 0 {
		return fmt.Errorf("TouchLogInterval must be positive")
	}

	l.maintRunning.Store(true)
	l.maintWg.Add(1)

	go func() {
		defer l.maintWg.Done()
		defer l.maintRunning.Store(false)

		ticker := time.NewTicker(time.Duration(l.config.TouchLogInterval) * time.Second)
		defer ticker.Stop()

		for {
			select {
			case <-ticker.C:
				if err := l.PerformMaintenance(); err != nil {
					fmt.Fprintf(os.Stderr, "Log maintenance failed: %v\n", err)
				}
			case <-ctx.Done():
				return
			}
		}
	}()

	return nil
}

// StopMaintenance stops the maintenance goroutine if it's running.
// It waits for the goroutine to finish before returning.
func (l *Logger) StopMaintenance() {
	if l.maintRunning.Load() {
		l.maintWg.Wait()
	}
}

// writeLog writes a log message and updates the size counter.
// It's OK to go one line over the limit - rotation happens before the next write.
func (l *Logger) writeLog(logFunc func() int) {
	// Check and perform rotation if needed (before write)
	if err := l.rotateLogIfNeeded(); err != nil {
		// If rotation fails, still try to log (but don't panic)
		fmt.Fprintf(os.Stderr, "Log rotation failed: %v\n", err)
	}

	// Perform the log write and get bytes written
	bytesWritten := logFunc()

	// Update size after write - use the actual bytes written
	l.currentSize.Add(int64(bytesWritten))
}

// Error logs an error message
func (l *Logger) Error(dest Destination, msg string, args ...any) {
	if !l.shouldLog(dest, VerbosityError) {
		return
	}
	logger := l.logger.Load()
	l.writeLog(func() int {
		// Estimate bytes written
		size := len(msg) + 50 // Base overhead
		for _, arg := range args {
			size += len(fmt.Sprint(arg))
		}
		logger.Error(msg, append([]any{"destination", destinationString(dest)}, args...)...)
		return size
	})
}

// Warn logs a warning message
func (l *Logger) Warn(dest Destination, msg string, args ...any) {
	if !l.shouldLog(dest, VerbosityWarn) {
		return
	}
	logger := l.logger.Load()
	l.writeLog(func() int {
		size := len(msg) + 50
		for _, arg := range args {
			size += len(fmt.Sprint(arg))
		}
		logger.Warn(msg, append([]any{"destination", destinationString(dest)}, args...)...)
		return size
	})
}

// Info logs an info message
func (l *Logger) Info(dest Destination, msg string, args ...any) {
	if !l.shouldLog(dest, VerbosityInfo) {
		return
	}
	logger := l.logger.Load()
	l.writeLog(func() int {
		size := len(msg) + 50
		for _, arg := range args {
			size += len(fmt.Sprint(arg))
		}
		logger.Info(msg, append([]any{"destination", destinationString(dest)}, args...)...)
		return size
	})
}

// Debug logs a debug message
func (l *Logger) Debug(dest Destination, msg string, args ...any) {
	if !l.shouldLog(dest, VerbosityDebug) {
		return
	}
	logger := l.logger.Load()
	l.writeLog(func() int {
		size := len(msg) + 50
		for _, arg := range args {
			size += len(fmt.Sprint(arg))
		}
		logger.Debug(msg, append([]any{"destination", destinationString(dest)}, args...)...)
		return size
	})
}

// Errorf logs an error message with Printf-style formatting
func (l *Logger) Errorf(dest Destination, format string, args ...any) {
	if !l.shouldLog(dest, VerbosityError) {
		return
	}
	msg := formatMessage(format, args...)
	logger := l.logger.Load()
	l.writeLog(func() int {
		logger.Error(msg, "destination", destinationString(dest))
		return len(msg) + 50
	})
}

// Warnf logs a warning message with Printf-style formatting
func (l *Logger) Warnf(dest Destination, format string, args ...any) {
	if !l.shouldLog(dest, VerbosityWarn) {
		return
	}
	msg := formatMessage(format, args...)
	logger := l.logger.Load()
	l.writeLog(func() int {
		logger.Warn(msg, "destination", destinationString(dest))
		return len(msg) + 50
	})
}

// Infof logs an info message with Printf-style formatting
func (l *Logger) Infof(dest Destination, format string, args ...any) {
	if !l.shouldLog(dest, VerbosityInfo) {
		return
	}
	msg := formatMessage(format, args...)
	logger := l.logger.Load()
	l.writeLog(func() int {
		logger.Info(msg, "destination", destinationString(dest))
		return len(msg) + 50
	})
}

// Debugf logs a debug message with Printf-style formatting
func (l *Logger) Debugf(dest Destination, format string, args ...any) {
	if !l.shouldLog(dest, VerbosityDebug) {
		return
	}
	msg := formatMessage(format, args...)
	logger := l.logger.Load()
	l.writeLog(func() int {
		logger.Debug(msg, "destination", destinationString(dest))
		return len(msg) + 50
	})
}

// formatMessage is a helper to format Printf-style messages
func formatMessage(format string, args ...any) string {
	if len(args) == 0 {
		return format
	}
	return fmt.Sprintf(format, args...)
}
