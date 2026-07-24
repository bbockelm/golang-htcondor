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
	stdlog "log"
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
	DestinationMCP                          // MCP server logs
)

// Config holds logging configuration
type Config struct {
	// OutputPath is where logs are written ("stdout", "stderr", or file path)
	OutputPath string
	// DestinationLevels specifies verbosity level for each destination
	// If a destination is not in the map, DefaultLevel is used
	DestinationLevels map[Destination]Verbosity
	// DefaultLevel is the verbosity level for destinations not in DestinationLevels
	// Default: VerbosityWarn
	DefaultLevel Verbosity
	// SkipGlobalInstall controls whether this logger is set as the global slog default
	// When false (default), external libraries like Cedar will use this logger
	// When true, only explicit Logger method calls will use this logger
	SkipGlobalInstall bool
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
	levels       atomic.Pointer[levelSet]    // Live per-destination levels; swapped by ApplyLevels
	logger       atomic.Pointer[slog.Logger] // Atomic pointer to allow handler updates
	logFile      atomic.Pointer[os.File]     // Atomic pointer to current log file (nil for stdout/stderr)
	currentSize  atomic.Int64                // Current size of log file
	rotating     atomic.Int32                // Flag to indicate rotation in progress (0 or 1)
	maintWg      sync.WaitGroup              // WaitGroup for maintenance goroutine
	maintRunning atomic.Bool                 // Indicates if maintenance is running

	rotMu    sync.Mutex       // guards onRotate
	onRotate []func(*os.File) // called with the new file after each rotation/reopen
}

// File returns the current log output file, or nil when logging to a std stream
// (stdout/stderr) or when open failed. The file changes on rotation, so a caller that
// holds onto it (e.g. redirecting process stdout/stderr into the log) must also register
// OnRotate to follow the new file.
func (l *Logger) File() *os.File { return l.logFile.Load() }

// OnRotate registers fn to be invoked with the new log file each time the log rotates or
// is reopened. Used to re-point an external redirection (process stdout/stderr) at the new
// file so it does not keep writing into the rotated-away one. fn must not block.
func (l *Logger) OnRotate(fn func(*os.File)) {
	l.rotMu.Lock()
	l.onRotate = append(l.onRotate, fn)
	l.rotMu.Unlock()
}

// fireRotate notifies OnRotate subscribers of the new file after a rotation/reopen.
func (l *Logger) fireRotate(f *os.File) {
	l.rotMu.Lock()
	fns := make([]func(*os.File), len(l.onRotate))
	copy(fns, l.onRotate)
	l.rotMu.Unlock()
	for _, fn := range fns {
		fn(f)
	}
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

// levelSet is an immutable snapshot of the per-destination verbosity configuration.
// It is swapped atomically (see Logger.levels) so log levels can be re-applied live on
// condor_reconfig without racing concurrent log calls: readers Load() a consistent
// snapshot, ApplyLevels Store()s a fresh one.
type levelSet struct {
	destinationLevels map[Destination]Verbosity
	defaultLevel      Verbosity
}

// levelFor returns the configured verbosity for dest, falling back to the default.
func (ls *levelSet) levelFor(dest Destination) Verbosity {
	if ls.destinationLevels != nil {
		if level, ok := ls.destinationLevels[dest]; ok {
			return level
		}
	}
	return ls.defaultLevel
}

// filteringHandler wraps an slog.Handler and filters messages based on destination attributes.
// It reads the current levels through a shared atomic pointer so a level reconfig takes
// effect for handlers already installed (including the process-global default and any
// post-rotation handler).
type filteringHandler struct {
	handler slog.Handler
	levels  *atomic.Pointer[levelSet]
}

// Enabled checks if a log level should be enabled based on destination filtering
func (h *filteringHandler) Enabled(_ context.Context, _ slog.Level) bool {
	// We need to see all levels to do per-destination filtering
	return true
}

// Handle processes a log record with destination-based filtering
func (h *filteringHandler) Handle(ctx context.Context, r slog.Record) error {
	// Extract destination from attributes
	var dest Destination
	found := false
	r.Attrs(func(a slog.Attr) bool {
		if a.Key == "destination" {
			if destStr, ok := a.Value.Any().(string); ok {
				if d, ok := parseDestination(destStr); ok {
					dest = d
					found = true
					return false // Stop iteration
				}
			}
		}
		return true // Continue iteration
	})

	// Determine configured level for this destination (from the live snapshot). An
	// unrecognized/absent destination attribute falls back to the default level.
	ls := h.levels.Load()
	configuredLevel := ls.defaultLevel
	if found {
		configuredLevel = ls.levelFor(dest)
	}

	// Convert slog level to our Verbosity
	var msgLevel Verbosity
	switch {
	case r.Level >= slog.LevelError:
		msgLevel = VerbosityError
	case r.Level >= slog.LevelWarn:
		msgLevel = VerbosityWarn
	case r.Level >= slog.LevelInfo:
		msgLevel = VerbosityInfo
	default:
		msgLevel = VerbosityDebug
	}

	// Only pass through if message level is at or below configured level
	if msgLevel <= configuredLevel {
		return h.handler.Handle(ctx, r)
	}
	return nil
}

// WithAttrs returns a new handler with additional attributes
func (h *filteringHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	return &filteringHandler{
		handler: h.handler.WithAttrs(attrs),
		levels:  h.levels,
	}
}

// WithGroup returns a new handler with a group name
func (h *filteringHandler) WithGroup(name string) slog.Handler {
	return &filteringHandler{
		handler: h.handler.WithGroup(name),
		levels:  h.levels,
	}
}

// New creates a new Logger with the given configuration
func New(config *Config) (*Logger, error) {
	if config == nil {
		config = &Config{
			OutputPath:        "stderr",
			DestinationLevels: nil,
			DefaultLevel:      VerbosityWarn,
			MaxLogSize:        DefaultMaxLogSize,
			MaxNumLogs:        DefaultMaxNumLogs,
			TruncateOnOpen:    false,
			TouchLogInterval:  DefaultTouchLogInterval,
		}
	}

	// Set defaults for parameters if not specified
	// Note: DefaultLevel of 0 (VerbosityError) is valid, so we don't set a default here
	// Users who want VerbosityWarn as default should explicitly set it
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

		// 0644 to match C++ HTCondor's world-readable daemon logs.
		//nolint:gosec // G302: daemon logs are intentionally world-readable, as in C++ HTCondor
		f, err := os.OpenFile(config.OutputPath, flags, 0644)
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
			forceLogPerm(f)

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

	// Build the Logger and publish its initial level snapshot. Handlers reference
	// &l.levels (not a copy), so ApplyLevels can swap levels live for handlers already
	// installed -- including the process-global default below and any post-rotation one.
	l := &Logger{
		config: config,
	}
	l.levels.Store(&levelSet{
		destinationLevels: config.DestinationLevels,
		defaultLevel:      config.DefaultLevel,
	})
	l.logger.Store(l.buildFilteredLogger(writer))
	l.logFile.Store(logFile)
	l.currentSize.Store(currentSize)

	// By default, set as global default so external dependencies (like Cedar) use our logger
	// Skip if SkipGlobalInstall is true
	if !config.SkipGlobalInstall {
		// A filtering handler that accepts DEBUG level but filters per destination, so Cedar
		// logs tagged destination=cedar are filtered appropriately.
		slog.SetDefault(l.buildFilteredLogger(writer))
	}

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

// DefaultDaemonLevel is the fallback verbosity for destinations without an explicit
// <DAEMON>_DEBUG entry, matching HTCondor's "D_ALWAYS shows up by default" baseline so an
// unconfigured daemon still logs routine activity. Used by both startup and reconfig.
const DefaultDaemonLevel = VerbosityInfo

// ParseDestinationLevels parses a daemon's <DAEMON>_DEBUG configuration into a
// per-destination verbosity map. The cedar destination defaults to Warn (its per-step Info
// chatter logs sensitive session IDs and is very noisy; operators opt in via
// <DAEMON>_DEBUG = cedar:debug). Shared by FromConfigWithDaemon (startup) and the daemon's
// reconfig path so both derive levels identically from the same config.
func ParseDestinationLevels(daemonName string, cfg *config.Config) map[Destination]Verbosity {
	levels := map[Destination]Verbosity{
		DestinationCedar: VerbosityWarn,
	}
	if cfg == nil {
		return levels
	}
	debugParam := strings.ToUpper(daemonName) + "_DEBUG"
	debugConfig, ok := cfg.Get(debugParam)
	if !ok || debugConfig == "" {
		return levels
	}
	// Split by comma or whitespace into destination:level pairs.
	for _, pair := range strings.Fields(strings.ReplaceAll(debugConfig, ",", " ")) {
		parts := strings.SplitN(pair, ":", 2)
		if len(parts) != 2 {
			continue // Skip malformed pairs
		}
		dest, ok := parseDestination(parts[0])
		if !ok {
			continue // Skip unknown destinations
		}
		levels[dest] = parseLevel(parts[1])
	}
	return levels
}

// ParseDestination converts a destination string (e.g. "cedar", "general") to a
// Destination. The bool is false for an empty or unknown string, in which case the
// returned Destination is DestinationGeneral. Exported for the daemon slog bridge, which
// routes a record to the destination its "destination" attribute names.
func ParseDestination(dest string) (Destination, bool) {
	return parseDestination(dest)
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
	case "mcp":
		return DestinationMCP, true
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

	// Parse destination levels from <DAEMON>_DEBUG.
	//
	// Default the cedar destination to Warn so cedar's own
	// per-step Info chatter (handshake stages, "Found cached
	// session <id>", "Registered inherited session") doesn't end
	// up in the daemon log. Two reasons:
	//   1. Cedar logs the full session ID at Info — those IDs are
	//      sensitive lookup keys, and daemon logs are typically
	//      world-readable on stock HTCondor installs (mode 0644).
	//   2. The cedar Info stream is extremely chatty — useful
	//      during a security debug pass, noise the rest of the
	//      time.
	// Operators who need cedar Info or Debug can opt in via
	//   HTTP_API_DEBUG = cedar:debug
	// in their condor config.
	destinationLevels := ParseDestinationLevels(daemonName, cfg)

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
		// Match HTCondor's "D_ALWAYS shows up by default" baseline:
		// without an explicit <DAEMON>_DEBUG knob, an unconfigured
		// daemon should still produce its routine startup / activity
		// logs. Leaving DefaultLevel at the Go zero value
		// (VerbosityError) silences every Info/Warn line, which is
		// what made our HttpApiLog appear "broken" — file was being
		// written, just empty after the filtering handler dropped
		// everything.
		DefaultLevel:     VerbosityInfo,
		MaxLogSize:       maxLogSize,
		MaxNumLogs:       maxNumLogs,
		TruncateOnOpen:   truncateOnOpen,
		TouchLogInterval: touchLogInterval,
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

// currentLevels returns the live level snapshot, falling back to the static config for a
// Logger constructed as a struct literal (i.e. not via New(), so levels was never stored).
func (l *Logger) currentLevels() *levelSet {
	if ls := l.levels.Load(); ls != nil {
		return ls
	}
	return &levelSet{destinationLevels: l.config.DestinationLevels, defaultLevel: l.config.DefaultLevel}
}

// shouldLog checks if a log should be written based on destination-specific verbosity level
func (l *Logger) shouldLog(dest Destination, msgLevel Verbosity) bool {
	// Only log if message level is at or below the destination's configured level
	// (from the live snapshot).
	return msgLevel <= l.currentLevels().levelFor(dest)
}

// buildFilteredLogger wraps w in a per-destination filtering handler bound to this
// Logger's live level snapshot (&l.levels). Used at construction, on log rotation, and
// for the process-global default so every path shares one dynamically-updatable level set.
func (l *Logger) buildFilteredLogger(w io.Writer) *slog.Logger {
	base := slog.NewTextHandler(w, &slog.HandlerOptions{Level: slog.LevelDebug})
	return slog.New(&filteringHandler{handler: base, levels: &l.levels})
}

// ApplyLevels replaces the live per-destination verbosity configuration. Because the
// installed handlers (local, process-global, post-rotation) all read levels through the
// shared atomic pointer, this single swap re-applies levels everywhere with no handler
// rebuild -- the mechanism condor_reconfig uses to change log levels on a running daemon.
// A nil destinationLevels means "all destinations use defaultLevel".
func (l *Logger) ApplyLevels(destinationLevels map[Destination]Verbosity, defaultLevel Verbosity) {
	l.levels.Store(&levelSet{
		destinationLevels: destinationLevels,
		defaultLevel:      defaultLevel,
	})
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
	case DestinationMCP:
		return "mcp"
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

	// Create new log file (0644 to match C++ HTCondor's world-readable daemon logs).
	//nolint:gosec // G304 - logPath is internal to logger, not user-controlled
	f, err := os.OpenFile(logPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
	if err != nil {
		return fmt.Errorf("failed to create new log file: %w", err)
	}
	forceLogPerm(f)

	// Update file handle and reset size atomically
	l.logFile.Store(f)
	l.currentSize.Store(0)
	l.fireRotate(f)

	// Rebuild through the per-destination filtering handler (bound to the live level
	// snapshot) so post-rotation direct-slog calls stay filtered.
	l.logger.Store(l.buildFilteredLogger(f))

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
	// Re-assert 0644 on the heartbeat, as C++ HTCondor does (dprintf.cpp): keeps the log
	// world-readable even if the file was recreated/chmod'd out from under us.
	//nolint:gosec // G302: daemon logs are intentionally world-readable, as in C++ HTCondor
	_ = os.Chmod(logPath, 0644)

	return nil
}

// forceLogPerm sets a freshly opened log file to 0644 regardless of the process umask,
// matching C++ HTCondor (which chmod's its logs to 0644; see dprintf.cpp). os.OpenFile's
// create mode is masked by umask, so a daemon under a restrictive umask (e.g. 077) would
// otherwise get 0600 despite the 0644 argument; an explicit fchmod is not umask-subject.
// Best-effort, like C++'s (void) chmod.
func forceLogPerm(f *os.File) {
	if f != nil {
		//nolint:gosec // G302: daemon logs are intentionally world-readable, as in C++ HTCondor
		_ = f.Chmod(0644)
	}
}

// reopenLogFile reopens the log file after external rotation or deletion.
func (l *Logger) reopenLogFile() error {
	logPath := l.config.OutputPath

	// Open new file (0644 to match C++ HTCondor's world-readable daemon logs).
	//nolint:gosec // G304 - logPath is internal to logger, not user-controlled
	f, err := os.OpenFile(logPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
	if err != nil {
		return fmt.Errorf("failed to reopen log file: %w", err)
	}
	forceLogPerm(f)

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
	l.fireRotate(f)

	// Reset size to current file size
	l.currentSize.Store(stat.Size())

	// Rebuild through the per-destination filtering handler (bound to the live level
	// snapshot) so post-rotation direct-slog calls stay filtered -- a bare TextHandler
	// here would bypass per-destination levels after every rotation.
	l.logger.Store(l.buildFilteredLogger(f))

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
	// Pre-filter based on destination level (lightweight check)
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
	// Pre-filter based on destination level (lightweight check)
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
	// Pre-filter based on destination level (lightweight check)
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
	// Pre-filter based on destination level (lightweight check)
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
	// Pre-filter based on destination level (lightweight check)
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
	// Pre-filter based on destination level (lightweight check)
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
	// Pre-filter based on destination level (lightweight check)
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
	// Pre-filter based on destination level (lightweight check)
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

// RedirectStdLog routes the Go standard library's "log" package
// (log.Print, log.Fatal, log.Fatalf, …) through this Logger as INFO
// records on the General destination. Use this in a binary's main()
// after constructing the Logger, so any fatal error from an
// init/startup path reaches the same stream operators are reading
// instead of going to stderr where it may not be captured (e.g. a
// container running under condor_master with HTTP_API_LOG pointed
// at a file and kubectl logs reading the file, not stderr).
//
// Specifically: stdlib log.Fatalf calls Output() then os.Exit(1).
// Without redirection, the Output() call writes to stderr — invisible
// in deployments that route kubectl logs through a file. With
// redirection, the message lands in the slog stream first, then
// os.Exit(1) still ends the process. So an init failure shows up as
// a structured log line just before the exit.
//
// Goroutine-safe; safe to call once at startup. Calling again
// replaces the redirect. Pass through stdlib's standard import via
// "log" — we deliberately avoid importing "log" at the top of this
// file to keep the API surface small; stdlibLog is set in init().
func (l *Logger) RedirectStdLog() {
	stdlog.SetOutput(&stdlibLogWriter{logger: l})
	// Strip the stdlib log's flags — the slog handler stamps its own
	// timestamp + level, and a stdlib "2026/05/07 12:00:00" prefix
	// would just be noise inside the slog message field.
	stdlog.SetFlags(0)
}

// stdlibLogWriter adapts stdlib log writes into Logger.Info on the
// General destination. We log at Info rather than Error because
// stdlib log doesn't carry a level — surfacing every legacy log line
// as ERROR would be misleading.
type stdlibLogWriter struct {
	logger *Logger
}

func (w *stdlibLogWriter) Write(p []byte) (int, error) {
	// stdlib log appends "\n"; trim so the slog message field doesn't
	// carry it forward into the rendered text.
	msg := strings.TrimRight(string(p), "\n")
	if msg != "" {
		w.logger.Info(DestinationGeneral, msg)
	}
	return len(p), nil
}

// EarlyBuffer captures stdlib `log.*` output produced *before* the
// structured logger is constructed, so those startup lines (the
// daemon-core inheritance diagnostic, "Using UID_DOMAIN", any
// log.Println from imported packages) can be replayed through the
// daemon log file once slog is wired up. Without this, the early
// trace only ever lands on stderr — invisible to anyone who's
// tailing $(LOG)/HttpApiLog and trying to figure out what the
// daemon did at startup.
//
// Lines are tee'd: they continue to write to the underlying stderr
// (or whatever `log.Default()` was using) AND to an in-memory ring,
// so an operator watching the process directly still sees them
// immediately.
type EarlyBuffer struct {
	mu       sync.Mutex
	lines    []earlyLine
	cap      int
	upstream io.Writer // tee target — usually os.Stderr
	replayed bool
}

type earlyLine struct {
	t   time.Time
	msg string
}

// InstallEarlyBuffer redirects the stdlib `log` package's default
// destination to a tee that writes to both `upstream` (typically
// os.Stderr) and a bounded in-memory ring. The returned *EarlyBuffer
// holds the captured lines until Replay drains them through a
// structured Logger.
//
// `capLines` caps the ring at that many entries; older lines are
// dropped FIFO when the cap is exceeded. Pick a generous default —
// startup typically emits well under 100 lines, so even 256 is
// effectively unbounded for normal runs while bounding pathological
// loops.
//
// Pair every InstallEarlyBuffer with exactly one of Replay (success
// path; drains to the logger and switches stdlib log into Logger
// directly) or Detach (failure path; resumes plain stderr writes
// without replay). Calling neither is a leak: subsequent log.*
// calls keep accumulating lines forever.
func InstallEarlyBuffer(upstream io.Writer, capLines int) *EarlyBuffer {
	if upstream == nil {
		upstream = os.Stderr
	}
	if capLines <= 0 {
		capLines = 256
	}
	b := &EarlyBuffer{cap: capLines, upstream: upstream}
	stdlog.SetOutput(b)
	return b
}

// Write implements io.Writer. Each call corresponds to one stdlib
// log line (stdlib log writes the entire formatted line in a single
// Write). We pass it through to upstream verbatim so the operator
// keeps seeing it on stderr in real time, and we strip the trailing
// newline before stashing in the ring so replay doesn't double up
// the line break.
func (b *EarlyBuffer) Write(p []byte) (int, error) {
	if b.upstream != nil {
		// Best-effort tee: a stderr write failure shouldn't kill
		// log.Println.
		_, _ = b.upstream.Write(p)
	}
	msg := strings.TrimRight(string(p), "\n")
	if msg == "" {
		return len(p), nil
	}
	b.mu.Lock()
	b.lines = append(b.lines, earlyLine{t: time.Now(), msg: msg})
	if len(b.lines) > b.cap {
		// Drop oldest. Keeping a sliding window means a runaway
		// log loop can't OOM the process.
		b.lines = b.lines[len(b.lines)-b.cap:]
	}
	b.mu.Unlock()
	return len(p), nil
}

// Replay drains the buffered lines into l as Info records on the
// General destination, then re-points stdlib log at the structured
// logger directly (equivalent to calling Logger.RedirectStdLog).
// Subsequent log.* calls go straight through and bypass the buffer.
//
// The replayed lines carry the original capture timestamp in the
// message so an operator can see the original ordering even though
// slog stamps its own time when the record is emitted.
func (b *EarlyBuffer) Replay(l *Logger) {
	if l == nil {
		return
	}
	b.mu.Lock()
	if b.replayed {
		b.mu.Unlock()
		return
	}
	lines := b.lines
	b.lines = nil
	b.replayed = true
	b.mu.Unlock()

	for _, ln := range lines {
		l.Info(DestinationGeneral, ln.msg, "captured_at", ln.t.Format(time.RFC3339Nano))
	}
	// Hand the stdlib log over to the structured logger directly —
	// future log.* calls don't need to go through the buffer
	// anymore.
	l.RedirectStdLog()
}

// Detach restores stdlib log to its underlying writer (no replay).
// Use on the failure path: if the daemon is exiting before the
// structured logger could be built, calling Detach lets any further
// log.Fatalf line still reach stderr instead of getting swallowed by
// the buffer. Idempotent.
func (b *EarlyBuffer) Detach() {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.replayed {
		return
	}
	b.replayed = true
	stdlog.SetOutput(b.upstream)
}

// formatMessage is a helper to format Printf-style messages
func formatMessage(format string, args ...any) string {
	if len(args) == 0 {
		return format
	}
	return fmt.Sprintf(format, args...)
}
