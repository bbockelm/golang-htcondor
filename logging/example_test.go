package logging_test

import (
	"github.com/bbockelm/golang-htcondor/logging"
)

// ExampleLogger demonstrates various logging patterns
func ExampleLogger() {
	// Create a logger with debug enabled for all destinations
	logger, err := logging.New(&logging.Config{
		OutputPath: "stdout",
		DestinationLevels: map[logging.Destination]logging.Verbosity{
			logging.DestinationHTTP:      logging.VerbosityDebug,
			logging.DestinationSchedd:    logging.VerbosityDebug,
			logging.DestinationSecurity:  logging.VerbosityDebug,
			logging.DestinationCollector: logging.VerbosityDebug,
			logging.DestinationMetrics:   logging.VerbosityDebug,
		},
	})
	if err != nil {
		panic(err)
	}

	// Info log with structured fields
	logger.Info(logging.DestinationHTTP, "Server started", "port", 8080, "tls_enabled", true)

	// Error log with structured fields
	logger.Error(logging.DestinationSchedd, "Failed to connect", "address", "localhost:9618", "error", "connection refused")

	// Debug log with structured fields
	logger.Debug(logging.DestinationSecurity, "Token generated", "username", "user@example.com", "expiry", "60s")

	// Printf-style logging (for compatibility)
	logger.Infof(logging.DestinationCollector, "Discovered %d schedd daemons", 3)

	// Warn log
	logger.Warn(logging.DestinationMetrics, "High memory usage", "usage_mb", 1024, "threshold_mb", 800)
}

// ExampleLogger_withFiltering demonstrates per-destination verbosity levels
func ExampleLogger_withFiltering() {
	// Create a logger with different levels for different destinations
	logger, err := logging.New(&logging.Config{
		OutputPath: "stdout",
		DestinationLevels: map[logging.Destination]logging.Verbosity{
			logging.DestinationHTTP:     logging.VerbosityInfo,  // Info and above for HTTP
			logging.DestinationSecurity: logging.VerbosityDebug, // Debug and above for Security
			logging.DestinationCedar:    logging.VerbosityDebug, // Debug and above for Cedar
			// Other destinations default to Warn
		},
	})
	if err != nil {
		panic(err)
	}

	// This will be logged (HTTP is at Info level)
	logger.Info(logging.DestinationHTTP, "Request received", "method", "GET", "path", "/api/v1/jobs")

	// This will NOT be logged (Schedd defaults to Warn, and Info is more verbose than Warn)
	logger.Info(logging.DestinationSchedd, "Job submitted", "cluster_id", 123)

	// This will be logged (Security is at Debug level)
	logger.Debug(logging.DestinationSecurity, "Authentication successful", "user", "alice")
	
	// This will be logged (Warn is allowed for all destinations by default)
	logger.Warn(logging.DestinationSchedd, "Connection slow", "latency_ms", 500)
}
