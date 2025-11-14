package logging_test

import (
	"github.com/bbockelm/golang-htcondor/logging"
)

// ExampleLogger demonstrates various logging patterns
func ExampleLogger() {
	// Create a logger with default config
	logger, err := logging.New(&logging.Config{
		OutputPath:   "stdout",
		MinVerbosity: logging.VerbosityDebug,
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

// ExampleLogger_withFiltering demonstrates destination filtering
func ExampleLogger_withFiltering() {
	// Create a logger that only logs HTTP and Security destinations
	logger, err := logging.New(&logging.Config{
		OutputPath:   "stdout",
		MinVerbosity: logging.VerbosityInfo,
		EnabledDestinations: map[logging.Destination]bool{
			logging.DestinationHTTP:     true,
			logging.DestinationSecurity: true,
		},
	})
	if err != nil {
		panic(err)
	}

	// This will be logged
	logger.Info(logging.DestinationHTTP, "Request received", "method", "GET", "path", "/api/v1/jobs")

	// This will NOT be logged (destination not enabled)
	logger.Info(logging.DestinationSchedd, "Job submitted", "cluster_id", 123)

	// This will be logged
	logger.Debug(logging.DestinationSecurity, "Authentication successful", "user", "alice")
}
