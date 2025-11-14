//go:build ignore
// +build ignore

package main

import (
	"errors"

	"github.com/bbockelm/golang-htcondor/logging"
)

func main() {
	// Create logger with default config (Info level, all destinations enabled)
	logger, err := logging.New(&logging.Config{
		OutputPath:   "stderr",
		MinVerbosity: logging.VerbosityInfo,
	})
	if err != nil {
		panic(err)
	}

	// Server lifecycle logs (like in server.go)
	logger.Info(logging.DestinationHTTP, "Starting HTCondor API server", "address", ":8080")
	logger.Info(logging.DestinationHTTP, "Starting HTCondor API server with TLS", "address", ":8443")

	// Schedd discovery logs (like in server.go)
	logger.Infof(logging.DestinationSchedd, "ScheddAddr not provided, discovering schedd '%s' from collector...", "condor-schedd")
	logger.Info(logging.DestinationSchedd, "Discovered schedd", "address", "<192.168.1.100:9618>")

	// Security logs (like in server.go) - Debug level won't show with Info verbosity
	logger.Debug(logging.DestinationSecurity, "Generating token for user", "username", "alice@example.com", "header", "X-Remote-User")

	// Error logs (like in handlers.go)
	sampleErr := errors.New("connection refused")
	logger.Error(logging.DestinationSchedd, "Error receiving job sandbox", "job_id", "123.0", "error", sampleErr)

	// Shutdown
	logger.Info(logging.DestinationHTTP, "Shutting down HTTP server")

	// Now create a debug-level logger to show debug output
	debugLogger, _ := logging.New(&logging.Config{
		OutputPath:   "stderr",
		MinVerbosity: logging.VerbosityDebug,
	})

	println("\n--- With Debug verbosity enabled ---")
	debugLogger.Debug(logging.DestinationSecurity, "Generating token for user", "username", "bob@example.com", "header", "X-Remote-User")

	// Example with destination filtering
	println("\n--- With only HTTP destination enabled ---")
	httpOnlyLogger, _ := logging.New(&logging.Config{
		OutputPath:   "stderr",
		MinVerbosity: logging.VerbosityInfo,
		EnabledDestinations: map[logging.Destination]bool{
			logging.DestinationHTTP: true,
		},
	})

	httpOnlyLogger.Info(logging.DestinationHTTP, "This will be logged")
	httpOnlyLogger.Info(logging.DestinationSchedd, "This will be filtered out")
}
