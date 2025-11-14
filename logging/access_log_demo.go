//go:build ignore
// +build ignore

package main

import (
	"fmt"

	"github.com/bbockelm/golang-htcondor/logging"
)

func main() {
	fmt.Println("=== Access Logging Demo ===\n")
	fmt.Println("When HTTP requests are made to the server, access logs will appear like:\n")

	// Create logger that writes to stdout (like demo mode)
	logger, err := logging.New(&logging.Config{
		OutputPath:   "stdout",
		MinVerbosity: logging.VerbosityInfo,
	})
	if err != nil {
		panic(err)
	}

	// Simulate access log entries
	fmt.Println("Example 1: Anonymous request")
	logger.Info(
		logging.DestinationHTTP,
		"HTTP request",
		"client_ip", "192.168.1.100",
		"identity", "-",
		"method", "GET",
		"path", "/openapi.json",
		"status", 200,
		"duration_ms", int64(15),
		"bytes", 5234,
		"user_agent", "Mozilla/5.0",
	)

	fmt.Println("\nExample 2: Authenticated request via user header")
	logger.Info(
		logging.DestinationHTTP,
		"HTTP request",
		"client_ip", "10.0.0.50",
		"identity", "alice@example.com",
		"method", "GET",
		"path", "/api/v1/jobs",
		"status", 200,
		"duration_ms", int64(234),
		"bytes", 1523,
		"user_agent", "htcondor-cli/1.0",
	)

	fmt.Println("\nExample 3: Token-authenticated request")
	logger.Info(
		logging.DestinationHTTP,
		"HTTP request",
		"client_ip", "172.16.0.10",
		"identity", "token",
		"method", "POST",
		"path", "/api/v1/jobs",
		"status", 201,
		"duration_ms", int64(567),
		"bytes", 342,
		"user_agent", "python-requests/2.28",
	)

	fmt.Println("\nExample 4: Error response")
	logger.Info(
		logging.DestinationHTTP,
		"HTTP request",
		"client_ip", "203.0.113.42",
		"identity", "bob@example.com",
		"method", "DELETE",
		"path", "/api/v1/jobs/123.0",
		"status", 404,
		"duration_ms", int64(12),
		"bytes", 78,
		"user_agent", "curl/7.68.0",
	)

	fmt.Println("\n=== Demo Complete ===")
	fmt.Println("\nIn demo mode (--demo flag), these logs go to stdout.")
	fmt.Println("In normal mode, configure with LOG=<path>, LOG_VERBOSITY=INFO, LOG_DESTINATIONS=HTTP")
}

