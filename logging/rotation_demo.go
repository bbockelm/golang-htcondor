//go:build ignore

package main

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/bbockelm/golang-htcondor/logging"
)

func main() {
	// Create a temporary directory for demo logs
	tmpDir, err := os.MkdirTemp("", "htcondor-log-rotation-demo")
	if err != nil {
		panic(err)
	}
	defer os.RemoveAll(tmpDir)

	logPath := filepath.Join(tmpDir, "daemon.log")
	fmt.Printf("Demo: Log rotation with HTCondor daemon log rotation logic\n")
	fmt.Printf("Log path: %s\n\n", logPath)

	// Create logger with small max size to trigger rotation quickly
	logger, err := logging.New(&logging.Config{
		OutputPath: logPath,
		MaxLogSize: 500, // Very small for demo purposes (500 bytes)
		MaxNumLogs: 3,   // Keep 3 rotated logs
		DestinationLevels: map[logging.Destination]logging.Verbosity{
			logging.DestinationGeneral: logging.VerbosityDebug,
		},
	})
	if err != nil {
		panic(err)
	}

	// Write messages that will trigger rotation
	fmt.Println("Writing log messages (will trigger rotation)...")
	for i := 0; i < 20; i++ {
		logger.Info(logging.DestinationGeneral, "Sample log message with some data", "iteration", i, "status", "running")
	}

	// List all log files created
	fmt.Println("\nLog files after rotation:")
	entries, err := os.ReadDir(tmpDir)
	if err != nil {
		panic(err)
	}

	for _, entry := range entries {
		info, _ := entry.Info()
		fmt.Printf("  %s (size: %d bytes)\n", entry.Name(), info.Size())
	}

	fmt.Println("\nLog rotation follows HTCondor daemon conventions:")
	fmt.Println("  - Current log: daemon.log")
	fmt.Println("  - Most recent rotated: daemon.log.old")
	fmt.Println("  - Next older: daemon.log.old.1")
	fmt.Println("  - Oldest: daemon.log.old.2")
	fmt.Println("  - When rotating again, daemon.log.old.2 is deleted")
}
