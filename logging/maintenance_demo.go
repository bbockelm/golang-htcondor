//go:build ignore

package main

import (
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/bbockelm/golang-htcondor/logging"
)

func main() {
	// Create a temporary directory for demo logs
	tmpDir, err := os.MkdirTemp("", "htcondor-maintenance-demo")
	if err != nil {
		panic(err)
	}
	defer os.RemoveAll(tmpDir)

	logPath := filepath.Join(tmpDir, "daemon.log")
	fmt.Printf("Demo: Log maintenance with external rotation detection\n")
	fmt.Printf("Log path: %s\n\n", logPath)

	// Create logger with maintenance enabled
	logger, err := logging.New(&logging.Config{
		OutputPath:       logPath,
		MaxLogSize:       10000,
		MaxNumLogs:       2,
		TouchLogInterval: 2, // Touch every 2 seconds
		DestinationLevels: map[logging.Destination]logging.Verbosity{
			logging.DestinationGeneral: logging.VerbosityDebug,
		},
	})
	if err != nil {
		panic(err)
	}

	// Start maintenance goroutine
	if err := logger.StartMaintenance(); err != nil {
		panic(err)
	}
	defer logger.StopMaintenance()

	fmt.Println("Starting log maintenance (touches log every 2 seconds)...")

	// Write initial messages
	fmt.Println("\n1. Writing initial messages...")
	for i := 0; i < 3; i++ {
		logger.Info(logging.DestinationGeneral, "Initial message", "iteration", i)
	}

	time.Sleep(3 * time.Second)

	// Simulate external rotation
	fmt.Println("\n2. Simulating external log rotation...")
	if err := os.Rename(logPath, logPath+".external"); err != nil {
		panic(err)
	}
	fmt.Println("   Moved log to daemon.log.external")

	// Wait for maintenance to detect and fix
	fmt.Println("\n3. Waiting for maintenance to detect rotation...")
	time.Sleep(3 * time.Second)

	// Write more messages - should work with reopened file
	fmt.Println("\n4. Writing messages after maintenance detected rotation...")
	for i := 0; i < 3; i++ {
		logger.Info(logging.DestinationGeneral, "Message after rotation", "iteration", i)
	}

	// List all log files
	fmt.Println("\n5. Log files after external rotation:")
	entries, err := os.ReadDir(tmpDir)
	if err != nil {
		panic(err)
	}

	for _, entry := range entries {
		info, _ := entry.Info()
		fmt.Printf("   %s (size: %d bytes)\n", entry.Name(), info.Size())
	}

	fmt.Println("\nMaintenance features demonstrated:")
	fmt.Println("  - Periodic file touching (updates mtime)")
	fmt.Println("  - Detection of external rotation via inode comparison")
	fmt.Println("  - Automatic file reopening when external rotation detected")
	fmt.Println("  - Continue logging seamlessly after external rotation")
}
