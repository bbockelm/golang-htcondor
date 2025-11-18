// Package main demonstrates schedd address update functionality.
//
// This example shows how the HTTP server automatically updates the schedd
// address when it's discovered from the collector. The address is checked
// approximately every 60 seconds.
//
// When the schedd address is provided explicitly via Config.ScheddAddr,
// the updater is NOT started and the address remains fixed.
//
// When the schedd address is discovered from the collector (Config.ScheddAddr
// is empty), the updater IS started and will periodically query the collector
// for address updates.
package main

import (
	"context"
	"fmt"
	"log"
	"time"

	htcondor "github.com/bbockelm/golang-htcondor"
	"github.com/bbockelm/golang-htcondor/httpserver"
)

func main() {
	// Example 1: Explicit schedd address (no automatic updates)
	fmt.Println("Example 1: Explicit schedd address")
	serverExplicit, err := httpserver.NewServer(httpserver.Config{
		ListenAddr: ":8080",
		ScheddName: "my-schedd",
		ScheddAddr: "127.0.0.1:9618", // Explicit address - no updates
	})
	if err != nil {
		log.Fatalf("Failed to create server: %v", err)
	}
	fmt.Println("  - Schedd address is fixed at 127.0.0.1:9618")
	fmt.Println("  - No automatic updates will occur")
	_ = serverExplicit

	fmt.Println()

	// Example 2: Discovered schedd address (automatic updates enabled)
	fmt.Println("Example 2: Discovered schedd address")

	// Create a collector for discovery
	collector := htcondor.NewCollector("localhost")

	serverDiscovered, err := httpserver.NewServer(httpserver.Config{
		ListenAddr: ":8081",
		ScheddName: "my-schedd",
		ScheddAddr: "", // Empty - will be discovered from collector
		Collector:  collector,
	})
	if err != nil {
		log.Fatalf("Failed to create server: %v", err)
	}
	fmt.Println("  - Schedd address will be discovered from collector")
	fmt.Println("  - Address will be checked every ~60 seconds")
	fmt.Println("  - Server will automatically update if address changes")

	// Start the server (this starts the updater goroutine)
	go func() {
		if err := serverDiscovered.Start(); err != nil {
			log.Printf("Server stopped: %v", err)
		}
	}()

	// Wait a bit to show the updater is running
	time.Sleep(2 * time.Second)

	// Shutdown gracefully
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := serverDiscovered.Shutdown(ctx); err != nil {
		log.Printf("Shutdown error: %v", err)
	}

	fmt.Println()
	fmt.Println("Server shutdown complete - background goroutines stopped")
}
