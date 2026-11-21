package main

import (
	"fmt"
	"log"

	"github.com/htcondor/golang-htcondor/config"
)

func main() {
	fmt.Println("=== HTCondor Config with Param Defaults Demo ===\n")

	// Example 1: Basic config with defaults
	fmt.Println("1. Creating basic config with default parameters...")
	cfg, err := config.New()
	if err != nil {
		log.Fatal(err)
	}

	// Show some loaded defaults
	fmt.Println("   Loaded param defaults from HTCondor 25.3.1:")
	showParam(cfg, "SHUTDOWN_FAST_TIMEOUT")
	showParam(cfg, "PREEN_INTERVAL")
	showParam(cfg, "SUBSYSTEM")
	fmt.Println()

	// Example 2: Config with subsystem specified
	fmt.Println("2. Creating config for SCHEDD subsystem...")
	scheddCfg, err := config.NewWithOptions(config.ConfigOptions{
		Subsystem: "SCHEDD",
		LocalName: "submit-01",
	})
	if err != nil {
		log.Fatal(err)
	}

	fmt.Println("   Subsystem-specific configuration:")
	showParam(scheddCfg, "SUBSYSTEM")
	showParam(scheddCfg, "LOCAL_NAME")
	fmt.Println()

	// Example 3: Macro expansion with defaults
	fmt.Println("3. Testing macro expansion with param defaults...")
	cfg.Set("SBIN", "/usr/local/condor/sbin")
	cfg.Set("LIBEXEC", "/usr/local/condor/libexec")

	fmt.Println("   After setting base directories:")
	showParam(cfg, "MASTER")
	showParam(cfg, "STARTER_DIAGNOSTIC_send_ep_logs")
	fmt.Println()

	fmt.Println("=== Demo Complete ===")
}

func showParam(cfg *config.Config, name string) {
	val, ok := cfg.Get(name)
	if ok {
		fmt.Printf("   %s = %s\n", name, val)
	} else {
		fmt.Printf("   %s = (not set)\n", name)
	}
}
