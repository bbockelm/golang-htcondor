// Package main demonstrates how to use GetSecurityConfig with collector queries
package main

import (
	"context"
	"fmt"
	"log"
	"os"

	"github.com/bbockelm/cedar/commands"
	htcondor "github.com/bbockelm/golang-htcondor"
	"github.com/bbockelm/golang-htcondor/config"
)

func main() {
	// Load HTCondor configuration from environment
	cfg, err := config.New()
	if err != nil {
		log.Fatalf("Failed to load HTCondor configuration: %v", err)
	}

	// Get collector host from configuration
	collectorHost, ok := cfg.Get("COLLECTOR_HOST")
	if !ok {
		log.Fatal("COLLECTOR_HOST not defined in configuration")
	}

	fmt.Printf("Collector host: %s\n", collectorHost)

	// Get security configuration for CLIENT context
	// This reads SEC_CLIENT_* and SEC_DEFAULT_* parameters
	secConfig, err := htcondor.GetSecurityConfig(cfg, int(commands.QUERY_STARTD_ADS), "CLIENT")
	if err != nil {
		log.Fatalf("Failed to get security configuration: %v", err)
	}

	// Display security configuration
	fmt.Println("\nSecurity Configuration:")
	fmt.Printf("  Authentication: %v\n", secConfig.Authentication)
	fmt.Printf("  Encryption: %v\n", secConfig.Encryption)
	fmt.Printf("  Integrity: %v\n", secConfig.Integrity)

	fmt.Printf("  Authentication Methods: ")
	for i, method := range secConfig.AuthMethods {
		if i > 0 {
			fmt.Print(", ")
		}
		fmt.Print(method)
	}
	fmt.Println()

	fmt.Printf("  Crypto Methods: ")
	for i, method := range secConfig.CryptoMethods {
		if i > 0 {
			fmt.Print(", ")
		}
		fmt.Print(method)
	}
	fmt.Println()

	if secConfig.CertFile != "" {
		fmt.Printf("  SSL Cert File: %s\n", secConfig.CertFile)
	}
	if secConfig.KeyFile != "" {
		fmt.Printf("  SSL Key File: %s\n", secConfig.KeyFile)
	}
	if secConfig.CAFile != "" {
		fmt.Printf("  SSL CA File: %s\n", secConfig.CAFile)
	}
	if secConfig.TokenDir != "" {
		fmt.Printf("  Token Directory: %s\n", secConfig.TokenDir)
	}

	// Example: Query collector for startd ads
	// This would typically use the secConfig with a collector query
	collector := htcondor.NewCollector(collectorHost) // Uses COLLECTOR_HOST from config
	ctx := context.Background()

	fmt.Println("\nQuerying collector for startd ads...")
	ads, err := collector.QueryAds(ctx, "StartdAd", "True")
	if err != nil {
		// Note: This may fail if no HTCondor installation is present
		fmt.Fprintf(os.Stderr, "Warning: Collector query failed: %v\n", err)
		fmt.Println("(This is expected if HTCondor is not installed)")
		return
	}

	fmt.Printf("Found %d startd ads\n", len(ads))
	for i, ad := range ads {
		if i >= 3 {
			fmt.Printf("... and %d more\n", len(ads)-3)
			break
		}

		name, ok := ad.EvaluateAttrString("Name")
		if ok {
			fmt.Printf("  - %s\n", name)
		}
	}
}
