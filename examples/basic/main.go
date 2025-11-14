package main

import (
	"context"
	"fmt"
	"log"
	"time"

	htcondor "github.com/bbockelm/golang-htcondor"
)

func main() {
	fmt.Println("HTCondor Go Client Example")
	fmt.Println("===========================\n")

	// Example 1: Query a collector for ads
	fmt.Println("Example 1: Querying collector for ads")
	fmt.Println("--------------------------------------")

	// Create a collector instance
	// For testing, use a known public collector like OSG's
	collector := htcondor.NewCollector("cm-1.ospool.osg-htc.org:9618")
	fmt.Printf("Created collector: %s\n", "cm-1.ospool.osg-htc.org:9618")

	// Create a context with timeout
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// Query for startd ads (machines)
	fmt.Println("\nQuerying for Machine ads (limited to 3)...")
	ads, err := collector.QueryAds(ctx, "StartdAd", "")
	if err != nil {
		log.Printf("QueryAds error: %v\n", err)
		log.Println("Note: This requires network access to the collector")
	} else {
		fmt.Printf("✓ Found %d machine ads\n", len(ads))

		// Print first few ads
		limit := 3
		if len(ads) < limit {
			limit = len(ads)
		}
		for i := 0; i < limit; i++ {
			ad := ads[i]
			if name, ok := ad.EvaluateAttrString("Name"); ok {
				fmt.Printf("  - Machine: %s\n", name)
			}
		}
	}

	// Example 2: Create a schedd instance
	fmt.Println("\n\nExample 2: Creating Schedd client")
	fmt.Println("----------------------------------")
	_ = htcondor.NewSchedd("test_schedd", "schedd.example.com:9618")
	fmt.Printf("Created schedd: %s at %s\n", "test_schedd", "schedd.example.com:9618")
	fmt.Println("Note: Schedd query implementation is still in progress")

	fmt.Println("\n✓ Examples complete!")
	fmt.Println("\nFor a more detailed query demo, see query_demo.go")
}
