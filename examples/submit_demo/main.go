// Package main demonstrates how to use the high-level Schedd.Submit API
package main

import (
	"context"
	"fmt"
	"log"
	"time"

	htcondor "github.com/bbockelm/golang-htcondor"
)

func main() {
	// Create a schedd instance
	// Adjust address to match your HTCondor setup
	schedd := htcondor.NewSchedd("local", "localhost:9618")

	// Define a simple submit file
	submitFile := `
universe = vanilla
executable = /bin/sleep
arguments = 10
output = test.out
error = test.err
log = test.log
queue
`

	// Submit the job
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	clusterID, err := schedd.Submit(ctx, submitFile)
	if err != nil {
		log.Fatalf("Failed to submit job: %v", err)
	}

	fmt.Printf("✅ Successfully submitted job cluster %s\n", clusterID)

	// Example with multiple procs
	multiProcSubmit := `
universe = vanilla
executable = /bin/echo
arguments = "Process $(Process)"
output = proc.$(Process).out
error = proc.$(Process).err
log = test.log
queue 5
`

	clusterID2, err := schedd.Submit(ctx, multiProcSubmit)
	if err != nil {
		log.Fatalf("Failed to submit multi-proc job: %v", err)
	}

	fmt.Printf("✅ Successfully submitted job cluster %s with 5 procs\n", clusterID2)

	// Example with queue variables (use 'in' for inline lists)
	variableSubmit := `
universe = vanilla
executable = /bin/echo
arguments = "Hello $(name)"
output = greeting.$(name).out
error = greeting.$(name).err
log = test.log
queue name in (Alice, Bob, Charlie)
`

	clusterID3, err := schedd.Submit(ctx, variableSubmit)
	if err != nil {
		log.Fatalf("Failed to submit job with variables: %v", err)
	}

	fmt.Printf("✅ Successfully submitted job cluster %s with queue variables\n", clusterID3)
}
