// Package main provides an example of using the classadlog package to monitor HTCondor job queue logs.
package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"time"

	"github.com/bbockelm/golang-htcondor/classadlog"
)

func main() {
	logFile := flag.String("log", "/var/lib/condor/spool/job_queue.log", "Path to job_queue.log file")
	pollInterval := flag.Duration("interval", 5*time.Second, "Poll interval for updates")
	constraint := flag.String("constraint", "", "ClassAd constraint for filtering jobs")
	once := flag.Bool("once", false, "Read once and exit")
	flag.Parse()

	if err := run(*logFile, *pollInterval, *constraint, *once); err != nil {
		log.Fatalf("Error: %v", err)
	}
}

func run(logFile string, pollInterval time.Duration, constraint string, once bool) error {
	if _, err := os.Stat(logFile); os.IsNotExist(err) {
		return fmt.Errorf("log file does not exist: %s", logFile)
	}

	reader, err := classadlog.NewReader(logFile)
	if err != nil {
		return fmt.Errorf("failed to create reader: %w", err)
	}
	defer func() {
		if err := reader.Close(); err != nil {
			log.Printf("Error closing reader: %v", err)
		}
	}()

	fmt.Printf("Reading HTCondor job queue log: %s\n", logFile)
	if constraint != "" {
		fmt.Printf("Constraint: %s\n", constraint)
	}
	fmt.Println()

	ctx := context.Background()

	if err := reader.Poll(ctx); err != nil {
		return fmt.Errorf("initial poll failed: %w", err)
	}

	printJobSummary(reader, constraint)

	if once {
		return nil
	}

	ticker := time.NewTicker(pollInterval)
	defer ticker.Stop()

	fmt.Printf("\nPolling every %v for updates...\n\n", pollInterval)

	for range ticker.C {
		if err := reader.Poll(ctx); err != nil {
			log.Printf("Poll error: %v", err)
			continue
		}
		printJobSummary(reader, constraint)
	}

	return nil
}

func printJobSummary(reader *classadlog.Reader, constraint string) {
	jobs, err := reader.Query(constraint, []string{"ClusterId", "ProcId", "Owner", "JobStatus"})
	if err != nil {
		log.Printf("Query error: %v", err)
		return
	}

	fmt.Printf("[%s] Total jobs in queue: %d\n", time.Now().Format("15:04:05"), reader.Len())

	if constraint != "" {
		fmt.Printf("Jobs matching constraint: %d\n", len(jobs))
	}

	statusCounts := make(map[int64]int)
	ownerCounts := make(map[string]int)

	for _, job := range jobs {
		if status, ok := job.EvaluateAttrInt("JobStatus"); ok {
			statusCounts[status]++
		}
		if owner, ok := job.EvaluateAttrString("Owner"); ok {
			ownerCounts[owner]++
		}
	}

	fmt.Println("\nJobs by status:")
	statusNames := map[int64]string{
		1: "Idle",
		2: "Running",
		3: "Removed",
		4: "Completed",
		5: "Held",
		6: "Transferring Output",
		7: "Suspended",
	}
	for status, count := range statusCounts {
		name := statusNames[status]
		if name == "" {
			name = fmt.Sprintf("Status %d", status)
		}
		fmt.Printf("  %s: %d\n", name, count)
	}

	if len(ownerCounts) > 0 {
		fmt.Println("\nJobs by owner:")
		for owner, count := range ownerCounts {
			fmt.Printf("  %s: %d\n", owner, count)
		}
	}

	fmt.Println()
}
