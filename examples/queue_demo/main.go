package main

import (
	"fmt"
	"os"
	"strings"

	htcondor "github.com/bbockelm/golang-htcondor"
)

func main() {
	// Example 1: Simple queue with count
	fmt.Println("Example 1: Queue 3 jobs")
	fmt.Println("========================")
	submit1 := `
universe = vanilla
executable = /bin/echo
arguments = "Job $(Process)"
output = job_$(Process).out
queue 3
`
	sf1, _ := htcondor.ParseSubmitFile(strings.NewReader(submit1))
	result1, _ := sf1.Submit(1000)
	fmt.Printf("Created %d jobs (Cluster %d)\n\n", result1.NumProcs, result1.ClusterID)

	// Example 2: Queue with list iteration
	fmt.Println("Example 2: Queue with list iteration")
	fmt.Println("====================================")
	submit2 := `
universe = vanilla
executable = /bin/process
arguments = --input $(item)
output = output_$(item).txt
queue item in (alpha, beta, gamma)
`
	sf2, _ := htcondor.ParseSubmitFile(strings.NewReader(submit2))
	result2, _ := sf2.Submit(1001)
	fmt.Printf("Created %d jobs (Cluster %d)\n\n", result2.NumProcs, result2.ClusterID)

	// Example 3: Queue from file. Reading an itemdata file (and the
	// glob in example 4) needs AllowLocalAccess: this demo is the local
	// user, unlike a daemon parsing a submit file it received.
	fmt.Println("Example 3: Queue from file")
	fmt.Println("==========================")

	// Create a temporary file with data
	tmpFile, err := os.CreateTemp("", "queue_data_*.txt")
	if err != nil {
		fmt.Printf("Error creating temp file: %v\n", err)
		return
	}
	defer os.Remove(tmpFile.Name())

	tmpFile.WriteString("input1.dat\ninput2.dat\ninput3.dat\n")
	tmpFile.Close()

	submit3 := fmt.Sprintf(`
universe = vanilla
executable = /bin/analyze
arguments = --file $(datafile)
output = result_$(datafile).out
queue datafile from "%s"
`, tmpFile.Name())

	sf3, _ := htcondor.ParseSubmitFileWithOptions(strings.NewReader(submit3), htcondor.SubmitParseOptions{AllowLocalAccess: true})
	result3, _ := sf3.Submit(1002)
	fmt.Printf("Created %d jobs (Cluster %d)\n\n", result3.NumProcs, result3.ClusterID)

	// Example 4: Queue matching files
	fmt.Println("Example 4: Queue matching files")
	fmt.Println("================================")

	// Create some temporary files to match
	tmpDir, _ := os.MkdirTemp("", "queue_test_")
	defer os.RemoveAll(tmpDir)

	for i := 1; i <= 4; i++ {
		f, _ := os.Create(fmt.Sprintf("%s/data%d.txt", tmpDir, i))
		f.Close()
	}

	// Change to temp directory for glob
	oldDir, _ := os.Getwd()
	os.Chdir(tmpDir)
	defer os.Chdir(oldDir)

	submit4 := `
universe = vanilla
executable = /bin/process
arguments = $(ITEM)
output = processed_$(ITEM).out
queue matching "data*.txt"
`
	sf4, _ := htcondor.ParseSubmitFileWithOptions(strings.NewReader(submit4), htcondor.SubmitParseOptions{AllowLocalAccess: true})
	result4, _ := sf4.Submit(1003)
	fmt.Printf("Created %d jobs (Cluster %d)\n\n", result4.NumProcs, result4.ClusterID)

	// Example 5: Multiple jobs per item
	fmt.Println("Example 5: Multiple jobs per item (3 jobs × 2 items = 6 total)")
	fmt.Println("=================================================================")
	submit5 := `
universe = vanilla
executable = /bin/simulation
arguments = --seed $(Step) --config $(config)
output = sim_$(config)_$(Step).out
queue 3 config in (setup_A, setup_B)
`
	sf5, _ := htcondor.ParseSubmitFile(strings.NewReader(submit5))
	result5, _ := sf5.Submit(1004)
	fmt.Printf("Created %d jobs (Cluster %d)\n\n", result5.NumProcs, result5.ClusterID)

	fmt.Println("All examples completed successfully!")
}
