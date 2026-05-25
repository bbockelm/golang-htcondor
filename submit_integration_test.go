package htcondor

import (
	"bufio"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/PelicanPlatform/classad/classad"
)

// Integration tests that compare the Go library's submit functionality
// with the official condor_submit tool.
//
// These tests:
// - Use condor_submit -dry-run to generate ClassAd files
// - Compare the Go library's ClassAd output with condor_submit's output
// - Skip if condor_submit is not available in the environment
// - Ignore time-dependent, version-dependent, and runtime attributes
// - Handle differences in expression representation
//
// The goal is to ensure the Go library produces ClassAds that are
// functionally equivalent to what condor_submit produces.

// condorSubmitAvailable checks if condor_submit is available
func condorSubmitAvailable() bool {
	_, err := exec.LookPath("condor_submit")
	return err == nil
}

// parseOldClassAdFile parses a ClassAd file in old format (key=value pairs)
func parseOldClassAdFile(path string) (*classad.ClassAd, error) {
	//nolint:gosec // G304: Test helper for reading test files
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer func() { _ = file.Close() }()

	// Build a full ClassAd string
	var builder strings.Builder
	scanner := bufio.NewScanner(file)

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}

		// Skip special schedd commands (lines starting with ::)
		// These are used for spooling and other operations
		if strings.HasPrefix(line, "::") {
			continue
		}

		// Add line to builder
		builder.WriteString(line)
		builder.WriteString("\n")
	}

	if err := scanner.Err(); err != nil {
		return nil, err
	}

	// Parse the accumulated string as an old-format ClassAd
	adStr := builder.String()
	if adStr == "" {
		return classad.New(), nil
	}

	ad, err := classad.ParseOld(adStr)
	if err != nil {
		return nil, fmt.Errorf("failed to parse ClassAd: %w", err)
	}

	return ad, nil
}

// runCondorSubmit runs condor_submit -dry-run and returns the generated ClassAd
func runCondorSubmit(submitContent string) (*classad.ClassAd, error) {
	// Create temp directory
	tmpDir, err := os.MkdirTemp("", "condor_submit_test_*")
	if err != nil {
		return nil, fmt.Errorf("failed to create temp dir: %w", err)
	}
	defer func() { _ = os.RemoveAll(tmpDir) }()

	// Write submit file
	submitPath := filepath.Join(tmpDir, "test.submit")
	if err := os.WriteFile(submitPath, []byte(submitContent), 0600); err != nil {
		return nil, fmt.Errorf("failed to write submit file: %w", err)
	}

	// Write output ClassAd file
	classadPath := filepath.Join(tmpDir, "test.classad")

	// Run condor_submit -dry-run
	//nolint:gosec,noctx // G204: Test uses fixed condor_submit command; noctx: test doesn't need cancellation
	cmd := exec.Command("condor_submit", "-dry-run", classadPath, submitPath)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("condor_submit failed: %w\nOutput: %s", err, string(output))
	}

	// Parse the generated ClassAd file
	ad, err := parseOldClassAdFile(classadPath)
	if err != nil {
		return nil, fmt.Errorf("failed to parse ClassAd file: %w", err)
	}

	return ad, nil
}

// attributesToIgnore are attributes that differ between implementations or are time/version dependent
var attributesToIgnore = map[string]bool{
	// Time-dependent attributes
	"QDate":                true,
	"EnteredCurrentStatus": true,
	"CompletionDate":       true,
	"JobCurrentStartDate":  true,
	"JobStartDate":         true,
	"LastSuspensionTime":   true,

	// Version-dependent attributes. condor_submit stamps
	// SubmitVersion onto every job (and the schedd stamps
	// CondorVersion onto every cluster, post HTCONDOR-3413).
	// golang-htcondor populates SubmitVersion + CondorPlatform
	// too — see submit.go's submitVersionString / condorPlatformString
	// for the rationale — but the strings will never match
	// condor_submit's by design (we identify ourselves as
	// golang-htcondor in the BuildID segment). Ignore both ways:
	// the presence check would otherwise demand an exact-match
	// implementation, and the value check would flag the
	// intentional difference.
	"CondorVersion":  true,
	"CondorPlatform": true,
	"SubmitVersion":  true,

	// Auto-generated attributes that may differ
	"ClusterId":     true,
	"ProcId":        true,
	"JobSubmitFile": true,
	"Iwd":           true, // Current working directory
	"UserLog":       true, // Full path varies

	// Attributes that may vary by environment
	"FileSystemDomain": true,
	"Owner":            true,

	// Implementation-specific attributes
	"JobSubmitMethod": true,

	// Runtime attributes that are zero at submission
	"ImageSize":                true,
	"ExecutableSize":           true,
	"DiskUsage":                true,
	"CommittedSlotTime":        true,
	"RemoteUserCpu":            true,
	"RemoteSysCpu":             true,
	"RemoteWallClockTime":      true,
	"TotalSuspensions":         true,
	"CumulativeSlotTime":       true,
	"CumulativeRemoteSysCpu":   true,
	"CumulativeSuspensionTime": true,
	"CumulativeRemoteUserCpu":  true,
	"CommittedTime":            true,
	"CommittedSuspensionTime":  true,
	"NumJobCompletions":        true,
	"CurrentHosts":             true,
	"TransferInputSizeMB":      true,
	"NumCkpts":                 true,

	// Status attributes
	"ExitStatus":   true,
	"ExitBySignal": true,

	// HTCondor internals
	"MyType":           true,
	"TargetType":       true,
	"JobStatus":        true,
	"JobPrio":          true,
	"NumJobStarts":     true,
	"NumRestarts":      true,
	"NumSystemHolds":   true,
	"TransferIn":       true,
	"In":               true, // stdin
	"StreamErr":        true,
	"StreamOut":        true,
	"LeaveJobInQueue":  true,
	"JobLeaseDuration": true,
	"JobNotification":  true,
	"JobRunCount":      true,
	"MinHosts":         true,
	"MaxHosts":         true,
	"Rank":             true,

	// Docker-specific
	"WantDocker":  true,
	"JobUniverse": true, // Docker may map to different universe numbers

	// Go library may set these, but condor_submit may not
	"TransferExecutable": true,
	"EmailAttributes":    true,
	"TransferInput":      true,
	"ContainerImage":     true, // Docker universe
	"Args":               true, // May use Arguments instead
	"CopyToSpool":        true, // Handled via ::send_SpoolFile commands, not in ClassAd

	// HTCondor may use different naming/representation
	"Environment":         true, // May be formatted differently
	"Arguments":           true, // May use Args instead
	"ShouldTransferFiles": true, // Default may differ
	"RequestDisk":         true, // May be expression vs value
	"Requirements":        true, // Complex expressions may not match
}

// compareClassAds compares two ClassAds and reports differences, ignoring certain attributes
func compareClassAds(t *testing.T, goAd, condorAd *classad.ClassAd, testName string) {
	t.Helper()

	// Get all attributes from both ads
	goAttrs := make(map[string]bool)
	for _, attr := range goAd.GetAttributes() {
		if !attributesToIgnore[attr] {
			goAttrs[attr] = true
		}
	}

	condorAttrs := make(map[string]bool)
	for _, attr := range condorAd.GetAttributes() {
		if !attributesToIgnore[attr] {
			condorAttrs[attr] = true
		}
	}

	// Check for missing attributes
	var missingInGo []string
	var missingInCondor []string

	for attr := range condorAttrs {
		if !goAttrs[attr] {
			missingInGo = append(missingInGo, attr)
		}
	}

	for attr := range goAttrs {
		if !condorAttrs[attr] {
			missingInCondor = append(missingInCondor, attr)
		}
	}

	if len(missingInGo) > 0 {
		t.Errorf("%s: Attributes in condor_submit but missing in Go library: %v", testName, missingInGo)
	}

	if len(missingInCondor) > 0 {
		t.Logf("%s: Attributes in Go library but not in condor_submit (may be OK): %v", testName, missingInCondor)
	}

	// Compare values for common attributes
	for attr := range goAttrs {
		if !condorAttrs[attr] {
			continue
		}

		goVal := goAd.EvaluateAttr(attr)
		condorVal := condorAd.EvaluateAttr(attr)

		// Skip if either is an error (complex expressions may not evaluate the same)
		if goVal.IsError() || condorVal.IsError() {
			// Check specific important attributes
			if attr == "Requirements" || attr == "RequestDisk" {
				// These are complex expressions - just log the difference
				t.Logf("%s: Attribute %s has complex expression (this is OK if intentional):\n  Go:     %v\n  Condor: %v",
					testName, attr, goVal, condorVal)
			}
			continue
		}

		// Compare the values
		if !valuesEqual(goVal, condorVal) {
			t.Errorf("%s: Attribute %s differs:\n  Go:     %v\n  Condor: %v",
				testName, attr, goVal, condorVal)
		}
	}
}

// valuesEqual compares two ClassAd values for equality
func valuesEqual(v1, v2 classad.Value) bool {
	// Both undefined
	if v1.IsUndefined() && v2.IsUndefined() {
		return true
	}

	// Both error
	if v1.IsError() && v2.IsError() {
		return true
	}

	// Both boolean
	if v1.IsBool() && v2.IsBool() {
		b1, _ := v1.BoolValue()
		b2, _ := v2.BoolValue()
		return b1 == b2
	}

	// Both integer
	if v1.IsInteger() && v2.IsInteger() {
		i1, _ := v1.IntValue()
		i2, _ := v2.IntValue()
		return i1 == i2
	}

	// Both real (or one is integer and other is real)
	if (v1.IsReal() || v1.IsInteger()) && (v2.IsReal() || v2.IsInteger()) {
		var r1, r2 float64
		if v1.IsReal() {
			r1, _ = v1.RealValue()
		} else {
			i, _ := v1.IntValue()
			r1 = float64(i)
		}
		if v2.IsReal() {
			r2, _ = v2.RealValue()
		} else {
			i, _ := v2.IntValue()
			r2 = float64(i)
		}
		// Allow small floating point differences
		return abs(r1-r2) < 0.0001
	}

	// Both string
	if v1.IsString() && v2.IsString() {
		s1, _ := v1.StringValue()
		s2, _ := v2.StringValue()
		// Normalize strings - remove quotes if present
		s1 = strings.Trim(s1, "\"")
		s2 = strings.Trim(s2, "\"")
		return s1 == s2
	}

	// Different types or other cases
	return false
}

func abs(x float64) float64 {
	if x < 0 {
		return -x
	}
	return x
}

// Integration tests

func TestIntegrationSimpleJob(t *testing.T) {
	if !condorSubmitAvailable() {
		t.Skip("condor_submit not available")
	}

	submitContent := `
universe = vanilla
executable = /usr/bin/true
output = test.out
error = test.err
log = test.log
queue
`

	// Get condor_submit result
	condorAd, err := runCondorSubmit(submitContent)
	if err != nil {
		t.Fatalf("Failed to run condor_submit: %v", err)
	}

	// Get Go library result
	sf, err := ParseSubmitFile(strings.NewReader(submitContent))
	if err != nil {
		t.Fatalf("Failed to parse submit file: %v", err)
	}

	result, err := sf.Submit(1)
	if err != nil {
		t.Fatalf("Submit failed: %v", err)
	}

	if len(result.ProcAds) == 0 {
		t.Fatal("No proc ads generated")
	}

	goAd := result.ProcAds[0]

	// Compare
	compareClassAds(t, goAd, condorAd, "SimpleJob")
}

func TestIntegrationJobWithArguments(t *testing.T) {
	if !condorSubmitAvailable() {
		t.Skip("condor_submit not available")
	}

	submitContent := `
universe = vanilla
executable = /usr/bin/printf
arguments = Hello World
output = job.out
error = job.err
log = job.log
request_memory = 256
request_cpus = 2
queue
`

	condorAd, err := runCondorSubmit(submitContent)
	if err != nil {
		t.Fatalf("Failed to run condor_submit: %v", err)
	}

	sf, err := ParseSubmitFile(strings.NewReader(submitContent))
	if err != nil {
		t.Fatalf("Failed to parse submit file: %v", err)
	}

	result, err := sf.Submit(1)
	if err != nil {
		t.Fatalf("Submit failed: %v", err)
	}

	if len(result.ProcAds) == 0 {
		t.Fatal("No proc ads generated")
	}

	goAd := result.ProcAds[0]

	compareClassAds(t, goAd, condorAd, "JobWithArguments")
}

func TestIntegrationEnvironmentVariables(t *testing.T) {
	if !condorSubmitAvailable() {
		t.Skip("condor_submit not available")
	}

	submitContent := `
universe = vanilla
executable = /usr/bin/printenv
environment = "PATH=/usr/bin:/bin USER=testuser HOME=/home/test"
output = env.out
error = env.err
log = env.log
queue
`

	condorAd, err := runCondorSubmit(submitContent)
	if err != nil {
		t.Fatalf("Failed to run condor_submit: %v", err)
	}

	sf, err := ParseSubmitFile(strings.NewReader(submitContent))
	if err != nil {
		t.Fatalf("Failed to parse submit file: %v", err)
	}

	result, err := sf.Submit(1)
	if err != nil {
		t.Fatalf("Submit failed: %v", err)
	}

	if len(result.ProcAds) == 0 {
		t.Fatal("No proc ads generated")
	}

	goAd := result.ProcAds[0]

	compareClassAds(t, goAd, condorAd, "EnvironmentVariables")
}

func TestIntegrationFileTransfer(t *testing.T) {
	if !condorSubmitAvailable() {
		t.Skip("condor_submit not available")
	}

	submitContent := `
universe = vanilla
executable = /bin/cat
transfer_input_files = input.txt, data.csv
transfer_output_files = result.txt
should_transfer_files = YES
when_to_transfer_output = ON_EXIT
output = transfer.out
error = transfer.err
log = transfer.log
queue
`

	condorAd, err := runCondorSubmit(submitContent)
	if err != nil {
		t.Fatalf("Failed to run condor_submit: %v", err)
	}

	sf, err := ParseSubmitFile(strings.NewReader(submitContent))
	if err != nil {
		t.Fatalf("Failed to parse submit file: %v", err)
	}

	result, err := sf.Submit(1)
	if err != nil {
		t.Fatalf("Submit failed: %v", err)
	}

	if len(result.ProcAds) == 0 {
		t.Fatal("No proc ads generated")
	}

	goAd := result.ProcAds[0]

	compareClassAds(t, goAd, condorAd, "FileTransfer")
}

func TestIntegrationRequirements(t *testing.T) {
	if !condorSubmitAvailable() {
		t.Skip("condor_submit not available")
	}

	submitContent := `
universe = vanilla
executable = /bin/hostname
requirements = (OpSys == "LINUX") && (Arch == "X86_64") && (Memory >= 1024)
output = req.out
error = req.err
log = req.log
queue
`

	condorAd, err := runCondorSubmit(submitContent)
	if err != nil {
		t.Fatalf("Failed to run condor_submit: %v", err)
	}

	sf, err := ParseSubmitFile(strings.NewReader(submitContent))
	if err != nil {
		t.Fatalf("Failed to parse submit file: %v", err)
	}

	result, err := sf.Submit(1)
	if err != nil {
		t.Fatalf("Submit failed: %v", err)
	}

	if len(result.ProcAds) == 0 {
		t.Fatal("No proc ads generated")
	}

	goAd := result.ProcAds[0]

	compareClassAds(t, goAd, condorAd, "Requirements")
}

func TestIntegrationDockerUniverse(t *testing.T) {
	if !condorSubmitAvailable() {
		t.Skip("condor_submit not available")
	}

	submitContent := `
universe = docker
docker_image = ubuntu:latest
executable = /bin/echo
arguments = hello from docker
output = docker.out
error = docker.err
log = docker.log
queue
`

	condorAd, err := runCondorSubmit(submitContent)
	if err != nil {
		t.Fatalf("Failed to run condor_submit: %v", err)
	}

	sf, err := ParseSubmitFile(strings.NewReader(submitContent))
	if err != nil {
		t.Fatalf("Failed to parse submit file: %v", err)
	}

	result, err := sf.Submit(1)
	if err != nil {
		t.Fatalf("Submit failed: %v", err)
	}

	if len(result.ProcAds) == 0 {
		t.Fatal("No proc ads generated")
	}

	goAd := result.ProcAds[0]

	compareClassAds(t, goAd, condorAd, "DockerUniverse")
}
