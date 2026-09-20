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

// attributesToIgnore are attributes compareClassAds does not hold the two
// implementations to.
//
// Every entry states why. An entry with no stated reason is a hole: it
// hides a real divergence from the only test in this repo that asks
// condor_submit what a submit file means, and the Out/Err canonicalization
// bug is the kind of thing that ships through one. Each entry below was
// checked by deleting it and re-running TestIntegration*; the note says
// what the failure was, or that the entry is intentional.
//
// Note also that compareClassAds is asymmetric: an attribute only
// condor_submit sets is an error, but an attribute only the Go library
// sets is a t.Logf. Entries tagged "Go-only" therefore suppress just the
// value comparison.
var attributesToIgnore = map[string]bool{
	// Differ every run by construction.
	"QDate":                true, // submit timestamp
	"EnteredCurrentStatus": true, // submit timestamp
	"LastSuspensionTime":   true, // condor_submit stamps 0; the Go library omits it

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
	"SubmitVersion":  true, // Go-only here; condor_submit -dry-run omits it

	// Identity of the submission, not of the job description.
	"ClusterId":     true, // dry-run always says 1/0; the Go library uses the id it was handed
	"ProcId":        true,
	"JobSubmitFile": true, // condor_submit names the file on disk; the Go library parses a reader
	"Iwd":           true, // both use the process cwd today, but only because no test sets initialdir
	"UserLog":       true, // MASKS: condor_submit absolutizes the log path against Iwd, the Go library stores it as written

	// Properties of the submitting host/account that condor_submit reads
	// from the local config and the Go library does not stamp at all.
	"FileSystemDomain": true, // MASKS: condor_submit sets it, and its own Requirements reference MY.FileSystemDomain
	"Owner":            true, // dry-run leaves it undefined; the real value comes from the schedd
	"JobSubmitMethod":  true, // MASKS: condor_submit stamps 0; this library is not condor_submit

	// Runtime counters. condor_submit stamps the zero value for each and
	// the Go library omits them; the schedd/shadow initialize them either
	// way, so the ads are equivalent to a running job but not textually.
	// MASKS: every one of these is "in condor_submit, missing in Go".
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
	"NumCkpts":                 true,
	"ExitStatus":               true,
	"ExitBySignal":             true,
	// TransferInputSizeMB is the same kind of stamp, but it is not inert:
	// condor_submit's default RequestDisk expression reads it, which is
	// part of why RequestDisk is ignored below.
	"TransferInputSizeMB": true,

	// Ad typing. condor_submit writes MyType/TargetType as ordinary
	// attributes; a classad-native ad carries them out of band.
	"MyType":     true,
	"TargetType": true,

	// Submit-time defaults condor_submit writes and the Go library does
	// not. Each is a real divergence, left ignored rather than fixed
	// because fixing them is a change to what this library submits, not
	// a test change. MASKS, with the value condor_submit writes:
	"JobPrio":          true, // 0
	"MinHosts":         true, // 1
	"MaxHosts":         true, // 1
	"JobNotification":  true, // 0 (NEVER), unless the submit file says otherwise
	"JobLeaseDuration": true, // 2400
	"LeaveJobInQueue":  true, // false

	// Docker/container mapping.
	"WantDocker":  true,
	"JobUniverse": true, // Docker may map to different universe numbers

	// Go-only attributes: set by this library, absent from condor_submit's
	// ad, so only their value comparison is suppressed.
	"TransferExecutable": true,
	"EmailAttributes":    true,
	"TransferInput":      true,
	"ContainerImage":     true, // Docker universe
	"JobRunCount":        true,
	"CopyToSpool":        true, // Handled via ::send_SpoolFile commands, not in ClassAd

	// Arguments representation. MASKS: condor_submit emits Arguments (the
	// V2 form) and the Go library emits Args (V1) for the same submit
	// file, so neither name lines up.
	"Args":      true,
	"Arguments": true,

	// Values that genuinely differ and are known to.
	"Environment":         true, // MASKS: condor_submit always emits Environment (""), and the V1/V2 forms differ
	"ShouldTransferFiles": true, // MASKS: condor_submit defaults to IF_NEEDED, this library to YES
	"RequestDisk":         true, // condor_submit emits the MAX(...) expression, this library a number
	"Requirements":        true, // complex expressions do not render identically
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

// TestIntegrationCustomAttributes compares the two syntaxes for custom
// job attributes against condor_submit itself.
//
// This is the check that matters for them: the Go library and its unit
// tests can agree with each other and still both be wrong about what
// `+Attr = expr` means. condor_submit is the definition, so ask it.
func TestIntegrationCustomAttributes(t *testing.T) {
	if !condorSubmitAvailable() {
		t.Skip("condor_submit not available")
	}

	submitContent := `
universe = vanilla
executable = /usr/bin/true
output = test.out
error = test.err
log = test.log
+Tag = "nightly"
+Retries = 3
+WantGPU = true
+HalfMem = RequestMemory / 2
+X = 1
MY.ProjectID = "project_123"
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

	// Check the custom attributes explicitly as well as through the
	// general comparison: compareClassAds tolerates attributes that
	// only one side has in some categories, and an attribute silently
	// missing from BOTH sides is exactly the failure being guarded
	// against here.
	for _, attr := range []string{"Tag", "Retries", "WantGPU", "HalfMem", "X", "ProjectID"} {
		condorExpr, condorHas := condorAd.Lookup(attr)
		if !condorHas {
			t.Errorf("condor_submit did not set %s; the expectation in this test is wrong, not the library", attr)
			continue
		}
		goExpr, goHas := goAd.Lookup(attr)
		if !goHas {
			t.Errorf("Go ad is missing %s (condor_submit has %s)", attr, condorExpr.String())
			continue
		}
		// Both sides were parsed and are printed by the same ClassAd
		// library, so equivalent expressions render identically.
		if goExpr.String() != condorExpr.String() {
			t.Errorf("%s: Go has %s, condor_submit has %s", attr, goExpr.String(), condorExpr.String())
		}
	}

	compareClassAds(t, goAd, condorAd, "CustomAttributes")
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

// TestIntegrationNoStdioFiles is the case every other test in this file
// misses: a submit file that names no output, error or input. All the
// others set output and error, so the comparison never saw what the two
// implementations do when the submit file is silent — which is where
// condor_submit canonicalizes to /dev/null and this library used to emit
// nothing at all.
func TestIntegrationNoStdioFiles(t *testing.T) {
	if !condorSubmitAvailable() {
		t.Skip("condor_submit not available")
	}

	submitContent := `
universe = vanilla
executable = /usr/bin/true
log = test.log
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

	// Assert the canonicalization directly as well as through
	// compareClassAds: this is the attribute set the shadow reads to
	// decide there is no stdout/stderr to bring back, so "both sides
	// omit it" must not be able to pass here.
	for _, attr := range []string{"In", "Out", "Err"} {
		condorExpr, condorHas := condorAd.Lookup(attr)
		if !condorHas {
			t.Errorf("condor_submit did not set %s; the expectation in this test is wrong, not the library", attr)
			continue
		}
		if got := condorExpr.String(); got != `"/dev/null"` {
			t.Errorf("condor_submit set %s = %s, expected the null file", attr, got)
		}
		goExpr, goHas := goAd.Lookup(attr)
		if !goHas {
			t.Errorf("Go ad is missing %s (condor_submit has %s)", attr, condorExpr.String())
			continue
		}
		if goExpr.String() != condorExpr.String() {
			t.Errorf("%s: Go has %s, condor_submit has %s", attr, goExpr.String(), condorExpr.String())
		}
	}

	compareClassAds(t, goAd, condorAd, "NoStdioFiles")
}

// TestIntegrationStreamedStdio asks condor_submit what stream_input,
// stream_output and stream_error mean. No other test in this file sets
// them, and StreamOut/StreamErr used to be ignored outright, so the
// misnamed StreamOutput/StreamError attributes were invisible here.
func TestIntegrationStreamedStdio(t *testing.T) {
	if !condorSubmitAvailable() {
		t.Skip("condor_submit not available")
	}

	submitContent := `
universe = vanilla
executable = /usr/bin/true
input = stream.in
output = stream.out
error = stream.err
log = stream.log
stream_input = true
stream_output = true
stream_error = true
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

	// Check the names explicitly as well as through compareClassAds:
	// StreamIn is not in either ad for a job with no input file, and
	// "absent from both" is exactly the failure this guards against.
	for _, attr := range []string{"StreamIn", "StreamOut", "StreamErr"} {
		condorExpr, condorHas := condorAd.Lookup(attr)
		if !condorHas {
			t.Errorf("condor_submit did not set %s; the expectation in this test is wrong, not the library", attr)
			continue
		}
		goExpr, goHas := goAd.Lookup(attr)
		if !goHas {
			t.Errorf("Go ad is missing %s (condor_submit has %s)", attr, condorExpr.String())
			continue
		}
		if goExpr.String() != condorExpr.String() {
			t.Errorf("%s: Go has %s, condor_submit has %s", attr, goExpr.String(), condorExpr.String())
		}
	}

	compareClassAds(t, goAd, condorAd, "StreamedStdio")
}

// TestIntegrationTransferStdioOff covers the transfer_input,
// transfer_output and transfer_error submit commands: the route by which
// a standard stream stops being transferred even though the submit file
// names a real file for it.
//
// In, Out, Err, TransferOut and TransferErr are all compared for real
// here, so the cases also pin that turning transfer off does not disturb
// the filename.
//
// The submit files below deliberately name no input, which leaves
// transfer_input invisible to the comparison: with no input named,
// checkStdFile has already turned that stream off, so transfer_input =
// false changes nothing condor_submit can be asked about. The stdin half
// is covered by TestSubmitTransferStdioOff.
func TestIntegrationTransferStdioOff(t *testing.T) {
	if !condorSubmitAvailable() {
		t.Skip("condor_submit not available")
	}

	for _, tc := range []struct {
		name  string
		extra string
	}{
		{"OutputOff", "transfer_output = false"},
		{"ErrorOff", "transfer_error = false"},
		{"BothOff", "transfer_output = false\ntransfer_error = false"},
		{"OutputOn", "transfer_output = true"},
		// The bool spellings condor_submit accepts. It rejects
		// "no"/"yes" outright, which this library's parseBool does not.
		{"OutputOffZero", "transfer_output = 0"},
		{"ErrorOffUpper", "transfer_error = FALSE"},
		{"OutputOnOne", "transfer_output = 1"},
		// Asking to stream a stream that is not transferred: the
		// streaming attribute is not written at all.
		{"OutputOffStreamOn", "transfer_output = false\nstream_output = true"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			submitContent := `
universe = vanilla
executable = /usr/bin/true
output = test.out
error = test.err
log = test.log
` + tc.extra + `
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

			compareClassAds(t, result.ProcAds[0], condorAd, "TransferStdioOff/"+tc.name)
		})
	}
}
