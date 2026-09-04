package htcondor

import (
	"strings"
	"testing"

	"github.com/bbockelm/golang-htcondor/version"
)

func TestParseSimpleSubmitFile(t *testing.T) {
	submit := `
universe = vanilla
executable = /bin/echo
arguments = hello world
output = output.txt
error = error.txt
log = job.log
`

	sf, err := ParseSubmitFile(strings.NewReader(submit))
	if err != nil {
		t.Fatalf("Failed to parse submit file: %v", err)
	}

	if sf.universe != UniverseVanilla {
		t.Errorf("Expected universe %d, got %d", UniverseVanilla, sf.universe)
	}

	// Default queue count when no queue statement is present
	if sf.queueCount != 1 {
		t.Errorf("Expected queue count 1, got %d", sf.queueCount)
	}
}

func TestMakeJobAd(t *testing.T) {
	submit := `
universe = vanilla
executable = /bin/echo
arguments = hello world
output = output.txt
error = error.txt
log = job.log
request_cpus = 2
request_memory = 1024
request_disk = 2048
environment = "PATH=/usr/bin:/bin HOME=/home/user"
requirements = (OpSys == "LINUX") && (Arch == "X86_64")
rank = Memory
`

	submitFile, err := ParseSubmitFile(strings.NewReader(submit))
	if err != nil {
		t.Fatalf("Failed to parse submit file: %v", err)
	}

	jobID := JobID{Cluster: 100, Proc: 0}
	ad, err := submitFile.MakeJobAd(jobID, map[string]string{})
	if err != nil {
		t.Fatalf("Failed to create job ad: %v", err)
	}

	if ad == nil {
		t.Fatal("Expected non-nil job ad")
	}

	// Basic validation that ad was created
	// Note: ClassAd.Get() is not available in this test context,
	// but we can verify the ad object was created
}

func TestParseUniverse(t *testing.T) {
	tests := []struct {
		input    string
		expected int
	}{
		{"vanilla", UniverseVanilla},
		{"VANILLA", UniverseVanilla},
		{"standard", UniverseStandard},
		{"grid", UniverseGrid},
		{"java", UniverseJava},
		{"parallel", UniverseParallel},
		{"mpi", UniverseParallel},
		{"local", UniverseLocal},
		{"vm", UniverseVM},
		{"docker", UniverseDocker},
		{"unknown", UniverseVanilla}, // Default
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			result := parseUniverse(tt.input)
			if result != tt.expected {
				t.Errorf("parseUniverse(%q) = %d, want %d", tt.input, result, tt.expected)
			}
		})
	}
}

func TestSubmitWithMultipleProcs(t *testing.T) {
	submit := `
universe = vanilla
executable = /bin/echo
arguments = test
`

	sf, err := ParseSubmitFile(strings.NewReader(submit))
	if err != nil {
		t.Fatalf("Failed to parse submit file: %v", err)
	}

	clusterID := 1001
	result, err := sf.Submit(clusterID)
	if err != nil {
		t.Fatalf("Submit failed: %v", err)
	}

	if result.NumProcs != 1 {
		t.Errorf("Expected 1 proc, got %d", result.NumProcs)
	}

	// Verify cluster ad + proc ads
	if result.ClusterAd == nil {
		t.Error("Expected non-nil cluster ad")
	}

	if len(result.ProcAds) != 1 {
		t.Errorf("Expected 1 proc ad, got %d", len(result.ProcAds))
	}
}

func TestMissingExecutable(t *testing.T) {
	submit := `
universe = vanilla
arguments = hello world
`

	sf, err := ParseSubmitFile(strings.NewReader(submit))
	if err != nil {
		t.Fatalf("Failed to parse submit file: %v", err)
	}

	jobID := JobID{Cluster: 100, Proc: 0}
	_, err = sf.MakeJobAd(jobID, map[string]string{})
	if err == nil {
		t.Fatal("Expected error for missing executable, got nil")
	}
}

func TestCustomAttributes(t *testing.T) {
	submit := `
universe = vanilla
executable = /bin/echo
arguments = test
+MyCustomAttr = "CustomValue"
+Priority = 10
+IsHighPriority = true
MY.Department = "Engineering"
MY.ProjectCode = 12345
`

	sf, err := ParseSubmitFile(strings.NewReader(submit))
	if err != nil {
		t.Fatalf("Failed to parse submit file: %v", err)
	}

	jobID := JobID{Cluster: 100, Proc: 0}
	ad, err := sf.MakeJobAd(jobID, map[string]string{})
	if err != nil {
		t.Fatalf("Failed to create job ad: %v", err)
	}

	if ad == nil {
		t.Fatal("Expected non-nil job ad")
	}

	// Note: We can't easily verify the attributes without ClassAd.Get() being available,
	// but we verify that the job ad was created successfully with custom attributes
}

func TestFileTransferDetails(t *testing.T) {
	submit := `
universe = vanilla
executable = /bin/echo
arguments = test
transfer_input_files = input1.txt, input2.dat, /path/to/file3.bin
transfer_output_files = output1.txt, output2.dat
transfer_output_remaps = "output1.txt=renamed1.txt; output2.dat=renamed2.dat"
encrypt_input_files = input1.txt, input2.dat
preserve_relative_paths = true
transfer_plugins = http, https
`

	sf, err := ParseSubmitFile(strings.NewReader(submit))
	if err != nil {
		t.Fatalf("Failed to parse submit file: %v", err)
	}

	jobID := JobID{Cluster: 100, Proc: 0}
	ad, err := sf.MakeJobAd(jobID, map[string]string{})
	if err != nil {
		t.Fatalf("Failed to create job ad: %v", err)
	}

	if ad == nil {
		t.Fatal("Expected non-nil job ad")
	}

	// Verify the job ad was created successfully with file transfer settings
}

func TestContainerSettings(t *testing.T) {
	submit := `
universe = vanilla
executable = /bin/echo
arguments = test
docker_image = ubuntu:22.04
docker_network_type = host
docker_volumes = /data:/data, /home:/home
docker_pull_policy = always
container_target_dir = /workspace
require_container = true
`

	sf, err := ParseSubmitFile(strings.NewReader(submit))
	if err != nil {
		t.Fatalf("Failed to parse submit file: %v", err)
	}

	jobID := JobID{Cluster: 100, Proc: 0}
	ad, err := sf.MakeJobAd(jobID, map[string]string{})
	if err != nil {
		t.Fatalf("Failed to create job ad: %v", err)
	}

	if ad == nil {
		t.Fatal("Expected non-nil job ad")
	}

	// Verify the job ad was created successfully with container settings
}

func TestJobStatusControl(t *testing.T) {
	submit := `
universe = vanilla
executable = /bin/echo
arguments = test
hold = true
hold_reason = "Waiting for approval"
priority = 10
nice_user = false
max_retries = 3
job_max_vacate_time = 120
keep_claim_idle = 600
concurrency_limits = DATABASE:2
`

	sf, err := ParseSubmitFile(strings.NewReader(submit))
	if err != nil {
		t.Fatalf("Failed to parse submit file: %v", err)
	}

	jobID := JobID{Cluster: 100, Proc: 0}
	ad, err := sf.MakeJobAd(jobID, map[string]string{})
	if err != nil {
		t.Fatalf("Failed to create job ad: %v", err)
	}

	if ad == nil {
		t.Fatal("Expected non-nil job ad")
	}

	// Verify the job ad was created successfully with job status/control settings
}

func TestImprovedRequirements(t *testing.T) {
	submit := `
universe = vanilla
executable = /bin/echo
arguments = test
request_cpus = 4
request_memory = 4096
request_disk = 10240
request_gpus = 2
request_gpu_memory = 8192
docker_image = tensorflow/tensorflow:latest-gpu
request_opsys = "LINUX"
request_arch = "X86_64"
`

	sf, err := ParseSubmitFile(strings.NewReader(submit))
	if err != nil {
		t.Fatalf("Failed to parse submit file: %v", err)
	}

	jobID := JobID{Cluster: 100, Proc: 0}
	ad, err := sf.MakeJobAd(jobID, map[string]string{})
	if err != nil {
		t.Fatalf("Failed to create job ad: %v", err)
	}

	if ad == nil {
		t.Fatal("Expected non-nil job ad")
	}

	// Verify the job ad was created successfully with enhanced requirements
}

// TestSubmitVersionIsParseableByCondor guards the SubmitVersion stamped
// onto every job ad. condor_q, condor_history and log tooling parse it
// with CondorVersionInfo, which requires a three-part HTCondor version;
// this module's own version does not qualify.
func TestSubmitVersionIsParseableByCondor(t *testing.T) {
	wantPrefix := "$CondorVersion: " + version.HTCondorCompat + " "
	if !strings.HasPrefix(submitVersionString, wantPrefix) {
		t.Errorf("submitVersionString = %q, want prefix %q", submitVersionString, wantPrefix)
	}
	if !strings.HasSuffix(submitVersionString, " $") {
		t.Errorf("submitVersionString = %q, must end in %q", submitVersionString, " $")
	}
	if !strings.Contains(submitVersionString, "golang-htcondor") {
		t.Errorf("submitVersionString = %q, loses the golang-htcondor marker", submitVersionString)
	}
}

// TestWireVersionStringMatchesSubmit keeps the file-transfer/peek streams
// on the same announced version as job ads; they used to carry an
// unrelated hardcoded literal.
func TestWireVersionStringMatchesSubmit(t *testing.T) {
	if got, want := wireVersionString(), submitVersionString; got != want {
		t.Errorf("wireVersionString() = %q, submitVersionString = %q; these must agree", got, want)
	}
}
