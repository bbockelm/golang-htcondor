package htcondor

import (
	"strings"
	"testing"

	"github.com/PelicanPlatform/classad/classad"
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
		flavor   containerFlavor
	}{
		{"vanilla", UniverseVanilla, flavorNone},
		{"VANILLA", UniverseVanilla, flavorNone},
		{"standard", UniverseStandard, flavorNone},
		{"grid", UniverseGrid, flavorNone},
		{"java", UniverseJava, flavorNone},
		{"parallel", UniverseParallel, flavorNone},
		{"mpi", UniverseParallel, flavorNone},
		{"local", UniverseLocal, flavorNone},
		{"vm", UniverseVM, flavorNone},
		// docker and container are not universes of their own: they are
		// vanilla jobs carrying a container flavour.
		{"docker", UniverseVanilla, flavorDocker},
		{"container", UniverseVanilla, flavorContainer},
		{"unknown", UniverseVanilla, flavorNone}, // Default
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			result, flavor := parseUniverse(tt.input)
			if result != tt.expected {
				t.Errorf("parseUniverse(%q) = %d, want %d", tt.input, result, tt.expected)
			}
			if flavor != tt.flavor {
				t.Errorf("parseUniverse(%q) flavor = %d, want %d", tt.input, flavor, tt.flavor)
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

// mustMakeJobAd parses submit and returns the first job ad, failing the
// test on any error along the way.
func mustMakeJobAd(t *testing.T, submit string) *classad.ClassAd {
	t.Helper()

	sf, err := ParseSubmitFile(strings.NewReader(submit))
	if err != nil {
		t.Fatalf("Failed to parse submit file: %v", err)
	}

	ad, err := sf.MakeJobAd(JobID{Cluster: 100, Proc: 0}, map[string]string{})
	if err != nil {
		t.Fatalf("Failed to create job ad: %v", err)
	}
	if ad == nil {
		t.Fatal("Expected non-nil job ad")
	}
	return ad
}

// mustFailMakeJobAd parses submit, which must succeed, and requires
// MakeJobAd to report an error rather than quietly producing an ad.
func mustFailMakeJobAd(t *testing.T, submit string) {
	t.Helper()

	sf, err := ParseSubmitFile(strings.NewReader(submit))
	if err != nil {
		t.Fatalf("Failed to parse submit file: %v", err)
	}
	if _, err := sf.MakeJobAd(JobID{Cluster: 100, Proc: 0}, nil); err == nil {
		t.Error("Expected MakeJobAd to fail, got no error")
	}
}

// assertUnset fails if attr is present in the ad. Used to check that a
// docker job carries no container attributes and vice versa: naming both
// tells the starter two contradictory things.
func assertUnset(t *testing.T, ad *classad.ClassAd, attr string) {
	t.Helper()
	if _, ok := ad.Lookup(attr); ok {
		t.Errorf("Expected %s to be unset, but the ad defines it", attr)
	}
}

// assertTrue fails unless attr is present and evaluates to true.
func assertTrue(t *testing.T, ad *classad.ClassAd, attr string) {
	t.Helper()
	val, ok := ad.EvaluateAttrBool(attr)
	if !ok {
		t.Fatalf("Expected %s to be set", attr)
	}
	if !val {
		t.Errorf("Expected %s = true, got false", attr)
	}
}

func TestContainerSettings(t *testing.T) {
	ad := mustMakeJobAd(t, `
universe = vanilla
executable = /bin/echo
arguments = test
docker_image = ubuntu:22.04
docker_network_type = host
docker_volumes = /data:/data, /home:/home
docker_pull_policy = always
container_target_dir = /workspace
require_container = true
`)

	if img, ok := ad.EvaluateAttrString("DockerImage"); !ok || img != "ubuntu:22.04" {
		t.Errorf("Expected DockerImage = ubuntu:22.04, got %q (set: %v)", img, ok)
	}

	// WantDocker is what condor_starter keys off to invoke docker. An
	// image attribute on its own is ignored and the job silently runs on
	// the bare worker node.
	assertTrue(t, ad, "WantDocker")

	assertUnset(t, ad, "ContainerImage")
	assertUnset(t, ad, "WantContainer")

	if univ, ok := ad.EvaluateAttrInt("JobUniverse"); !ok || univ != UniverseVanilla {
		t.Errorf("Expected JobUniverse = %d, got %d (set: %v)", UniverseVanilla, univ, ok)
	}
}

// TestContainerImageInVanillaUniverse is the regression test for the
// original bug: a submit file naming container_image without saying
// `universe = container` produced ContainerImage and the
// HasApptainer/HasSingularity requirement but no WantContainer, so the
// job matched a container-capable slot, ran outside the requested image,
// and reported success.
func TestContainerImageInVanillaUniverse(t *testing.T) {
	ad := mustMakeJobAd(t, `
universe = vanilla
executable = /bin/echo
arguments = test
container_image = /cvmfs/example.org/images/analysis.sif
`)

	assertTrue(t, ad, "WantContainer")

	if img, ok := ad.EvaluateAttrString("ContainerImage"); !ok || img != "/cvmfs/example.org/images/analysis.sif" {
		t.Errorf("Expected ContainerImage to be set to the submitted image, got %q (set: %v)", img, ok)
	}

	assertUnset(t, ad, "DockerImage")
	assertUnset(t, ad, "WantDocker")
}

func TestContainerUniverse(t *testing.T) {
	ad := mustMakeJobAd(t, `
universe = container
executable = /bin/echo
arguments = test
container_image = docker://ubuntu:22.04
`)

	// Container is a pseudo-universe: condor_submit runs it as a vanilla
	// job flagged with WantContainer.
	if univ, ok := ad.EvaluateAttrInt("JobUniverse"); !ok || univ != UniverseVanilla {
		t.Errorf("Expected JobUniverse = %d, got %d (set: %v)", UniverseVanilla, univ, ok)
	}

	assertTrue(t, ad, "WantContainer")

	if img, ok := ad.EvaluateAttrString("ContainerImage"); !ok || img != "docker://ubuntu:22.04" {
		t.Errorf("Expected ContainerImage = docker://ubuntu:22.04, got %q (set: %v)", img, ok)
	}

	assertUnset(t, ad, "DockerImage")
	assertUnset(t, ad, "WantDocker")

	req, ok := ad.Lookup("Requirements")
	if !ok {
		t.Fatal("Expected Requirements to be set")
	}
	if got := req.String(); !strings.Contains(got, "HasApptainer") {
		t.Errorf("Expected a container requirement in Requirements, got: %s", got)
	}
}

func TestDockerUniverse(t *testing.T) {
	ad := mustMakeJobAd(t, `
universe = docker
executable = /bin/echo
arguments = test
docker_image = ubuntu:22.04
`)

	// Docker is a pseudo-universe too: JobUniverse 14 is not a universe
	// HTCondor knows (14 is CONDOR_UNIVERSE_MAX).
	if univ, ok := ad.EvaluateAttrInt("JobUniverse"); !ok || univ != UniverseVanilla {
		t.Errorf("Expected JobUniverse = %d, got %d (set: %v)", UniverseVanilla, univ, ok)
	}

	assertTrue(t, ad, "WantDocker")
	assertUnset(t, ad, "WantContainer")

	req, ok := ad.Lookup("Requirements")
	if !ok {
		t.Fatal("Expected Requirements to be set")
	}
	if got := req.String(); !strings.Contains(got, "HasDocker") {
		t.Errorf("Expected a docker requirement in Requirements, got: %s", got)
	}
}

// TestContainerSubmitErrors covers the ambiguous submit files. These are
// rejected rather than submitted: a job ad that names an image but never
// asks for it runs outside that image and reports no error anywhere.
func TestContainerSubmitErrors(t *testing.T) {
	tests := []struct {
		name   string
		submit string
	}{
		{
			name: "container universe without an image",
			submit: `
universe = container
executable = /bin/echo
`,
		},
		{
			name: "docker universe without an image",
			submit: `
universe = docker
executable = /bin/echo
`,
		},
		{
			name: "both image commands",
			submit: `
universe = vanilla
executable = /bin/echo
docker_image = ubuntu:22.04
container_image = /images/analysis.sif
`,
		},
		{
			name: "docker universe with a container image",
			submit: `
universe = docker
executable = /bin/echo
container_image = /images/analysis.sif
`,
		},
		{
			name: "container universe with a docker image",
			submit: `
universe = container
executable = /bin/echo
docker_image = ubuntu:22.04
`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := ParseSubmitFile(strings.NewReader(tt.submit)); err == nil {
				t.Error("Expected an error, got none")
			}
		})
	}
}

// TestResourceSizeSuffixes covers the unit suffixes on size-valued submit
// commands. They used to be truncated away -- Sscanf("%d") on "4GB"
// yields 4 -- so `request_disk = 4GB` asked for 4 KiB of scratch and the
// job died partway through with ENOSPC instead of waiting for a slot that
// could hold the image.
func TestResourceSizeSuffixes(t *testing.T) {
	tests := []struct {
		command string
		attr    string
		want    int64
	}{
		// RequestMemory is denominated in MiB.
		{"request_memory = 512", "RequestMemory", 512},
		{"request_memory = 1GB", "RequestMemory", 1024},
		{"request_memory = 2048MB", "RequestMemory", 2048},
		{"request_memory = 1 GB", "RequestMemory", 1024},
		{"request_memory = 4G", "RequestMemory", 4096},
		// Partial units round up: a request is a floor.
		{"request_memory = 100KB", "RequestMemory", 1},

		// RequestDisk is denominated in KiB.
		{"request_disk = 2048", "RequestDisk", 2048},
		{"request_disk = 4GB", "RequestDisk", 4 * 1024 * 1024},
		{"request_disk = 64MB", "RequestDisk", 64 * 1024},
		{"request_disk = 1.5GB", "RequestDisk", 1536 * 1024},

		// RequestGpuMemory is denominated in MiB.
		{"request_gpu_memory = 8GB", "RequestGpuMemory", 8192},
	}

	for _, tt := range tests {
		t.Run(tt.command, func(t *testing.T) {
			ad := mustMakeJobAd(t, `
universe = vanilla
executable = /bin/echo
`+tt.command+"\n")

			got, ok := ad.EvaluateAttrInt(tt.attr)
			if !ok {
				t.Fatalf("Expected %s to be set", tt.attr)
			}
			if got != tt.want {
				t.Errorf("Expected %s = %d, got %d", tt.attr, tt.want, got)
			}
		})
	}
}

func TestResourceRequestDefaults(t *testing.T) {
	ad := mustMakeJobAd(t, `
universe = vanilla
executable = /bin/echo
`)

	if mem, ok := ad.EvaluateAttrInt("RequestMemory"); !ok || mem != 128 {
		t.Errorf("Expected the default RequestMemory = 128, got %d (set: %v)", mem, ok)
	}
	if disk, ok := ad.EvaluateAttrInt("RequestDisk"); !ok || disk != 1024 {
		t.Errorf("Expected the default RequestDisk = 1024, got %d (set: %v)", disk, ok)
	}
	// No default for GPU memory: the attribute stays out of the ad.
	assertUnset(t, ad, "RequestGpuMemory")
}

// TestResourceRequestExpression covers the expression form condor_submit
// also accepts for these commands.
func TestResourceRequestExpression(t *testing.T) {
	ad := mustMakeJobAd(t, `
universe = vanilla
executable = /bin/echo
request_memory = 2 * 1024
`)

	req, ok := ad.Lookup("RequestMemory")
	if !ok {
		t.Fatal("Expected RequestMemory to be set")
	}
	if got := req.String(); !strings.Contains(got, "*") {
		t.Errorf("Expected RequestMemory to keep the expression, got: %s", got)
	}
}

// TestResourceRequestInvalid checks that a size that is neither a
// quantity nor an expression is an error. Falling back to the default
// would hand the job an allocation the submit file never asked for.
func TestResourceRequestInvalid(t *testing.T) {
	mustFailMakeJobAd(t, `
universe = vanilla
executable = /bin/echo
request_disk = 4ZB
`)
}

// TestCustomAttributes covers the +Attr / MY.Attr escape hatch. The +
// form used to be dropped from the ad entirely (the parser strips the +
// before the value reaches the config, so setCustomAttributes never saw
// one), and the MY. form used to reach the schedd with the prefix still
// attached, which SetAttribute rejects with EINVAL.
func TestCustomAttributes(t *testing.T) {
	ad := mustMakeJobAd(t, `
universe = vanilla
executable = /bin/echo
+WantContainer = true
+ProjectName = "CMS"
+MaxRetries = 3
+BigMachine = TARGET.Memory > 1024
MY.NumRetries = 5
`)

	assertTrue(t, ad, "WantContainer")

	if project, ok := ad.EvaluateAttrString("ProjectName"); !ok || project != "CMS" {
		t.Errorf("Expected ProjectName = CMS, got %q (set: %v)", project, ok)
	}

	if retries, ok := ad.EvaluateAttrInt("MaxRetries"); !ok || retries != 3 {
		t.Errorf("Expected MaxRetries = 3, got %d (set: %v)", retries, ok)
	}

	// The value is a ClassAd expression, not a string.
	expr, ok := ad.Lookup("BigMachine")
	if !ok {
		t.Fatal("Expected BigMachine to be set")
	}
	if got := expr.String(); !strings.Contains(got, "TARGET.Memory") {
		t.Errorf("Expected BigMachine to keep the expression, got: %s", got)
	}

	// MY.NumRetries becomes NumRetries: an attribute name containing a
	// dot is rejected by the schedd.
	if retries, ok := ad.EvaluateAttrInt("NumRetries"); !ok || retries != 5 {
		t.Errorf("Expected NumRetries = 5, got %d (set: %v)", retries, ok)
	}
	assertUnset(t, ad, "MY.NumRetries")
}

// TestCustomAttributesOverride checks that a custom attribute wins over
// the value the rest of the submit file derived. That is what makes it
// usable as a workaround for anything this package gets wrong.
func TestCustomAttributesOverride(t *testing.T) {
	ad := mustMakeJobAd(t, `
universe = vanilla
executable = /bin/echo
request_cpus = 1
+RequestCpus = 4
`)

	if cpus, ok := ad.EvaluateAttrInt("RequestCpus"); !ok || cpus != 4 {
		t.Errorf("Expected the custom attribute to win with RequestCpus = 4, got %d (set: %v)", cpus, ok)
	}
}

func TestCustomAttributeErrors(t *testing.T) {
	// A dotted attribute name is rejected at parse time rather than by
	// the schedd, where it surfaces as "error code 22".
	if _, err := ParseSubmitFile(strings.NewReader(`
universe = vanilla
executable = /bin/echo
MY.Bad.Name = 1
`)); err == nil {
		t.Error("Expected an error for a dotted attribute name, got none")
	}

	// A value that is not a ClassAd expression is reported, not dropped.
	mustFailMakeJobAd(t, `
universe = vanilla
executable = /bin/echo
+Comment = hello world
`)
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
