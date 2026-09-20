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
		// docker and container are vanilla-universe toppings, not
		// universes of their own (there is no universe 14).
		{"docker", UniverseVanilla},
		{"container", UniverseVanilla},
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

	// Verify the attributes actually landed. This test used to stop at
	// "the ad was created", on the belief that the values could not be
	// read back — they can, with Lookup — and it therefore passed
	// throughout the period when every one of these attributes was
	// being silently dropped.
	for attr, want := range map[string]string{
		"MyCustomAttr":   `"CustomValue"`,
		"Priority":       "10",
		"IsHighPriority": "true",
		"Department":     `"Engineering"`, // MY. prefix is not part of the name
		"ProjectCode":    "12345",
	} {
		expr, ok := ad.Lookup(attr)
		if !ok {
			t.Errorf("job ad is missing custom attribute %s (want %s)", attr, want)
			continue
		}
		if got := expr.String(); got != want {
			t.Errorf("%s = %s, want %s", attr, got, want)
		}
	}
	if _, ok := ad.Lookup("MY.Department"); ok {
		t.Error("job ad carries MY.Department; the prefix selects the namespace and is not part of the attribute name")
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

// adFromSubmit parses a submit description and returns the first proc's job ad.
func adFromSubmit(t *testing.T, submit string) *classad.ClassAd {
	t.Helper()
	sf, err := ParseSubmitFile(strings.NewReader(submit))
	if err != nil {
		t.Fatalf("parse submit: %v", err)
	}
	ad, err := sf.MakeJobAd(JobID{Cluster: 100, Proc: 0}, map[string]string{})
	if err != nil {
		t.Fatalf("MakeJobAd: %v", err)
	}
	if ad == nil {
		t.Fatal("nil job ad")
	}
	return ad
}

func lookupStr(t *testing.T, ad *classad.ClassAd, attr string) string {
	t.Helper()
	expr, ok := ad.Lookup(attr)
	if !ok {
		return ""
	}
	return expr.String()
}

// TestContainerSettings asserts the docker "topping" produces a job the
// shadow can actually run: JobUniverse VANILLA (not the bogus universe
// 14 that "cannot support universe" comes from), WantDocker set so the
// starter selects the docker proc, the image, and a HasDocker
// requirement. The previous version of this test only checked the ad was
// non-nil, so it passed throughout the period JobUniverse was 14.
func TestContainerSettings(t *testing.T) {
	ad := adFromSubmit(t, `
universe = docker
executable = /bin/echo
arguments = test
docker_image = ubuntu:22.04
docker_network_type = host
`)

	if got := lookupStr(t, ad, "JobUniverse"); got != "5" {
		t.Errorf("JobUniverse = %q, want 5 (VANILLA)", got)
	}
	if got := lookupStr(t, ad, "WantDocker"); got != "true" {
		t.Errorf("WantDocker = %q, want true", got)
	}
	if got := lookupStr(t, ad, "DockerImage"); got != `"ubuntu:22.04"` {
		t.Errorf("DockerImage = %q, want \"ubuntu:22.04\"", got)
	}
	// docker_image must not masquerade as a container job (that would set
	// WantContainer and make the starter pick the wrong proc).
	if _, ok := ad.Lookup("WantContainer"); ok {
		t.Error("a docker_image job set WantContainer")
	}
	if req := lookupStr(t, ad, "Requirements"); !strings.Contains(req, "HasDocker") {
		t.Errorf("Requirements does not require HasDocker: %s", req)
	}
}

// TestContainerUniverse is the container topping, the shape the Jupyter
// path now emits. It must also be VANILLA, set WantContainer, carry the
// image, and require any of the container runtimes so it matches
// Apptainer/Singularity nodes, not only Docker ones.
func TestContainerUniverse(t *testing.T) {
	ad := adFromSubmit(t, `
universe = container
executable = /bin/echo
arguments = test
container_image = docker://quay.io/jupyter/scipy-notebook:latest
`)

	if got := lookupStr(t, ad, "JobUniverse"); got != "5" {
		t.Errorf("JobUniverse = %q, want 5 (VANILLA)", got)
	}
	if got := lookupStr(t, ad, "WantContainer"); got != "true" {
		t.Errorf("WantContainer = %q, want true", got)
	}
	if got := lookupStr(t, ad, "ContainerImage"); got != `"docker://quay.io/jupyter/scipy-notebook:latest"` {
		t.Errorf("ContainerImage = %q", got)
	}
	if _, ok := ad.Lookup("WantDocker"); ok {
		t.Error("a container_image job set WantDocker")
	}
	// The image-kind flag is what turns the container runtime on in the
	// starter (Singularity::job_enabled). A docker:// image is WantDockerImage;
	// WantSIF/WantSandboxImage must NOT be set. Missing this flag is why an
	// Apptainer node ran the job on bare metal.
	if got := lookupStr(t, ad, "WantDockerImage"); got != "true" {
		t.Errorf("WantDockerImage = %q, want true (starter keys on it to enable the runtime)", got)
	}
	for _, notWant := range []string{"WantSIF", "WantSandboxImage"} {
		if _, ok := ad.Lookup(notWant); ok {
			t.Errorf("a docker:// image should not set %s", notWant)
		}
	}
	// HTCondor's container-universe requirement: the node must support
	// the container universe (HasContainer) and be able to pull the image
	// kind. A docker:// repo needs HasDockerURL, which is runtime-agnostic
	// -- an Apptainer node that can pull a docker repo advertises it -- so
	// the job is not pinned to Docker or to a specific runtime attribute.
	req := lookupStr(t, ad, "Requirements")
	for _, want := range []string{"HasContainer", "HasDockerURL"} {
		if !strings.Contains(req, want) {
			t.Errorf("Requirements missing %s: %s", want, req)
		}
	}
	for _, notWant := range []string{"HasSingularity", "HasApptainer", "HasDocker =", "HasSIF", "HasSandboxImage"} {
		if strings.Contains(req, notWant) {
			t.Errorf("Requirements should not contain %s for a docker:// image: %s", notWant, req)
		}
	}
}

// TestContainerImageCapability pins the image-kind -> node-capability
// mapping, matching HTCondor's image_type_from_string.
func TestContainerImageKind(t *testing.T) {
	cases := []struct {
		image, wantAttr, capability string
	}{
		{"docker://quay.io/x:latest", "WantDockerImage", "HasDockerURL"},
		{"docker:x", "WantDockerImage", "HasDockerURL"},
		{"/pool/images/foo.sif", "WantSIF", "HasSIF"},
		{"/pool/images/sandbox/", "WantSandboxImage", "HasSandboxImage"},
		{"just-a-name", "WantSandboxImage", "HasSandboxImage"},
	}
	for _, c := range cases {
		wantAttr, capability := containerImageKind(c.image)
		if wantAttr != c.wantAttr {
			t.Errorf("containerImageKind(%q) wantAttr = %q, want %q", c.image, wantAttr, c.wantAttr)
		}
		if !strings.Contains(capability, c.capability) {
			t.Errorf("containerImageKind(%q) capability = %q, want it to name %s", c.image, capability, c.capability)
		}
	}
}

// TestContainerImageKindFlagInAd checks that a .sif container_image sets
// WantSIF on the job ad (and not the docker/sandbox flags) -- the same
// starter-visible mechanism as the docker:// case in TestContainerUniverse.
func TestContainerImageKindFlagInAd(t *testing.T) {
	ad := adFromSubmit(t, `
universe = container
executable = /bin/echo
container_image = /cvmfs/x/images/foo.sif
`)
	if got := lookupStr(t, ad, "WantSIF"); got != "true" {
		t.Errorf("WantSIF = %q, want true", got)
	}
	for _, notWant := range []string{"WantDockerImage", "WantSandboxImage"} {
		if _, ok := ad.Lookup(notWant); ok {
			t.Errorf("a .sif image should not set %s", notWant)
		}
	}
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

// TestStdioFilesCanonicalizeToNullFile pins the canonicalization
// condor_submit performs in CheckStdFile: a submit file that names no
// input/output/error still gets In/Out/Err = "/dev/null", plus
// TransferIn/TransferOut/TransferErr = false.
//
// Omitting the attribute is not equivalent. The shadow decides "nothing
// to send back" by string-matching /dev/null (nullfile.cpp); with Out
// unset it instead seeds the failure-file list with the empty name and
// uploads the job's whole sandbox into the AP's spool.
func TestStdioFilesCanonicalizeToNullFile(t *testing.T) {
	tests := []struct {
		name         string
		submit       string
		wantIn       string
		wantOut      string
		wantErr      string
		wantTransfer map[string]bool // attribute -> expected value; absent means must not be set
	}{
		{
			name:    "no stdio commands at all",
			submit:  "universe = vanilla\nexecutable = /bin/true\n",
			wantIn:  "/dev/null",
			wantOut: "/dev/null",
			wantErr: "/dev/null",
			wantTransfer: map[string]bool{
				"TransferIn":  false,
				"TransferOut": false,
				"TransferErr": false,
			},
		},
		{
			name:         "all three named",
			submit:       "universe = vanilla\nexecutable = /bin/true\ninput = a.in\noutput = a.out\nerror = a.err\n",
			wantIn:       "a.in",
			wantOut:      "a.out",
			wantErr:      "a.err",
			wantTransfer: map[string]bool{},
		},
		{
			name:    "empty values",
			submit:  "universe = vanilla\nexecutable = /bin/true\ninput =\noutput =\nerror =\n",
			wantIn:  "/dev/null",
			wantOut: "/dev/null",
			wantErr: "/dev/null",
			wantTransfer: map[string]bool{
				"TransferIn":  false,
				"TransferOut": false,
				"TransferErr": false,
			},
		},
		{
			name:    "explicit /dev/null turns transfer off too",
			submit:  "universe = vanilla\nexecutable = /bin/true\noutput = /dev/null\nerror = a.err\n",
			wantIn:  "/dev/null",
			wantOut: "/dev/null",
			wantErr: "a.err",
			wantTransfer: map[string]bool{
				"TransferIn":  false,
				"TransferOut": false,
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			ad := adFromSubmit(t, tc.submit)

			for attr, want := range map[string]string{"In": tc.wantIn, "Out": tc.wantOut, "Err": tc.wantErr} {
				got, ok := classad.GetAs[string](ad, attr)
				if !ok {
					t.Errorf("%s is not set; condor_submit always sets it", attr)
					continue
				}
				if got != want {
					t.Errorf("%s = %q, want %q", attr, got, want)
				}
			}

			for _, attr := range []string{"TransferIn", "TransferOut", "TransferErr"} {
				got, ok := classad.GetAs[bool](ad, attr)
				want, wantSet := tc.wantTransfer[attr]
				switch {
				case wantSet && !ok:
					t.Errorf("%s is not set, want %v", attr, want)
				case !wantSet && ok:
					t.Errorf("%s = %v, want unset (condor_submit only writes it when transfer is off)", attr, got)
				case wantSet && got != want:
					t.Errorf("%s = %v, want %v", attr, got, want)
				}
			}
		})
	}
}

// TestSubmittedAdsCarryStdioFiles is the consequence check: every proc ad
// Submit() hands to the schedd must carry Out and Err, because that is
// what the shadow reads when it decides whether there is stdout/stderr
// to bring home.
func TestSubmittedAdsCarryStdioFiles(t *testing.T) {
	sf, err := ParseSubmitFile(strings.NewReader("universe = vanilla\nexecutable = /bin/true\nqueue 3\n"))
	if err != nil {
		t.Fatalf("parse submit: %v", err)
	}
	result, err := sf.Submit(1)
	if err != nil {
		t.Fatalf("Submit: %v", err)
	}
	if len(result.ProcAds) != 3 {
		t.Fatalf("got %d proc ads, want 3", len(result.ProcAds))
	}
	for i, ad := range result.ProcAds {
		for _, attr := range []string{"In", "Out", "Err"} {
			got, ok := classad.GetAs[string](ad, attr)
			if !ok {
				t.Errorf("proc %d: %s missing from the submitted ad", i, attr)
				continue
			}
			if got != "/dev/null" {
				t.Errorf("proc %d: %s = %q, want %q", i, attr, got, "/dev/null")
			}
		}
	}
}

// TestStreamAttributeNames pins the attribute names HTCondor actually
// reads. stream_output was written as StreamOutput and stream_error as
// StreamError, neither of which anything looks up, so asking to stream
// was silently a no-op.
func TestStreamAttributeNames(t *testing.T) {
	ad := adFromSubmit(t, `
universe = vanilla
executable = /bin/true
input = a.in
output = a.out
error = a.err
stream_input = true
stream_output = true
stream_error = true
`)

	for _, attr := range []string{"StreamIn", "StreamOut", "StreamErr"} {
		got, ok := classad.GetAs[bool](ad, attr)
		if !ok {
			t.Errorf("%s is not set; that is the name the starter and shadow look up", attr)
			continue
		}
		if !got {
			t.Errorf("%s = false, want true", attr)
		}
	}

	// The old names must be gone, not merely duplicated: a job ad
	// carrying both would keep passing a name check while still
	// shipping the attribute nothing reads.
	for _, attr := range []string{"StreamInput", "StreamOutput", "StreamError"} {
		if _, ok := ad.Lookup(attr); ok {
			t.Errorf("%s is set; HTCondor has no such attribute", attr)
		}
	}
}

// TestStreamAttributeDefaults follows condor_submit: the attribute is
// written for every transferred stream, defaulting to false, and omitted
// for a stream that is not transferred at all.
func TestStreamAttributeDefaults(t *testing.T) {
	t.Run("named files default to not streaming", func(t *testing.T) {
		ad := adFromSubmit(t, "universe = vanilla\nexecutable = /bin/true\noutput = a.out\nerror = a.err\n")
		for _, attr := range []string{"StreamOut", "StreamErr"} {
			got, ok := classad.GetAs[bool](ad, attr)
			if !ok {
				t.Errorf("%s is not set; condor_submit writes it for every transferred stream", attr)
				continue
			}
			if got {
				t.Errorf("%s = true, want false", attr)
			}
		}
		if _, ok := ad.Lookup("StreamIn"); ok {
			t.Error("StreamIn is set, but this job has no input file to stream")
		}
	})

	t.Run("streaming a file that is not transferred is dropped", func(t *testing.T) {
		// condor_submit's CheckStdFile forces stream_it false when the
		// file is /dev/null or unnamed, and then SetStdout/SetStderr
		// skip the assignment entirely.
		ad := adFromSubmit(t, `
universe = vanilla
executable = /bin/true
output = /dev/null
stream_output = true
stream_error = true
`)
		for _, attr := range []string{"StreamOut", "StreamErr"} {
			if _, ok := ad.Lookup(attr); ok {
				t.Errorf("%s is set, but its file is the null file", attr)
			}
		}
	})
}

// TestSubmitTransferStdioOff covers the halves of the transfer_input /
// transfer_output / transfer_error handling that the differential test
// against condor_submit cannot see: transfer_input = false is
// indistinguishable from the null-file default unless an input file is
// named, and naming one drags in StreamIn, which condor_submit
// writes for a transferred stdin and the comparison then trips on. The streaming attribute is invisible to the
// comparison for that same reason.
//
// The oracle for the expectations below is condor_submit -dry-run on the
// same submit files; see TestIntegrationTransferStdioOff.
func TestSubmitTransferStdioOff(t *testing.T) {
	// present reports whether the ad carries attr, and its value when
	// the value is a bool.
	present := func(ad *classad.ClassAd, attr string) (bool, bool) {
		expr, ok := ad.Lookup(attr)
		if !ok {
			return false, false
		}
		b, _ := expr.Eval(nil).BoolValue()
		return true, b
	}

	for _, tc := range []struct {
		name   string
		submit string
		// want maps an attribute to its expected boolean value; an
		// attribute listed in absent must not be in the ad at all.
		want   map[string]bool
		absent []string
	}{
		{
			name:   "InputNotTransferred",
			submit: "input = in.txt\ntransfer_input = false\n",
			want:   map[string]bool{"TransferIn": false},
			absent: []string{"StreamIn"},
		},
		{
			name:   "InputTransferredByDefault",
			submit: "input = in.txt\n",
			absent: []string{"TransferIn"},
		},
		{
			name:   "InputTransferExplicitlyOn",
			submit: "input = in.txt\ntransfer_input = true\n",
			absent: []string{"TransferIn"},
		},
		{
			// Asking to stream a stream that is not transferred leaves
			// no streaming attribute: in SetStdin/SetStdout/SetStderr
			// the Stream<X> assignment sits behind "if (transfer_it)".
			name:   "StreamRequestedButNotTransferred",
			submit: "output = out.txt\nstream_output = true\ntransfer_output = false\n",
			want:   map[string]bool{"TransferOut": false},
			absent: []string{"StreamOut"},
		},
		{
			name:   "StreamRequestedAndTransferred",
			submit: "output = out.txt\nstream_output = true\n",
			want:   map[string]bool{"StreamOut": true},
			absent: []string{"TransferOut"},
		},
		{
			name:   "ErrorNotTransferred",
			submit: "error = err.txt\nstream_error = true\ntransfer_error = false\n",
			want:   map[string]bool{"TransferErr": false},
			absent: []string{"StreamErr"},
		},
		{
			// 0, false and FALSE are the spellings condor_submit
			// itself accepts here; it rejects "no"/"yes" outright
			// ("must eval to a boolean"), which parseBool does not.
			name:   "AllThreeOff",
			submit: "input = in.txt\noutput = out.txt\nerror = err.txt\ntransfer_input = 0\ntransfer_output = false\ntransfer_error = FALSE\n",
			want:   map[string]bool{"TransferIn": false, "TransferOut": false, "TransferErr": false},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			sf, err := ParseSubmitFile(strings.NewReader("executable = /bin/true\n" + tc.submit))
			if err != nil {
				t.Fatalf("ParseSubmitFile: %v", err)
			}
			result, err := sf.Submit(1)
			if err != nil {
				t.Fatalf("Submit: %v", err)
			}
			ad := result.ProcAds[0]

			for attr, wantVal := range tc.want {
				got, gotVal := present(ad, attr)
				if !got {
					t.Errorf("%s missing from the ad, want %v", attr, wantVal)
					continue
				}
				if gotVal != wantVal {
					t.Errorf("%s = %v, want %v", attr, gotVal, wantVal)
				}
			}
			for _, attr := range tc.absent {
				if got, gotVal := present(ad, attr); got {
					t.Errorf("%s = %v, want the attribute to be absent", attr, gotVal)
				}
			}
		})
	}
}
