package htcondor

import (
	"strings"
	"testing"
)

func TestSignalHandling(t *testing.T) {
	submit := `
universe = vanilla
executable = /bin/long_job
arguments = test
kill_sig = SIGTERM
remove_kill_sig = SIGKILL
kill_sig_timeout = 120
output = job.out
error = job.err
log = job.log
queue
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

	// Signal handling attributes should be set
}

func TestSignalHandlingNumeric(t *testing.T) {
	submit := `
universe = vanilla
executable = /bin/job
arguments = test
kill_sig = 15
remove_kill_sig = 9
kill_sig_timeout = 60
queue
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
}

func TestSimpleJobExprs(t *testing.T) {
	submit := `
universe = vanilla
executable = /bin/echo
arguments = hello
notification = always
want_remote_io = true
stream_output = true
stream_error = true
description = Test job for simple expressions
copy_to_spool = false
buffer_size = 524288
buffer_block_size = 32768
batch_name = test_batch_001
stack_size = 2048
remote_initialdir = /tmp/remote
output = job.out
error = job.err
log = job.log
queue
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

	// Simple job expression attributes should be set
}

func TestNotificationTypes(t *testing.T) {
	tests := []struct {
		notification string
		description  string
	}{
		{"always", "Always notify"},
		{"complete", "Notify on completion"},
		{"error", "Notify on error"},
		{"never", "Never notify"},
		{"1", "Numeric: always"},
		{"2", "Numeric: complete"},
	}

	for _, tt := range tests {
		t.Run(tt.description, func(t *testing.T) {
			submit := `
universe = vanilla
executable = /bin/echo
notification = ` + tt.notification + `
queue
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
		})
	}
}

func TestExtendedJobExprs(t *testing.T) {
	submit := `
universe = vanilla
executable = /bin/process
arguments = data.txt
append_files = output.log
compress_files = results.dat
file_remaps = "input.txt=/scratch/input.txt;output.txt=/scratch/output.txt"
want_graceful_removal = true
run_as_owner = true
load_profile = true
job_ad_information_attrs = RequestMemory,RequestCpus,JobStatus
want_io_proxy = false
job_machine_attrs = Machine,Arch,OpSys
job_machine_attrs_history_length = 10
allowed_execute_duration = 3600
allowed_job_duration = 7200
want_checkpoint = true
checkpoint_exit_code = 77
max_transfer_input_mb = 100
max_transfer_output_mb = 500
preserve_relative_executable = false
output = job.out
error = job.err
log = job.log
queue
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

	// Extended job expression attributes should be set
}

func TestJavaKeystoreParameters(t *testing.T) {
	submit := `
universe = java
executable = MyApp
jar_files = myapp.jar
java_vm_args = -Xmx1024m
keystore_file = /path/to/keystore.jks
keystore_alias = myapp
keystore_passphrase_file = /path/to/passphrase
output = java_job.out
error = java_job.err
log = java_job.log
queue
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
}

func TestStreamingIO(t *testing.T) {
	submit := `
universe = vanilla
executable = /bin/streaming_app
arguments = realtime
stream_input = true
stream_output = true
stream_error = true
want_remote_io = true
want_remote_syscalls = false
output = stream.out
error = stream.err
log = stream.log
queue
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
}

func TestFileTransferLimits(t *testing.T) {
	submit := `
universe = vanilla
executable = /bin/data_processor
arguments = large_dataset
should_transfer_files = YES
transfer_input_files = input_data.tar.gz
max_transfer_input_mb = 1000
max_transfer_output_mb = 2000
when_to_transfer_output = ON_EXIT
output = transfer.out
error = transfer.err
log = transfer.log
queue
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
}

func TestCheckpointConfiguration(t *testing.T) {
	submit := `
universe = vanilla
executable = /bin/checkpointable_app
arguments = long_computation
want_checkpoint = true
checkpoint_exit_code = 85
output = checkpoint.out
error = checkpoint.err
log = checkpoint.log
queue
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
}

func TestJobDurationLimits(t *testing.T) {
	submit := `
universe = vanilla
executable = /bin/timed_job
arguments = compute
allowed_execute_duration = 1800
allowed_job_duration = 3600
output = duration.out
error = duration.err
log = duration.log
queue
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
}

func TestMachineAttributeTracking(t *testing.T) {
	submit := `
universe = vanilla
executable = /bin/tracked_job
arguments = analysis
job_machine_attrs = Machine,Arch,OpSys,Memory,Cpus
job_machine_attrs_history_length = 5
output = tracking.out
error = tracking.err
log = tracking.log
queue
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
}

func TestCompleteJobWithAllFeatures(t *testing.T) {
	submit := `
universe = vanilla
executable = /bin/comprehensive_job
arguments = --mode full --config advanced.cfg

# Signal handling
kill_sig = SIGTERM
remove_kill_sig = SIGKILL
kill_sig_timeout = 90

# Simple job expressions
notification = complete
want_remote_io = true
stream_output = true
stream_error = false
description = Comprehensive test job with all features
copy_to_spool = false
buffer_size = 1048576
batch_name = comprehensive_batch
stack_size = 4096
remote_initialdir = /tmp/job_$(Cluster)_$(Process)

# Extended job expressions
want_graceful_removal = true
run_as_owner = false
load_profile = true
job_ad_information_attrs = ClusterId,ProcId,RequestMemory,RequestCpus
job_machine_attrs = Machine,Arch,OpSys
job_machine_attrs_history_length = 3
allowed_execute_duration = 7200
allowed_job_duration = 14400
max_transfer_input_mb = 500
max_transfer_output_mb = 1000

# File transfer
should_transfer_files = YES
transfer_input_files = config.txt, data.dat
when_to_transfer_output = ON_EXIT

# Resource requests
request_cpus = 4
request_memory = 8192
request_disk = 10000000

# Standard I/O
output = full_job_$(Process).out
error = full_job_$(Process).err
log = full_job.log

queue 3
`

	sf, err := ParseSubmitFile(strings.NewReader(submit))
	if err != nil {
		t.Fatalf("Failed to parse submit file: %v", err)
	}

	if sf.queueCount != 3 {
		t.Errorf("Expected queue count 3, got %d", sf.queueCount)
	}

	result, err := sf.Submit(3000)
	if err != nil {
		t.Fatalf("Submit failed: %v", err)
	}

	if result.NumProcs != 3 {
		t.Errorf("Expected 3 procs, got %d", result.NumProcs)
	}

	if len(result.ProcAds) != 3 {
		t.Errorf("Expected 3 proc ads, got %d", len(result.ProcAds))
	}
}

func TestCustomAttributesIntegration(t *testing.T) {
	submit := `
universe = vanilla
executable = /bin/custom_job
arguments = test

# Custom attributes (already implemented, testing integration)
+CustomString = "test value"
+CustomNumber = 42
+CustomBool = true
MY.ProjectID = "project_123"

# Signal handling
kill_sig = 15

# Simple expressions
notification = error
batch_name = custom_test

# Extended expressions
allowed_execute_duration = 600

output = custom.out
error = custom.err
log = custom.log
queue
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

	// The point of the test is that custom attributes survive being
	// mixed with everything else in a realistic submit file, so check
	// them rather than only checking that nothing errored.
	for attr, want := range map[string]string{
		"CustomString": `"test value"`,
		"CustomNumber": "42",
		"CustomBool":   "true",
		"ProjectID":    `"project_123"`,
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
	// And the submit commands alongside them still took effect.
	if expr, ok := ad.Lookup("JobBatchName"); !ok || expr.String() != `"custom_test"` {
		t.Errorf("JobBatchName = %v (present=%v), want \"custom_test\"", expr, ok)
	}
}
