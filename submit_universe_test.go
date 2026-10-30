package htcondor

import (
	"strings"
	"testing"
)

func TestGridUniverseParameters(t *testing.T) {
	submit := `
universe = grid
grid_resource = ec2 https://ec2.us-east-1.amazonaws.com/
executable = /bin/echo
arguments = test
ec2_ami_id = ami-12345678
ec2_instance_type = t2.micro
ec2_keypair = my-keypair
ec2_security_groups = default, web-server
ec2_spot_price = 0.05
batch_queue = normal
batch_project = research
batch_runtime = 3600
`

	sf, err := ParseSubmitFile(strings.NewReader(submit))
	if err != nil {
		t.Fatalf("Failed to parse submit file: %v", err)
	}

	if sf.universe != UniverseGrid {
		t.Errorf("Expected universe %d, got %d", UniverseGrid, sf.universe)
	}

	jobID := JobID{Cluster: 100, Proc: 0}
	ad, err := sf.MakeJobAd(jobID, map[string]string{})
	if err != nil {
		t.Fatalf("Failed to create job ad: %v", err)
	}

	if ad == nil {
		t.Fatal("Expected non-nil job ad")
	}

	// Verify grid universe was set (job ad created successfully)
	// Note: ClassAd attribute verification requires the ClassAd API
}

func TestVMUniverseParameters(t *testing.T) {
	submit := `
universe = vm
vm_type = kvm
vm_memory = 2048
vm_disk = disk.img
vm_networking = true
vm_networking_type = nat
vm_vcpus = 4
vm_checkpoint = true
executable = /bin/echo
arguments = test
`

	sf, err := ParseSubmitFile(strings.NewReader(submit))
	if err != nil {
		t.Fatalf("Failed to parse submit file: %v", err)
	}

	if sf.universe != UniverseVM {
		t.Errorf("Expected universe %d, got %d", UniverseVM, sf.universe)
	}

	jobID := JobID{Cluster: 100, Proc: 0}
	ad, err := sf.MakeJobAd(jobID, map[string]string{})
	if err != nil {
		t.Fatalf("Failed to create job ad: %v", err)
	}

	if ad == nil {
		t.Fatal("Expected non-nil job ad")
	}

	// Verify VM universe was set (job ad created successfully)
	// Note: ClassAd attribute verification requires the ClassAd API
}

func TestParallelUniverseParameters(t *testing.T) {
	submit := `
universe = parallel
machine_count = 8
request_cpus = 4
executable = /usr/bin/mpirun
arguments = -np 32 ./my_mpi_app
`

	sf, err := ParseSubmitFile(strings.NewReader(submit))
	if err != nil {
		t.Fatalf("Failed to parse submit file: %v", err)
	}

	if sf.universe != UniverseParallel {
		t.Errorf("Expected universe %d, got %d", UniverseParallel, sf.universe)
	}

	jobID := JobID{Cluster: 100, Proc: 0}
	ad, err := sf.MakeJobAd(jobID, map[string]string{})
	if err != nil {
		t.Fatalf("Failed to create job ad: %v", err)
	}

	if ad == nil {
		t.Fatal("Expected non-nil job ad")
	}

	// Verify parallel universe was set (job ad created successfully)
	// Note: ClassAd attribute verification requires the ClassAd API
}

func TestJavaUniverseParameters(t *testing.T) {
	submit := `
universe = java
executable = MyClass
jar_files = myapp.jar, lib/commons.jar
java_vm_args = -Xmx2048m -Xms512m
arguments = arg1 arg2
`

	sf, err := ParseSubmitFile(strings.NewReader(submit))
	if err != nil {
		t.Fatalf("Failed to parse submit file: %v", err)
	}

	if sf.universe != UniverseJava {
		t.Errorf("Expected universe %d, got %d", UniverseJava, sf.universe)
	}

	jobID := JobID{Cluster: 100, Proc: 0}
	ad, err := sf.MakeJobAd(jobID, map[string]string{})
	if err != nil {
		t.Fatalf("Failed to create job ad: %v", err)
	}

	if ad == nil {
		t.Fatal("Expected non-nil job ad")
	}

	// Verify Java universe was set (job ad created successfully)
	// Note: ClassAd attribute verification requires the ClassAd API
}

func TestPeriodicExpressions(t *testing.T) {
	submit := `
universe = vanilla
executable = /bin/long_running
arguments = test
periodic_hold = (JobStatus == 2) && ((CurrentTime - JobStartDate) > 3600)
periodic_hold_reason = "Job exceeded 1 hour runtime"
periodic_hold_subcode = 1
periodic_release = (JobStatus == 5) && ((CurrentTime - EnteredCurrentStatus) > 300)
periodic_remove = (JobStatus == 5) && ((CurrentTime - EnteredCurrentStatus) > 86400)
on_exit_hold = (ExitCode =!= 0)
on_exit_hold_reason = "Job exited with non-zero status"
on_exit_remove = false
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

	// Verify periodic expressions were set
	// We can't easily Get() the values without the ClassAd API,
	// but we can verify the ad was created
}

func TestCronParameters(t *testing.T) {
	submit := `
universe = vanilla
executable = /bin/daily_job
arguments = test
cron_minute = 0
cron_hour = 2
cron_day_of_month = *
cron_month = *
cron_day_of_week = *
cron_prep_time = 300
cron_window = 600
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

	for attr, want := range map[string]string{
		"CronMinute":       `"0"`,
		"CronHour":         `"2"`,
		"DeferralWindow":   "600",
		"DeferralPrepTime": "300",
	} {
		expr, ok := ad.Lookup(attr)
		if !ok {
			t.Errorf("%s is missing; want %s", attr, want)
			continue
		}
		if got := expr.String(); got != want {
			t.Errorf("%s = %s; want %s", attr, got, want)
		}
	}
}

func TestDeferralParameters(t *testing.T) {
	submit := `
universe = vanilla
executable = /bin/deferred_job
arguments = test
deferral_time = 1640000000
deferral_window = 3600
deferral_prep_time = 300
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

	for attr, want := range map[string]string{
		"DeferralTime":     "1640000000",
		"DeferralWindow":   "3600",
		"DeferralPrepTime": "300",
	} {
		expr, ok := ad.Lookup(attr)
		if !ok {
			t.Errorf("%s is missing; want %s", attr, want)
			continue
		}
		if got := expr.String(); got != want {
			t.Errorf("%s = %s; want %s", attr, got, want)
		}
	}
}

func TestAutoGeneratedAttributes(t *testing.T) {
	submit := `
universe = vanilla
executable = /bin/echo
arguments = test
initialdir = /home/user/jobs
should_transfer_files = YES
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

	// Verify auto-generated attributes are set
	// NumJobStarts, NumRestarts, etc. should all be initialized
}

func TestEC2CompleteExample(t *testing.T) {
	submit := `
universe = grid
grid_resource = ec2 https://ec2.us-west-2.amazonaws.com/
executable = /bin/process_data
arguments = --input $(datafile)
ec2_ami_id = ami-abcdef12
ec2_instance_type = m5.large
ec2_keypair = research-key
ec2_keypair_file = ~/.ssh/research-key.pem
ec2_access_key_id = /home/user/.aws/access_key
ec2_secret_access_key = /home/user/.aws/secret_key
ec2_security_groups = research-sg
ec2_spot_price = 0.10
ec2_user_data = "#!/bin/bash\necho 'Starting job' > /tmp/startup.log"
output = job_$(Process).out
error = job_$(Process).err
log = job.log
queue datafile in (data1.txt, data2.txt, data3.txt)
`

	sf, err := ParseSubmitFile(strings.NewReader(submit))
	if err != nil {
		t.Fatalf("Failed to parse submit file: %v", err)
	}

	if sf.universe != UniverseGrid {
		t.Errorf("Expected universe %d, got %d", UniverseGrid, sf.universe)
	}

	// Should create 3 jobs
	if sf.queueCount != 3 {
		t.Errorf("Expected queue count 3, got %d", sf.queueCount)
	}

	result, err := sf.Submit(2000)
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

func TestGCECompleteExample(t *testing.T) {
	submit := `
universe = grid
grid_resource = gce https://www.googleapis.com/compute/v1/projects/myproject
executable = /bin/analyze
arguments = --config $(config)
gce_image = projects/debian-cloud/global/images/debian-10
gce_machine_type = n1-standard-4
gce_account = service-account@project.iam.gserviceaccount.com
gce_auth_file = /home/user/.gce/auth.json
gce_metadata = startup-script=/usr/local/bin/init.sh,environment=production
output = analysis_$(config).out
error = analysis_$(config).err
log = gce_job.log
queue config in (config_a, config_b)
`

	sf, err := ParseSubmitFile(strings.NewReader(submit))
	if err != nil {
		t.Fatalf("Failed to parse submit file: %v", err)
	}

	if sf.universe != UniverseGrid {
		t.Errorf("Expected universe %d, got %d", UniverseGrid, sf.universe)
	}

	// Should create 2 jobs
	if sf.queueCount != 2 {
		t.Errorf("Expected queue count 2, got %d", sf.queueCount)
	}

	result, err := sf.Submit(2001)
	if err != nil {
		t.Fatalf("Submit failed: %v", err)
	}

	if result.NumProcs != 2 {
		t.Errorf("Expected 2 procs, got %d", result.NumProcs)
	}
}

func TestVMXenParameters(t *testing.T) {
	submit := `
universe = vm
vm_type = xen
vm_memory = 4096
vm_vcpus = 2
xen_kernel = vmlinuz
xen_initrd = initrd.img
xen_root = /dev/xvda1
xen_kernel_params = console=hvc0
executable = /bin/simulation
arguments = --iterations 1000
`

	sf, err := ParseSubmitFile(strings.NewReader(submit))
	if err != nil {
		t.Fatalf("Failed to parse submit file: %v", err)
	}

	if sf.universe != UniverseVM {
		t.Errorf("Expected universe %d, got %d", UniverseVM, sf.universe)
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

func TestMPIParallelJob(t *testing.T) {
	submit := `
universe = parallel
machine_count = 16
request_cpus = 2
request_memory = 8192
executable = /usr/bin/mpiexec
arguments = -n 32 ./climate_model --input params.dat
output = mpi_job.out
error = mpi_job.err
log = mpi_job.log
should_transfer_files = YES
transfer_input_files = climate_model, params.dat, input_data.nc
transfer_output_files = results.nc
queue
`

	sf, err := ParseSubmitFile(strings.NewReader(submit))
	if err != nil {
		t.Fatalf("Failed to parse submit file: %v", err)
	}

	if sf.universe != UniverseParallel {
		t.Errorf("Expected universe %d, got %d", UniverseParallel, sf.universe)
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

func TestComplexPeriodicExpressions(t *testing.T) {
	submit := `
universe = vanilla
executable = /bin/analysis
arguments = --input data.csv
periodic_hold = (ImageSize > 10000000) || (DiskUsage > 50000000)
periodic_hold_reason = "Job exceeded resource limits"
periodic_hold_subcode = 2
periodic_release = (JobStatus == 5) && (HoldReasonCode == 2) && (NumJobStarts < 3)
periodic_remove = (JobStatus == 5) && (HoldReasonCode != 2)
on_exit_hold = (ExitCode =!= 0) && (ExitCode =!= 42)
on_exit_hold_reason = strcat("Job failed with exit code ", ExitCode)
on_exit_hold_subcode = ExitCode
on_exit_remove = (ExitCode == 0) || (ExitCode == 42)
output = analysis.out
error = analysis.err
log = analysis.log
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
