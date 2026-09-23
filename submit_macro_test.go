package htcondor

import (
	"strings"
	"testing"
)

func TestMacroExpansionClusterProcess(t *testing.T) {
	submit := `
universe = vanilla
executable = /bin/process_$(Cluster)_$(Process)
arguments = --cluster $(Cluster) --proc $(Process)
output = job_$(Cluster).$(Process).out
error = job_$(Cluster).$(Process).err
log = cluster_$(Cluster).log
queue 3
`

	sf, err := ParseSubmitFile(strings.NewReader(submit))
	if err != nil {
		t.Fatalf("Failed to parse submit file: %v", err)
	}

	result, err := sf.Submit(5000)
	if err != nil {
		t.Fatalf("Submit failed: %v", err)
	}

	if result.NumProcs != 3 {
		t.Errorf("Expected 3 procs, got %d", result.NumProcs)
	}

	// Verify macros were expanded in each proc ad
	// Note: We can't easily verify the exact values without ClassAd.Get(),
	// but we verify the ads were created
	if len(result.ProcAds) != 3 {
		t.Errorf("Expected 3 proc ads, got %d", len(result.ProcAds))
	}
}

func TestMacroExpansionWithQueueVariables(t *testing.T) {
	submit := `
universe = vanilla
executable = /bin/process
arguments = --input $(inputfile) --output result_$(Process).dat
output = job_$(inputfile)_$(Process).out
error = job_$(inputfile)_$(Process).err
log = jobs.log
queue inputfile in (data1.txt, data2.txt, data3.txt)
`

	sf, err := ParseSubmitFile(strings.NewReader(submit))
	if err != nil {
		t.Fatalf("Failed to parse submit file: %v", err)
	}

	result, err := sf.Submit(6000)
	if err != nil {
		t.Fatalf("Submit failed: %v", err)
	}

	if result.NumProcs != 3 {
		t.Errorf("Expected 3 procs, got %d", result.NumProcs)
	}
}

func TestMacroExpansionItemIndex(t *testing.T) {
	submit := `
universe = vanilla
executable = /bin/echo
arguments = Processing item $(ItemIndex) from $(filename)
output = output_$(ItemIndex).txt
error = error_$(ItemIndex).txt
log = job.log
queue filename in (file1.txt, file2.txt, file3.txt, file4.txt)
`

	sf, err := ParseSubmitFile(strings.NewReader(submit))
	if err != nil {
		t.Fatalf("Failed to parse submit file: %v", err)
	}

	result, err := sf.Submit(7000)
	if err != nil {
		t.Fatalf("Submit failed: %v", err)
	}

	if result.NumProcs != 4 {
		t.Errorf("Expected 4 procs, got %d", result.NumProcs)
	}
}

func TestMacroExpansionStepRow(t *testing.T) {
	submit := `
universe = vanilla
executable = /bin/analyze
arguments = --step $(Step) --row $(Row)
output = step_$(Step)_row_$(Row).out
error = step_$(Step)_row_$(Row).err
log = analysis.log
queue 5
`

	sf, err := ParseSubmitFile(strings.NewReader(submit))
	if err != nil {
		t.Fatalf("Failed to parse submit file: %v", err)
	}

	result, err := sf.Submit(8000)
	if err != nil {
		t.Fatalf("Submit failed: %v", err)
	}

	if result.NumProcs != 5 {
		t.Errorf("Expected 5 procs, got %d", result.NumProcs)
	}
}

func TestLateMaterializationBasic(t *testing.T) {
	submit := `
universe = vanilla
executable = /bin/sleep
arguments = 60
output = sleep_$(Process).out
error = sleep_$(Process).err
log = sleep.log
queue 10
`

	sf, err := ParseSubmitFile(strings.NewReader(submit))
	if err != nil {
		t.Fatalf("Failed to parse submit file: %v", err)
	}

	// Use late materialization submission
	result, err := sf.SubmitLate(9000)
	if err != nil {
		t.Fatalf("SubmitLate failed: %v", err)
	}

	if result.NumProcs != 10 {
		t.Errorf("Expected 10 procs, got %d", result.NumProcs)
	}

	if result.ClusterAd == nil {
		t.Error("Expected non-nil cluster ad")
	}

	if len(result.ProcAds) != 10 {
		t.Errorf("Expected 10 proc ads, got %d", len(result.ProcAds))
	}
}

func TestLateMaterializationWithVariables(t *testing.T) {
	submit := `
universe = vanilla
executable = /bin/process
arguments = --config $(config) --proc $(Process)
output = $(config)_$(Process).out
error = $(config)_$(Process).err
log = processing.log
queue config in (config_a, config_b, config_c)
`

	sf, err := ParseSubmitFile(strings.NewReader(submit))
	if err != nil {
		t.Fatalf("Failed to parse submit file: %v", err)
	}

	result, err := sf.SubmitLate(10000)
	if err != nil {
		t.Fatalf("SubmitLate failed: %v", err)
	}

	if result.NumProcs != 3 {
		t.Errorf("Expected 3 procs, got %d", result.NumProcs)
	}

	if result.ClusterAd == nil {
		t.Error("Expected non-nil cluster ad")
	}
}

func TestMakeClusterAd(t *testing.T) {
	submit := `
universe = vanilla
executable = /bin/test
arguments = test
output = test.out
error = test.err
log = test.log
queue
`

	sf, err := ParseSubmitFile(strings.NewReader(submit))
	if err != nil {
		t.Fatalf("Failed to parse submit file: %v", err)
	}

	clusterAd, err := sf.MakeClusterAd(11000)
	if err != nil {
		t.Fatalf("MakeClusterAd failed: %v", err)
	}

	if clusterAd == nil {
		t.Fatal("Expected non-nil cluster ad")
	}
}

func TestMakeProcAd(t *testing.T) {
	submit := `
universe = vanilla
executable = /bin/test
arguments = --proc $(Process)
output = proc_$(Process).out
error = proc_$(Process).err
log = test.log
queue
`

	sf, err := ParseSubmitFile(strings.NewReader(submit))
	if err != nil {
		t.Fatalf("Failed to parse submit file: %v", err)
	}

	procAd, err := sf.MakeProcAd(12000, 5, map[string]string{})
	if err != nil {
		t.Fatalf("MakeProcAd failed: %v", err)
	}

	if procAd == nil {
		t.Fatal("Expected non-nil proc ad")
	}
}

func TestMacroExpansionComplex(t *testing.T) {
	submit := `
universe = vanilla
executable = /bin/complex_job
arguments = --cluster $(Cluster) --proc $(Process) --input $(inputfile) --index $(ItemIndex)
initialdir = /tmp/cluster_$(Cluster)/proc_$(Process)
output = $(inputfile)_$(Process).out
error = $(inputfile)_$(Process).err
log = cluster_$(Cluster).log
transfer_input_files = $(inputfile)
transfer_output_files = result_$(Process).dat, summary_$(ItemIndex).txt
queue inputfile in (exp1.dat, exp2.dat, exp3.dat, exp4.dat, exp5.dat)
`

	sf, err := ParseSubmitFile(strings.NewReader(submit))
	if err != nil {
		t.Fatalf("Failed to parse submit file: %v", err)
	}

	result, err := sf.Submit(13000)
	if err != nil {
		t.Fatalf("Submit failed: %v", err)
	}

	if result.NumProcs != 5 {
		t.Errorf("Expected 5 procs, got %d", result.NumProcs)
	}
}

func TestMacroExpansionMultipleVariables(t *testing.T) {
	submit := `
universe = vanilla
executable = /bin/process
arguments = --x $(xval) --y $(yval)
output = result_$(xval)_$(yval).out
error = result_$(xval)_$(yval).err
log = multi.log
queue xval, yval in ("1 10", "2 20", "3 30", "4 40")
`

	sf, err := ParseSubmitFile(strings.NewReader(submit))
	if err != nil {
		t.Fatalf("Failed to parse submit file: %v", err)
	}

	result, err := sf.Submit(14000)
	if err != nil {
		t.Fatalf("Submit failed: %v", err)
	}

	if result.NumProcs != 4 {
		t.Errorf("Expected 4 procs, got %d", result.NumProcs)
	}
}

func TestExpandSubmitMacrosHelper(t *testing.T) {
	submit := `
universe = vanilla
executable = /bin/test
queue
`

	sf, err := ParseSubmitFile(strings.NewReader(submit))
	if err != nil {
		t.Fatalf("Failed to parse submit file: %v", err)
	}

	jobID := JobID{Cluster: 1000, Proc: 5}
	queueVars := map[string]string{
		"inputfile": "data.txt",
		"ItemIndex": "2",
	}

	input := "job_$(Cluster)_$(Process)_$(inputfile)_$(ItemIndex).out"
	result := sf.expandSubmitMacros(input, jobID, queueVars)

	expected := "job_1000_5_data.txt_2.out"
	if result != expected {
		t.Errorf("Expected %q, got %q", expected, result)
	}
}

func TestMacroExpansionNodeAlias(t *testing.T) {
	// Node is an alias for Process in parallel universe
	submit := `
universe = parallel
executable = /usr/bin/mpiexec
arguments = -n 16 ./mpi_app --node $(Node)
machine_count = 4
output = mpi_node_$(Node).out
error = mpi_node_$(Node).err
log = mpi.log
queue 4
`

	sf, err := ParseSubmitFile(strings.NewReader(submit))
	if err != nil {
		t.Fatalf("Failed to parse submit file: %v", err)
	}

	result, err := sf.Submit(15000)
	if err != nil {
		t.Fatalf("Submit failed: %v", err)
	}

	if result.NumProcs != 4 {
		t.Errorf("Expected 4 procs, got %d", result.NumProcs)
	}
}

func TestMacroExpansionClusterIdProcId(t *testing.T) {
	// ClusterId and ProcId are aliases
	submit := `
universe = vanilla
executable = /bin/job
arguments = --cluster-id $(ClusterId) --proc-id $(ProcId)
output = cid_$(ClusterId)_pid_$(ProcId).out
error = cid_$(ClusterId)_pid_$(ProcId).err
log = job.log
queue 3
`

	sf, err := ParseSubmitFile(strings.NewReader(submit))
	if err != nil {
		t.Fatalf("Failed to parse submit file: %v", err)
	}

	result, err := sf.Submit(16000)
	if err != nil {
		t.Fatalf("Submit failed: %v", err)
	}

	if result.NumProcs != 3 {
		t.Errorf("Expected 3 procs, got %d", result.NumProcs)
	}
}

func TestLateMaterializationLargeJob(t *testing.T) {
	submit := `
universe = vanilla
executable = /bin/parametric_sweep
arguments = --param $(param) --iteration $(Process)
output = sweep_$(param)_$(Process).out
error = sweep_$(param)_$(Process).err
log = sweep.log
queue param in (alpha, beta, gamma, delta, epsilon, zeta, eta, theta, iota, kappa)
`

	sf, err := ParseSubmitFile(strings.NewReader(submit))
	if err != nil {
		t.Fatalf("Failed to parse submit file: %v", err)
	}

	result, err := sf.SubmitLate(17000)
	if err != nil {
		t.Fatalf("SubmitLate failed: %v", err)
	}

	if result.NumProcs != 10 {
		t.Errorf("Expected 10 procs, got %d", result.NumProcs)
	}

	if result.ClusterAd == nil {
		t.Error("Expected non-nil cluster ad")
	}

	if len(result.ProcAds) != 10 {
		t.Errorf("Expected 10 proc ads, got %d", len(result.ProcAds))
	}
}

// TestSubmitMacrosAreCaseInsensitive pins the fix for a macro that silently
// expands to nothing.
//
// HTCondor macro names do not distinguish case: $(cluster), $(Cluster) and
// $(CLUSTER) are one macro, and condor_submit_dag writes the lowercase
// spelling into the submit file it generates. This library resolved the
// submit-time macros through a raw map index, which is case-sensitive, so
// $(cluster) expanded to the empty string while $(Cluster) expanded to the
// cluster id. Nothing failed: the job was submitted with an argument, a file
// name or an OtherJobRemoveRequirements that had a hole in it.
func TestSubmitMacrosAreCaseInsensitive(t *testing.T) {
	sf, err := ParseSubmitFile(strings.NewReader(
		"universe = vanilla\n" +
			"executable = /bin/true\n" +
			`arguments = "$(cluster) $(process) $(Cluster) $(CLUSTER) $(ClusterId) $(clusterid)"` + "\n" +
			"queue\n"))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	ad, err := sf.MakeJobAd(JobID{Cluster: 42, Proc: 7}, nil)
	if err != nil {
		t.Fatalf("MakeJobAd: %v", err)
	}
	args, ok := ad.EvaluateAttrString("Arguments")
	if !ok {
		if args, ok = ad.EvaluateAttrString("Args"); !ok {
			t.Fatal("job ad has neither Arguments nor Args")
		}
	}
	if want := "42 7 42 42 42 42"; args != want {
		t.Errorf("arguments = %q, want %q: a macro spelled in the wrong case expanded to nothing", args, want)
	}
}
