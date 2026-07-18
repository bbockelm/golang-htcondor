package mcpserver

import (
	"fmt"
	"strings"
)

// defaultInstructions builds generic HTCondor MCP instructions that are
// always included, regardless of per-deployment configuration. The
// scheddName (access point hostname) is inserted when available.
func defaultInstructions(scheddName string) string {
	var b strings.Builder

	// Identity
	if scheddName != "" {
		fmt.Fprintf(&b, "This is the HTCondor access point %q.\n\n", scheddName)
	} else {
		b.WriteString("This is an HTCondor access point.\n\n")
	}

	b.WriteString(`HTCondor is a high-throughput computing (HTC) workload management system. ` +
		`Users submit batch jobs that are matched to available compute resources and ` +
		`executed remotely. An "access point" (AP) is the server through which users ` +
		`submit and manage their jobs.` + "\n\n")

	// Job lifecycle
	b.WriteString("## Job states\n\n")
	b.WriteString("Every job has a JobStatus attribute:\n")
	b.WriteString("  1 = Idle      — waiting to be matched to a resource\n")
	b.WriteString("  2 = Running   — executing on a remote machine\n")
	b.WriteString("  3 = Removed   — deleted by the user or system\n")
	b.WriteString("  4 = Completed — finished execution\n")
	b.WriteString("  5 = Held      — paused due to an error; see HoldReason\n")
	b.WriteString("  6 = Transferring Output — sending results back\n")
	b.WriteString("  7 = Suspended — temporarily paused\n\n")

	// Common workflow
	b.WriteString("## Typical workflow\n\n")
	b.WriteString("1. submit_job — submit a job with an HTCondor submit-file description.\n")
	b.WriteString("2. upload_job_input — upload the executable and small input files (< 100 KB total recommended). " +
		"For larger inputs, use HTTP/HTTPS URLs in transfer_input_files.\n")
	b.WriteString("3. query_jobs — poll until JobStatus changes to 4 (Completed) or 5 (Held).\n")
	b.WriteString("4. get_job_stdout / get_job_stderr — retrieve output after the job finishes.\n")
	b.WriteString("5. get_job_output — retrieve any other output files.\n\n")

	// Submit file basics
	b.WriteString("## Submit file basics\n\n")
	b.WriteString("A minimal submit file that uploads a custom script:\n\n")
	b.WriteString("  executable = my_script.sh\n")
	b.WriteString("  log        = job.log\n")
	b.WriteString("  output     = output.txt\n")
	b.WriteString("  error      = error.txt\n")
	b.WriteString("  request_cpus   = 1\n")
	b.WriteString("  request_memory = 1024\n")
	b.WriteString("  request_disk   = 1024\n")
	b.WriteString("  queue 1\n\n")
	b.WriteString("The \"queue\" line determines how many job processes to create.\n\n")

	// transfer_executable guidance
	b.WriteString("## transfer_executable\n\n")
	b.WriteString("By default, HTCondor transfers the executable to the remote machine. " +
		"If the executable is a standard system command (e.g., /bin/bash, /usr/bin/python3, " +
		"/usr/bin/env), set transfer_executable = false so HTCondor uses the command " +
		"already installed on the execute node and you do not need to upload it.\n\n")
	b.WriteString("Example using bash as the executable (no upload needed):\n\n")
	b.WriteString("  executable = /bin/bash\n")
	b.WriteString("  transfer_executable = false\n")
	b.WriteString("  arguments  = -c \"echo Hello World\"\n")
	b.WriteString("  log        = job.log\n")
	b.WriteString("  output     = output.txt\n")
	b.WriteString("  error      = error.txt\n")
	b.WriteString("  queue 1\n\n")
	b.WriteString("When transfer_executable = false AND no transfer_input_files are specified, " +
		"the job does not need input spooling and will go directly to Idle.\n\n")

	// ClassAd essentials
	b.WriteString("## Key job attributes (ClassAd)\n\n")
	b.WriteString("When querying jobs, useful attributes include:\n")
	b.WriteString("  ClusterId, ProcId — job identifier (ClusterId.ProcId, e.g. 123.0)\n")
	b.WriteString("  Owner             — submitting user\n")
	b.WriteString("  JobStatus         — numeric state (see above)\n")
	b.WriteString("  HoldReason        — why a job is held\n")
	b.WriteString("  RemoteHost        — machine running the job\n")
	b.WriteString("  RequestCpus, RequestMemory, RequestDisk — resource requests\n")
	b.WriteString("  NumJobStarts      — how many times the job has started\n")
	b.WriteString("  EnteredCurrentStatus — timestamp of last state change\n\n")

	// Constraint expressions
	b.WriteString("## Constraint expressions\n\n")
	b.WriteString("Use ClassAd constraint expressions to filter jobs:\n")
	b.WriteString("  \"Owner == \\\"alice\\\"\"         — jobs owned by alice\n")
	b.WriteString("  \"JobStatus == 5\"              — held jobs\n")
	b.WriteString("  \"ClusterId == 123\"            — all procs in cluster 123\n")
	b.WriteString("  \"JobStatus == 1 && RequestCpus > 4\" — idle jobs wanting >4 CPUs\n\n")

	// Other tools
	b.WriteString("## Other tools\n\n")
	b.WriteString("  hold_job / release_job — pause and resume jobs\n")
	b.WriteString("  edit_job — change job attributes (e.g. increase RequestMemory)\n")
	b.WriteString("  remove_job / remove_jobs — cancel jobs\n")
	b.WriteString("  query_job_epochs — view retry history for jobs that ran multiple times\n")
	b.WriteString("  query_job_archive — search completed/removed jobs in the history\n")
	b.WriteString("  query_transfer_history — view file transfer details\n")
	b.WriteString("  get_credential_status / store_service_credential / list_service_credentials / " +
		"delete_service_credential — manage stored credentials\n")
	b.WriteString("  advertise_to_collector — publish a ClassAd to the HTCondor collector\n")

	return b.String()
}

// buildInstructions combines the default HTCondor instructions with any
// additional deployment-specific instructions from configuration.
func buildInstructions(scheddName, customInstructions string) string {
	base := defaultInstructions(scheddName)
	if customInstructions == "" {
		return base
	}
	return base + "\n## Deployment-specific notes\n\n" + customInstructions
}
