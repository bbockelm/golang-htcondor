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
	b.WriteString("3. watch_jobs / check_watches — wait for the job to finish (or be held) without polling; " +
		"a watch fires even if it already happened. Call watch_jobs once to register; call check_watches to " +
		"see whether it has been answered. Use query_jobs for a one-off status snapshot.\n")
	b.WriteString("4. tail_job_output — while it RUNS, read the end of its stdout/stderr straight from " +
		"the execute node. This is how you watch progress or find out why a job is stuck, instead of " +
		"waiting for it to finish. Pass the offsets it returns back on the next call to get only what " +
		"is new, and poll no more than every 5 seconds.\n")
	b.WriteString("5. get_job_stdout / get_job_stderr — retrieve output after the job FINISHES. " +
		"These read the transferred files, so they are the right tools once a job is done and the " +
		"wrong ones while it runs; tail_job_output is the reverse.\n")
	b.WriteString("6. get_job_output — retrieve any other output files.\n\n")

	// Interactive sessions
	b.WriteString("## Interactive sessions vs batch jobs\n\n")
	b.WriteString("The workflow above is one job per command, with a queue wait each time. " +
		"When several steps need the same machine and the same files — build then test, explore a " +
		"dataset, reproduce a failure by hand — start an interactive session instead and run the " +
		"steps inside it:\n\n")
	b.WriteString("1. interactive_session_start — name the session; it queues like any other job.\n")
	b.WriteString("2. interactive_session_exec — run a command in it (waits for the job to start). " +
		"Repeat as needed; each call returns exit code, stdout and stderr.\n")
	b.WriteString("3. interactive_session_stop — release the slot when finished.\n\n")
	b.WriteString("To run a single command inside a job that is ALREADY running — including an " +
		"ordinary batch job, not just a session — use exec_in_job. It connects, runs the command, " +
		"and disconnects, which makes it the tool for inspecting a running job (ls the sandbox, " +
		"check a process, read a file mid-run) without starting a session or disturbing the job. " +
		"Use a session instead when several commands need the same shell.\n\n")
	b.WriteString("Three things to know:\n")
	b.WriteString("  - The session name is the only handle. Pass it on every call; " +
		"interactive_session_list finds sessions from earlier conversations.\n")
	b.WriteString("  - A session holds its CPUs and memory until stopped, and is reclaimed " +
		"automatically after ~30 minutes with no calls. Stop sessions you are done with.\n")
	b.WriteString("  - Each exec is a fresh shell: the working directory resets and environment " +
		"changes do not carry over, so chain dependent steps in one command with '&&'. " +
		"Files written into the sandbox do persist.\n\n")

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
	b.WriteString("Leaving it at the default with a system-path executable does not fail at submit time: " +
		"HTCondor spool-copies the executable, the copy does not exist, and the job holds on file transfer " +
		"(HoldReasonCode 13, HoldReasonSubCode 2). submit_job rejects that combination up front.\n\n")

	// $(...) macro expansion
	b.WriteString("## $(...) is macro expansion, not shell substitution\n\n")
	b.WriteString("The submit parser expands every $(...) itself, so the shell never sees it; an undefined " +
		"name expands to an empty string and the job runs with a corrupted command line:\n\n")
	b.WriteString("  arguments = -c \"echo HOST:$(hostname)\"   # bash receives: -c \"echo HOST:\"\n\n")
	b.WriteString("$(Cluster), $(Process), $(ProcId), $(ItemIndex), $(Step), $(Row) and submit-file macros " +
		"are the intended use. To run shell commands, write a script, name it as the executable, and upload " +
		"it with upload_job_input.\n\n")

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
	b.WriteString("  analyze_job_match — explain why a job is or is not matching slots; the first " +
		"stop for a job stuck idle\n")
	b.WriteString("  query_job_epochs — view retry history for jobs that ran multiple times\n")
	b.WriteString("  query_job_archive — search completed/removed jobs in the history\n")
	b.WriteString("  query_transfer_history — view file transfer details\n")
	b.WriteString("  get_credential_status / store_service_credential / list_service_credentials / " +
		"delete_service_credential — manage stored credentials\n")
	b.WriteString("  advertise_to_collector — publish a ClassAd to the HTCondor collector\n")
	b.WriteString("  interactive_session_start / _exec / _list / _stop — run commands inside a " +
		"long-lived job (see above)\n")
	b.WriteString("  tail_job_output — read the end of a RUNNING job's stdout/stderr from the " +
		"execute node\n")
	b.WriteString("  exec_in_job — run one command inside a job that is already running\n")
	b.WriteString("  get_version — report this server's build (version, git commit, linked library versions); " +
		"use it to confirm which code is deployed\n")
	b.WriteString("  whoami — who this server authenticated you as, whether you are an administrator, and whether " +
		"the other tools are confined to your own jobs; ask it when a query returns less than you expect.\n")

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

// SetInstructions installs the deployment-specific instructions, combining them
// with the generic HTCondor guidance the same way construction does. It is the
// dynamic half of MCP_INSTRUCTIONS: a reconfigure calls this so an operator can
// correct the guidance agents receive without restarting the daemon and
// dropping every live session.
//
// Only sessions that initialize after this call see the new text. MCP delivers
// instructions once, in the initialize response, so an agent already connected
// keeps the text it was given -- there is no way to push a revision to it.
func (s *Server) SetInstructions(custom string) {
	s.customInstructions.Store(&custom)
	s.rebuildInstructions()
}

// rebuildInstructions regenerates the initialize text from the operator's
// instructions and the skills currently loaded.
//
// Both inputs can change independently at runtime -- MCP_INSTRUCTIONS on a
// reconfigure, the library when a checkout is reloaded -- and the text has
// to reflect whichever changed without discarding the other.
func (s *Server) rebuildInstructions() {
	name := ""
	if sc := s.getSchedd(); sc != nil {
		name = sc.Name()
	}
	custom := ""
	if p := s.customInstructions.Load(); p != nil {
		custom = *p
	}
	built := buildInstructions(name, custom) + skillsInstructions(s.skillsLibrary())
	s.instructions.Store(&built)
	// The SDK transport bakes this text, and the catalogue it is built
	// from, into servers it caches per scope set. Bumping the generation
	// is what makes those caches notice; without it a reconfigure would
	// change the text every other surface serves and not this one.
	s.catalogGen.Add(1)
}
