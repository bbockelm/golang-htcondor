// Package htcondor provides HTCondor job submission functionality.
//
//nolint:unparam // Many functions return error for interface consistency even when currently not failing
package htcondor

import (
	"fmt"
	"io"
	"strconv"
	"strings"

	"github.com/PelicanPlatform/classad/classad"
	"github.com/bbockelm/golang-htcondor/config"
)

// SubmitFile represents a parsed HTCondor submit file
type SubmitFile struct {
	cfg      *config.Config
	universe int

	// Queue statement information
	queueCount    int
	queueVars     []string
	queueIterator SubmitIterator
}

// SubmitIterator provides iteration over queue items
type SubmitIterator interface {
	// Next advances to the next item and returns true if successful
	Next() bool
	// Values returns the current row's variable values
	Values() map[string]string
	// Count returns the total number of items
	Count() int
}

// JobID represents a cluster/proc pair
type JobID struct {
	Cluster int
	Proc    int
}

// SubmitResult contains the results of submitting jobs
type SubmitResult struct {
	ClusterID int
	NumProcs  int
	ClusterAd *classad.ClassAd
	ProcAds   []*classad.ClassAd
}

// Universe constants matching HTCondor
const (
	UniverseMin       = 0
	UniverseStandard  = 1
	UniverseVanilla   = 5
	UniverseScheduler = 7
	UniverseGrid      = 9
	UniverseJava      = 10
	UniverseParallel  = 11
	UniverseLocal     = 12
	UniverseVM        = 13
	UniverseDocker    = 14 // Deprecated, use Vanilla + container
)

// ParseSubmitFile parses a submit file from a reader
func ParseSubmitFile(r io.Reader) (*SubmitFile, error) {
	// We need to parse the submit file in two passes:
	// 1. Parse to get the queue statement
	// 2. Execute assignments to build the config

	// First pass: parse to get statements including queue
	lexer := config.NewLexer(r)
	stmts, err := config.Parse(lexer)
	if err != nil {
		return nil, fmt.Errorf("failed to parse submit file: %w", err)
	}

	// Find the queue statement (should be last, but we'll take the first we find)
	var queueStmt *config.QueueStatement
	var configStmts []config.Statement

	for _, stmt := range stmts {
		if qs, ok := stmt.(*config.QueueStatement); ok {
			if queueStmt == nil {
				queueStmt = qs
			}
			// Don't include queue statements in config execution
			continue
		}
		configStmts = append(configStmts, stmt)
	}

	// Create config and execute non-queue statements
	cfg := config.NewEmpty()
	if err := cfg.ExecuteStatements(configStmts); err != nil {
		return nil, fmt.Errorf("failed to execute submit file: %w", err)
	}

	sf := &SubmitFile{
		cfg:        cfg,
		universe:   UniverseVanilla, // Default
		queueCount: 1,               // Default if no queue statement
	}

	// Set universe if specified
	if univ, ok := cfg.Get("universe"); ok {
		sf.universe = parseUniverse(univ)
	}

	// Create iterator from queue statement
	if queueStmt != nil {
		iterator, err := createIteratorFromQueue(queueStmt)
		if err != nil {
			return nil, fmt.Errorf("failed to create queue iterator: %w", err)
		}
		sf.queueIterator = iterator
		sf.queueCount = iterator.Count()
		sf.queueVars = queueStmt.VarNames
	} else {
		// No queue statement means queue 1
		sf.queueIterator = newSimpleIterator(1)
		sf.queueCount = 1
	}

	return sf, nil
}

// parseUniverse converts universe string to integer constant
func parseUniverse(univ string) int {
	univ = strings.ToLower(strings.TrimSpace(univ))
	switch univ {
	case "standard":
		return UniverseStandard
	case "vanilla":
		return UniverseVanilla
	case "scheduler":
		return UniverseScheduler
	case "grid":
		return UniverseGrid
	case "java":
		return UniverseJava
	case "parallel", "mpi":
		return UniverseParallel
	case "local":
		return UniverseLocal
	case "vm":
		return UniverseVM
	case "docker":
		return UniverseDocker
	default:
		return UniverseVanilla
	}
}

// MakeJobAd creates a ClassAd for a single job
// This is the main transformation from submit file to job ClassAd
// queueVars contains variable substitutions from the queue statement
func (sf *SubmitFile) MakeJobAd(jobID JobID, queueVars map[string]string) (*classad.ClassAd, error) {
	ad := classad.New()

	// Set basic job identifiers
	_ = ad.Set("ClusterId", jobID.Cluster)
	_ = ad.Set("ProcId", jobID.Proc)
	_ = ad.Set("JobUniverse", sf.universe)

	// Set job status (1 = idle)
	_ = ad.Set("JobStatus", 1)

	// Apply live macro substitutions using a macro context
	// This implements HTCondor's "live" macros that change per-job
	sf.pushMacroContext(jobID, queueVars)
	defer sf.popMacroContext()

	// Set executable
	if err := sf.setExecutable(ad); err != nil {
		return nil, err
	}

	// Set arguments
	if err := sf.setArguments(ad); err != nil {
		return nil, err
	}

	// Set environment
	if err := sf.setEnvironment(ad); err != nil {
		return nil, err
	}

	// Set input/output/error files
	if err := sf.setStandardFiles(ad); err != nil {
		return nil, err
	}

	// Set file transfer settings
	if err := sf.setFileTransfer(ad); err != nil {
		return nil, err
	}

	// Set container/docker settings
	if err := sf.setContainerSettings(ad); err != nil {
		return nil, err
	}

	// Set requirements
	if err := sf.setRequirements(ad); err != nil {
		return nil, err
	}

	// Set request_* resources
	if err := sf.setResourceRequests(ad); err != nil {
		return nil, err
	}

	// Set notification
	if err := sf.setNotification(ad); err != nil {
		return nil, err
	}

	// Set rank
	if err := sf.setRank(ad); err != nil {
		return nil, err
	}

	// Set owner and accounting
	if err := sf.setOwnership(ad); err != nil {
		return nil, err
	}

	// Set job status and control attributes
	if err := sf.setJobStatusControl(ad); err != nil {
		return nil, err
	}

	// Set any custom attributes (+ or MY.)
	if err := sf.setCustomAttributes(ad); err != nil {
		return nil, err
	}

	// Set universe-specific parameters
	switch sf.universe {
	case UniverseGrid:
		if err := sf.setGridParams(ad); err != nil {
			return nil, err
		}
	case UniverseVM:
		if err := sf.setVMParams(ad); err != nil {
			return nil, err
		}
	case UniverseParallel:
		if err := sf.setParallelParams(ad); err != nil {
			return nil, err
		}
	case UniverseJava:
		if err := sf.setJavaParams(ad); err != nil {
			return nil, err
		}
	}

	// Set periodic expressions (all universes)
	if err := sf.setPeriodicExpressions(ad); err != nil {
		return nil, err
	}

	// Set signal handling
	if err := sf.setSignalHandling(ad); err != nil {
		return nil, err
	}

	// Set simple job expressions
	if err := sf.setSimpleJobExprs(ad); err != nil {
		return nil, err
	}

	// Set extended job expressions
	if err := sf.setExtendedJobExprs(ad); err != nil {
		return nil, err
	}

	// Set auto-generated attributes (should be last)
	if err := sf.setAutoAttributes(ad); err != nil {
		return nil, err
	}

	return ad, nil
}

// setExecutable sets the executable attribute
func (sf *SubmitFile) setExecutable(ad *classad.ClassAd) error {
	exec, ok := sf.cfg.Get("executable")
	if !ok {
		return fmt.Errorf("executable is required")
	}

	_ = ad.Set("Cmd", exec)
	return nil
}

// setArguments sets the arguments attribute
func (sf *SubmitFile) setArguments(ad *classad.ClassAd) error {
	// Check both "arguments" and "args"
	args, ok := sf.cfg.Get("arguments")
	if !ok {
		args, ok = sf.cfg.Get("args")
	}

	if ok && args != "" {
		_ = ad.Set("Args", args)
	} else {
		_ = ad.Set("Args", "")
	}

	return nil
}

// setEnvironment sets the environment attribute
func (sf *SubmitFile) setEnvironment(ad *classad.ClassAd) error {
	env, ok := sf.cfg.Get("environment")
	if !ok {
		env, ok = sf.cfg.Get("env")
	}

	if ok && env != "" {
		_ = ad.Set("Environment", env)
	}

	return nil
}

// setStandardFiles sets input, output, and error file attributes
func (sf *SubmitFile) setStandardFiles(ad *classad.ClassAd) error {
	// Input
	if input, ok := sf.cfg.Get("input"); ok {
		_ = ad.Set("In", input)
	}

	// Output
	if output, ok := sf.cfg.Get("output"); ok {
		_ = ad.Set("Out", output)
	}

	// Error
	if errFile, ok := sf.cfg.Get("error"); ok {
		_ = ad.Set("Err", errFile)
	}

	// Log
	if logFile, ok := sf.cfg.Get("log"); ok {
		_ = ad.Set("UserLog", logFile)
	}

	return nil
}

// setFileTransfer sets file transfer related attributes
func (sf *SubmitFile) setFileTransfer(ad *classad.ClassAd) error {
	// should_transfer_files
	if stf, ok := sf.cfg.Get("should_transfer_files"); ok {
		_ = ad.Set("ShouldTransferFiles", strings.ToUpper(stf))
	} else {
		// Default: YES
		_ = ad.Set("ShouldTransferFiles", "YES")
	}

	// when_to_transfer_output
	if wto, ok := sf.cfg.Get("when_to_transfer_output"); ok {
		_ = ad.Set("WhenToTransferOutput", strings.ToUpper(wto))
	} else {
		_ = ad.Set("WhenToTransferOutput", "ON_EXIT")
	}

	// transfer_input_files - parse comma-separated list
	if tif, ok := sf.cfg.Get("transfer_input_files"); ok {
		files := parseFileList(tif)
		if len(files) > 0 {
			// Join with commas for ClassAd string list format
			_ = ad.Set("TransferInputFiles", strings.Join(files, ","))
		}
	}

	// transfer_output_files - parse comma-separated list
	if tof, ok := sf.cfg.Get("transfer_output_files"); ok {
		files := parseFileList(tof)
		if len(files) > 0 {
			_ = ad.Set("TransferOutput", strings.Join(files, ","))
		}
	}

	// transfer_output_remaps - format: "name1=path1;name2=path2"
	if tor, ok := sf.cfg.Get("transfer_output_remaps"); ok {
		remaps := parseRemaps(tor)
		if len(remaps) > 0 {
			// Format as ClassAd string with semicolons
			var remapStrs []string
			for src, dst := range remaps {
				remapStrs = append(remapStrs, src+"="+dst)
			}
			_ = ad.Set("TransferOutputRemaps", strings.Join(remapStrs, ";"))
		}
	}

	// transfer_executable
	transferExec := true
	if te, ok := sf.cfg.Get("transfer_executable"); ok {
		transferExec = parseBool(te, true)
	}
	_ = ad.Set("TransferExecutable", transferExec)

	// encrypt_input_files - comma-separated list of files to encrypt
	if eif, ok := sf.cfg.Get("encrypt_input_files"); ok {
		files := parseFileList(eif)
		if len(files) > 0 {
			_ = ad.Set("EncryptInputFiles", strings.Join(files, ","))
		}
	}

	// encrypt_output_files - comma-separated list of files to encrypt
	if eof, ok := sf.cfg.Get("encrypt_output_files"); ok {
		files := parseFileList(eof)
		if len(files) > 0 {
			_ = ad.Set("EncryptOutputFiles", strings.Join(files, ","))
		}
	}

	// dont_encrypt_input_files - comma-separated list
	if deif, ok := sf.cfg.Get("dont_encrypt_input_files"); ok {
		files := parseFileList(deif)
		if len(files) > 0 {
			_ = ad.Set("DontEncryptInputFiles", strings.Join(files, ","))
		}
	}

	// dont_encrypt_output_files - comma-separated list
	if deof, ok := sf.cfg.Get("dont_encrypt_output_files"); ok {
		files := parseFileList(deof)
		if len(files) > 0 {
			_ = ad.Set("DontEncryptOutputFiles", strings.Join(files, ","))
		}
	}

	// transfer_plugins - semicolon-separated list
	if tp, ok := sf.cfg.Get("transfer_plugins"); ok {
		plugins := strings.Split(tp, ";")
		var cleanPlugins []string
		for _, p := range plugins {
			p = strings.TrimSpace(p)
			if p != "" {
				cleanPlugins = append(cleanPlugins, p)
			}
		}
		if len(cleanPlugins) > 0 {
			_ = ad.Set("TransferPlugins", strings.Join(cleanPlugins, ";"))
		}
	}

	// skip_filechecks - don't check if input files exist
	if sfc, ok := sf.cfg.Get("skip_filechecks"); ok {
		_ = ad.Set("SkipFileChecks", parseBool(sfc, false))
	}

	// preserve_relative_paths
	if prp, ok := sf.cfg.Get("preserve_relative_paths"); ok {
		_ = ad.Set("PreserveRelativePaths", parseBool(prp, false))
	}

	return nil
}

// setContainerSettings sets container/docker related attributes
func (sf *SubmitFile) setContainerSettings(ad *classad.ClassAd) error {
	// docker_image or container_image
	var containerImage string
	if img, ok := sf.cfg.Get("docker_image"); ok {
		containerImage = img
	} else if img, ok := sf.cfg.Get("container_image"); ok {
		containerImage = img
	}

	if containerImage != "" {
		_ = ad.Set("DockerImage", containerImage)
		// Also set container_image for newer HTCondor versions
		_ = ad.Set("ContainerImage", containerImage)
	}

	// docker_network_type or container_network
	if network, ok := sf.cfg.Get("docker_network_type"); ok {
		_ = ad.Set("DockerNetworkType", network)
	} else if network, ok := sf.cfg.Get("container_network"); ok {
		_ = ad.Set("DockerNetworkType", network)
	}

	// docker_volumes or container_volumes - comma-separated list
	if volumes, ok := sf.cfg.Get("docker_volumes"); ok {
		volList := parseFileList(volumes)
		if len(volList) > 0 {
			_ = ad.Set("DockerVolumes", strings.Join(volList, ","))
		}
	} else if volumes, ok := sf.cfg.Get("container_volumes"); ok {
		volList := parseFileList(volumes)
		if len(volList) > 0 {
			_ = ad.Set("DockerVolumes", strings.Join(volList, ","))
		}
	}

	// docker_pull_policy
	if policy, ok := sf.cfg.Get("docker_pull_policy"); ok {
		_ = ad.Set("DockerPullPolicy", policy)
	}

	// container_service_names - comma-separated list
	if services, ok := sf.cfg.Get("container_service_names"); ok {
		serviceList := parseFileList(services)
		if len(serviceList) > 0 {
			_ = ad.Set("ContainerServiceNames", strings.Join(serviceList, ","))
		}
	}

	// require_container - force use of container
	if rc, ok := sf.cfg.Get("require_container"); ok {
		_ = ad.Set("RequireContainer", parseBool(rc, false))
	}

	// container_target_dir - working directory inside container
	if targetDir, ok := sf.cfg.Get("container_target_dir"); ok {
		_ = ad.Set("ContainerTargetDir", targetDir)
	}

	// docker_mount_volumes or mount_under_scratch
	if mv, ok := sf.cfg.Get("docker_mount_volumes"); ok {
		_ = ad.Set("DockerMountVolumes", parseBool(mv, true))
	} else if mus, ok := sf.cfg.Get("mount_under_scratch"); ok {
		_ = ad.Set("MountUnderScratch", parseBool(mus, true))
	}

	// Additional docker-specific options
	if override, ok := sf.cfg.Get("docker_override_entrypoint"); ok {
		_ = ad.Set("DockerOverrideEntrypoint", parseBool(override, false))
	}

	// container_image_sha256
	if sha, ok := sf.cfg.Get("container_image_sha256"); ok {
		_ = ad.Set("ContainerImageSHA256", sha)
	}

	return nil
}

// setRequirements sets the Requirements expression
func (sf *SubmitFile) setRequirements(ad *classad.ClassAd) error {
	var reqParts []string

	// Start with user-specified requirements
	if req, ok := sf.cfg.Get("requirements"); ok {
		reqParts = append(reqParts, "("+req+")")
	}

	// Add TARGET.OpSys check for non-grid jobs
	if sf.universe != UniverseGrid {
		// Target type requirement - must be a machine (not another job, etc.)
		reqParts = append(reqParts, "(TARGET.Arch =!= UNDEFINED)")
		reqParts = append(reqParts, "(TARGET.OpSys =!= UNDEFINED)")
	}

	// Add TARGET.Disk check if we're transferring files
	if stf, ok := sf.cfg.Get("should_transfer_files"); ok {
		if strings.ToUpper(stf) == "YES" {
			reqParts = append(reqParts, "(TARGET.Disk >= RequestDisk)")
		}
	}

	// Add memory requirement check if specified
	if _, ok := sf.cfg.Get("request_memory"); ok {
		reqParts = append(reqParts, "(TARGET.Memory >= RequestMemory)")
	}

	// Add CPU requirement check if specified
	if _, ok := sf.cfg.Get("request_cpus"); ok {
		reqParts = append(reqParts, "(TARGET.Cpus >= RequestCpus)")
	}

	// Add GPU requirement check if specified
	if reqGpus, ok := sf.cfg.Get("request_gpus"); ok {
		if intGpus, err := parseInt(reqGpus); err == nil && intGpus > 0 {
			reqParts = append(reqParts, "(TARGET.Gpus >= RequestGpus)")
		}
	}

	// Add specific OpSys requirement if specified
	if reqOpsys, ok := sf.cfg.Get("request_opsys"); ok {
		reqParts = append(reqParts, fmt.Sprintf("(TARGET.OpSys == %q)", reqOpsys))
	}

	// Add specific Arch requirement if specified
	if reqArch, ok := sf.cfg.Get("request_arch"); ok {
		reqParts = append(reqParts, fmt.Sprintf("(TARGET.Arch == %q)", reqArch))
	}

	// Add container requirement if container image is specified
	if _, ok := sf.cfg.Get("docker_image"); ok {
		reqParts = append(reqParts, "(TARGET.HasDocker =?= true)")
	} else if _, ok := sf.cfg.Get("container_image"); ok {
		reqParts = append(reqParts, "(TARGET.HasSingularity =?= true || TARGET.HasApptainer =?= true)")
	}

	// Require container support if explicitly requested
	if rc, ok := sf.cfg.Get("require_container"); ok {
		if parseBool(rc, false) {
			reqParts = append(reqParts, "(TARGET.HasDocker =?= true || TARGET.HasSingularity =?= true || TARGET.HasApptainer =?= true)")
		}
	}

	// Add file system domain requirements
	if fsDomain, ok := sf.cfg.Get("file_system_domain"); ok {
		reqParts = append(reqParts, fmt.Sprintf("(TARGET.FileSystemDomain == %q)", fsDomain))
	}

	// Add HasFileTransfer requirement if needed
	if stf, ok := sf.cfg.Get("should_transfer_files"); ok {
		if strings.ToUpper(stf) == "YES" {
			reqParts = append(reqParts, "(TARGET.HasFileTransfer)")
		}
	}

	if len(reqParts) > 0 {
		requirements := strings.Join(reqParts, " && ")
		// Requirements is an expression, not a string - parse it
		reqExpr, err := classad.ParseExpr(requirements)
		if err != nil {
			return fmt.Errorf("failed to parse requirements expression: %w", err)
		}
		_ = ad.Set("Requirements", reqExpr)
	}

	return nil
}

// setResourceRequests sets resource request attributes
func (sf *SubmitFile) setResourceRequests(ad *classad.ClassAd) error {
	// Request CPUs (default: 1)
	cpus := 1
	if reqCpus, ok := sf.cfg.Get("request_cpus"); ok {
		if n, err := parseInt(reqCpus); err == nil {
			cpus = n
		}
	}
	_ = ad.Set("RequestCpus", cpus)

	// Request Memory in MB (default: 128)
	memory := 128
	if reqMem, ok := sf.cfg.Get("request_memory"); ok {
		if n, err := parseInt(reqMem); err == nil {
			memory = n
		}
	}
	_ = ad.Set("RequestMemory", memory)

	// Request Disk in KB (default: 1024)
	disk := 1024
	if reqDisk, ok := sf.cfg.Get("request_disk"); ok {
		if n, err := parseInt(reqDisk); err == nil {
			disk = n
		}
	}
	_ = ad.Set("RequestDisk", disk)

	// Request GPUs (default: 0)
	if reqGpus, ok := sf.cfg.Get("request_gpus"); ok {
		if n, err := parseInt(reqGpus); err == nil {
			_ = ad.Set("RequestGpus", n)
		}
	}

	// GPU memory per device (MB)
	if gpuMem, ok := sf.cfg.Get("request_gpu_memory"); ok {
		if n, err := parseInt(gpuMem); err == nil {
			_ = ad.Set("RequestGpuMemory", n)
		}
	}

	// Specific GPU properties
	if gpuProps, ok := sf.cfg.Get("require_gpus"); ok {
		_ = ad.Set("RequireGpus", gpuProps)
	}

	return nil
}

// setNotification sets notification preference
func (sf *SubmitFile) setNotification(ad *classad.ClassAd) error {
	notification := "NEVER"
	if notif, ok := sf.cfg.Get("notification"); ok {
		notification = strings.ToUpper(notif)
	}
	_ = ad.Set("EmailAttributes", notification)

	// Set email address if provided
	if email, ok := sf.cfg.Get("notify_user"); ok {
		_ = ad.Set("NotifyUser", email)
	}

	return nil
}

// setRank sets the rank expression
func (sf *SubmitFile) setRank(ad *classad.ClassAd) error {
	if rank, ok := sf.cfg.Get("rank"); ok {
		_ = ad.Set("Rank", rank)
	} else {
		// Default rank
		_ = ad.Set("Rank", 0.0)
	}
	return nil
}

// setOwnership sets owner and accounting attributes
func (sf *SubmitFile) setOwnership(ad *classad.ClassAd) error {
	// Owner - would typically come from authentication
	// For now, use a placeholder
	// _ = ad.Set("Owner", "unknown")

	// Accounting group
	if group, ok := sf.cfg.Get("accounting_group"); ok {
		_ = ad.Set("AccountingGroup", group)
	}

	// Accounting group user
	if user, ok := sf.cfg.Get("accounting_group_user"); ok {
		_ = ad.Set("AccountingGroupUser", user)
	}

	return nil
}

// setJobStatusControl sets job status and control attributes
func (sf *SubmitFile) setJobStatusControl(ad *classad.ClassAd) error {
	// hold - initial hold state
	if hold, ok := sf.cfg.Get("hold"); ok {
		if parseBool(hold, false) {
			_ = ad.Set("JobStatus", 5) // 5 = HELD
		}
	}

	// hold_reason - reason for initial hold
	if reason, ok := sf.cfg.Get("hold_reason"); ok {
		_ = ad.Set("HoldReason", reason)
		// Set release reason code if not already set
		if _, ok := sf.cfg.Get("hold_reason_code"); !ok {
			_ = ad.Set("HoldReasonCode", 1)
		}
	}

	// hold_reason_code
	if code, ok := sf.cfg.Get("hold_reason_code"); ok {
		if intCode, err := parseInt(code); err == nil {
			_ = ad.Set("HoldReasonCode", intCode)
		}
	}

	// hold_reason_subcode
	if subcode, ok := sf.cfg.Get("hold_reason_subcode"); ok {
		if intSubcode, err := parseInt(subcode); err == nil {
			_ = ad.Set("HoldReasonSubCode", intSubcode)
		}
	}

	// priority - user priority for job
	if priority, ok := sf.cfg.Get("priority"); ok {
		if intPriority, err := parseInt(priority); err == nil {
			_ = ad.Set("JobPrio", intPriority)
		}
	}

	// nice_user - reduce priority to be nice
	if niceUser, ok := sf.cfg.Get("nice_user"); ok {
		_ = ad.Set("NiceUser", parseBool(niceUser, false))
	}

	// max_job_retirement_time - time to allow for graceful shutdown
	if maxRetire, ok := sf.cfg.Get("max_job_retirement_time"); ok {
		if intRetire, err := parseInt(maxRetire); err == nil {
			_ = ad.Set("MaxJobRetirementTime", intRetire)
		}
	}

	// job_max_vacate_time - time for job to vacate before killing
	if maxVacate, ok := sf.cfg.Get("job_max_vacate_time"); ok {
		if intVacate, err := parseInt(maxVacate); err == nil {
			_ = ad.Set("JobMaxVacateTime", intVacate)
		}
	}

	// max_retries - number of times to retry on failure
	if maxRetries, ok := sf.cfg.Get("max_retries"); ok {
		if intRetries, err := parseInt(maxRetries); err == nil {
			_ = ad.Set("MaxRetries", intRetries)
		}
	}

	// retry_until - expression for when to stop retrying
	if retryUntil, ok := sf.cfg.Get("retry_until"); ok {
		_ = ad.Set("RetryUntil", retryUntil)
	}

	// success_exit_code - exit code(s) considered success
	if successCode, ok := sf.cfg.Get("success_exit_code"); ok {
		_ = ad.Set("SuccessExitCode", successCode)
	}

	// leave_in_queue - keep job in queue after completion
	if leaveInQueue, ok := sf.cfg.Get("leave_in_queue"); ok {
		_ = ad.Set("LeaveJobInQueue", parseBool(leaveInQueue, false))
	}

	// keep_claim_idle - keep claim after job completes
	if keepClaim, ok := sf.cfg.Get("keep_claim_idle"); ok {
		if intKeep, err := parseInt(keepClaim); err == nil {
			_ = ad.Set("KeepClaimIdle", intKeep)
		}
	}

	// job_lease_duration - how long schedd can keep job leased
	if leaseDuration, ok := sf.cfg.Get("job_lease_duration"); ok {
		if intLease, err := parseInt(leaseDuration); err == nil {
			_ = ad.Set("JobLeaseDuration", intLease)
		}
	}

	// concurrency_limits - resources this job needs
	if concLimits, ok := sf.cfg.Get("concurrency_limits"); ok {
		_ = ad.Set("ConcurrencyLimits", concLimits)
	}

	// concurrency_limits_expr - expression for concurrency limits
	if concExpr, ok := sf.cfg.Get("concurrency_limits_expr"); ok {
		_ = ad.Set("ConcurrencyLimitsExpr", concExpr)
	}

	return nil
}

// setCustomAttributes processes + or MY. prefixed attributes
func (sf *SubmitFile) setCustomAttributes(ad *classad.ClassAd) error {
	// Iterate through all submit file keys
	for _, key := range sf.cfg.Keys() {
		var attrName string
		isCustom := false

		// Check for + prefix (adds attribute to job ad)
		if strings.HasPrefix(key, "+") {
			attrName = strings.TrimPrefix(key, "+")
			isCustom = true
		} else if strings.HasPrefix(key, "MY.") {
			// MY. prefix adds attribute to job ad with MY. prefix
			attrName = key // Keep the MY. prefix
			isCustom = true
		}

		if !isCustom {
			continue
		}

		// Get the value
		value, ok := sf.cfg.Get(key)
		if !ok {
			continue
		}

		// Try to parse as different types
		// First, check if it's a boolean
		value = strings.TrimSpace(value)
		if strings.ToLower(value) == "true" || strings.ToLower(value) == "false" {
			_ = ad.Set(attrName, parseBool(value, false))
			continue
		}

		// Check if it's an integer
		if intVal, err := strconv.ParseInt(value, 10, 64); err == nil {
			_ = ad.Set(attrName, int(intVal))
			continue
		}

		// Check if it's a float
		if floatVal, err := strconv.ParseFloat(value, 64); err == nil {
			_ = ad.Set(attrName, floatVal)
			continue
		}

		// Check if it's a ClassAd expression (contains operators, parentheses, etc.)
		// For now, treat values with specific characters as expressions
		if strings.ContainsAny(value, "()&|=<>!") {
			// This is likely a ClassAd expression, store as string
			// The ClassAd library will parse it as an expression
			_ = ad.Set(attrName, value)
			continue
		}

		// Default to string
		_ = ad.Set(attrName, value)
	}

	return nil
}

// Helper functions

func parseBool(s string, def bool) bool {
	s = strings.ToLower(strings.TrimSpace(s))
	switch s {
	case "true", "yes", "1":
		return true
	case "false", "no", "0":
		return false
	default:
		return def
	}
}

func parseInt(s string) (int, error) {
	s = strings.TrimSpace(s)
	var n int
	_, err := fmt.Sscanf(s, "%d", &n)
	return n, err
}

// parseFileList parses a comma-separated list of files
// Handles whitespace and empty entries
func parseFileList(list string) []string {
	parts := strings.Split(list, ",")
	var files []string
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p != "" {
			files = append(files, p)
		}
	}
	return files
}

// parseRemaps parses transfer_output_remaps format: "name1=path1;name2=path2"
// Returns a map of source -> destination paths
func parseRemaps(remaps string) map[string]string {
	result := make(map[string]string)
	pairs := strings.Split(remaps, ";")
	for _, pair := range pairs {
		pair = strings.TrimSpace(pair)
		if pair == "" {
			continue
		}
		parts := strings.SplitN(pair, "=", 2)
		if len(parts) == 2 {
			src := strings.TrimSpace(parts[0])
			dst := strings.TrimSpace(parts[1])
			if src != "" && dst != "" {
				result[src] = dst
			}
		}
	}
	return result
}

// setGridParams sets grid universe specific parameters
//
//nolint:gocyclo // Complex function required for grid universe parameter handling
func (sf *SubmitFile) setGridParams(ad *classad.ClassAd) error {
	// grid_resource - Required for grid universe
	if gridResource, ok := sf.cfg.Get("grid_resource"); ok {
		_ = ad.Set("GridResource", gridResource)
	}

	// EC2 parameters
	if ec2AmiID, ok := sf.cfg.Get("ec2_ami_id"); ok {
		_ = ad.Set("EC2AmiID", ec2AmiID)
	}
	if ec2InstanceType, ok := sf.cfg.Get("ec2_instance_type"); ok {
		_ = ad.Set("EC2InstanceType", ec2InstanceType)
	}
	if ec2KeyPair, ok := sf.cfg.Get("ec2_keypair"); ok {
		_ = ad.Set("EC2KeyPair", ec2KeyPair)
	}
	if ec2KeyPairFile, ok := sf.cfg.Get("ec2_keypair_file"); ok {
		_ = ad.Set("EC2KeyPairFile", ec2KeyPairFile)
	}
	if ec2AccessKeyID, ok := sf.cfg.Get("ec2_access_key_id"); ok {
		_ = ad.Set("EC2AccessKeyId", ec2AccessKeyID)
	}
	if ec2SecretAccessKey, ok := sf.cfg.Get("ec2_secret_access_key"); ok {
		_ = ad.Set("EC2SecretAccessKey", ec2SecretAccessKey)
	}
	if ec2SecurityGroups, ok := sf.cfg.Get("ec2_security_groups"); ok {
		_ = ad.Set("EC2SecurityGroups", ec2SecurityGroups)
	}
	if ec2SecurityIDs, ok := sf.cfg.Get("ec2_security_ids"); ok {
		_ = ad.Set("EC2SecurityIDs", ec2SecurityIDs)
	}
	if ec2SpotPrice, ok := sf.cfg.Get("ec2_spot_price"); ok {
		_ = ad.Set("EC2SpotPrice", ec2SpotPrice)
	}
	if ec2UserData, ok := sf.cfg.Get("ec2_user_data"); ok {
		_ = ad.Set("EC2UserData", ec2UserData)
	}
	if ec2UserDataFile, ok := sf.cfg.Get("ec2_user_data_file"); ok {
		_ = ad.Set("EC2UserDataFile", ec2UserDataFile)
	}

	// GCE parameters
	if gceImage, ok := sf.cfg.Get("gce_image"); ok {
		_ = ad.Set("GceImage", gceImage)
	}
	if gceMachineType, ok := sf.cfg.Get("gce_machine_type"); ok {
		_ = ad.Set("GceMachineType", gceMachineType)
	}
	if gceAccount, ok := sf.cfg.Get("gce_account"); ok {
		_ = ad.Set("GceAccount", gceAccount)
	}
	if gceAuthFile, ok := sf.cfg.Get("gce_auth_file"); ok {
		_ = ad.Set("GceAuthFile", gceAuthFile)
	}
	if gceJSONFile, ok := sf.cfg.Get("gce_json_file"); ok {
		_ = ad.Set("GceJsonFile", gceJSONFile)
	}
	if gceMetadata, ok := sf.cfg.Get("gce_metadata"); ok {
		_ = ad.Set("GceMetadata", gceMetadata)
	}

	// Azure parameters
	if azureImage, ok := sf.cfg.Get("azure_image"); ok {
		_ = ad.Set("AzureImage", azureImage)
	}
	if azureSize, ok := sf.cfg.Get("azure_size"); ok {
		_ = ad.Set("AzureSize", azureSize)
	}
	if azureLocation, ok := sf.cfg.Get("azure_location"); ok {
		_ = ad.Set("AzureLocation", azureLocation)
	}
	if azureAuthFile, ok := sf.cfg.Get("azure_auth_file"); ok {
		_ = ad.Set("AzureAuthFile", azureAuthFile)
	}
	if azureAdminUsername, ok := sf.cfg.Get("azure_admin_username"); ok {
		_ = ad.Set("AzureAdminUsername", azureAdminUsername)
	}
	if azureAdminKey, ok := sf.cfg.Get("azure_admin_key"); ok {
		_ = ad.Set("AzureAdminKey", azureAdminKey)
	}

	// Batch system parameters (PBS, LSF, SGE, Slurm, etc.)
	if batchQueue, ok := sf.cfg.Get("batch_queue"); ok {
		_ = ad.Set("BatchQueue", batchQueue)
	}
	if batchProject, ok := sf.cfg.Get("batch_project"); ok {
		_ = ad.Set("BatchProject", batchProject)
	}
	if batchRuntime, ok := sf.cfg.Get("batch_runtime"); ok {
		if intRuntime, err := parseInt(batchRuntime); err == nil {
			_ = ad.Set("BatchRuntime", intRuntime)
		}
	}
	if batchExtraArgs, ok := sf.cfg.Get("batch_extra_submit_args"); ok {
		_ = ad.Set("BatchExtraSubmitArgs", batchExtraArgs)
	}

	// ARC parameters
	if arcRte, ok := sf.cfg.Get("arc_rte"); ok {
		_ = ad.Set("ArcRte", arcRte)
	}
	if arcResources, ok := sf.cfg.Get("arc_resources"); ok {
		_ = ad.Set("ArcResources", arcResources)
	}

	// Delegate credentials
	if delegateJobGSI, ok := sf.cfg.Get("delegate_job_gsi_credentials_lifetime"); ok {
		if intLifetime, err := parseInt(delegateJobGSI); err == nil {
			_ = ad.Set("DelegateJobGSICredentialsLifetime", intLifetime)
		}
	}

	return nil
}

// setVMParams sets VM universe specific parameters
func (sf *SubmitFile) setVMParams(ad *classad.ClassAd) error {
	// vm_type - Required: type of VM (kvm, xen, vmware)
	if vmType, ok := sf.cfg.Get("vm_type"); ok {
		_ = ad.Set("VM_Type", vmType)
	}

	// vm_memory - Memory for the VM in MB
	if vmMemory, ok := sf.cfg.Get("vm_memory"); ok {
		if intMem, err := parseInt(vmMemory); err == nil {
			_ = ad.Set("VM_Memory", intMem)
		}
	}

	// vm_disk - Disk space for VM
	if vmDisk, ok := sf.cfg.Get("vm_disk"); ok {
		_ = ad.Set("VM_Disk", vmDisk)
	}

	// vm_networking - Enable networking for VM
	if vmNet, ok := sf.cfg.Get("vm_networking"); ok {
		_ = ad.Set("VM_Networking", parseBool(vmNet, false))
	}

	// vm_networking_type - Type of networking (nat, bridge, none)
	if vmNetType, ok := sf.cfg.Get("vm_networking_type"); ok {
		_ = ad.Set("VM_NetworkingType", vmNetType)
	}

	// vm_macaddr - MAC address for VM
	if vmMac, ok := sf.cfg.Get("vm_macaddr"); ok {
		_ = ad.Set("VM_MACAddr", vmMac)
	}

	// vm_checkpoint - Enable checkpointing
	if vmCheckpoint, ok := sf.cfg.Get("vm_checkpoint"); ok {
		_ = ad.Set("VM_Checkpoint", parseBool(vmCheckpoint, false))
	}

	// vm_vcpus - Number of virtual CPUs
	if vmVCPUs, ok := sf.cfg.Get("vm_vcpus"); ok {
		if intVCPUs, err := parseInt(vmVCPUs); err == nil {
			_ = ad.Set("VM_VCPUs", intVCPUs)
		}
	}

	// xen_kernel - Xen kernel image
	if xenKernel, ok := sf.cfg.Get("xen_kernel"); ok {
		_ = ad.Set("Xen_Kernel", xenKernel)
	}

	// xen_initrd - Xen initial ramdisk
	if xenInitrd, ok := sf.cfg.Get("xen_initrd"); ok {
		_ = ad.Set("Xen_Initrd", xenInitrd)
	}

	// xen_root - Xen root device
	if xenRoot, ok := sf.cfg.Get("xen_root"); ok {
		_ = ad.Set("Xen_Root", xenRoot)
	}

	// xen_kernel_params - Xen kernel parameters
	if xenParams, ok := sf.cfg.Get("xen_kernel_params"); ok {
		_ = ad.Set("Xen_KernelParams", xenParams)
	}

	// vmware_dir - VMware working directory
	if vmwareDir, ok := sf.cfg.Get("vmware_dir"); ok {
		_ = ad.Set("VMWARE_Dir", vmwareDir)
	}

	// vmware_snapshot_disk - Use snapshot disk
	if vmwareSnapshot, ok := sf.cfg.Get("vmware_snapshot_disk"); ok {
		_ = ad.Set("VMWARE_SnapshotDisk", parseBool(vmwareSnapshot, false))
	}

	// vmware_should_transfer_files - Transfer files
	if vmwareTransfer, ok := sf.cfg.Get("vmware_should_transfer_files"); ok {
		_ = ad.Set("VMWARE_ShouldTransferFiles", parseBool(vmwareTransfer, true))
	}

	return nil
}

// setParallelParams sets parallel/MPI universe specific parameters
func (sf *SubmitFile) setParallelParams(ad *classad.ClassAd) error {
	// machine_count - Required: number of machines/nodes needed
	if machineCount, ok := sf.cfg.Get("machine_count"); ok {
		if intCount, err := parseInt(machineCount); err == nil {
			_ = ad.Set("MachineCount", intCount)
		}
	}

	// request_cpus for parallel jobs means CPUs per node
	// This is already handled by setResourceRequests, but we may need special handling

	return nil
}

// setJavaParams sets Java universe specific parameters
func (sf *SubmitFile) setJavaParams(ad *classad.ClassAd) error {
	// jar_files - JAR files to include
	if jarFiles, ok := sf.cfg.Get("jar_files"); ok {
		_ = ad.Set("JarFiles", jarFiles)
	}

	// java_vm_args - Arguments for the JVM
	if javaVMArgs, ok := sf.cfg.Get("java_vm_args"); ok {
		_ = ad.Set("JavaVMArgs", javaVMArgs)
	}

	// For Java universe, the "executable" is actually the main class
	// The actual executable is the JVM, which HTCondor provides
	// We may need to transform Cmd to JavaMainClass

	return nil
}

// setPeriodicExpressions sets periodic hold/remove/release expressions
func (sf *SubmitFile) setPeriodicExpressions(ad *classad.ClassAd) error {
	// periodic_hold - Expression to periodically hold job
	if periodicHold, ok := sf.cfg.Get("periodic_hold"); ok {
		_ = ad.Set("PeriodicHold", periodicHold)
	}

	// periodic_hold_reason - Reason string when periodic hold triggers
	if holdReason, ok := sf.cfg.Get("periodic_hold_reason"); ok {
		_ = ad.Set("PeriodicHoldReason", holdReason)
	}

	// periodic_hold_subcode - Subcode when periodic hold triggers
	if holdSubcode, ok := sf.cfg.Get("periodic_hold_subcode"); ok {
		if intSubcode, err := parseInt(holdSubcode); err == nil {
			_ = ad.Set("PeriodicHoldSubCode", intSubcode)
		}
	}

	// periodic_release - Expression to periodically release held job
	if periodicRelease, ok := sf.cfg.Get("periodic_release"); ok {
		_ = ad.Set("PeriodicRelease", periodicRelease)
	}

	// periodic_remove - Expression to periodically remove job
	if periodicRemove, ok := sf.cfg.Get("periodic_remove"); ok {
		_ = ad.Set("PeriodicRemove", periodicRemove)
	}

	// on_exit_hold - Hold job based on exit condition
	if onExitHold, ok := sf.cfg.Get("on_exit_hold"); ok {
		_ = ad.Set("OnExitHold", onExitHold)
	}

	// on_exit_hold_reason - Reason for on_exit hold
	if onExitHoldReason, ok := sf.cfg.Get("on_exit_hold_reason"); ok {
		_ = ad.Set("OnExitHoldReason", onExitHoldReason)
	}

	// on_exit_hold_subcode - Subcode for on_exit hold
	if onExitHoldSubcode, ok := sf.cfg.Get("on_exit_hold_subcode"); ok {
		if intSubcode, err := parseInt(onExitHoldSubcode); err == nil {
			_ = ad.Set("OnExitHoldSubCode", intSubcode)
		}
	}

	// on_exit_remove - Remove job based on exit condition
	if onExitRemove, ok := sf.cfg.Get("on_exit_remove"); ok {
		_ = ad.Set("OnExitRemove", onExitRemove)
	}

	// cron_* parameters for job deferral
	if cronMinute, ok := sf.cfg.Get("cron_minute"); ok {
		_ = ad.Set("CronMinute", cronMinute)
	}
	if cronHour, ok := sf.cfg.Get("cron_hour"); ok {
		_ = ad.Set("CronHour", cronHour)
	}
	if cronDayOfMonth, ok := sf.cfg.Get("cron_day_of_month"); ok {
		_ = ad.Set("CronDayOfMonth", cronDayOfMonth)
	}
	if cronMonth, ok := sf.cfg.Get("cron_month"); ok {
		_ = ad.Set("CronMonth", cronMonth)
	}
	if cronDayOfWeek, ok := sf.cfg.Get("cron_day_of_week"); ok {
		_ = ad.Set("CronDayOfWeek", cronDayOfWeek)
	}
	if cronPrepTime, ok := sf.cfg.Get("cron_prep_time"); ok {
		if intPrepTime, err := parseInt(cronPrepTime); err == nil {
			_ = ad.Set("CronPrepTime", intPrepTime)
		}
	}
	if cronWindow, ok := sf.cfg.Get("cron_window"); ok {
		if intWindow, err := parseInt(cronWindow); err == nil {
			_ = ad.Set("CronWindow", intWindow)
		}
	}

	// deferral_time - Defer job start until specified time
	if deferralTime, ok := sf.cfg.Get("deferral_time"); ok {
		if intTime, err := parseInt(deferralTime); err == nil {
			_ = ad.Set("DeferralTime", intTime)
		}
	}

	// deferral_window - Time window for deferred job
	if deferralWindow, ok := sf.cfg.Get("deferral_window"); ok {
		if intWindow, err := parseInt(deferralWindow); err == nil {
			_ = ad.Set("DeferralWindow", intWindow)
		}
	}

	// deferral_prep_time - Preparation time before deferral
	if deferralPrepTime, ok := sf.cfg.Get("deferral_prep_time"); ok {
		if intPrepTime, err := parseInt(deferralPrepTime); err == nil {
			_ = ad.Set("DeferralPrepTime", intPrepTime)
		}
	}

	return nil
}

// setAutoAttributes sets auto-generated attributes
func (sf *SubmitFile) setAutoAttributes(ad *classad.ClassAd) error {
	// IWD (Initial Working Directory) - defaults to submit directory
	// In a real implementation, this would be the directory where condor_submit is run
	// For now, we'll only set it if explicitly specified
	if iwd, ok := sf.cfg.Get("initialdir"); ok {
		_ = ad.Set("Iwd", iwd)
	}

	// Owner - the user submitting the job
	// This would typically come from the authenticated user
	if owner, ok := sf.cfg.Get("owner"); ok {
		_ = ad.Set("Owner", owner)
	}

	// QDate - Time job was submitted (in Unix epoch seconds)
	// We'll set this when actually submitting
	// For now, just note that it should be set

	// CompletionDate - Time job completed
	// This is set by the schedd, not by us

	// JobStartDate - Time job started executing
	// This is set by the startd/schedd, not by us

	// EnteredCurrentStatus - Time job entered current status
	// This is managed by the schedd

	// JobCurrentStartDate - Time of most recent start
	// This is managed by the schedd

	// CurrentHosts - Machines currently running the job
	// This is managed by the schedd

	// NumJobStarts - Number of times job has started
	// Initialize to 0
	_ = ad.Set("NumJobStarts", 0)

	// NumRestarts - Number of times job has been restarted
	// Initialize to 0
	_ = ad.Set("NumRestarts", 0)

	// NumSystemHolds - Number of times placed on hold by system
	// Initialize to 0
	_ = ad.Set("NumSystemHolds", 0)

	// JobRunCount - Number of times job has run
	// Initialize to 0
	_ = ad.Set("JobRunCount", 0)

	// TransferInput - Set to true if input files are specified and streaming is disabled
	// This should be true when transfer_input_files is specified
	if tif, ok := sf.cfg.Get("transfer_input_files"); ok {
		files := parseFileList(tif)
		if len(files) > 0 {
			_ = ad.Set("TransferInput", true)
		}
	}

	return nil
}

// Submit submits the jobs from this submit file
// Returns the cluster ID and number of procs created
func (sf *SubmitFile) Submit(clusterID int) (*SubmitResult, error) {
	result := &SubmitResult{
		ClusterID: clusterID,
		NumProcs:  sf.queueCount,
		ProcAds:   make([]*classad.ClassAd, 0, sf.queueCount),
	}

	// Iterate through queue items to create job ads
	proc := 0
	for sf.queueIterator.Next() {
		queueVars := sf.queueIterator.Values()

		jobID := JobID{Cluster: clusterID, Proc: proc}
		procAd, err := sf.MakeJobAd(jobID, queueVars)
		if err != nil {
			return nil, fmt.Errorf("failed to create proc %d ad: %w", proc, err)
		}

		if proc == 0 {
			result.ClusterAd = procAd
		}
		result.ProcAds = append(result.ProcAds, procAd)
		proc++
	}

	return result, nil
}

// pushMacroContext sets up live macros for job ad creation
// These are HTCondor-specific macros that change with each job/proc
func (sf *SubmitFile) pushMacroContext(jobID JobID, queueVars map[string]string) {
	// Set standard HTCondor submit-time macros
	// These are "live" values that change for each proc
	sf.cfg.Set("Cluster", strconv.Itoa(jobID.Cluster))
	sf.cfg.Set("Process", strconv.Itoa(jobID.Proc))
	sf.cfg.Set("ProcId", strconv.Itoa(jobID.Proc))       // Alias for Process
	sf.cfg.Set("ClusterId", strconv.Itoa(jobID.Cluster)) // Alias for Cluster
	sf.cfg.Set("Node", strconv.Itoa(jobID.Proc))         // Alias for Process (parallel universe)

	// Set queue-specific macros
	for varName, varValue := range queueVars {
		sf.cfg.Set(varName, varValue)
	}

	// Set Item, Step, Row if they're in queueVars
	// These are used with queue from/in statements
	if itemIndex, ok := queueVars["ItemIndex"]; ok {
		sf.cfg.Set("ItemIndex", itemIndex)
		sf.cfg.Set("Item", itemIndex) // Alias for ItemIndex
	} else {
		// If not in queue vars, default to process ID
		sf.cfg.Set("ItemIndex", strconv.Itoa(jobID.Proc))
		sf.cfg.Set("Item", strconv.Itoa(jobID.Proc))
	}

	if step, ok := queueVars["Step"]; ok {
		sf.cfg.Set("Step", step)
	} else {
		sf.cfg.Set("Step", strconv.Itoa(jobID.Proc))
	}

	if row, ok := queueVars["Row"]; ok {
		sf.cfg.Set("Row", row)
	} else {
		sf.cfg.Set("Row", strconv.Itoa(jobID.Proc))
	}
}

// popMacroContext cleans up after job ad creation
// Note: In current implementation, we don't need to restore values
// because each Submit() call gets fresh macro values
func (sf *SubmitFile) popMacroContext() {
	// Currently a no-op since we don't cache and restore
	// In a full implementation, this would restore saved values
}

// MakeClusterAd creates a cluster ad with common attributes for all jobs
// This is part of late materialization - the cluster ad serves as a template
func (sf *SubmitFile) MakeClusterAd(clusterID int) (*classad.ClassAd, error) {
	// Create a cluster ad using ProcId = -1 (HTCondor convention)
	clusterJobID := JobID{Cluster: clusterID, Proc: -1}

	// For late materialization, we create the first proc ad and use it as template
	// In true late materialization, only common attributes go in cluster ad
	// but for simplicity, we'll create a full ad with Proc 0
	return sf.MakeJobAd(clusterJobID, map[string]string{})
}

// MakeProcAd creates a proc-specific ad given a cluster ad template
// This is used in late materialization to create individual proc ads efficiently
func (sf *SubmitFile) MakeProcAd(clusterID int, procID int, queueVars map[string]string) (*classad.ClassAd, error) {
	jobID := JobID{Cluster: clusterID, Proc: procID}
	return sf.MakeJobAd(jobID, queueVars)
}

// SubmitLate performs late materialization submission
// This creates a cluster ad template and individual proc ads with only differing attributes
// This is more efficient for large job submissions
func (sf *SubmitFile) SubmitLate(clusterID int) (*SubmitResult, error) {
	result := &SubmitResult{
		ClusterID: clusterID,
		NumProcs:  sf.queueCount,
		ProcAds:   make([]*classad.ClassAd, 0, sf.queueCount),
	}

	// Create cluster ad (template for all procs)
	// For now, we use proc 0 as the cluster ad template
	proc := 0
	sf.queueIterator.Next()
	queueVars := sf.queueIterator.Values()

	clusterAd, err := sf.MakeJobAd(JobID{Cluster: clusterID, Proc: 0}, queueVars)
	if err != nil {
		return nil, fmt.Errorf("failed to create cluster ad: %w", err)
	}
	result.ClusterAd = clusterAd
	result.ProcAds = append(result.ProcAds, clusterAd)
	proc++

	// Create remaining proc ads
	for sf.queueIterator.Next() {
		queueVars := sf.queueIterator.Values()

		procAd, err := sf.MakeProcAd(clusterID, proc, queueVars)
		if err != nil {
			return nil, fmt.Errorf("failed to create proc %d ad: %w", proc, err)
		}

		result.ProcAds = append(result.ProcAds, procAd)
		proc++
	}

	return result, nil
}

// expandSubmitMacros expands HTCondor submit-specific macros in a string
// This is a helper for explicit macro expansion when needed
func (sf *SubmitFile) expandSubmitMacros(value string, jobID JobID, queueVars map[string]string) string {
	// Common submit-time macros that might not be in config
	macros := map[string]string{
		"Cluster":   strconv.Itoa(jobID.Cluster),
		"ClusterId": strconv.Itoa(jobID.Cluster),
		"Process":   strconv.Itoa(jobID.Proc),
		"ProcId":    strconv.Itoa(jobID.Proc),
		"Node":      strconv.Itoa(jobID.Proc),
	}

	// Add queue variables
	for k, v := range queueVars {
		macros[k] = v
	}

	// Simple macro expansion (real implementation would use config.expandMacros)
	result := value
	for macro, replacement := range macros {
		result = strings.ReplaceAll(result, "$("+macro+")", replacement)
	}

	return result
}

// setSignalHandling sets signal handling attributes for the job
func (sf *SubmitFile) setSignalHandling(ad *classad.ClassAd) error {
	// kill_sig - signal to use when killing job
	if killSig, ok := sf.cfg.Get("kill_sig"); ok {
		// Can be a signal name (SIGTERM) or number (15)
		if intSig, err := parseInt(killSig); err == nil {
			_ = ad.Set("KillSig", intSig)
		} else {
			// Try as string (signal name)
			_ = ad.Set("KillSig", killSig)
		}
	}

	// remove_kill_sig - signal to use when removing job
	if removeSig, ok := sf.cfg.Get("remove_kill_sig"); ok {
		if intSig, err := parseInt(removeSig); err == nil {
			_ = ad.Set("RemoveKillSig", intSig)
		} else {
			_ = ad.Set("RemoveKillSig", removeSig)
		}
	}

	// kill_sig_timeout - how long to wait after kill signal before using SIGKILL
	if killTimeout, ok := sf.cfg.Get("kill_sig_timeout"); ok {
		if intTimeout, err := parseInt(killTimeout); err == nil {
			_ = ad.Set("KillSigTimeout", intTimeout)
		}
	}

	return nil
}

// setSimpleJobExprs sets simple job expression attributes
// These are standard HTCondor job attributes that are commonly used
func (sf *SubmitFile) setSimpleJobExprs(ad *classad.ClassAd) error {
	// image_size - disk image size (often auto-calculated)
	if imageSize, ok := sf.cfg.Get("image_size"); ok {
		if intSize, err := parseInt(imageSize); err == nil {
			_ = ad.Set("ImageSize", intSize)
		}
	}

	// executable_size - size of executable
	if execSize, ok := sf.cfg.Get("executable_size"); ok {
		if intSize, err := parseInt(execSize); err == nil {
			_ = ad.Set("ExecutableSize", intSize)
		}
	}

	// disk_usage - disk usage
	if diskUsage, ok := sf.cfg.Get("disk_usage"); ok {
		if intUsage, err := parseInt(diskUsage); err == nil {
			_ = ad.Set("DiskUsage", intUsage)
		}
	}

	// remote_initial_dir - initial directory on remote machine
	if remoteDir, ok := sf.cfg.Get("remote_initialdir"); ok {
		_ = ad.Set("RemoteInitialDir", remoteDir)
	}

	// JobNotification - when to send email
	if notification, ok := sf.cfg.Get("notification"); ok {
		// Convert notification string to integer code
		notifCode := 0
		switch strings.ToLower(notification) {
		case "always":
			notifCode = 1
		case "complete":
			notifCode = 2
		case "error":
			notifCode = 3
		case "never":
			notifCode = 0
		default:
			// Try parsing as integer
			if intNotif, err := parseInt(notification); err == nil {
				notifCode = intNotif
			}
		}
		_ = ad.Set("JobNotification", notifCode)
	}

	// WantRemoteIO - request remote I/O
	if wantIO, ok := sf.cfg.Get("want_remote_io"); ok {
		_ = ad.Set("WantRemoteIO", parseBool(wantIO, false))
	}

	// WantRemoteSyscalls - request remote system calls
	if wantSyscalls, ok := sf.cfg.Get("want_remote_syscalls"); ok {
		_ = ad.Set("WantRemoteSyscalls", parseBool(wantSyscalls, false))
	}

	// StreamInput - stream stdin
	if streamIn, ok := sf.cfg.Get("stream_input"); ok {
		_ = ad.Set("StreamInput", parseBool(streamIn, false))
	}

	// StreamOutput - stream stdout
	if streamOut, ok := sf.cfg.Get("stream_output"); ok {
		_ = ad.Set("StreamOutput", parseBool(streamOut, false))
	}

	// StreamError - stream stderr
	if streamErr, ok := sf.cfg.Get("stream_error"); ok {
		_ = ad.Set("StreamError", parseBool(streamErr, false))
	}

	// JobDescription - human-readable description of job
	if desc, ok := sf.cfg.Get("description"); ok {
		_ = ad.Set("JobDescription", desc)
	}

	// copy_to_spool - copy files to spool directory
	if copyToSpool, ok := sf.cfg.Get("copy_to_spool"); ok {
		_ = ad.Set("CopyToSpool", parseBool(copyToSpool, false))
	}

	// buffer_size - I/O buffer size
	if bufSize, ok := sf.cfg.Get("buffer_size"); ok {
		if intSize, err := parseInt(bufSize); err == nil {
			_ = ad.Set("BufferSize", intSize)
		}
	}

	// buffer_block_size - I/O buffer block size
	if blockSize, ok := sf.cfg.Get("buffer_block_size"); ok {
		if intSize, err := parseInt(blockSize); err == nil {
			_ = ad.Set("BufferBlockSize", intSize)
		}
	}

	// JobBatchName - batch name for grouping jobs
	if batchName, ok := sf.cfg.Get("batch_name"); ok {
		_ = ad.Set("JobBatchName", batchName)
	}

	// StackSize - stack size in KB
	if stackSize, ok := sf.cfg.Get("stack_size"); ok {
		if intSize, err := parseInt(stackSize); err == nil {
			_ = ad.Set("StackSize", intSize)
		}
	}

	return nil
}

// setExtendedJobExprs sets extended job expression attributes
// These are less common attributes that provide additional job control
//
//nolint:gocyclo // Complex function required for extended job expression handling
func (sf *SubmitFile) setExtendedJobExprs(ad *classad.ClassAd) error {
	// append_files - files to append instead of truncate
	if appendFiles, ok := sf.cfg.Get("append_files"); ok {
		_ = ad.Set("AppendFiles", appendFiles)
	}

	// compress_files - files to compress before transfer
	if compressFiles, ok := sf.cfg.Get("compress_files"); ok {
		_ = ad.Set("CompressFiles", compressFiles)
	}

	// fetch_files - files to fetch from submit machine
	if fetchFiles, ok := sf.cfg.Get("fetch_files"); ok {
		_ = ad.Set("FetchFiles", fetchFiles)
	}

	// local_files - files that should not be transferred
	if localFiles, ok := sf.cfg.Get("local_files"); ok {
		_ = ad.Set("LocalFiles", localFiles)
	}

	// file_remaps - remap file paths
	if fileRemaps, ok := sf.cfg.Get("file_remaps"); ok {
		_ = ad.Set("FileRemaps", fileRemaps)
	}

	// want_graceful_removal - request graceful removal
	if wantGraceful, ok := sf.cfg.Get("want_graceful_removal"); ok {
		_ = ad.Set("WantGracefulRemoval", parseBool(wantGraceful, false))
	}

	// job_max_vacate_time - max time for vacating (already in setJobStatusControl, but keep for completeness)
	if maxVacate, ok := sf.cfg.Get("job_max_vacate_time"); ok {
		if intVacate, err := parseInt(maxVacate); err == nil {
			_ = ad.Set("JobMaxVacateTime", intVacate)
		}
	}

	// run_as_owner - run as the submitting user
	if runAsOwner, ok := sf.cfg.Get("run_as_owner"); ok {
		_ = ad.Set("RunAsOwner", parseBool(runAsOwner, false))
	}

	// load_profile - load user profile before running
	if loadProfile, ok := sf.cfg.Get("load_profile"); ok {
		_ = ad.Set("LoadProfile", parseBool(loadProfile, false))
	}

	// JobAdInformationAttrs - attributes to include in job ad information
	if infoAttrs, ok := sf.cfg.Get("job_ad_information_attrs"); ok {
		_ = ad.Set("JobAdInformationAttrs", infoAttrs)
	}

	// want_io_proxy - request I/O proxy
	if wantProxy, ok := sf.cfg.Get("want_io_proxy"); ok {
		_ = ad.Set("WantIOProxy", parseBool(wantProxy, false))
	}

	// job_machine_attrs - machine attributes to record in job ad
	if machAttrs, ok := sf.cfg.Get("job_machine_attrs"); ok {
		_ = ad.Set("JobMachineAttrs", machAttrs)
	}

	// job_machine_attrs_history_length - how many machine attrs to keep
	if histLen, ok := sf.cfg.Get("job_machine_attrs_history_length"); ok {
		if intLen, err := parseInt(histLen); err == nil {
			_ = ad.Set("JobMachineAttrsHistoryLength", intLen)
		}
	}

	// ec2_tag_names - EC2 tags to apply (grid universe)
	if ec2Tags, ok := sf.cfg.Get("ec2_tag_names"); ok {
		_ = ad.Set("EC2TagNames", ec2Tags)
	}

	// allowed_execute_duration - maximum execution time
	if maxDuration, ok := sf.cfg.Get("allowed_execute_duration"); ok {
		if intDuration, err := parseInt(maxDuration); err == nil {
			_ = ad.Set("AllowedExecuteDuration", intDuration)
		}
	}

	// allowed_job_duration - maximum total job duration
	if maxJobDuration, ok := sf.cfg.Get("allowed_job_duration"); ok {
		if intDuration, err := parseInt(maxJobDuration); err == nil {
			_ = ad.Set("AllowedJobDuration", intDuration)
		}
	}

	// checkpoint_exit_code - exit code that indicates checkpoint
	if checkpointCode, ok := sf.cfg.Get("checkpoint_exit_code"); ok {
		if intCode, err := parseInt(checkpointCode); err == nil {
			_ = ad.Set("CheckpointExitCode", intCode)
		}
	}

	// want_checkpoint - request checkpoint capability
	if wantCheckpoint, ok := sf.cfg.Get("want_checkpoint"); ok {
		_ = ad.Set("WantCheckpoint", parseBool(wantCheckpoint, false))
	}

	// max_transfer_input_mb - maximum input file transfer size in MB
	if maxInputMB, ok := sf.cfg.Get("max_transfer_input_mb"); ok {
		if intMB, err := parseInt(maxInputMB); err == nil {
			_ = ad.Set("MaxTransferInputMB", intMB)
		}
	}

	// max_transfer_output_mb - maximum output file transfer size in MB
	if maxOutputMB, ok := sf.cfg.Get("max_transfer_output_mb"); ok {
		if intMB, err := parseInt(maxOutputMB); err == nil {
			_ = ad.Set("MaxTransferOutputMB", intMB)
		}
	}

	// preserve_relative_executable - keep relative path for executable
	if preserveExec, ok := sf.cfg.Get("preserve_relative_executable"); ok {
		_ = ad.Set("PreserveRelativeExecutable", parseBool(preserveExec, false))
	}

	// remote_nodenumber - for MPI jobs, the node number
	if nodeNum, ok := sf.cfg.Get("remote_nodenumber"); ok {
		if intNum, err := parseInt(nodeNum); err == nil {
			_ = ad.Set("RemoteNodeNumber", intNum)
		}
	}

	// KeystoreFile, KeystoreAlias, KeystorePassphraseFile - Java universe security
	if keystore, ok := sf.cfg.Get("keystore_file"); ok {
		_ = ad.Set("KeystoreFile", keystore)
	}
	if keystoreAlias, ok := sf.cfg.Get("keystore_alias"); ok {
		_ = ad.Set("KeystoreAlias", keystoreAlias)
	}
	if keystorePass, ok := sf.cfg.Get("keystore_passphrase_file"); ok {
		_ = ad.Set("KeystorePassphraseFile", keystorePass)
	}

	return nil
}
