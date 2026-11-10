package htcondor

// SubmitBehavior selects the choices condor_submit makes differently in
// different HTCondor releases.
//
// The job ad a submit file produces is not fixed: HTCondor changes what
// condor_submit writes, and a job ad built for one release can differ from
// the one the next release builds out of the same file. This library has to
// be able to produce either, because it submits to whatever access point the
// caller has -- and because the differential fuzzer compares it against a
// pinned HTCondor in pull-request CI and against HTCondor's main branch every
// night, so both shapes have to be reachable from one tree.
//
// The zero value is the behavior of the releases this library has always
// emulated, so a caller that says nothing keeps the job ad it has been
// getting. Each field names the upstream change it follows and the first
// release that carries it.
//
// SubmitBehaviorFor is how to set one: it maps an HTCondor release to the
// behavior of that release's condor_submit, including a version string read
// straight from a schedd ad. The fields below say what each choice IS, which
// is what makes them reviewable and testable, but choosing a correct
// combination by hand means knowing which upstream change went into which
// release -- so they are the vocabulary and SubmitBehaviorFor is the
// sentence.
//
// Setting a field directly is still allowed, and is the way to follow one
// change without the others.
type SubmitBehavior struct {
	// OmitExitStatus leaves ExitStatus out of the job ad.
	//
	// condor_submit wrote `ExitStatus = 0` into every job ad until
	// HTCONDOR-4020 removed it. The schedd and the shadow own the
	// attribute once the job runs; what the submitted ad carries decides
	// only what reads of a job that has NOT run yet see.
	OmitExitStatus bool

	// OmitZeroedRunTimeCounters leaves RemoteUserCpu, RemoteSysCpu,
	// LastSuspensionTime and ExitBySignal out of the job ad.
	//
	// HTCONDOR-3998 stopped initializing them in the cluster ad. It left
	// RemoteWallClockTime and the Cumulative* counters in place, so this
	// omits exactly the four it removed and not the family they belong to.
	//
	// The ones it leaves out read as UNDEFINED until the job runs, which
	// is not the same as zero: a constraint that should hold for a job
	// that has not started matches nothing, and arithmetic over one is
	// neither true nor false. See setSubmitTimeDefaults.
	OmitZeroedRunTimeCounters bool

	// OmitVanillaDiskClause leaves the automatic disk clause out of a
	// vanilla job's Requirements.
	//
	// condor_submit added `TARGET.Disk >= RequestDisk` so a job would only
	// match a machine with room for it. Common-files transfer made that
	// wrong -- RequestDisk no longer describes what the job puts on the
	// slot -- and the clause was first guarded by a startd version check
	// and then, by HTCONDOR-3932, dropped for vanilla jobs entirely.
	//
	// Only vanilla. Every other universe still gets the clause.
	OmitVanillaDiskClause bool

	// OmitTransferVersionCheck leaves the `versioncmp(..., "8.9.7") >= 0`
	// clause out of Requirements.
	//
	// condor_submit added it for a job using checkpoint files, relative
	// path preservation or `when_to_transfer_output = ON_SUCCESS`, none of
	// which a pre-8.9.7 startd understands. HTCONDOR-3932 removed it:
	// nothing that old is still running, and the clause excluded any
	// machine whose CondorVersion it could not parse.
	OmitTransferVersionCheck bool

	// OmitLocalAndSchedulerMachineChecks leaves Arch, OpSys and the disk
	// clause out of Requirements for the local and scheduler universes.
	//
	// Those jobs are run by the schedd rather than matched to a startd, so
	// the clauses describe a machine that is never consulted -- and the
	// schedd's own ad does not advertise what they ask for. HTCONDOR-3926
	// stopped emitting them, which also means a job with nothing else to
	// say gets `Requirements = true` rather than an expression about a
	// machine it will never match.
	OmitLocalAndSchedulerMachineChecks bool

	// OmitLocalAndSchedulerResourceDefaults applies no
	// JOB_DEFAULT_REQUEST{CPUS,MEMORY,DISK,GPUS} to a local- or
	// scheduler-universe job.
	//
	// HTCONDOR-3926 turned UseDefaultResourceParams off for them, for the
	// same reason: no startd ever reads the request, so a default only
	// puts a number in the ad that nothing acts on.
	OmitLocalAndSchedulerResourceDefaults bool

	// OmitRemoteIOKeywords stops the standard-universe RemoteIO submit
	// commands from writing anything.
	//
	// HTCONDOR-3998 removed the RemoteIO code and its eight keywords:
	// buffer_size, buffer_files, buffer_block_size, file_remaps,
	// fetch_files, compress_files, append_files and local_files. Standard
	// universe has been gone for years and nothing read the attributes.
	//
	// The commands are still ACCEPTED, because an unrecognized submit
	// command is an ordinary macro rather than an error, which is what a
	// newer condor_submit does with them too. They simply write no job
	// attribute.
	OmitRemoteIOKeywords bool

	// OmitContainerIsCommonAttr stops container_is_common from writing the
	// ContainerIsCommon job attribute.
	//
	// HTCONDOR-3932 kept the submit command and moved it to the container
	// handling with no attribute of its own, so the value steers how the
	// submission is built without appearing in the ad under that name.
	OmitContainerIsCommonAttr bool

	// CommonContainerVanillaOnly decides a container image is COMMON
	// only for a vanilla job.
	//
	// HTCONDOR-4003 narrowed it. container_is_common and the
	// CONTAINER_IMAGES_COMMON_BY_DEFAULT and
	// CONTAINER_REGEX_COMMON_BY_DEFAULT knobs were read in every
	// universe, so a local-universe job asking for a common image got
	// CommonInputCatalogs and no image in its input list -- naming a
	// cached image on an execute node that a local job never reaches.
	// The whole decision is now skipped outside vanilla, and the image
	// is transferred like any other input file.
	//
	// Vanilla covers the container and docker universes, which are
	// vanilla jobs carrying a want-flag.
	//
	// condor_submit skips the decision for a REMOTE submission too, and
	// refuses common_input_files outside vanilla or on one. Neither has
	// a counterpart here: this library builds the same ad however the
	// caller intends to deliver it, and it does not implement
	// common_input_files at all, so no job ad it builds carries the
	// attribute that check reads.
	CommonContainerVanillaOnly bool

	// OmitLeaveJobInQueueDefault writes no LeaveJobInQueue for a job whose
	// submit file does not set one.
	//
	// HTCONDOR-3998 narrowed SetLeaveInQueue to spooling submissions: a
	// local submission used to get `LeaveJobInQueue = false` and now gets
	// nothing, leaving the decision to the schedd's own default.
	OmitLeaveJobInQueueDefault bool
}
