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
// Fields are set individually rather than derived from a version number.
// HTCondor backports across release branches, so one change reaches a 25.x
// patch release and a 26.x release with no version between them that
// separates the two, and a caller who knows their access point is better
// placed to decide than a table in here would be.
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

	// OmitLeaveJobInQueueDefault writes no LeaveJobInQueue for a job whose
	// submit file does not set one.
	//
	// HTCONDOR-3998 narrowed SetLeaveInQueue to spooling submissions: a
	// local submission used to get `LeaveJobInQueue = false` and now gets
	// nothing, leaving the decision to the schedd's own default.
	OmitLeaveJobInQueueDefault bool
}
