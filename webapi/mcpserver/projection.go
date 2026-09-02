package mcpserver

import (
	"strings"

	htcondor "github.com/bbockelm/golang-htcondor"
)

// What a listing tool returns per row, when the caller does not say.
//
// The default used to be every attribute, because no projection was
// sent and the schedd returns the whole ad for an unprojected query.
// Measured against a live schedd, one trivial /bin/sleep job comes back
// as 71 attributes and 2.1KB of JSON — and that is the floor. A real
// job carries Environment, TransferInput, a long Requirements and
// arguments, which is how a single ad reaches tens of kilobytes.
//
// Multiplied by a listing, that is the whole context window spent on
// fields nobody asked about: at 500 rows the old default is megabytes.
// Capping rows without capping columns bounds nothing, so the default
// is a working set, and "everything" is something a caller opts into.
//
// Chosen for the questions these tools are actually asked — what is it,
// whose is it, what state is it in, where did it run, why did it stop,
// what did it ask for — and deliberately without Environment,
// Requirements or the transfer lists, which are large, rarely the
// question, and available by naming them.

// defaultJobAttrs is the working set for live job listings.
var defaultJobAttrs = []string{
	// Identity
	"ClusterId", "ProcId", "Owner", "GlobalJobId", "JobBatchName",
	// State, and when it changed
	"JobStatus", "EnteredCurrentStatus", "QDate", "JobStartDate",
	// What it runs
	"JobUniverse", "Cmd", "Args", "Iwd",
	// Where it ran
	"RemoteHost", "LastRemoteHost",
	// Why it stopped
	"ExitCode", "ExitBySignal", "HoldReason", "HoldReasonCode", "HoldReasonSubCode",
	// What it asked for
	"RequestCpus", "RequestMemory", "RequestDisk",
}

// defaultHistoryAttrs is the working set for completed-job listings.
// Same shape as the live one plus how it finished, and without the
// fields that only mean something while a job is running.
var defaultHistoryAttrs = []string{
	"ClusterId", "ProcId", "Owner", "GlobalJobId", "JobBatchName",
	"JobStatus", "EnteredCurrentStatus", "QDate", "JobStartDate", "CompletionDate",
	"JobUniverse", "Cmd", "Args", "Iwd",
	"LastRemoteHost",
	"ExitCode", "ExitBySignal", "ExitStatus", "HoldReason", "HoldReasonCode",
	"RequestCpus", "RequestMemory", "RequestDisk",
	"RemoteWallClockTime", "RemoteUserCpu",
}

// defaultEpochAttrs is the working set for per-run epoch records, whose
// point is when and where each run happened.
var defaultEpochAttrs = []string{
	"ClusterId", "ProcId", "EpochNumber", "Owner",
	"JobStartDate", "JobCurrentStartDate", "RemoteHost",
	"JobStatus", "ExitCode", "ExitBySignal",
}

// defaultTransferAttrs is the working set for file-transfer records.
var defaultTransferAttrs = []string{
	"ClusterId", "ProcId", "Owner", "TransferType",
	"TransferStartTime", "TransferEndTime", "TransferSuccess",
	"TransferFileBytes", "TransferTotalBytes", "TransferError",
}

// defaultAttrsFor picks the working set matching a history source. The
// records differ enough that one list would return mostly-empty rows
// for two of the three.
func defaultAttrsFor(source htcondor.HistoryRecordSource) []string {
	switch source {
	case htcondor.HistorySourceJobEpoch:
		return defaultEpochAttrs
	case htcondor.HistorySourceTransfer:
		return defaultTransferAttrs
	default:
		return defaultHistoryAttrs
	}
}

// describeProjection renders the `projection` argument's documentation
// from the list the code actually uses.
//
// These descriptions used to name a default in prose while the code
// applied none — the tools claimed "Default: ClusterId, ProcId, Owner,
// JobStatus, ..." from the commit that introduced them and returned
// every attribute for the next year. Generating the text from the list
// is what keeps that from being possible again: there is no second
// place to update.
func describeProjection(defaults []string) string {
	return "Attributes to return. Defaults to a working set: " + strings.Join(defaults, ", ") +
		". Use ['*'] for every attribute — expensive: a single ad is 70+ attributes and can reach tens of " +
		"kilobytes, so a listing of them will crowd out the rest of your context."
}

// wantsAllAttributes reports the documented spelling of "everything".
func wantsAllAttributes(projection []string) bool {
	return len(projection) == 1 && projection[0] == "*"
}

// projectionOrDefault resolves what to ask the schedd for.
//
// An empty projection means the caller did not choose, and gets the
// working set. ["*"] is the documented way to ask for everything and is
// honored — expensively, and the caller is told so, because a model
// that asks for every attribute of many jobs will spend its context on
// the answer rather than on the work.
func projectionOrDefault(requested, fallback []string) (projection []string, note string) {
	if wantsAllAttributes(requested) {
		return nil, "\n\nReturning every attribute, which is far larger than the default working set " +
			"(a single job ad can be tens of kilobytes). Name the attributes you need in `projection` " +
			"if this crowds out the rest of the answer."
	}
	if len(requested) > 0 {
		return requested, ""
	}
	return fallback, ""
}
