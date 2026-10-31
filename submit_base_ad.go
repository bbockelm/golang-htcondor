package htcondor

import (
	"fmt"
	"strings"

	"github.com/PelicanPlatform/classad/classad"
)

// setSubmitTimeDefaults writes the attributes condor_submit puts in every job
// ad before it reads a single submit command -- SubmitHash::init_base_ad's
// half of the job ad.
//
// They are the job's RUN-TIME bookkeeping, zeroed: how much CPU it has used,
// how many times it has been suspended, started, held or checkpointed, what
// it exited with. Nothing in the submit file sets them and the schedd and the
// shadow own them from the moment the job is in the queue -- but the schedd
// does not CREATE them, it updates what the ad already carries, and an
// attribute that is absent reads as undefined to everything that looks.
//
// That matters because these are what the usual reports are built from.
// `condor_q -l` shows nothing for an undefined RemoteUserCpu, a `condor_q
// -constraint 'RemoteUserCpu > 60'` does not match a job that has no such
// attribute rather than one that has used no CPU, and an expression that
// does arithmetic on one gets UNDEFINED rather than a number -- which
// propagates, so a policy expression like `RemoteUserCpu > 3600` is neither
// true nor false. Writing them at submit time is how condor_submit makes a
// fresh job's state readable, and it is one assignment per attribute rather
// than any derivation, which is why they are listed rather than computed.
//
// It runs first, so every keyword the submit file sets overwrites what is
// here -- the same order as C++, where these go in the base ad the proc ad is
// built from.
func (sf *SubmitFile) setSubmitTimeDefaults(ad *classad.ClassAd) {
	// The ad's own type names. MyType is what a ClassAd reader uses to tell
	// a job ad from a machine ad; TargetType is what a job ad says it wants
	// to be matched against, and HTCondor before 23.0 needs it present.
	_ = ad.Set("MyType", "Job")
	_ = ad.Set("TargetType", "Machine")

	// The CPU and wall-clock counters are REALS on the C++ side, not
	// integers: the shadow writes fractional seconds into them, and a
	// consumer that reads one with an integer lookup gets nothing from a
	// real. 0.0 keeps the type the same from the start.
	for _, attr := range []string{
		"RemoteWallClockTime",
		"RemoteUserCpu",
		"RemoteSysCpu",
		"CumulativeRemoteUserCpu",
		"CumulativeRemoteSysCpu",
	} {
		_ = ad.Set(attr, 0.0)
	}

	for _, attr := range []string{
		"ExitStatus",
		"NumCkpts",
		"NumJobStarts",
		"NumJobCompletions",
		"NumRestarts",
		"NumSystemHolds",
		"CommittedTime",
		"CommittedSlotTime",
		"CumulativeSlotTime",
		"TotalSuspensions",
		"LastSuspensionTime",
		"CumulativeSuspensionTime",
		"CommittedSuspensionTime",
	} {
		_ = ad.Set(attr, 0)
	}

	_ = ad.Set("ExitBySignal", false)
}

// notificationCodes are the five words `notification` accepts, mapped to the
// NOTIFY_* values in condor_includes/proc.h. condor_submit compares the words
// and nothing else: a number is not accepted, and an unrecognized word makes
// it refuse the submit file rather than fall back to a default.
var notificationCodes = map[string]int{
	"never":    0,
	"always":   1,
	"complete": 2,
	"error":    3,
	"start":    4,
}

// setNotification stores JobNotification, which decides when the schedd mails
// the submitter about the job.
//
// It is always written, even when the submit file says nothing: the keyword's
// default comes from JOB_DEFAULT_NOTIFICATION and, failing that, is NEVER. A
// job ad with no JobNotification is not "never" to the schedd, which reads
// the attribute and treats an undefined one as its own default, so leaving it
// out hands the decision to a different piece of configuration than the one
// the submitter's pool set.
func (sf *SubmitFile) setNotification(ad *classad.ClassAd) error {
	how, ok := sf.simpleKeywordParam("notification", "JobNotification")
	if !ok {
		how, _ = sf.param("JOB_DEFAULT_NOTIFICATION")
	}
	if how == "" {
		_ = ad.Set("JobNotification", notificationCodes["never"])
		return nil
	}
	code, known := notificationCodes[strings.ToLower(strings.TrimSpace(how))]
	if !known {
		return fmt.Errorf("notification must be 'Never', 'Always', 'Complete', 'Start', or 'Error', not %q", how)
	}
	_ = ad.Set("JobNotification", code)
	return nil
}

// setDefaultJobLease gives a job that can reconnect a JobLeaseDuration when
// the submit file named none, from JOB_DEFAULT_LEASE_DURATION.
//
// The lease is what lets a job survive a disconnect: the schedd keeps the
// claim for that long while the shadow is gone, and the job carries on. With
// no lease at all there is nothing to keep, so a network blip between the
// submit and execute nodes becomes a lost execution rather than a
// reconnection -- which is why condor_submit defaults it to 2400 seconds
// instead of leaving it out.
//
// Only the universes that CAN reconnect get it (vanilla, java, parallel and
// vm, per universeCanReconnect in condor_universe.cpp): the rest have nothing
// to reconnect to, and a lease on one of those jobs would only tell the
// schedd to hold a claim nobody will come back for. The knob's value is
// stored as an expression, as condor_submit stores it, so a pool can make the
// lease depend on the job.
func (sf *SubmitFile) setDefaultJobLease(ad *classad.ClassAd) {
	if !universeCanReconnect(sf.universe) {
		return
	}
	if _, ok := ad.Lookup("JobLeaseDuration"); ok {
		return
	}
	value, ok := sf.param("JOB_DEFAULT_LEASE_DURATION")
	if !ok || strings.TrimSpace(value) == "" {
		return
	}
	if expr, err := classad.ParseExpr(strings.TrimSpace(value)); err == nil {
		_ = ad.Set("JobLeaseDuration", expr)
	}
}

// universeCanReconnect is CAN_RECONNECT in condor_universe.cpp's table: the
// universes whose jobs keep running while the shadow is away, so a lease
// means something for them.
func universeCanReconnect(universe int) bool {
	switch universe {
	case UniverseVanilla, UniverseJava, UniverseParallel, UniverseVM:
		return true
	default:
		return false
	}
}
