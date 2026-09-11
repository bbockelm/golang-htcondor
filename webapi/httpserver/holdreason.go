package httpserver

import "fmt"

// Hold reason codes, from HTCondor's src/condor_utils/condor_holdcodes.h.
//
// A code alone is a number an operator has to go and look up. The label
// is what turns "10,238 held" into a diagnosis -- and the difference
// between the common causes matters: a queue held on SpoolingInput is a
// routine submit in progress, one held on TransferInputError is a
// thousand jobs pointing at a file that is not there, and they look
// identical in a count.
//
// Only the codes a hosted access point actually sees are named. The grid
// and EC2 families are deliberately left to the numeric fallback rather
// than padded out: a label nobody reads is a maintenance cost, and the
// hold message itself carries the detail.
var holdReasonLabels = map[int64]string{
	0:  "unspecified",
	1:  "held by user request",
	3:  "held by a job policy expression (periodic_hold)",
	4:  "corrupted credential",
	5:  "job policy expression was undefined",
	6:  "failed to create the process",
	7:  "could not open the output file",
	8:  "could not open the input file",
	9:  "could not open the output stream",
	10: "could not open the input stream",
	11: "invalid transfer acknowledgement",
	12: "output file transfer failed",
	13: "input file transfer failed",
	14: "initial working directory is not accessible",
	15: "submitted on hold (submit described it that way)",
	16: "input is still spooling (a submit in progress, not a failure)",
	17: "shadow mismatch",
	19: "the prepare-job hook failed",
	20: "missed its deferred execution time",
	21: "put on hold by the execute machine",
	22: "could not initialise the user log",
	23: "could not access the user account",
	24: "no compatible shadow",
	25: "invalid cron settings",
	26: "held by a system policy (the pool administrator's)",
	27: "system policy expression was undefined",
	32: "input sandbox exceeded the maximum transfer size",
	33: "output sandbox exceeded the maximum transfer size",
	34: "ran out of resources (memory or disk)",
	35: "invalid container image",
	36: "failed to checkpoint",
	43: "the pre script failed",
	44: "the post script failed",
	45: "the container runtime test failed",
	46: "exceeded its allowed duration",
	47: "exceeded its allowed execute time",
	48: "the shadow prepare-job hook failed",
	49: "could not switch primary group",
	50: "per-job VPN setup failed",
}

// holdReasonLabel names a hold code, falling back to the number when it
// is one of the families deliberately left unnamed. The fallback says
// the code plainly rather than "unknown", because the number is what an
// operator searches for.
func holdReasonLabel(code int64) string {
	if label, ok := holdReasonLabels[code]; ok {
		return label
	}
	if code >= 1000 {
		// The 1000+ family is vacate/eviction rather than a submission
		// problem, which is the distinction worth drawing even without a
		// per-code label.
		return fmt.Sprintf("evicted or vacated (code %d)", code)
	}
	return fmt.Sprintf("hold code %d", code)
}

// holdReasonIsRoutine reports whether a hold is part of normal operation
// rather than something to act on. Spooling input is the one that
// matters: a dashboard that counts it as a failure makes every large
// submit look like an outage while it is still uploading.
func holdReasonIsRoutine(code int64) bool { return code == 16 }
