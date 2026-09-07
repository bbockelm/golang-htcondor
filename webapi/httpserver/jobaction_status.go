package httpserver

import (
	"fmt"
	"net/http"

	htcondor "github.com/bbockelm/golang-htcondor"
)

// jobActionRefusal turns "the schedd acted on nothing" into the reason it
// gave, when it gave one.
//
// ACT_ON_JOBS reports per-outcome totals -- not found, bad status, already
// done, permission denied -- and the action returns them alongside its
// error so a caller can see what happened. The handler used to discard
// them and answer 500 with "action failed: result=0", which says a server
// fault for what is usually a request that no longer makes sense: holding
// a job that is already held is the common one, and it is reached just by
// racing the spool window on a fresh submission. A 500 there is both
// wrong and alarming, and indistinguishable from a schedd that is
// genuinely broken.
//
// Returns ok=false when the results explain nothing, leaving the caller's
// 500 in place -- an unexplained failure is a server fault until shown
// otherwise.
func jobActionRefusal(results *htcondor.JobActionResults, actionVerb string) (int, string, bool) {
	if results == nil || results.Success > 0 {
		return 0, "", false
	}
	switch {
	case results.NotFound > 0:
		return http.StatusNotFound,
			fmt.Sprintf("Cannot %s: no such job, or it has already left the queue", actionVerb), true
	case results.PermissionDenied > 0:
		return http.StatusForbidden,
			fmt.Sprintf("Not permitted to %s this job", actionVerb), true
	case results.AlreadyDone > 0:
		// Not an error in any useful sense: the caller asked for a state
		// the job is already in.
		return http.StatusConflict,
			fmt.Sprintf("Cannot %s: the job is already in that state", actionVerb), true
	case results.BadStatus > 0:
		return http.StatusConflict,
			fmt.Sprintf("Cannot %s a job in its current state", actionVerb), true
	case results.LimitExceeded > 0:
		return http.StatusTooManyRequests,
			fmt.Sprintf("Cannot %s: a schedd limit was exceeded", actionVerb), true
	}
	return 0, "", false
}
