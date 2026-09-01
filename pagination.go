package htcondor

import "errors"

// ErrPaginationUnsupported is returned for a job query carrying a page
// token, because a schedd cannot be walked page by page.
//
// Two independent reasons, either of which is enough:
//
// There is no order to page by. QUERY_JOB_ADS walks the job queue's
// ClassAdLog, a HashTable, and LimitResults stops that walk early — so
// the jobs a page returns are an arbitrary subset of the matches, and a
// cursor taken from one either returns the same page forever or
// silently skips every job the page did not include. Imposing an order
// on this side means sorting every match, which is only possible by
// fetching every match.
//
// And there is no index to make the next page cheap. filter_iterator
// (condor_utils/classad_log.h) runs that hash table from begin() to
// end() evaluating the constraint against every ad; matching jobs sit
// in whatever buckets they hash to, so no bound on ClusterId prunes
// anything. Every page costs a full queue walk, which means walking a
// queue in P pages costs the schedd P full walks where reading it once
// costs one. Pagination against a schedd is more load than the thing it
// exists to avoid.
//
// Where pagination does work is an htcondordb mirror: it resumes from a
// storage cursor against a snapshot, with no scan and no reordering
// (see webapi/dbmirror). Callers with no mirror raise the limit, narrow
// the constraint, or use a server-side aggregate for counts.
var ErrPaginationUnsupported = errors.New(
	"the schedd cannot paginate: its job queue is a hash table with no order to resume from " +
		"and no index to seek with, so each page would cost a full queue scan. " +
		"Raise the limit to read more at once, narrow the constraint, or query an htcondordb mirror")
