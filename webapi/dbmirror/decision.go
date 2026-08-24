package dbmirror

import "net/http"

// Reason is the machine-readable half of a routing decision, carried
// alongside the prose. The prose is for the human reading a response's provenance
// note; the Reason is for everything that has to branch or aggregate on
// why routing went the way it did — the Prometheus label, the readiness
// snapshot, and the HTTP status when the mirror is mandatory.
//
// The prose cannot do that job: it interpolates numbers ("stale (94s
// since last sync...)"), so using it as a metric label would mint a new
// time series per second of staleness. Reason values are a closed set
// and are part of the daemon's observable interface: renaming one
// breaks dashboards and alerts, so treat them as API.
type Reason string

const (
	// ReasonServed is the only Reason with Use = true.
	ReasonServed Reason = "served"

	// The rest are declines. These first ones are availability and
	// freshness: the mirror could serve this query, but not right now.
	// Transient — the same query may route to the mirror a minute later.

	// ReasonNotConfigured is set when no collector or no HTCondor config, so
	// routing cannot run at all.
	ReasonNotConfigured Reason = "not_configured"
	// ReasonNoMirror is set when nothing is advertising, or the ad has no usable
	// address.
	ReasonNoMirror Reason = "no_mirror"
	// ReasonStale is set when the mirror is outside the freshness tolerance for
	// this kind of read.
	ReasonStale Reason = "stale"
	// ReasonNotCaughtUp is set when the mirror had not drained the schedd's
	// job_queue.log at its last poll.
	ReasonNotCaughtUp Reason = "not_caught_up"
	// ReasonHistoryGap is set when the mirror reported a history durability gap.
	ReasonHistoryGap Reason = "history_gap"
	// ReasonDialFailed is set when could not connect or authenticate to the mirror.
	ReasonDialFailed Reason = "dial_failed"
	// ReasonQueryFailed is set when the mirror errored partway through the query.
	ReasonQueryFailed Reason = "query_failed"
	// ReasonBadRow is set when a row the mirror returned would not parse.
	ReasonBadRow Reason = "bad_row"
	// ReasonOversized is set when more matches than the mirror read may return, so
	// the schedd owns ordering.
	ReasonOversized Reason = "oversized"
	// ReasonNoPagination is set when the mirror is too old to understand
	// the cursor opcode a paginated read needs.
	ReasonNoPagination Reason = "no_pagination"

	// The last three are query shape: this particular request cannot be
	// served from the mirror no matter how healthy it is. Not transient
	// — retrying changes nothing, the caller has to ask differently.

	// ReasonUnsupportedQuery is set when scan semantics the mirror cannot
	// reproduce, such as a scan_limit budget or a forward scan.
	ReasonUnsupportedQuery Reason = "unsupported_query"
	// ReasonPageToken is set when the rest of this walk belongs to the
	// schedd.
	ReasonPageToken Reason = "page_token"
	// ReasonNoOwnerScope is set when no authenticated caller to confine the read
	// to, and the mirror serves only owner-scoped reads.
	ReasonNoOwnerScope Reason = "no_owner_scope"
)

// QueryShape reports whether the reason is a property of the request
// rather than of the mirror's health. It decides the status code when
// the mirror is mandatory: a query shape the mirror cannot serve is the
// caller's to fix (400), while an unavailable or lagging mirror is the
// deployment's (503, and worth retrying).
func (r Reason) QueryShape() bool {
	switch r {
	case ReasonUnsupportedQuery, ReasonPageToken, ReasonNoOwnerScope:
		return true
	}
	return false
}

// Decision is the outcome of asking whether a read may be served from
// the mirror. Note is the human-readable half, surfaced in provenance.
type Decision struct {
	Use    bool
	Reason Reason
	Note   string
}

// Status is the HTTP status a declined decision becomes when the mirror
// is mandatory. Not used on the default best-effort path, where a
// decline is invisible to the caller.
func (d Decision) Status() int {
	if d.Use {
		return http.StatusOK
	}
	if d.Reason.QueryShape() {
		return http.StatusBadRequest
	}
	return http.StatusServiceUnavailable
}

// serve and decline keep the policy functions readable.
func serve(note string) Decision { return Decision{Use: true, Reason: ReasonServed, Note: note} }

func decline(r Reason, note string) Decision { return Decision{Reason: r, Note: note} }
