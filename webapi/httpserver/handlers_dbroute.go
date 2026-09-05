package httpserver

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"

	"github.com/PelicanPlatform/classad/dbrpc"

	"github.com/PelicanPlatform/classad/classad"

	htcondor "github.com/bbockelm/golang-htcondor"
	"github.com/bbockelm/golang-htcondor/logging"
	"github.com/bbockelm/golang-htcondor/webapi/dbmirror"
)

// The REST job and history reads are the two heaviest things this API
// asks of a schedd: condor_history scans the on-disk history file, and a
// broad job query walks the queue — both competing with scheduling and
// negotiation. When a synchronized htcondordb mirror is advertising and
// current, they are served from it instead. The freshness policy lives
// in webapi/dbmirror, shared with the MCP tools so the two surfaces
// cannot drift apart on when routing is allowed.
//
// Every path here is best-effort: any miss (no mirror, stale mirror,
// dial/query/parse error, more rows than the cap) returns ok=false and
// the caller proceeds to the schedd exactly as before.
//
// What a routed read must never do is show a caller something the
// schedd would not have. Two facts settle when that holds. Reading the
// queue and the history are both READ-level commands on the schedd
// (QUERY_JOB_ADS, QUERY_SCHEDD_HISTORY), and neither applies an
// owner filter of its own — the schedd narrows a query to one owner
// only when the CLIENT asks it to, via the MyJobs flag this daemon sets
// for a scoped request. So any caller the schedd authenticates can
// already read every job ad; there is no per-caller ACL on reads for a
// mirror read to be missing.
//
// The one thing the mirror path does bypass is the schedd handshake
// itself, and that is the invariant these functions enforce: a read is
// routed only when the caller's identity is established, which here
// means the schedd accepted their credential — either a prior request
// got a 2xx with it (tokenCache.MarkValidated) or actorForSession
// pinged the schedd with that very credential and was told who they
// are. Without that, a caller the schedd would have refused outright
// could read the queue out of the mirror instead. An unauthenticated
// request therefore falls back to the schedd, which is exactly where it
// gets refused.
//
// Scoping is a separate matter and rides along: when the request was
// confined to one owner, the mirror read is confined the same way.

// jobsFromMirror tries to serve a live job listing from the mirror's
// "jobs" table (the mirrored job_queue.log), writing the response
// itself. owner is the identity the schedd attributes to this caller,
// and scoped says whether the listing is confined to their own jobs (see
// the package comment).
//
// Returns handled=false only while nothing has been written, so the
// caller can still fall back to the schedd; the returned Decision says
// why, which is what the caller needs to fail the request instead when
// the mirror is mandatory. Once the first row is on the wire the
// mirror owns the response, and a failure after that is reported the
// way the schedd path reports one: the JSON footer carries an "error"
// field and the array stops there. Buffering a whole result to preserve
// a fallback that a half-written response has already forfeited buys
// nothing.
//
// A paginated request is served here too, which is the point: paging a
// queue walk is the case the schedd likes least, because it re-walks
// from the top on every page. The mirror instead resumes its own scan
// from the sequence cursor the previous page returned, so page N costs
// a resume rather than another full walk, and the whole walk sees one
// consistent snapshot. Only a token the mirror itself issued is
// accepted (JobsDecision); a schedd-issued one belongs to the schedd's
// walk and is left to it.
func (s *Handler) jobsFromMirror(ctx context.Context, w http.ResponseWriter, constraint string, projection []string, limit int, pageToken, owner string, scoped bool) (bool, dbmirror.Decision) {
	if !s.dbMirror.Enabled() {
		return false, s.recordMirror("jobs", dbmirror.Decision{
			Reason: dbmirror.ReasonNotConfigured,
			Note:   "htcondordb routing is not configured",
		})
	}
	if owner == "" {
		return false, s.recordMirror("jobs", dbmirror.Decision{
			Reason: dbmirror.ReasonNoOwnerScope,
			Note:   "the schedd has not identified this caller, so the mirror must not answer on its behalf",
		})
	}
	info, err := s.dbMirror.Discover(ctx)
	if err != nil {
		return false, s.recordMirror("jobs", dbmirror.Decision{
			Reason: dbmirror.ReasonNoMirror,
			Note:   err.Error(),
		})
	}
	d := s.recordMirror("jobs", dbmirror.JobsDecision(info, pageToken))
	if !d.Use {
		return false, d
	}

	// Confine to the caller's own jobs when the request was confined.
	// scopeToOwner re-serializes the caller's constraint so it cannot
	// escape the enclosing AND; an unparseable one falls back to the
	// schedd rather than being widened. A whole-queue listing is passed
	// through as-is, which is what the schedd would have returned.
	mirrorConstraint := constraint
	if scoped {
		var err error
		if mirrorConstraint, err = scopeToOwner(ownerFromActor(owner), constraint); err != nil {
			return false, s.recordMirror("jobs", dbmirror.Decision{
				Reason: dbmirror.ReasonUnsupportedQuery,
				Note:   fmt.Sprintf("constraint cannot be owner-scoped for the mirror: %v", err),
			})
		}
	}

	// A mirror-issued token resumes its scan; a first page starts at the
	// beginning. JobsDecision has already refused a schedd-issued one.
	var cursor dbrpc.SeqCursor
	if pageToken != "" {
		c, err := dbmirror.DecodeCursor(pageToken)
		if err != nil {
			// The token says it is ours and is not readable. Restarting
			// silently would repeat rows the caller already has, so let the
			// schedd path report it as the bad request it is.
			s.logger.Warn(logging.DestinationHTTP, "unreadable htcondordb page token", "error", err)
			return false, s.recordMirror("jobs", dbmirror.Decision{
				Reason: dbmirror.ReasonPageToken,
				Note:   fmt.Sprintf("the mirror's page token is unreadable: %v", err),
			})
		}
		cursor = c
	}

	return s.streamMirrorRows(ctx, w, "jobs", mirrorConstraint, projection, limit,
		"jobs", dbmirror.Provenance(info, d.Note), &cursor)
}

// historyFromMirror tries to serve a completed-job listing from the
// mirror's "history" archive, writing the response itself. constraint
// arrives already confined if the request was confined; actor is the
// identity the schedd attributes to this caller, and an empty one keeps
// the read on the schedd (see the package comment).
//
// The archive returns matches newest first with the limit pushed down
// (ArchiveTable.QueryRawProjected), which is exactly condor_history's
// "last K" contract — so this path neither sorts nor over-fetches, and
// the keyset cursor the endpoint already accepts (before_cluster /
// before_proc) rides in the constraint. A paginated archive request is
// therefore one the mirror serves rather than declines.
func (s *Handler) historyFromMirror(ctx context.Context, w http.ResponseWriter, constraint string, opts *htcondor.HistoryQueryOptions, actor string) (bool, dbmirror.Decision) {
	if !s.dbMirror.Enabled() {
		return false, s.recordMirror("history", dbmirror.Decision{
			Reason: dbmirror.ReasonNotConfigured,
			Note:   "htcondordb routing is not configured",
		})
	}
	if actor == "" {
		return false, s.recordMirror("history", dbmirror.Decision{
			Reason: dbmirror.ReasonNoOwnerScope,
			Note:   "the schedd has not identified this caller, so the mirror must not answer on its behalf",
		})
	}
	info, err := s.dbMirror.Discover(ctx)
	if err != nil {
		return false, s.recordMirror("history", dbmirror.Decision{
			Reason: dbmirror.ReasonNoMirror,
			Note:   err.Error(),
		})
	}
	d := s.recordMirror("history", dbmirror.HistoryDecision(info, opts))
	if !d.Use {
		return false, d
	}

	// No cursor: an archive answers "the newest K" in one shot, and the
	// endpoint's own before_cluster/before_proc cursor rides in the
	// constraint.
	return s.streamMirrorRows(ctx, w, "history", constraint, opts.Projection, opts.Limit,
		"ads", dbmirror.Provenance(info, d.Note), nil)
}

// streamMirrorRows runs one bounded read against a mirror table and
// writes the rows out as they arrive, under the JSON key the endpoint
// uses ("jobs" or "ads").
//
// It returns false only if it gave up before writing anything, which is
// the caller's signal to use the schedd. After the first row it always
// returns true: the response is committed, and any later failure is
// reported inside it.
func (s *Handler) streamMirrorRows(ctx context.Context, w http.ResponseWriter, table, constraint string, projection []string, limit int, key, note string, cursor *dbrpc.SeqCursor) (bool, dbmirror.Decision) {
	effLimit := dbmirror.ClampLimit(limit)

	dbc, closer, _, err := s.dbMirror.Client(ctx)
	if err != nil {
		s.logger.Debug(logging.DestinationHTTP, "htcondordb mirror unavailable; using the schedd", "table", table, "error", err)
		return false, s.recordMirror(table, dbmirror.Decision{
			Reason: dbmirror.ReasonDialFailed,
			Note:   err.Error(),
		})
	}
	defer closer()

	rows := &mirrorRowStream{h: s, w: w, table: table, key: key, limit: effLimit, note: note}

	if cursor != nil {
		// The paginated read: the server resumes its own ordered scan and
		// hands back where to continue, so a page costs a resume rather
		// than a re-scan and page two sees the queue as page one did.
		var page *dbrpc.SeqPage
		page, err = dbc.QueryRawProjectedFromSeqStream(ctx, table, constraint, projection, *cursor, effLimit, rows.write)
		switch {
		case errors.Is(err, dbrpc.ErrPaginationUnsupported):
			// A mirror too old for the opcode. Nothing has been written
			// yet on a first page, so the schedd can still answer.
			s.logger.Debug(logging.DestinationHTTP, "htcondordb mirror does not support cursor pagination; using the schedd")
			if !rows.streamed {
				return false, s.recordMirror(table, dbmirror.Decision{
					Reason: dbmirror.ReasonNoPagination,
					Note:   "the htcondordb mirror is too old to resume a cursor",
				})
			}
		case err == nil && page != nil:
			rows.hasMore = page.More
			if page.More {
				rows.nextToken = dbmirror.EncodeCursor(page.Next)
			}
		}
	} else {
		// One past the limit, so a full page can report whether more
		// matched without a second round trip. The extra row is not written.
		err = dbc.QueryRawProjectStream(ctx, table, constraint, projection, effLimit+1, rows.write)
	}

	if declined := rows.readFailed(err); declined != nil {
		return false, s.recordMirror(table, *declined)
	}
	rows.finish(err)
	return true, dbmirror.Decision{Use: true, Reason: dbmirror.ReasonServed, Note: note}
}

// recordMirror counts a routing decision and returns it unchanged, so
// call sites can write `return false, s.recordMirror(...)` and cannot
// forget to record one. The Reason is the metric label — bounded by
// construction (see dbmirror.Reason); the prose note is not exported to
// Prometheus because it interpolates staleness numbers.
func (s *Handler) recordMirror(table string, d dbmirror.Decision) dbmirror.Decision {
	if s != nil && s.httpMetricsState != nil {
		s.httpMetricsState.recordMirrorDecision(table, d)
	}
	return d
}

// mirrorRequiredError answers a request that the mirror declined while
// HTTP_API_DBMIRROR_REQUIRED is set. The operator asked for the load to
// stay off the access point even at the cost of availability, so the
// request fails with the reason rather than quietly becoming schedd
// load. Returns true when it wrote a response.
//
// The status separates the two kinds of decline: a query the mirror
// structurally cannot serve is the caller's to change (400), while an
// absent or lagging mirror is the deployment's problem and worth
// retrying (503).
func (s *Handler) mirrorRequiredError(w http.ResponseWriter, d dbmirror.Decision) bool {
	if d.Use || !s.dbMirror.Required() {
		return false
	}
	s.logger.Warn(logging.DestinationHTTP, "htcondordb mirror is required and declined the query",
		"reason", string(d.Reason), "detail", d.Note)
	s.writeError(w, d.Status(), fmt.Sprintf(
		"This query must be served from the htcondordb mirror (HTTP_API_DBMIRROR_REQUIRED is set) and could not be: %s", d.Note))
	return true
}

// mirrorRowStream writes one mirror result out as the rows arrive. It
// exists so streamMirrorRows can stay about *which* read to run while
// this stays about writing a response that may already be half sent.
//
// The state it carries is what makes the fallback rule decidable:
// `streamed` is the point of no return. Before the first row nothing is
// on the wire and the schedd can still answer; after it, this response
// is committed and a later failure is reported inside it, the way the
// schedd path reports one.
type mirrorRowStream struct {
	h     *Handler
	w     http.ResponseWriter
	table string
	key   string
	limit int
	note  string

	written   int
	streamed  bool
	hasMore   bool
	failure   string
	nextToken string
}

// write emits one row, returning false to stop the read.
func (m *mirrorRowStream) write(row string) bool {
	if m.written >= m.limit {
		m.hasMore = true
		return false
	}
	ad, perr := classad.ParseOld(row)
	if perr != nil {
		m.failure = "unparseable row from the htcondordb mirror"
		m.h.logger.Warn(logging.DestinationHTTP, m.failure, "table", m.table, "error", perr)
		return false
	}
	adJSON, jerr := json.Marshal(ad)
	if jerr != nil {
		m.failure = "could not encode a row from the htcondordb mirror"
		m.h.logger.Error(logging.DestinationHTTP, m.failure, "table", m.table, "error", jerr)
		return false
	}

	if !m.streamed {
		if !m.begin() {
			return false
		}
	} else if _, werr := m.w.Write([]byte(",")); werr != nil {
		m.failure = "write failed"
		return false
	}
	if _, werr := m.w.Write(adJSON); werr != nil {
		m.failure = "write failed"
		return false
	}
	m.written++
	if flusher, ok := m.w.(http.Flusher); ok {
		flusher.Flush()
	}
	return true
}

// begin writes the response header and opens the array. After this the
// mirror owns the response.
func (m *mirrorRowStream) begin() bool {
	m.streamed = true
	m.w.Header().Set("Content-Type", "application/json")
	m.w.WriteHeader(http.StatusOK)
	if _, werr := fmt.Fprintf(m.w, `{%q:[`, m.key); werr != nil {
		m.failure = "write failed"
		return false
	}
	return true
}

// readFailed reports the decline to return when the read failed before
// anything was written, and nil when the caller should finish the
// response. An empty result is not a failure: a complete, empty answer
// is still an answer.
func (m *mirrorRowStream) readFailed(err error) *dbmirror.Decision {
	if m.streamed || (err == nil && m.failure == "") {
		return nil
	}
	m.h.logger.Debug(logging.DestinationHTTP, "htcondordb mirror query failed before any row; using the schedd",
		"table", m.table, "error", err, "failure", m.failure)
	note, reason := m.failure, dbmirror.ReasonBadRow
	if err != nil {
		note, reason = err.Error(), dbmirror.ReasonQueryFailed
	}
	return &dbmirror.Decision{Reason: reason, Note: note}
}

// finish closes the array and writes the metadata footer.
func (m *mirrorRowStream) finish(err error) {
	if !m.streamed && !m.begin() {
		m.h.logger.Error(logging.DestinationHTTP, "failed to write the mirror response header")
		return
	}
	if err != nil && m.failure == "" {
		m.failure = err.Error()
	}
	// Build the footer through the JSON encoder rather than by
	// formatting strings: the provenance note and any failure text come
	// from the mirror, and hand-quoting values into a response body is
	// how escaping bugs start. Marshal an object, then splice it in
	// after the array by dropping its opening brace.
	tail := map[string]interface{}{
		"total_returned": m.written,
		"has_more":       m.hasMore,
		"source":         "htcondordb",
		"source_note":    m.note,
	}
	if m.failure != "" {
		tail["error"] = m.failure
	}
	if m.nextToken != "" {
		tail["next_page_token"] = m.nextToken
	}
	tailJSON, mErr := json.Marshal(tail)
	if mErr != nil || len(tailJSON) < 2 {
		m.h.logger.Error(logging.DestinationHTTP, "failed to encode the mirror response footer", "error", mErr)
		tailJSON = []byte(`{"source":"htcondordb"}`)
	}
	if _, werr := m.w.Write(append([]byte("],"), tailJSON[1:]...)); werr != nil {
		m.h.logger.Error(logging.DestinationHTTP, "failed to write the mirror response footer", "error", werr)
	}
}
