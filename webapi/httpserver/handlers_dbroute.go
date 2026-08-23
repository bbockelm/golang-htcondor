package httpserver

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

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
// the caller proceeds to the schedd exactly as before. A read is only
// ever routed when its constraint is already confined to the caller's
// own records, because the mirror connection authenticates as this
// daemon rather than as the caller — the schedd's per-caller ACL does
// not apply there, so routing an unconfined read would widen what a
// caller can see.

// jobsFromMirror tries to serve a live job listing from the mirror's
// "jobs" table (the mirrored job_queue.log), writing the response
// itself. owner must be the authenticated caller; the result is
// confined to their jobs.
//
// Returns false only while nothing has been written, so the caller can
// still fall back to the schedd. Once the first row is on the wire the
// mirror owns the response, and a failure after that is reported the
// way the schedd path reports one: the JSON footer carries an "error"
// field and the array stops there. Buffering a whole result to preserve
// a fallback that a half-written response has already forfeited buys
// nothing.
//
// Still declined: a paginated request (JobsDecision), because the
// mutable "jobs" table has no documented scan order, so a keyset cursor
// over it would silently repeat or skip rows if that order ever
// changed. The archive path below has no such problem.
func (s *Handler) jobsFromMirror(ctx context.Context, w http.ResponseWriter, constraint string, projection []string, limit int, pageToken, owner string) bool {
	if !s.dbMirror.Enabled() || owner == "" {
		return false
	}
	info, err := s.dbMirror.Discover(ctx)
	if err != nil {
		return false
	}
	useDB, reason := dbmirror.JobsDecision(info, pageToken, time.Now().Unix())
	if !useDB {
		return false
	}

	// Confine to the caller's own jobs. scopeToOwner re-serializes the
	// caller's constraint so it cannot escape the enclosing AND; an
	// unparseable one falls back to the schedd rather than being
	// widened.
	scoped, err := scopeToOwner(ownerFromActor(owner), constraint)
	if err != nil {
		return false
	}

	return s.streamMirrorRows(ctx, w, "jobs", scoped, projection, limit,
		"jobs", dbmirror.Provenance(info, reason))
}

// historyFromMirror tries to serve a completed-job listing from the
// mirror's "history" archive, writing the response itself. constraint
// must already be confined to the caller's own records; see the package
// comment.
//
// The archive returns matches newest first with the limit pushed down
// (ArchiveTable.QueryRawProjected), which is exactly condor_history's
// "last K" contract — so this path neither sorts nor over-fetches, and
// the keyset cursor the endpoint already accepts (before_cluster /
// before_proc) rides in the constraint. A paginated archive request is
// therefore one the mirror serves rather than declines.
func (s *Handler) historyFromMirror(ctx context.Context, w http.ResponseWriter, constraint string, opts *htcondor.HistoryQueryOptions) bool {
	if !s.dbMirror.Enabled() {
		return false
	}
	info, err := s.dbMirror.Discover(ctx)
	if err != nil {
		return false
	}
	useDB, reason := dbmirror.HistoryDecision(info, opts)
	if !useDB {
		return false
	}

	return s.streamMirrorRows(ctx, w, "history", constraint, opts.Projection, opts.Limit,
		"ads", dbmirror.Provenance(info, reason))
}

// streamMirrorRows runs one bounded read against a mirror table and
// writes the rows out as they arrive, under the JSON key the endpoint
// uses ("jobs" or "ads").
//
// It returns false only if it gave up before writing anything, which is
// the caller's signal to use the schedd. After the first row it always
// returns true: the response is committed, and any later failure is
// reported inside it.
func (s *Handler) streamMirrorRows(ctx context.Context, w http.ResponseWriter, table, constraint string, projection []string, limit int, key, note string) bool {
	effLimit := dbmirror.ClampLimit(limit)

	dbc, closer, _, err := s.dbMirror.Client(ctx)
	if err != nil {
		s.logger.Debug(logging.DestinationHTTP, "htcondordb mirror unavailable; using the schedd", "table", table, "error", err)
		return false
	}
	defer closer()

	var (
		written  int
		hasMore  bool
		streamed bool
		failure  string
	)
	// One past the limit, so a full page can report whether more
	// matched without a second round trip. The extra row is not written.
	err = dbc.QueryRawProjectStream(ctx, table, constraint, projection, effLimit+1, func(row string) bool {
		if written >= effLimit {
			hasMore = true
			return false
		}
		ad, perr := classad.ParseOld(row)
		if perr != nil {
			failure = "unparseable row from the htcondordb mirror"
			s.logger.Warn(logging.DestinationHTTP, failure, "table", table, "error", perr)
			return false
		}
		adJSON, jerr := json.Marshal(ad)
		if jerr != nil {
			failure = "could not encode a row from the htcondordb mirror"
			s.logger.Error(logging.DestinationHTTP, failure, "table", table, "error", jerr)
			return false
		}

		if !streamed {
			// First row: the mirror owns this response from here on.
			streamed = true
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			if _, werr := fmt.Fprintf(w, `{%q:[`, key); werr != nil {
				failure = "write failed"
				return false
			}
		} else if _, werr := w.Write([]byte(",")); werr != nil {
			failure = "write failed"
			return false
		}
		if _, werr := w.Write(adJSON); werr != nil {
			failure = "write failed"
			return false
		}
		written++
		if flusher, ok := w.(http.Flusher); ok {
			flusher.Flush()
		}
		return true
	})

	switch {
	case !streamed && (err != nil || failure != ""):
		// Nothing written, so the schedd can still answer.
		s.logger.Debug(logging.DestinationHTTP, "htcondordb mirror query failed before any row; using the schedd",
			"table", table, "error", err, "failure", failure)
		return false
	case !streamed:
		// A complete, empty answer is still an answer.
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		if _, werr := fmt.Fprintf(w, `{%q:[`, key); werr != nil {
			s.logger.Error(logging.DestinationHTTP, "failed to write the mirror response header", "error", werr)
			return true
		}
	}

	if err != nil && failure == "" {
		failure = err.Error()
	}
	// Build the footer through the JSON encoder rather than by
	// formatting strings: the provenance note and any failure text come
	// from the mirror, and hand-quoting values into a response body is
	// how escaping bugs start. Marshal an object, then splice it in
	// after the array by dropping its opening brace.
	tail := map[string]interface{}{
		"total_returned": written,
		"has_more":       hasMore,
		"source":         "htcondordb",
		"source_note":    note,
	}
	if failure != "" {
		tail["error"] = failure
	}
	tailJSON, mErr := json.Marshal(tail)
	if mErr != nil || len(tailJSON) < 2 {
		s.logger.Error(logging.DestinationHTTP, "failed to encode the mirror response footer", "error", mErr)
		tailJSON = []byte(`{"source":"htcondordb"}`)
	}
	if _, werr := w.Write(append([]byte("],"), tailJSON[1:]...)); werr != nil {
		s.logger.Error(logging.DestinationHTTP, "failed to write the mirror response footer", "error", werr)
	}
	return true
}
