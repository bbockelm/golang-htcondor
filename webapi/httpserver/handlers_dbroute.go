package httpserver

import (
	"context"
	"net/http"
	"sort"
	"strings"
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
// "jobs" table (the mirrored job_queue.log). owner must be the
// authenticated caller, and the result is confined to their jobs.
func (s *Handler) jobsFromMirror(ctx context.Context, constraint string, projection []string, limit int, pageToken, owner string) (ads []*classad.ClassAd, note string, ok bool) {
	if !s.dbMirror.Enabled() || owner == "" {
		return nil, "", false
	}
	info, err := s.dbMirror.Discover(ctx)
	if err != nil {
		return nil, "", false
	}
	useDB, reason := dbmirror.JobsDecision(info, pageToken, time.Now().Unix())
	if !useDB {
		return nil, "", false
	}

	// Confine to the caller's own jobs. scopeToOwner re-serializes the
	// caller's constraint so it cannot escape the enclosing AND; an
	// unparseable one falls back to the schedd rather than being
	// widened.
	scoped, err := scopeToOwner(ownerFromActor(owner), constraint)
	if err != nil {
		return nil, "", false
	}

	ads, ok = s.mirrorQuery(ctx, "jobs", scoped, projection, limit)
	if !ok {
		return nil, "", false
	}
	return ads, dbmirror.Provenance(info, reason), true
}

// historyFromMirror tries to serve a completed-job (archive) listing
// from the mirror's "history" table. constraint must already be
// confined to the caller's own records; see the package comment.
func (s *Handler) historyFromMirror(ctx context.Context, constraint string, opts *htcondor.HistoryQueryOptions) (ads []*classad.ClassAd, note string, ok bool) {
	if !s.dbMirror.Enabled() {
		return nil, "", false
	}
	info, err := s.dbMirror.Discover(ctx)
	if err != nil {
		return nil, "", false
	}
	useDB, reason := dbmirror.HistoryDecision(info, opts)
	if !useDB {
		return nil, "", false
	}

	ads, ok = s.mirrorQuery(ctx, "history", constraint, opts.Projection, opts.Limit)
	if !ok {
		return nil, "", false
	}
	// The mirror has no reverse-chronological cursor, so ordering is
	// applied here over the complete matching set (mirrorQuery declines
	// anything larger than the limit for exactly this reason).
	sort.SliceStable(ads, func(i, j int) bool {
		return dbmirror.RecencyKey(ads[i]) > dbmirror.RecencyKey(ads[j])
	})
	return ads, dbmirror.Provenance(info, reason), true
}

// mirrorQuery runs one bounded read against a mirror table and parses
// the rows. It declines (ok=false) when the matching set is larger than
// the limit: a mirror read has no cursor, so the fetched subset is not
// guaranteed to be the newest or the "first" rows by any ordering the
// caller asked for — the schedd owns that case.
func (s *Handler) mirrorQuery(ctx context.Context, table, constraint string, projection []string, limit int) ([]*classad.ClassAd, bool) {
	effLimit := dbmirror.ClampLimit(limit)

	dbc, closer, _, err := s.dbMirror.Client(ctx)
	if err != nil {
		s.logger.Debug(logging.DestinationHTTP, "htcondordb mirror unavailable; using the schedd", "table", table, "error", err)
		return nil, false
	}
	defer closer()

	// Fetch one past the limit to detect the truncation case above.
	rows, err := dbc.QueryRawProject(ctx, table, constraint, projection, effLimit+1)
	if err != nil {
		s.logger.Debug(logging.DestinationHTTP, "htcondordb mirror query failed; using the schedd", "table", table, "error", err)
		return nil, false
	}
	if len(rows) > effLimit {
		return nil, false
	}

	ads := make([]*classad.ClassAd, 0, len(rows))
	for _, row := range rows {
		ad, perr := classad.ParseOld(row)
		if perr != nil {
			// A corrupt row means falling back, not silently dropping
			// records from the caller's result.
			s.logger.Warn(logging.DestinationHTTP, "unparseable row from the htcondordb mirror; using the schedd", "table", table, "error", perr)
			return nil, false
		}
		ads = append(ads, ad)
	}
	return ads, true
}

// ownerFromActor maps an authenticated actor to the value HTCondor
// stores in a job's Owner attribute: the bare username. The actor is
// often qualified ("alice@uid.domain"), a job's Owner never is.
func ownerFromActor(actor string) string {
	name, _, found := strings.Cut(actor, "@")
	if !found {
		return actor
	}
	return name
}

// writeMirrorJobs writes a mirror-served job listing in the same shape
// the streaming schedd path produces, plus the provenance fields. There
// is no pagination: routing only happens for an unpaginated request, and
// a result larger than the limit is declined upstream, so has_more is
// always false here.
func (s *Handler) writeMirrorJobs(w http.ResponseWriter, ads []*classad.ClassAd, note string) {
	payload := map[string]interface{}{
		"jobs":           ads,
		"total_returned": len(ads),
		"has_more":       false,
		"source":         "htcondordb",
		"source_note":    note,
	}
	s.writeJSON(w, http.StatusOK, payload)
}
