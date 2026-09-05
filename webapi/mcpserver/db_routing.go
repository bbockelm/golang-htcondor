package mcpserver

import (
	"context"
	"fmt"
	"sort"

	"github.com/PelicanPlatform/classad/classad"

	htcondor "github.com/bbockelm/golang-htcondor"
	"github.com/bbockelm/golang-htcondor/webapi/dbmirror"
)

// When a synchronized htcondordb mirror is advertising, completed-job (history)
// reads can be served from it instead of the schedd. condor_history on a busy
// schedd scans the on-disk history file and competes directly with scheduling
// and negotiation, so offloading it is the clearest load win -- and safe,
// because history is append-only. Live job state stays on the schedd (it is the
// source of truth for in-flight JobStatus); analytical counts already have the
// dedicated aggregate_jobs tool. Routing is best-effort with a transparent
// fallback: any miss (no mirror, stale, gap, dial/query error) silently uses the
// schedd, so a query never fails because the mirror is behind.

// tryHistoryFromDB attempts to serve a job-history query from the htcondordb
// mirror. It returns (result, true) when the mirror answered, or (nil, false) to
// tell the caller to fall back to the schedd -- for every reason: no mirror, the
// freshness gate declined, a dial/query error, or an unparseable row. The result
// shares toolQueryHistory's exact shape (marshaled []*classad.ClassAd) so the
// caller cannot tell the source apart except via the provenance note and the
// "source" metadata.
func (s *Server) tryHistoryFromDB(ctx context.Context, constraint string, opts *htcondor.HistoryQueryOptions, typeName string) (interface{}, bool, dbmirror.Decision) {
	if !s.htcondordbEnabled() {
		return nil, false, decline(dbmirror.ReasonNotConfigured, "htcondordb routing is not configured")
	}
	// Routing is what skips the schedd handshake, so a delegated server
	// must know the schedd accepted this caller before answering out of
	// the mirror -- otherwise a token the schedd would refuse still gets
	// history. Over stdio the process is the user and its own credential
	// is what would have been used either way, so there is nothing to
	// establish (the same split toolQueryJobs makes).
	if s.delegated && htcondor.GetAuthenticatedUserFromContext(ctx) == "" {
		return nil, false, decline(dbmirror.ReasonNoOwnerScope,
			"the schedd has not identified this caller, so the mirror must not answer on its behalf")
	}
	info, err := s.discoverHTCondorDB(ctx)
	if err != nil {
		return nil, false, decline(dbmirror.ReasonNoMirror, err.Error()) // no mirror discoverable -> schedd
	}
	d := dbmirror.HistoryDecision(info, opts)
	if !d.Use {
		return nil, false, d
	}

	// History defaults to unlimited on the schedd; the mirror read must be bounded.
	limit := opts.Limit
	if limit <= 0 || limit > dbmirror.MaxLimit {
		limit = dbmirror.MaxLimit
	}

	dbc, closer, _, err := s.dbClient(ctx)
	if err != nil {
		return nil, false, decline(dbmirror.ReasonDialFailed, err.Error()) // dial failed -> schedd
	}
	defer closer()

	// Fetch one past the limit. The mirror has no global reverse-chron cursor, so
	// it must fetch the FULL matching set to order it most-recent-first; if that
	// set exceeds the limit, the fetched subset is not guaranteed to hold the
	// newest records, so defer to the schedd's proper backwards scan instead of
	// silently returning a wrong "recent N".
	rows, err := dbc.QueryRawProject(ctx, "history", constraint, opts.Projection, limit+1)
	if err != nil {
		return nil, false, decline(dbmirror.ReasonQueryFailed, err.Error()) // query failed -> schedd
	}
	if len(rows) > limit {
		// more matches than the cap -> schedd owns ordering
		return nil, false, decline(dbmirror.ReasonOversized,
			fmt.Sprintf("more than %d matches; the schedd's backwards scan owns ordering beyond that", limit))
	}

	records := make([]*classad.ClassAd, 0, len(rows))
	for _, r := range rows {
		ad, perr := classad.ParseOld(r)
		if perr != nil {
			// a corrupt row -> fall back rather than drop records
			return nil, false, decline(dbmirror.ReasonBadRow, perr.Error())
		}
		records = append(records, ad)
	}
	// Order the complete matching set most-recent-first (opts.Backwards default).
	sort.SliceStable(records, func(i, j int) bool {
		return dbmirror.RecencyKey(records[i]) > dbmirror.RecencyKey(records[j])
	})

	return historyResult(records, typeName, constraint, "htcondordb", "\n"+dbmirror.Provenance(info, d.Note)), true, d
}

// tryJobsFromDB attempts to serve a live job query (query_jobs) from the
// htcondordb mirror's "jobs" table (the mirrored job_queue.log). Returns
// (result, true) when the mirror answered, or (nil, false) to fall back to the
// schedd for every reason: DB tools disabled, no mirror, the freshness gate
// declined, no authenticated user to scope by, or a dial/query/parse error.
//
// It reproduces toolQueryJobs' scoping exactly, which is the point: routing must
// change where an answer comes from and never what it covers. Both paths take the
// scope from Server.ownerScope, so a confined call is confined identically here
// and an admin's unconfined one stays unconfined. The result shares
// toolQueryJobs' shape (renderJobsBase) so only the provenance note and "source"
// metadata reveal the backend.
func (s *Server) tryJobsFromDB(ctx context.Context, constraint string, projection []string, limit int, pageToken string) (interface{}, bool, dbmirror.Decision) {
	if !s.htcondordbEnabled() {
		return nil, false, decline(dbmirror.ReasonNotConfigured, "htcondordb routing is not configured")
	}
	// Without an identity we cannot tell whether this call is confined or
	// deliberately unconfined, so the mirror must not answer it.
	scope, ok := s.ownerScope(ctx)
	if !ok {
		return nil, false, decline(dbmirror.ReasonNoOwnerScope,
			"the caller could not be identified, so the mirror cannot tell whose jobs to return")
	}
	info, err := s.discoverHTCondorDB(ctx)
	if err != nil {
		return nil, false, decline(dbmirror.ReasonNoMirror, err.Error())
	}
	d := dbmirror.JobsDecision(info, pageToken)
	if !d.Use {
		return nil, false, d
	}

	// Owner-scope through the same helper the schedd path uses, so the
	// two backends cannot drift on what "my jobs" means. An unparseable
	// constraint declines to the schedd rather than being trusted.
	scoped := constraint
	if !scope.AllUsers {
		var err error
		if scoped, err = ownerScopedConstraint(scope.Owner, constraint); err != nil {
			return nil, false, decline(dbmirror.ReasonUnsupportedQuery,
				fmt.Sprintf("constraint cannot be owner-scoped for the mirror: %v", err))
		}
	}

	effLimit := limit
	if effLimit <= 0 || effLimit > dbmirror.MaxLimit {
		effLimit = dbmirror.MaxLimit
	}

	dbc, closer, _, err := s.dbClient(ctx)
	if err != nil {
		return nil, false, decline(dbmirror.ReasonDialFailed, err.Error())
	}
	defer closer()

	// Fetch one past the limit: if the full result exceeds what the caller asked
	// for, defer to the schedd so pagination (and its cursor/ordering) stays on
	// one backend -- the mirror only answers when it can answer completely, so it
	// never silently truncates while reporting has_more=false.
	rows, err := dbc.QueryRawProject(ctx, "jobs", scoped, projection, effLimit+1)
	if err != nil {
		return nil, false, decline(dbmirror.ReasonQueryFailed, err.Error())
	}
	if len(rows) > effLimit {
		return nil, false, decline(dbmirror.ReasonOversized,
			fmt.Sprintf("more than %d matches; pagination stays on the schedd", effLimit))
	}
	jobAds := make([]*classad.ClassAd, 0, len(rows))
	for _, r := range rows {
		ad, perr := classad.ParseOld(r)
		if perr != nil {
			return nil, false, decline(dbmirror.ReasonBadRow, perr.Error())
		}
		jobAds = append(jobAds, ad)
	}
	// Deterministic cluster.proc order (the schedd cursor is roughly this order).
	sort.SliceStable(jobAds, func(i, j int) bool { return jobKeyLess(jobAds[i], jobAds[j]) })

	note := "\n[source: htcondordb mirror"
	if info.Name != "" {
		note += fmt.Sprintf(" %q", info.Name)
	}
	if stale := dbmirror.JobQueueStaleness(info); stale > 0 {
		note += fmt.Sprintf("; job queue synced %ds ago", stale)
	}
	note += "; " + d.Note + "]"
	note += "\n" + scope.Note()

	text, metadata := renderJobsBase(jobAds, constraint, "htcondordb", note)
	return map[string]interface{}{
		"content":  []map[string]interface{}{{"type": "text", "text": text}},
		"metadata": metadata,
	}, true, d
}

// decline builds a Decision for a miss that happens outside the pure
// policy functions — discovery, dialing, or a result the mirror cannot
// answer completely. Same shape as a policy decline so the caller need
// not care which layer said no.
func decline(r dbmirror.Reason, note string) dbmirror.Decision {
	return dbmirror.Decision{Reason: r, Note: note}
}

// jobKeyLess orders two job ads by (ClusterId, ProcId) ascending.
func jobKeyLess(a, b *classad.ClassAd) bool {
	ac, _ := a.EvaluateAttrInt("ClusterId")
	bc, _ := b.EvaluateAttrInt("ClusterId")
	if ac != bc {
		return ac < bc
	}
	ap, _ := a.EvaluateAttrInt("ProcId")
	bp, _ := b.EvaluateAttrInt("ProcId")
	return ap < bp
}

// mirrorRequiredError turns a decline into a tool error when the mirror
// is mandatory (HTTP_API_DBMIRROR_REQUIRED). The operator has said the
// access point must not absorb this load even if that costs
// availability, so the tool reports why the mirror could not answer
// instead of quietly becoming schedd load. Returns nil on the default
// best-effort path, where the caller falls back.
func (s *Server) mirrorRequiredError(d dbmirror.Decision) error {
	if d.Use || !s.dbMirror.Required() {
		return nil
	}
	return fmt.Errorf("this query must be served from the htcondordb mirror "+
		"(HTTP_API_DBMIRROR_REQUIRED is set) and could not be: %s", d.Note)
}
