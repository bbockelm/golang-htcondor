package mcpserver

import (
	"context"
	"fmt"
	"slices"
	"sort"
	"strings"

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
// "source" metadata. limitCapped says the tool's ceiling, not the caller, set
// opts.Limit, which changes the advice a truncated answer carries.
func (s *Server) tryHistoryFromDB(ctx context.Context, constraint string, opts *htcondor.HistoryQueryOptions, typeName string, limitCapped bool) (interface{}, bool, dbmirror.Decision) {
	if !s.htcondordbEnabled() {
		return nil, false, decline(dbmirror.ReasonNotConfigured, "htcondordb routing is not configured")
	}
	// Routing is what skips the schedd handshake, so a delegated server
	// must know the schedd accepted this caller before answering out of
	// the mirror -- otherwise a token the schedd would refuse still gets
	// history. The HTTP transport sets the identity only from a
	// DC_NOP_READ ping the schedd accepted with the caller's own
	// credential, so an identity here means READ was granted. Over stdio
	// the process is the user and its own credential is what would have
	// been used either way, so there is nothing to establish (the same
	// split toolQueryJobs makes).
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

	dbc, closer, _, err := s.dbClient(ctx)
	if err != nil {
		return nil, false, decline(dbmirror.ReasonDialFailed, err.Error()) // dial failed -> schedd
	}
	defer closer()
	return mirrorHistoryResult(ctx, dbc, info, d, constraint, opts, typeName, limitCapped)
}

// mirrorHistoryResult is tryHistoryFromDB once routing has said yes (d) and the
// mirror is dialed: the read, and the result the tool returns.
func mirrorHistoryResult(ctx context.Context, dbc historyMirror, info *dbmirror.Info, d dbmirror.Decision,
	constraint string, opts *htcondor.HistoryQueryOptions, typeName string, limitCapped bool) (interface{}, bool, dbmirror.Decision) {
	// History defaults to unlimited on the schedd; the mirror read must be bounded.
	limit := opts.Limit
	if limit <= 0 || limit > dbmirror.MaxLimit {
		limit = dbmirror.MaxLimit
	}

	records, more, rd := readMirrorHistory(ctx, dbc, constraint, opts.Projection, limit)
	if !rd.Use {
		return nil, false, rd
	}
	if rd.Note != "" {
		d = rd
	}
	note := "\n" + dbmirror.Provenance(info, d.Note)
	if more {
		note = truncationNote(limit, limitCapped) + note
	}
	return historyResultWith(records, typeName, constraint, "htcondordb", note, historyExtras{hasMore: more}), true, d
}

// mirrorHistoryTable is the mirror's completed-job archive.
const mirrorHistoryTable = "history"

// historyMirror is the part of a dbrpc client a mirror history read uses.
type historyMirror interface {
	QueryRawProject(ctx context.Context, table, constraint string, attrs []string, limit int) ([]string, error)
	TopK(ctx context.Context, table, constraint string, attrs []string, orderAttr string, desc bool, k int) ([]string, error)
}

// readMirrorHistory reads the newest limit records matching constraint from the
// mirror's history archive, newest first, as the schedd's backwards scan would
// return them. more reports that further records matched. A decision with Use
// false means the mirror cannot answer faithfully and the schedd should; a
// served decision with a Note replaces the routing note in the provenance.
//
// A bounded probe (limit+1 rows) comes first. When it holds the whole match set,
// that set is ordered here. When it does not, the rows it holds are an arbitrary
// subset rather than the newest, so the mirror is asked again with server-side
// ordering (TopK on dbmirror.HistoryOrderAttr) -- see HistoryNewestDecision.
func readMirrorHistory(ctx context.Context, dbc historyMirror, constraint string, projection []string, limit int) ([]*classad.ClassAd, bool, dbmirror.Decision) {
	// Order by the same key in both branches. A projection that leaves the
	// order key out still needs it fetched to sort on; it is removed again
	// before the records go back.
	attrs, addedOrderAttr := withHistoryOrderAttr(projection)

	rows, err := dbc.QueryRawProject(ctx, mirrorHistoryTable, constraint, attrs, limit+1)
	if err != nil {
		return nil, false, decline(dbmirror.ReasonQueryFailed, err.Error()) // query failed -> schedd
	}
	if len(rows) <= limit {
		records, d := parseMirrorRows(rows)
		if !d.Use {
			return nil, false, d
		}
		sortNewestFirst(records)
		dropHistoryOrderAttr(records, addedOrderAttr)
		return records, false, d
	}

	if len(attrs) == 0 {
		return readNewestWholeHistory(ctx, dbc, constraint, limit)
	}
	top, err := dbc.TopK(ctx, mirrorHistoryTable, constraint, attrs, dbmirror.HistoryOrderAttr, true, limit+1)
	if d := dbmirror.HistoryNewestDecision(err, len(top), limit); !d.Use {
		return nil, false, d
	}
	records, pd := parseMirrorRows(top[:limit])
	if !pd.Use {
		return nil, false, pd
	}
	// TopK returns its rows best first, so they are not re-sorted.
	dropHistoryOrderAttr(records, addedOrderAttr)
	return records, true, dbmirror.HistoryNewestDecision(nil, len(top), limit)
}

// readNewestWholeHistory is readMirrorHistory's oversized branch for a caller
// that asked for every attribute. TopK returns only the attributes it is asked
// for, so it cannot carry whole ads; instead it finds the order-key value of the
// limit-th newest match, and the whole ads at or above that value are fetched in
// two bounded reads: everything strictly newer (fewer than limit rows), then as
// many rows tied at the boundary as are still needed.
func readNewestWholeHistory(ctx context.Context, dbc historyMirror, constraint string, limit int) ([]*classad.ClassAd, bool, dbmirror.Decision) {
	key := dbmirror.HistoryOrderAttr
	top, err := dbc.TopK(ctx, mirrorHistoryTable, constraint, []string{key}, key, true, limit+1)
	if d := dbmirror.HistoryNewestDecision(err, len(top), limit); !d.Use {
		return nil, false, d
	}
	boundaryAd, perr := classad.ParseOld(top[limit-1])
	if perr != nil {
		return nil, false, decline(dbmirror.ReasonBadRow, perr.Error())
	}
	boundary, ok := boundaryAd.EvaluateAttrInt(key)
	if !ok {
		return nil, false, decline(dbmirror.ReasonBadRow, fmt.Sprintf("an ordered row carries no integer %s", key))
	}

	newerRows, err := dbc.QueryRawProject(ctx, mirrorHistoryTable,
		fmt.Sprintf("(%s) && %s > %d", constraint, key, boundary), nil, limit+1)
	if err != nil {
		return nil, false, decline(dbmirror.ReasonQueryFailed, err.Error())
	}
	if len(newerRows) > limit {
		// Records arrived between the two reads and outnumber the page;
		// which of them are newest is no longer known from this read.
		return nil, false, decline(dbmirror.ReasonOversized,
			fmt.Sprintf("more than %d matches arrived while the mirror was being read; the schedd's backwards scan picks the newest", limit))
	}
	rows := newerRows
	if need := limit - len(newerRows); need > 0 {
		tied, err := dbc.QueryRawProject(ctx, mirrorHistoryTable,
			fmt.Sprintf("(%s) && %s == %d", constraint, key, boundary), nil, need)
		if err != nil {
			return nil, false, decline(dbmirror.ReasonQueryFailed, err.Error())
		}
		rows = append(rows, tied...)
	}
	records, d := parseMirrorRows(rows)
	if !d.Use {
		return nil, false, d
	}
	sortNewestFirst(records)
	return records, true, dbmirror.HistoryNewestDecision(nil, len(top), limit)
}

// withHistoryOrderAttr returns the attributes to fetch for projection so the
// order key is among them, and whether it had to be added. A nil projection
// (every attribute) already includes it.
func withHistoryOrderAttr(projection []string) ([]string, bool) {
	if len(projection) == 0 {
		return nil, false
	}
	for _, a := range projection {
		if strings.EqualFold(a, dbmirror.HistoryOrderAttr) {
			return projection, false
		}
	}
	return append(slices.Clip(projection), dbmirror.HistoryOrderAttr), true
}

// parseMirrorRows parses old-ClassAd rows. A row that will not parse declines
// the whole read rather than dropping a record.
func parseMirrorRows(rows []string) ([]*classad.ClassAd, dbmirror.Decision) {
	records := make([]*classad.ClassAd, 0, len(rows))
	for _, r := range rows {
		ad, perr := classad.ParseOld(r)
		if perr != nil {
			return nil, decline(dbmirror.ReasonBadRow, perr.Error())
		}
		records = append(records, ad)
	}
	return records, dbmirror.Decision{Use: true, Reason: dbmirror.ReasonServed}
}

// dropHistoryOrderAttr removes the order key from records that fetched it only
// to be ordered by it, so the caller gets the projection it asked for.
func dropHistoryOrderAttr(records []*classad.ClassAd, added bool) {
	if !added {
		return
	}
	for _, ad := range records {
		ad.Delete(dbmirror.HistoryOrderAttr)
	}
}

// sortNewestFirst orders history records most recent first, the order of the
// schedd's backwards scan (opts.Backwards, the default).
func sortNewestFirst(records []*classad.ClassAd) {
	sort.SliceStable(records, func(i, j int) bool {
		return dbmirror.RecencyKey(records[i]) > dbmirror.RecencyKey(records[j])
	})
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
	scope, ok := s.ownerScope(ctx, tierRead)
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
		if scoped, err = ownerScopedConstraint(scope, constraint); err != nil {
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

	text, metadata, structured := renderJobsBase(jobAds, constraint, "htcondordb", note)
	return withStructured(map[string]interface{}{
		"content":  []map[string]interface{}{{"type": "text", "text": text}},
		"metadata": metadata,
	}, structured), true, d
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
