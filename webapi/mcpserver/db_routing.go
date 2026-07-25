package mcpserver

import (
	"context"
	"fmt"
	"sort"

	"github.com/PelicanPlatform/classad/classad"

	htcondor "github.com/bbockelm/golang-htcondor"
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

// historyRouteToleranceSecs is the maximum mirror staleness at which history
// reads still prefer the mirror. Beyond it the mirror is lagging enough that the
// authoritative schedd is used instead.
const historyRouteToleranceSecs int64 = 300

// historyRouteDecision decides whether a job-history query may be served from the
// discovered htcondordb mirror rather than the schedd. It is pure so the policy
// is unit-tested without any I/O. useDB is true only when a fresh, gap-free
// mirror exists AND the request uses no schedd-specific scan semantics the mirror
// cannot reproduce faithfully (a `since` stop-scan, a `scan_limit` budget, or a
// forward/chronological scan). reason explains the choice for the provenance note.
func historyRouteDecision(info *htcondordbInfo, opts *htcondor.HistoryQueryOptions, toleranceSecs int64) (useDB bool, reason string) {
	if info == nil || info.Address == "" {
		return false, "no htcondordb mirror is advertising"
	}
	if info.HistoryGap {
		return false, "mirror reported a history durability gap"
	}
	if toleranceSecs > 0 && info.SecondsSinceSync > toleranceSecs {
		return false, fmt.Sprintf("mirror is stale (%ds since last sync > %ds tolerance)", info.SecondsSinceSync, toleranceSecs)
	}
	if opts != nil {
		if opts.Since != "" {
			return false, "query uses a 'since' stop-scan the mirror cannot reproduce"
		}
		if opts.ScanLimit > 0 {
			return false, "query sets scan_limit (a schedd scan budget)"
		}
		if !opts.Backwards {
			return false, "query requests a forward scan; the mirror serves recent-first only"
		}
	}
	return true, "served from the htcondordb mirror"
}

// jobsRouteToleranceSecs is the maximum job-queue mirror staleness at which live
// job queries prefer the mirror. It is much tighter than the history tolerance:
// job state (JobStatus, held/idle/running) is latency-sensitive, so a query is
// only served from the mirror when its job_queue.log tail is essentially current.
const jobsRouteToleranceSecs int64 = 60

// jobQueueStaleness is the mirror's CURRENT job-queue staleness in seconds. It
// uses the absolute last-sync time when advertised (now-LastSyncTime, correct
// regardless of how old the collector ad is) and falls back to the ad's frozen
// SecondsSinceSync only when the absolute stamp is missing.
func jobQueueStaleness(info *htcondordbInfo, nowUnix int64) int64 {
	if info.JobQueueLastSyncTime > 0 {
		if d := nowUnix - info.JobQueueLastSyncTime; d >= 0 {
			return d
		}
		return 0
	}
	return info.JobQueueSecondsSync
}

// jobsRouteDecision decides whether a live job query may be served from the
// htcondordb mirror rather than the schedd. Pure, so the policy is unit-tested.
// It requires a caught-up job-queue mirror whose current staleness is within
// tolerance, and it declines a paginated query (page_token) because the mirror
// read has no matching cursor -- the schedd owns pagination so successive pages
// stay on one backend with one ordering.
func jobsRouteDecision(info *htcondordbInfo, pageToken string, nowUnix, toleranceSecs int64) (useDB bool, reason string) {
	if info == nil || info.Address == "" {
		return false, "no htcondordb mirror is advertising"
	}
	if pageToken != "" {
		return false, "a paginated query continues on the schedd"
	}
	if !info.JobQueueCaughtUp {
		return false, "mirror's job queue is not caught up to the schedd"
	}
	if stale := jobQueueStaleness(info, nowUnix); toleranceSecs > 0 && stale > toleranceSecs {
		return false, fmt.Sprintf("mirror's job queue last synced %ds ago (> %ds tolerance)", stale, toleranceSecs)
	}
	return true, "served from the htcondordb mirror (job queue caught up)"
}

// recencyKey ranks a completed-job ad for reverse-chronological ordering: the
// last status transition, falling back to the completion time. Both are Unix
// seconds on a job ad; 0 sorts oldest.
func recencyKey(ad *classad.ClassAd) int64 {
	if v, ok := ad.EvaluateAttrInt("EnteredCurrentStatus"); ok && v > 0 {
		return v
	}
	v, _ := ad.EvaluateAttrInt("CompletionDate")
	return v
}

// tryHistoryFromDB attempts to serve a job-history query from the htcondordb
// mirror. It returns (result, true) when the mirror answered, or (nil, false) to
// tell the caller to fall back to the schedd -- for every reason: no mirror, the
// freshness gate declined, a dial/query error, or an unparseable row. The result
// shares toolQueryHistory's exact shape (marshaled []*classad.ClassAd) so the
// caller cannot tell the source apart except via the provenance note and the
// "source" metadata.
func (s *Server) tryHistoryFromDB(ctx context.Context, constraint string, opts *htcondor.HistoryQueryOptions, typeName string) (interface{}, bool) {
	if !s.htcondordbEnabled() {
		return nil, false
	}
	info, err := s.discoverHTCondorDB(ctx)
	if err != nil {
		return nil, false // no mirror discoverable -> schedd
	}
	useDB, reason := historyRouteDecision(info, opts, historyRouteToleranceSecs)
	if !useDB {
		return nil, false
	}

	// History defaults to unlimited on the schedd; the mirror read must be bounded.
	limit := opts.Limit
	if limit <= 0 || limit > dbMaxLimit {
		limit = dbMaxLimit
	}

	dbc, closer, _, err := s.dbClient(ctx)
	if err != nil {
		return nil, false // dial failed -> schedd
	}
	defer closer()

	// Fetch one past the limit. The mirror has no global reverse-chron cursor, so
	// it must fetch the FULL matching set to order it most-recent-first; if that
	// set exceeds the limit, the fetched subset is not guaranteed to hold the
	// newest records, so defer to the schedd's proper backwards scan instead of
	// silently returning a wrong "recent N".
	rows, err := dbc.QueryRawProject(ctx, "history", constraint, opts.Projection, limit+1)
	if err != nil {
		return nil, false // query failed -> schedd
	}
	if len(rows) > limit {
		return nil, false // more matches than the cap -> schedd owns ordering
	}

	records := make([]*classad.ClassAd, 0, len(rows))
	for _, r := range rows {
		ad, perr := classad.ParseOld(r)
		if perr != nil {
			return nil, false // a corrupt row -> fall back rather than drop records
		}
		records = append(records, ad)
	}
	// Order the complete matching set most-recent-first (opts.Backwards default).
	sort.SliceStable(records, func(i, j int) bool {
		return recencyKey(records[i]) > recencyKey(records[j])
	})

	note := "\n[source: htcondordb mirror"
	if info.Name != "" {
		note += fmt.Sprintf(" %q", info.Name)
	}
	if info.SecondsSinceSync > 0 {
		note += fmt.Sprintf("; synced %ds ago", info.SecondsSinceSync)
	}
	note += "; " + reason + "]"

	return historyResult(records, typeName, constraint, "htcondordb", note), true
}

// tryJobsFromDB attempts to serve a live job query (query_jobs) from the
// htcondordb mirror's "jobs" table (the mirrored job_queue.log). Returns
// (result, true) when the mirror answered, or (nil, false) to fall back to the
// schedd for every reason: DB tools disabled, no mirror, the freshness gate
// declined, no authenticated user to scope by, or a dial/query/parse error.
//
// It reproduces toolQueryJobs' scoping exactly: that path self-scopes to the
// authenticated user unconditionally (FetchMyJobs + Owner), with NO admin
// bypass, so this does the same via an Owner constraint -- routing must not widen
// what a caller sees. The result shares toolQueryJobs' shape (renderJobsBase) so
// only the provenance note and "source" metadata reveal the backend.
func (s *Server) tryJobsFromDB(ctx context.Context, constraint string, projection []string, limit int, pageToken string, nowUnix int64) (interface{}, bool) {
	if !s.htcondordbEnabled() {
		return nil, false
	}
	// toolQueryJobs self-scopes to the authenticated user; without one we cannot
	// safely bound the mirror read, so leave it to the schedd.
	user := htcondor.GetAuthenticatedUserFromContext(ctx)
	if user == "" {
		return nil, false
	}
	info, err := s.discoverHTCondorDB(ctx)
	if err != nil {
		return nil, false
	}
	useDB, reason := jobsRouteDecision(info, pageToken, nowUnix, jobsRouteToleranceSecs)
	if !useDB {
		return nil, false
	}

	if constraint == "" {
		constraint = "true"
	}
	// Owner-scope safely: AND the balanced, re-serialized constraint with the
	// owner clause so a crafted constraint cannot escape the AND and widen the
	// result past the caller's own jobs. An unparseable constraint falls back to
	// the schedd (whose job path is structurally owner-scoped) rather than trust.
	safeConstraint, err := classadBalanced(constraint)
	if err != nil {
		return nil, false
	}
	scoped := fmt.Sprintf("(%s) && (Owner == %s)", safeConstraint, classadStringLit(user))

	effLimit := limit
	if effLimit <= 0 || effLimit > dbMaxLimit {
		effLimit = dbMaxLimit
	}

	dbc, closer, _, err := s.dbClient(ctx)
	if err != nil {
		return nil, false
	}
	defer closer()

	// Fetch one past the limit: if the full result exceeds what the caller asked
	// for, defer to the schedd so pagination (and its cursor/ordering) stays on
	// one backend -- the mirror only answers when it can answer completely, so it
	// never silently truncates while reporting has_more=false.
	rows, err := dbc.QueryRawProject(ctx, "jobs", scoped, projection, effLimit+1)
	if err != nil {
		return nil, false
	}
	if len(rows) > effLimit {
		return nil, false
	}
	jobAds := make([]*classad.ClassAd, 0, len(rows))
	for _, r := range rows {
		ad, perr := classad.ParseOld(r)
		if perr != nil {
			return nil, false
		}
		jobAds = append(jobAds, ad)
	}
	// Deterministic cluster.proc order (the schedd cursor is roughly this order).
	sort.SliceStable(jobAds, func(i, j int) bool { return jobKeyLess(jobAds[i], jobAds[j]) })

	note := "\n[source: htcondordb mirror"
	if info.Name != "" {
		note += fmt.Sprintf(" %q", info.Name)
	}
	if stale := jobQueueStaleness(info, nowUnix); stale > 0 {
		note += fmt.Sprintf("; job queue synced %ds ago", stale)
	}
	note += "; " + reason + "]"

	text, metadata := renderJobsBase(jobAds, constraint, "htcondordb", note)
	return map[string]interface{}{
		"content":  []map[string]interface{}{{"type": "text", "text": text}},
		"metadata": metadata,
	}, true
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
