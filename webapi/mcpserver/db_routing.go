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

	// History defaults to unlimited on the schedd; the mirror read must be
	// bounded, so cap it and note when the cap bit.
	limit := opts.Limit
	capped := false
	if limit <= 0 || limit > dbMaxLimit {
		limit = dbMaxLimit
		capped = true
	}

	dbc, closer, _, err := s.dbClient(ctx)
	if err != nil {
		return nil, false // dial failed -> schedd
	}
	defer closer()

	rows, err := dbc.QueryRawProject(ctx, "history", constraint, opts.Projection, limit)
	if err != nil {
		return nil, false // query failed -> schedd
	}

	records := make([]*classad.ClassAd, 0, len(rows))
	for _, r := range rows {
		ad, perr := classad.ParseOld(r)
		if perr != nil {
			return nil, false // a corrupt row -> fall back rather than drop records
		}
		records = append(records, ad)
	}
	// The mirror has no global reverse-chron cursor, so order the fetched set
	// most-recent-first ourselves (opts.Backwards is the default here).
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
	note += "; " + reason
	if capped && len(records) >= limit {
		note += fmt.Sprintf("; capped at %d and ordered recent-first, so older matches beyond the cap are omitted -- narrow the constraint or set a limit for exact results", limit)
	}
	note += "]"

	return historyResult(records, typeName, constraint, "htcondordb", note), true
}
