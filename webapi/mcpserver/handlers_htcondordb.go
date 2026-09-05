package mcpserver

import (
	"context"

	"fmt"
	htcondor "github.com/bbockelm/golang-htcondor"
	"strings"
	"time"

	"github.com/PelicanPlatform/classad/dbrpc"

	"github.com/bbockelm/golang-htcondor/webapi/dbmirror"
)

// htcondordbEnabled reports whether the DB-backed tools can run
// (collector + config present, so the mirror can be discovered and
// authenticated to).
func (s *Server) htcondordbEnabled() bool {
	return s.dbMirror.Enabled()
}

// discoverHTCondorDB finds the mirror through the collector.
func (s *Server) discoverHTCondorDB(ctx context.Context) (*dbmirror.Info, error) {
	if !s.htcondordbEnabled() {
		return nil, fmt.Errorf("htcondordb tools unavailable: no collector or HTCondor config configured")
	}
	return s.dbMirror.Discover(ctx)
}

// dbClient dials the mirror over an authenticated DBSession.
func (s *Server) dbClient(ctx context.Context) (*dbrpc.Client, func(), *dbmirror.Info, error) {
	if !s.htcondordbEnabled() {
		return nil, nil, nil, fmt.Errorf("htcondordb tools unavailable: no collector or HTCondor config configured")
	}
	return s.dbMirror.Client(ctx)
}

// toolQueryHistoryDB queries completed jobs from the htcondordb "history" archive. Owner-scoped:
// a non-admin caller only ever sees their own completed jobs.
func (s *Server) toolQueryHistoryDB(ctx context.Context, args map[string]interface{}) (interface{}, error) {
	constraint, ok := s.scopeToOwner(ctx, stringArg(args, "constraint"))
	if !ok {
		return nil, fmt.Errorf("authentication required")
	}
	if constraint == "" {
		constraint = "true"
	}
	limit := dbLimitArg(args)

	dbc, closer, info, err := s.dbClient(ctx)
	if err != nil {
		return nil, err
	}
	defer closer()

	rows, err := dbc.QueryTable(ctx, "history", constraint, limit)
	if err != nil {
		return nil, fmt.Errorf("history query failed: %w", err)
	}
	return dbTextResult("completed jobs (history archive)", rows, limit, info), nil
}

// toolQueryJobsAsOf queries the live-jobs table as it was at a past instant (time-travel). Gated
// on the database having time-travel enabled. as_of accepts RFC3339 or a negative Go duration
// ("-1h") relative to now.
func (s *Server) toolQueryJobsAsOf(ctx context.Context, args map[string]interface{}) (interface{}, error) {
	constraint, ok := s.scopeToOwner(ctx, stringArg(args, "constraint"))
	if !ok {
		return nil, fmt.Errorf("authentication required")
	}
	if constraint == "" {
		constraint = "true"
	}
	asOf, err := parseAsOf(stringArg(args, "as_of"))
	if err != nil {
		return nil, err
	}
	limit := dbLimitArg(args)

	dbc, closer, info, err := s.dbClient(ctx)
	if err != nil {
		return nil, err
	}
	defer closer()
	if !info.TimeTravelEnabled {
		return nil, fmt.Errorf("this htcondordb database does not have time-travel enabled; cannot query historical state")
	}

	rows, err := dbc.QueryAsOfTable(ctx, "jobs", constraint, limit, asOf)
	if err != nil {
		return nil, fmt.Errorf("time-travel query failed: %w", err)
	}
	return dbTextResult(fmt.Sprintf("jobs as of %s", asOf.UTC().Format(time.RFC3339)), rows, limit, info), nil
}

// toolAggregateJobs runs a server-side GROUP BY over a table (default "jobs"), returning counts
// per group -- the right tool for "how many jobs are idle/held/running", cheap because only the
// grouped result crosses the wire.
func (s *Server) toolAggregateJobs(ctx context.Context, args map[string]interface{}) (interface{}, error) {
	constraint, ok := s.scopeToOwner(ctx, stringArg(args, "constraint"))
	if !ok {
		return nil, fmt.Errorf("authentication required")
	}
	if constraint == "" {
		constraint = "true"
	}
	table := stringArg(args, "table")
	if table == "" {
		table = "jobs"
	}
	var groupBy []string
	if raw, ok := args["group_by"].([]interface{}); ok {
		for _, g := range raw {
			if gs, _ := g.(string); gs != "" {
				groupBy = append(groupBy, gs)
			}
		}
	}

	dbc, closer, info, err := s.dbClient(ctx)
	if err != nil {
		// No mirror. The schedd can group live jobs itself, which is
		// the whole point of preferring a count over a listing: without
		// this, a pool with no htcondordb had no counting tool at all
		// and the advice everywhere else -- "use aggregate_jobs rather
		// than walking the queue" -- pointed at something that did not
		// work for them.
		//
		// Only the live queue, though. history and the other tables
		// exist in the mirror alone; the schedd has no such thing to
		// group over, and saying so beats a confusing empty result.
		if table != "jobs" {
			return nil, fmt.Errorf("aggregating %q needs an htcondordb mirror, which is not available: %w", table, err)
		}
		return s.aggregateJobsFromSchedd(ctx, constraint, groupBy)
	}
	defer closer()

	aggRows, err := dbc.AggregateTable(ctx, table, constraint, groupBy, []dbrpc.AggSpec{{Func: dbrpc.AggCount, Arg: "*"}})
	if err != nil {
		return nil, fmt.Errorf("aggregate query failed: %w", err)
	}

	var b strings.Builder
	fmt.Fprintf(&b, "Aggregate COUNT over %q (%d group(s))", table, len(aggRows))
	if len(groupBy) > 0 {
		fmt.Fprintf(&b, " by %s", strings.Join(groupBy, ", "))
	}
	b.WriteString(":\n")
	for _, r := range aggRows {
		if len(groupBy) > 0 {
			fmt.Fprintf(&b, "  %s = %s\n", strings.Join(r.Group, "/"), strings.Join(r.Values, ","))
		} else {
			fmt.Fprintf(&b, "  count = %s\n", strings.Join(r.Values, ","))
		}
	}
	b.WriteString(freshnessNote(info))
	return textResult(b.String()), nil
}

// --- helpers ---

func stringArg(args map[string]interface{}, key string) string {
	v, _ := args[key].(string)
	return strings.TrimSpace(v)
}

// dbLimitArg reads the optional "limit" tool argument, defaulting to
// dbmirror.DefaultLimit and clamping to dbmirror.MaxLimit.
func dbLimitArg(args map[string]interface{}) int {
	n := dbmirror.DefaultLimit
	switch v := args["limit"].(type) {
	case float64:
		n = int(v)
	case int:
		n = v
	}
	if n <= 0 {
		n = dbmirror.DefaultLimit
	}
	if n > dbmirror.MaxLimit {
		n = dbmirror.MaxLimit
	}
	return n
}

// parseAsOf accepts an RFC3339 timestamp or a negative Go duration relative to now ("-90m").
func parseAsOf(s string) (time.Time, error) {
	if s == "" {
		return time.Time{}, fmt.Errorf("as_of is required (an RFC3339 timestamp or a relative duration like \"-1h\")")
	}
	if t, err := time.Parse(time.RFC3339, s); err == nil {
		return t, nil
	}
	if d, err := time.ParseDuration(s); err == nil {
		if d > 0 {
			d = -d // a bare "1h" means "1h ago"
		}
		return time.Now().Add(d), nil
	}
	return time.Time{}, fmt.Errorf("could not parse as_of %q: use RFC3339 (2026-07-24T00:00:00Z) or a relative duration (-1h)", s)
}

// dbTextResult formats query rows (each an old-ClassAd text blob) into a text tool result with
// a count, truncation note, and freshness annotation.
func dbTextResult(title string, rows []string, limit int, info *dbmirror.Info) interface{} {
	var b strings.Builder
	fmt.Fprintf(&b, "%d %s", len(rows), title)
	if len(rows) >= limit {
		fmt.Fprintf(&b, " (capped at limit=%d; narrow the constraint or raise the limit for more)", limit)
	}
	b.WriteString(":\n\n")
	for i, r := range rows {
		fmt.Fprintf(&b, "--- record %d ---\n%s\n", i+1, strings.TrimSpace(r))
	}
	b.WriteString(freshnessNote(info))
	return textResult(b.String())
}

// freshnessNote annotates a result with the mirror's staleness and any durability gap, so an
// agent can weigh how current the DB-backed answer is. The staleness is recomputed from the
// mirror's absolute sync stamp rather than read off the ad, whose own figure is frozen at the
// ad's build time and so understates the lag by up to a collector update interval.
func freshnessNote(info *dbmirror.Info) string {
	if info == nil {
		return ""
	}
	var b strings.Builder
	b.WriteString("\n[source: htcondordb")
	if info.Name != "" {
		fmt.Fprintf(&b, " %q", info.Name)
	}
	if s := dbmirror.HistoryStaleness(info); s > 0 {
		fmt.Fprintf(&b, "; last synced %ds ago", s)
	}
	if info.HistoryGap {
		b.WriteString("; WARNING: a history durability gap was detected -- some completed jobs may be missing")
	}
	b.WriteString("]")
	return b.String()
}

func textResult(text string) interface{} {
	return map[string]interface{}{
		"content": []map[string]interface{}{
			{"type": "text", "text": text},
		},
	}
}

// aggregateJobsFromSchedd counts live jobs with the schedd doing the
// grouping, for deployments with no htcondordb mirror.
//
// The schedd walks its queue once and returns one row per group rather
// than one ad per job (ProjectionIsGroupBy; see
// Schedd.AggregateJobs). That is the difference between an answer and
// a transfer: counting by listing would move every matching ad here
// only to discard it.
func (s *Server) aggregateJobsFromSchedd(ctx context.Context, constraint string, groupBy []string) (interface{}, error) {
	// selfScopedQueryOptions rather than a hardcoded FetchMyJobs, so an
	// admin is exempt here as everywhere else. Note this is consistency
	// rather than a behaviour fix on its own: the schedd routes a
	// ProjectionIsGroupBy query to command_query_job_aggregates BEFORE
	// it looks at owner filtering at all, and this request ad never
	// carried a MyJobs attribute, so the flag was not confining anything.
	opts, ok := s.selfScopedQueryOptions(ctx, nil)
	if !ok {
		return nil, fmt.Errorf("authentication required")
	}

	// Ask for one more group than we will show. The schedd stops at
	// LimitResults and says nothing about it -- JobAggregationResults::
	// next() simply returns nullptr once results_returned reaches the
	// limit -- so an extra row is the only way to learn that more
	// existed. Without this the answer was silently the alphabetically
	// first 50 groups, because the default came from QueryOptions.
	// ApplyDefaults, which sets the LISTING default of 50. A GROUP BY is
	// not a listing.
	opts.Limit = aggregateGroupLimit + 1
	rows, err := s.schedd.AggregateJobs(ctx, constraint, groupBy, opts)
	if err != nil {
		return nil, fmt.Errorf("aggregate query failed: %w", err)
	}

	truncated := len(rows) > aggregateGroupLimit
	if truncated {
		rows = rows[:aggregateGroupLimit]
	}

	// A truncated grouping cannot be summed into a total -- that is how
	// the count came out ~15,000 short of the queue. Ask again without a
	// grouping, which returns one row and cannot be truncated, so the
	// headline number is right even when the breakdown is partial. Only
	// on the truncated path: the common case still costs one query.
	exactTotal := int64(-1)
	if truncated {
		totalOpts, ok := s.selfScopedQueryOptions(ctx, nil)
		if ok {
			totalOpts.Limit = 2
			if totalRows, terr := s.schedd.AggregateJobs(ctx, constraint, nil, totalOpts); terr == nil {
				exactTotal = 0
				for _, r := range totalRows {
					exactTotal += r.Count
				}
			}
		}
	}

	return textResult(renderScheddAggregate(constraint, groupBy, rows, truncated, exactTotal)), nil
}

// aggregateGroupLimit bounds how many groups an aggregate returns. It is
// deliberately not QueryOptions' listing default of 50: a "count jobs by
// owner" on a busy access point has hundreds of owners, and 50 of them
// is not an answer to the question asked.
const aggregateGroupLimit = 500

// renderScheddAggregate formats a schedd-served aggregate for an agent.
//
// Everything here exists because the previous version told the caller
// less than it knew. It reported a group count and a total, both derived
// from a silently truncated result, with no way for a reader to tell
// that either was partial -- and the total was simply wrong. An agent
// acting on that has no signal to look further.
//
// The effective constraint is echoed for the same reason. It is not
// always what the caller passed: a non-admin gets an owner clause ANDed
// in, so a caller seeing zero can tell "no such jobs" apart from "not
// your jobs", which is otherwise indistinguishable from the outside.
func renderScheddAggregate(constraint string, groupBy []string, rows []htcondor.AggregateRow, truncated bool, exactTotal int64) string {
	var b strings.Builder
	fmt.Fprintf(&b, "Aggregate COUNT over live jobs (%d group(s)", len(rows))
	if truncated {
		fmt.Fprintf(&b, ", TRUNCATED at %d -- more groups matched", aggregateGroupLimit)
	}
	b.WriteString(")")
	if len(groupBy) > 0 {
		fmt.Fprintf(&b, " by %s", strings.Join(groupBy, ", "))
	}
	b.WriteString(":\n")

	var shown int64
	for _, r := range rows {
		shown += r.Count
		if len(groupBy) > 0 {
			fmt.Fprintf(&b, "  %s = %d\n", strings.Join(r.Group, "/"), r.Count)
		} else {
			fmt.Fprintf(&b, "  count = %d\n", r.Count)
		}
	}

	b.WriteString("\n[source: schedd")

	// The constraint actually applied, which may not be the one asked
	// for.
	shownConstraint := constraint
	if shownConstraint == "" {
		shownConstraint = "true"
	}
	fmt.Fprintf(&b, "; constraint applied: %s", shownConstraint)

	switch {
	case truncated && exactTotal >= 0:
		fmt.Fprintf(&b, "; %d job(s) match in total, of which %d are in the %d group(s) shown. "+
			"The groups are the alphabetically first ones; narrow the constraint to see the rest",
			exactTotal, shown, len(rows))
	case truncated:
		fmt.Fprintf(&b, "; %d job(s) in the %d group(s) shown, and MORE GROUPS MATCHED that are not "+
			"listed -- this total is a lower bound. Narrow the constraint to see the rest", shown, len(rows))
	default:
		fmt.Fprintf(&b, "; %d job(s) in the live queue", shown)
	}

	b.WriteString(". Completed jobs are not included -- history lives in an htcondordb mirror, " +
		"which this pool does not have.]")
	return b.String()
}
