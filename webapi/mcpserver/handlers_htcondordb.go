package mcpserver

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/PelicanPlatform/classad/classad"
	"github.com/PelicanPlatform/classad/dbrpc"

	htcondor "github.com/bbockelm/golang-htcondor"
)

// dbSessionCommand is htcondordb's DBSession CEDAR command
// (github.com/bbockelm/htcondordb/command.DBSession = 74000). It is duplicated here so webapi
// need not depend on the htcondordb module, matching how htcondordb/kafkasync duplicates it.
const dbSessionCommand = 74000

// htcondordbAdType is the MyType an htcondordb daemon advertises to the collector.
const htcondordbAdType = "HTCondorDB"

const (
	dbDefaultLimit = 200
	dbMaxLimit     = 2000
	dbInfoTTL      = 30 * time.Second
)

// htcondordbInfo is a discovered database's location, capabilities, and freshness, parsed from
// its collector advertisement.
type htcondordbInfo struct {
	Name              string
	Address           string
	TimeTravelEnabled bool
	SecondsSinceSync  int64
	HistoryGap        bool
}

// discoverHTCondorDB finds the htcondordb database by querying the collector for its ad (result
// cached for dbInfoTTL). It errors when no collector is configured or nothing is advertising.
func (s *Server) discoverHTCondorDB(ctx context.Context) (*htcondordbInfo, error) {
	if s.collector == nil {
		return nil, fmt.Errorf("htcondordb tools unavailable: no collector configured for discovery")
	}
	s.dbMu.Lock()
	if s.dbInfo != nil && time.Since(s.dbInfoAt) < dbInfoTTL {
		info := s.dbInfo
		s.dbMu.Unlock()
		return info, nil
	}
	s.dbMu.Unlock()

	ads, err := s.collector.QueryAds(ctx, htcondordbAdType, "")
	if err != nil {
		return nil, fmt.Errorf("querying collector for the htcondordb ad: %w", err)
	}
	if len(ads) == 0 {
		return nil, fmt.Errorf("no htcondordb database is advertising to the collector")
	}
	info := parseHTCondorDBAd(ads[0])
	if info.Address == "" {
		return nil, fmt.Errorf("the htcondordb ad has no MyAddress; cannot connect")
	}
	s.dbMu.Lock()
	s.dbInfo, s.dbInfoAt = info, time.Now()
	s.dbMu.Unlock()
	return info, nil
}

func parseHTCondorDBAd(ad *classad.ClassAd) *htcondordbInfo {
	info := &htcondordbInfo{}
	info.Name, _ = ad.EvaluateAttrString("Name")
	info.Address, _ = ad.EvaluateAttrString("MyAddress")
	info.TimeTravelEnabled, _ = ad.EvaluateAttrBool("TimeTravelEnabled")
	info.HistoryGap, _ = ad.EvaluateAttrBool("HistoryGapDetected")
	info.SecondsSinceSync, _ = ad.EvaluateAttrInt("HistorySecondsSinceSync")
	return info
}

// dbClient dials the discovered htcondordb over an authenticated DBSession and returns a dbrpc
// client, a closer the caller must invoke, and the discovered info (for freshness annotation).
func (s *Server) dbClient(ctx context.Context) (*dbrpc.Client, func(), *htcondordbInfo, error) {
	info, err := s.discoverHTCondorDB(ctx)
	if err != nil {
		return nil, nil, nil, err
	}
	if s.htcondorConfig == nil {
		return nil, nil, nil, fmt.Errorf("htcondordb tools unavailable: no HTCondor config for authentication")
	}
	sec, err := htcondor.GetSecurityConfig(s.htcondorConfig, dbSessionCommand, "CLIENT")
	if err != nil {
		return nil, nil, nil, fmt.Errorf("building htcondordb security config: %w", err)
	}
	sec.Command = dbSessionCommand
	cl, err := htcondor.DialSinful(ctx, info.Address, sec, nil)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("connecting to htcondordb at %s: %w", info.Address, err)
	}
	dbc := dbrpc.NewClient(dbrpc.NewCedarConn(ctx, cl.GetStream()))
	return dbc, func() { _ = cl.Close() }, info, nil
}

// htcondordbEnabled reports whether the DB-backed tools can run (collector + config present).
func (s *Server) htcondordbEnabled() bool {
	return s.collector != nil && s.htcondorConfig != nil
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
	limit := dbIntArg(args, "limit", dbDefaultLimit, dbMaxLimit)

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
	limit := dbIntArg(args, "limit", dbDefaultLimit, dbMaxLimit)

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
		return nil, err
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

func dbIntArg(args map[string]interface{}, key string, def, max int) int {
	n := def
	switch v := args[key].(type) {
	case float64:
		n = int(v)
	case int:
		n = v
	}
	if n <= 0 {
		n = def
	}
	if n > max {
		n = max
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
func dbTextResult(title string, rows []string, limit int, info *htcondordbInfo) interface{} {
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
// agent can weigh how current the DB-backed answer is.
func freshnessNote(info *htcondordbInfo) string {
	if info == nil {
		return ""
	}
	var b strings.Builder
	b.WriteString("\n[source: htcondordb")
	if info.Name != "" {
		fmt.Fprintf(&b, " %q", info.Name)
	}
	if info.SecondsSinceSync > 0 {
		fmt.Fprintf(&b, "; last synced %ds ago", info.SecondsSinceSync)
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
