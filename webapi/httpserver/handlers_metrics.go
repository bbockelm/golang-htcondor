package httpserver

// The metrics query endpoint: a read-only, owner-scoped, time-bucketed
// aggregate over the htcondordb archive time-series tables (today just
// job_metrics -- per-job resource-usage samples). It is deliberately
// general: the job page is the first caller, but the same surface answers
// the fleet questions we already know are coming -- "memory by Owner",
// "GPU hours by ProjectName" -- by naming those columns in `group_by`.
//
// GET /api/v1/metrics/{table}
//   ?constraint=<ClassAd expr>      WHERE (owner-scoped server-side)
//   &group_by=RunInstanceID,Owner   dimensions, in output order
//   &bucket=15m                     time bucket on the table's time attr
//   &agg=max:MemoryUsage,avg:CpuUtil aggregates, func:Attr (or count:*)
//   &since=<unix>&until=<unix>       time window on the time attr
//
// Response: { enabled, table, columns:[{name,kind,func,attr,bucket_seconds}],
//             rows:[[...]] }. When the sampler is off (the archive does not
// exist, or this server is too old to aggregate archives) the endpoint
// answers 200 {enabled:false} rather than an error, so a caller can hide
// the feature without special-casing a failure.

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/PelicanPlatform/classad/dbrpc"
)

// metricsTableDef is an allowlisted archive table and the attribute its
// rows are timestamped by (the column `bucket`, `since` and `until` act on).
type metricsTableDef struct {
	timeAttr string
}

// metricsTables is the allowlist. Only these tables are reachable; an
// arbitrary archive name is rejected so this never becomes a generic
// read-any-table hole.
var metricsTables = map[string]metricsTableDef{
	"job_metrics": {timeAttr: "SampleTime"},
}

var metricsAggFuncs = map[string]dbrpc.AggFunc{
	"count": dbrpc.AggCount,
	"sum":   dbrpc.AggSum,
	"avg":   dbrpc.AggAvg,
	"mean":  dbrpc.AggAvg,
	"min":   dbrpc.AggMin,
	"max":   dbrpc.AggMax,
}

// metricsIdent guards attribute names before they go into a group column or
// an aggregate arg. Constraints are re-serialized by the ClassAd parser
// (bulkOwnerScope), but group/agg attrs are passed as names, so keep them
// to plain ClassAd identifiers.
var metricsIdent = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)

// metricsMaxRows caps the response so a broad group-by cannot return an
// unbounded result to the browser.
const metricsMaxRows = 20000

type metricsColumn struct {
	Name string `json:"name"`
	Kind string `json:"kind"` // "group" | "metric"
	Func string `json:"func,omitempty"`
	Attr string `json:"attr,omitempty"`
	// BucketSeconds is set on the time-bucketed group column only.
	BucketSeconds int64 `json:"bucket_seconds,omitempty"`
}

type metricsResponse struct {
	Enabled       bool            `json:"enabled"`
	Table         string          `json:"table"`
	TimeAttr      string          `json:"time_attr,omitempty"`
	BucketSeconds int64           `json:"bucket_seconds,omitempty"`
	Columns       []metricsColumn `json:"columns,omitempty"`
	Rows          [][]string      `json:"rows,omitempty"`
	Truncated     bool            `json:"truncated,omitempty"`
}

func (s *Handler) handleMetricsQuery(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		s.writeError(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}

	table := strings.Trim(strings.TrimPrefix(r.URL.Path, "/api/v1/metrics/"), "/")
	def, ok := metricsTables[table]
	if !ok {
		s.writeError(w, http.StatusNotFound, fmt.Sprintf("unknown metrics table %q", table))
		return
	}

	ctx, needsRedirect, err := s.requireAuthentication(r)
	if err != nil {
		if needsRedirect {
			s.redirectToLogin(w, r)
			return
		}
		s.writeError(w, http.StatusUnauthorized, fmt.Sprintf("Authentication failed: %v", err))
		return
	}

	// A server with no mirror has nothing to read: report the feature off
	// rather than erroring, same as a missing archive below.
	if !s.dbMirror.Enabled() {
		s.writeJSON(w, http.StatusOK, metricsResponse{Enabled: false, Table: table})
		return
	}

	q := r.URL.Query()

	bucket, err := parseBucketSeconds(q.Get("bucket"))
	if err != nil {
		s.writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	groups, groupCols, err := parseMetricsGroups(q.Get("group_by"), def.timeAttr, bucket)
	if err != nil {
		s.writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	aggs, aggCols, err := parseMetricsAggs(q.Get("agg"))
	if err != nil {
		s.writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	constraint, err := metricsConstraint(q.Get("constraint"), def.timeAttr, q.Get("since"), q.Get("until"))
	if err != nil {
		s.writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	// Owner-scope exactly as the bulk job endpoints do: a non-admin browser
	// session is confined to its own Owner, an admin or API-token caller is
	// left as-is. Archive reads are not ownership-checked downstream, so
	// this clause is what keeps one user out of another's samples.
	constraint, err = s.bulkOwnerScope(ctx, r, constraint)
	if err != nil {
		s.writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	dbc, closer, _, err := s.dbMirror.Client(ctx)
	if err != nil {
		s.writeError(w, http.StatusBadGateway, fmt.Sprintf("mirror unavailable: %v", err))
		return
	}
	defer closer()

	qctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()

	rows, err := dbc.ArchiveAggregateBucketed(qctx, table, constraint, groupCols, aggs)
	if err != nil {
		// The sampler being off looks like a missing archive; an older
		// server looks like unsupported. Either way the feature is simply
		// unavailable here -- report it off, do not 500 a page over it.
		if metricsUnavailable(err) {
			s.writeJSON(w, http.StatusOK, metricsResponse{Enabled: false, Table: table})
			return
		}
		s.writeError(w, http.StatusBadGateway, fmt.Sprintf("metrics query failed: %v", err))
		return
	}

	resp := metricsResponse{
		Enabled:  true,
		Table:    table,
		TimeAttr: def.timeAttr,
		Columns:  append(groups, aggCols...),
	}
	if bucket > 0 {
		resp.BucketSeconds = bucket
	}
	for _, row := range rows {
		if len(resp.Rows) >= metricsMaxRows {
			resp.Truncated = true
			break
		}
		out := make([]string, 0, len(row.Group)+len(row.Values))
		out = append(out, row.Group...)
		out = append(out, row.Values...)
		resp.Rows = append(resp.Rows, out)
	}
	s.writeJSON(w, http.StatusOK, resp)
}

// metricsUnavailable reports whether the error means "this server cannot
// serve this table" rather than a real failure -- a missing archive (the
// sampler is off) or a server too old for archive/bucketed aggregation.
func metricsUnavailable(err error) bool {
	if errors.Is(err, dbrpc.ErrArchiveAggregateUnsupported) ||
		errors.Is(err, dbrpc.ErrBucketedUnsupported) {
		return true
	}
	return strings.Contains(err.Error(), "no such archive")
}

// parseBucketSeconds accepts a duration ("15m", "900s", "1h") or a bare
// number of seconds ("900"); empty means no time bucketing.
func parseBucketSeconds(v string) (int64, error) {
	v = strings.TrimSpace(v)
	if v == "" {
		return 0, nil
	}
	if n, err := strconv.ParseInt(v, 10, 64); err == nil {
		if n <= 0 {
			return 0, fmt.Errorf("bucket must be positive")
		}
		return n, nil
	}
	d, err := time.ParseDuration(v)
	if err != nil {
		return 0, fmt.Errorf("invalid bucket %q: want a duration like 15m or a number of seconds", v)
	}
	if d <= 0 {
		return 0, fmt.Errorf("bucket must be positive")
	}
	return int64(d.Seconds()), nil
}

// parseMetricsGroups turns the group_by list into group columns and their
// output-column descriptors, appending the time bucket last when bucket>0.
func parseMetricsGroups(spec, timeAttr string, bucket int64) ([]metricsColumn, []dbrpc.GroupCol, error) {
	var cols []metricsColumn
	var group []dbrpc.GroupCol
	for _, name := range splitCSV(spec) {
		if !metricsIdent.MatchString(name) {
			return nil, nil, fmt.Errorf("invalid group_by attribute %q", name)
		}
		cols = append(cols, metricsColumn{Name: name, Kind: "group"})
		group = append(group, dbrpc.GroupCol{Attr: name})
	}
	if bucket > 0 {
		cols = append(cols, metricsColumn{Name: timeAttr, Kind: "group", BucketSeconds: bucket})
		group = append(group, dbrpc.GroupCol{Attr: timeAttr, BucketWidth: bucket})
	}
	return cols, group, nil
}

// parseMetricsAggs turns "max:MemoryUsage,avg:CpuUtil" into aggregate specs
// and their output-column descriptors. At least one is required.
func parseMetricsAggs(spec string) ([]dbrpc.AggSpec, []metricsColumn, error) {
	var aggs []dbrpc.AggSpec
	var cols []metricsColumn
	for _, item := range splitCSV(spec) {
		fn, arg, ok := strings.Cut(item, ":")
		if !ok {
			return nil, nil, fmt.Errorf("invalid agg %q: want func:Attr, e.g. max:MemoryUsage", item)
		}
		fn = strings.ToLower(strings.TrimSpace(fn))
		arg = strings.TrimSpace(arg)
		f, ok := metricsAggFuncs[fn]
		if !ok {
			return nil, nil, fmt.Errorf("unknown agg function %q (use count, sum, avg, min, max)", fn)
		}
		if arg != "*" && !metricsIdent.MatchString(arg) {
			return nil, nil, fmt.Errorf("invalid agg attribute %q", arg)
		}
		if arg == "*" && f != dbrpc.AggCount {
			return nil, nil, fmt.Errorf("%s requires an attribute, not *", fn)
		}
		aggs = append(aggs, dbrpc.AggSpec{Func: f, Arg: arg})
		cols = append(cols, metricsColumn{Name: fn + "_" + arg, Kind: "metric", Func: fn, Attr: arg})
	}
	if len(aggs) == 0 {
		return nil, nil, fmt.Errorf("at least one agg is required, e.g. agg=max:MemoryUsage")
	}
	return aggs, cols, nil
}

// metricsConstraint ANDs the optional time window onto the caller's
// constraint (before owner-scoping re-serializes the whole thing).
func metricsConstraint(constraint, timeAttr, since, until string) (string, error) {
	constraint = strings.TrimSpace(constraint)
	if constraint == "" {
		constraint = "true"
	}
	add := func(base, clause string) string {
		return fmt.Sprintf("(%s) && (%s)", base, clause)
	}
	if since = strings.TrimSpace(since); since != "" {
		n, err := strconv.ParseInt(since, 10, 64)
		if err != nil {
			return "", fmt.Errorf("invalid since (want unix seconds): %w", err)
		}
		constraint = add(constraint, fmt.Sprintf("%s >= %d", timeAttr, n))
	}
	if until = strings.TrimSpace(until); until != "" {
		n, err := strconv.ParseInt(until, 10, 64)
		if err != nil {
			return "", fmt.Errorf("invalid until (want unix seconds): %w", err)
		}
		constraint = add(constraint, fmt.Sprintf("%s <= %d", timeAttr, n))
	}
	return constraint, nil
}

func splitCSV(s string) []string {
	var out []string
	for _, p := range strings.Split(s, ",") {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}
