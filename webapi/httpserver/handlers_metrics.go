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
//
// Multi-AP mode reads the federation hub instead (multiap_metrics.go).

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

	"github.com/bbockelm/golang-htcondor/webapi/multiap"
	"github.com/bbockelm/golang-htcondor/webapi/utilization"
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
// (localReadOwnerScope), but group/agg attrs are passed as names, so keep them
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
	// Sources and Job are multi-AP mode's (multiap_metrics.go): the
	// sources block every multi-AP read carries, and the complete id of
	// the job a per-job read was for. Single-AP responses carry neither.
	Sources *multiap.Sources `json:"sources,omitempty"`
	Job     *metricsJob      `json:"job,omitempty"`
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
	if s.multi != nil {
		s.handleMultiMetricsQuery(w, r, table, def)
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
	// Every caller but an administrator is confined to its own Owner,
	// bearer or browser alike. The mirror is read with this daemon's
	// credential and nothing downstream checks ownership, so this clause
	// is what keeps one user out of another's samples.
	constraint, err = localReadOwnerScope(ctx, constraint, s.seesAllJobs(ctx, r, jobScopeRead))
	if errors.Is(err, errUnidentifiedCaller) {
		s.writeError(w, http.StatusUnauthorized, "Authentication failed: "+err.Error())
		return
	}
	if err != nil {
		s.writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	// The mirror is read with this daemon's credential, so it answers
	// only a caller the schedd accepts at READ. There is no schedd to
	// fall back to here.
	if !s.mirrorReadVerified(ctx, r) {
		s.writeError(w, http.StatusForbidden, errMirrorNotVerified.Error())
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

	s.writeJSON(w, http.StatusOK, metricsResult(table, def, bucket, append(groups, aggCols...), rows))
}

// metricsResult is the enabled response: the columns, and the rows up to
// metricsMaxRows.
func metricsResult(table string, def metricsTableDef, bucket int64, cols []metricsColumn, rows []dbrpc.AggRow) metricsResponse {
	resp := metricsResponse{
		Enabled:  true,
		Table:    table,
		TimeAttr: def.timeAttr,
		Columns:  cols,
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
	return resp
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
		spec := dbrpc.AggSpec{Func: f, Arg: arg}
		if metricsGPUUsageAttr(arg) {
			spec.Filter = utilization.GPUUsageSampleFilter(arg)
		}
		aggs = append(aggs, spec)
		cols = append(cols, metricsColumn{Name: fn + "_" + arg, Kind: "metric", Func: fn, Attr: arg})
	}
	if len(aggs) == 0 {
		return nil, nil, fmt.Errorf("at least one agg is required, e.g. agg=max:MemoryUsage")
	}
	return aggs, cols, nil
}

// metricsGPUUsageAttr reports whether a sample attribute is GPU usage in
// GPUs kept busy. An aggregate over one counts only the samples whose
// usage the job's GPUs could have produced: an execute point sometimes
// reports thousands of GPUs busy on a two-GPU job, and one such sample
// would swamp every other in its bucket. The filter narrows only that
// aggregate, so the bucket's other columns still see every sample.
func metricsGPUUsageAttr(attr string) bool {
	return strings.EqualFold(attr, "GpuUtil") || strings.EqualFold(attr, "GPUsAverageUsage")
}

// metricsConstraint ANDs the optional time window onto the caller's
// constraint (before owner-scoping re-serializes the whole thing).
func metricsConstraint(constraint, timeAttr, since, until string) (string, error) {
	constraint = strings.TrimSpace(constraint)
	if constraint == "" {
		constraint = "true"
	}
	window, err := metricsWindow(timeAttr, since, until)
	if err != nil {
		return "", err
	}
	for _, clause := range window {
		constraint = fmt.Sprintf("(%s) && (%s)", constraint, clause)
	}
	return constraint, nil
}

// metricsWindow is the optional time window on timeAttr, as clauses.
func metricsWindow(timeAttr, since, until string) ([]string, error) {
	var out []string
	if since = strings.TrimSpace(since); since != "" {
		n, err := strconv.ParseInt(since, 10, 64)
		if err != nil {
			return nil, fmt.Errorf("invalid since (want unix seconds): %w", err)
		}
		out = append(out, fmt.Sprintf("%s >= %d", timeAttr, n))
	}
	if until = strings.TrimSpace(until); until != "" {
		n, err := strconv.ParseInt(until, 10, 64)
		if err != nil {
			return nil, fmt.Errorf("invalid until (want unix seconds): %w", err)
		}
		out = append(out, fmt.Sprintf("%s <= %d", timeAttr, n))
	}
	return out, nil
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
