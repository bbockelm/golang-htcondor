package httpserver

import (
	"errors"
	"fmt"
	"net/http"
	"strings"

	"github.com/bbockelm/golang-htcondor/jobid"
	"github.com/bbockelm/golang-htcondor/webapi/multiap"
)

// GET /api/v1/metrics/job_metrics in multi-AP mode: the same aggregate
// as single-AP mode (handlers_metrics.go), over the hub's federated
// job_metrics archive, with
//
//   - the multi-AP owner scope: the caller's own samples (User ==
//     owner@UID_DOMAIN) on member APs only, for every caller --
//     administrators included, as for every other multi-AP read;
//   - ?job_id= for one job's samples: the codec's text form, complete,
//     or a bare cluster.proc that exactly one AP holds among the
//     caller's jobs (two is a 409 naming them);
//   - ?schedd= for one AP's;
//   - ScheddName grouped beside ClusterId or ProcId whenever group_by
//     names either, since those repeat across APs;
//   - "job" naming the complete id of a per-job read, and the sources
//     block, with each AP whose job_metrics stream into the hub is down.
//
// A hub that does not federate job_metrics answers {enabled:false}, as
// single-AP mode does without the sampler.

// metricsJob is the job a per-job read was for.
type metricsJob struct {
	Schedd  string `json:"schedd"`
	Cluster int64  `json:"cluster"`
	Proc    int64  `json:"proc"`
	JobID   string `json:"job_id"`
}

// multiAPMetricsPath is the one metrics route multi-AP mode serves.
const multiAPMetricsPath = "/api/v1/metrics/" + multiap.TableJobMetrics

func (s *Handler) handleMultiMetricsQuery(w http.ResponseWriter, r *http.Request, table string, def metricsTableDef) {
	ctx, user, ok := s.multiAPCaller(w, r)
	if !ok {
		return
	}
	svc := s.multi.svc
	off := func(src multiap.Sources) {
		s.writeJSON(w, http.StatusOK, metricsResponse{Enabled: false, Table: table, Sources: &src})
	}
	// Before the parameters, as single-AP mode reports the sampler off.
	if src, isOff := svc.MetricsOff(ctx); isOff {
		off(src)
		return
	}

	q := r.URL.Query()
	bucket, err := parseBucketSeconds(q.Get("bucket"))
	if err != nil {
		s.writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	groups, groupCols, err := parseMetricsGroups(withScheddGroup(q.Get("group_by")), def.timeAttr, bucket)
	if err != nil {
		s.writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	aggs, aggCols, err := parseMetricsAggs(q.Get("agg"))
	if err != nil {
		s.writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	window, err := metricsWindow(def.timeAttr, q.Get("since"), q.Get("until"))
	if err != nil {
		s.writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	var id *jobid.ID
	if text := q.Get("job_id"); text != "" {
		parsed, err := s.multi.codec.Parse(text)
		if err != nil {
			s.writeError(w, http.StatusBadRequest, fmt.Sprintf("Invalid job_id: %v", err))
			return
		}
		id = &parsed
	}

	res, err := svc.AggregateMetrics(ctx, multiap.MetricsRequest{
		User: user, Constraint: q.Get("constraint"), Clauses: window,
		Schedd: q.Get("schedd"), Job: id, Group: groupCols, Aggs: aggs,
	})
	if errors.Is(err, multiap.ErrMetricsNotFederated) {
		off(res.Sources)
		return
	}
	if err != nil {
		s.multiAPError(w, err)
		return
	}
	resp := metricsResult(table, def, bucket, append(groups, aggCols...), res.Rows)
	resp.Sources = &res.Sources
	if res.Job != nil {
		resp.Job = &metricsJob{Schedd: res.Job.Schedd, Cluster: res.Job.Cluster, Proc: res.Job.Proc,
			JobID: s.multi.codec.Format(*res.Job)}
	}
	s.writeJSON(w, http.StatusOK, resp)
}

// withScheddGroup adds ScheddName to a group_by list that names
// ClusterId or ProcId without it, just before the first of them: a
// cluster.proc identifies a job only together with its AP, and two APs'
// samples under one number would otherwise be merged into one row.
func withScheddGroup(spec string) string {
	names := splitCSV(spec)
	at := -1
	for i, n := range names {
		switch {
		case strings.EqualFold(n, multiap.AttrScheddName):
			return spec
		case at < 0 && (strings.EqualFold(n, "ClusterId") || strings.EqualFold(n, "ProcId")):
			at = i
		}
	}
	if at < 0 {
		return spec
	}
	out := append(append(append([]string{}, names[:at]...), multiap.AttrScheddName), names[at:]...)
	return strings.Join(out, ",")
}
