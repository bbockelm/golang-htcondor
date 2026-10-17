package multiap

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/PelicanPlatform/classad/dbrpc"

	"github.com/bbockelm/golang-htcondor/jobid"
	"github.com/bbockelm/golang-htcondor/webapi/ownerscope"
)

// Job resource-usage samples (job_metrics) in multi-AP mode.
//
// The hub federates each spoke's job_metrics archive into one, every
// sample carrying the ScheddName of the AP it came from. Cluster and
// proc numbers repeat across APs, so a read of one job selects on
// ScheddName as well, and a bare cluster.proc is completed among the
// caller's jobs first (ResolveJob's rules). A hub that does not federate
// job_metrics has nothing to read, which is an answer, not an error:
// ErrMetricsNotFederated.

// TableJobMetrics is the hub's archive of per-job resource-usage
// samples.
const TableJobMetrics = "job_metrics"

// ErrMetricsNotFederated is the answer for a samples read on a hub that
// does not federate job_metrics, or holds no such archive.
var ErrMetricsNotFederated = &Error{Status: http.StatusNotImplemented, Reason: ReasonMetricsNotFederated,
	Msg: "the federation hub does not federate job_metrics (HTCONDORDB_FEDERATE_TABLES)"}

// ReasonMetricsNotFederated is ErrMetricsNotFederated's reason.
const ReasonMetricsNotFederated = "job_metrics_not_federated"

// MetricsTimeout bounds one samples aggregate, in both modes: a fine
// bucket over a long window would otherwise hold the database -- in
// multi-AP mode the hub every AP's reads share -- for as long as the
// caller waits.
const MetricsTimeout = 30 * time.Second

// MetricsRequest is a time-bucketed aggregate over the caller's samples.
type MetricsRequest struct {
	// User is the caller's User value (UserFor). Required.
	User string
	// Constraint is the caller's own. It is re-serialized on its own
	// before anything is ANDed beside it, so it cannot escape the
	// clauses below.
	Constraint string
	// Clauses are conditions the server built (a time window), ANDed on.
	Clauses []string
	// Schedd restricts the read to one AP.
	Schedd string
	// Job, when set, restricts it to one job's samples. An incomplete id
	// is completed among the caller's jobs, live and archived.
	Job *jobid.ID
	// Group and Aggs are the aggregate, passed through.
	Group []dbrpc.GroupCol
	Aggs  []dbrpc.AggSpec
}

// MetricsResult is a samples aggregate.
type MetricsResult struct {
	Rows []dbrpc.AggRow
	// Sources is the sources block, with each AP whose job_metrics
	// stream into the hub cannot vouch for its samples.
	Sources Sources
	// Job is the complete id read, when the request named a job.
	Job *jobid.ID
}

// MetricsOff reports whether the hub has no job_metrics to read, with
// the sources block to answer with when it has none. ctx is the
// request's: every hub read a samples request makes -- this, the job
// resolution, the scope and its sources block, the aggregate -- is of
// the hub that request reads.
func (s *Service) MetricsOff(ctx context.Context) (Sources, bool) {
	ctx = s.PinHub(ctx)
	if s.Hub.For(ctx).Federates(TableJobMetrics) {
		return Sources{}, false
	}
	return s.TableSources(ctx, s.Sources(ctx), TableJobMetrics), true
}

// AggregateMetrics aggregates the caller's job_metrics samples on the
// hub. It fails with ErrMetricsNotFederated, returning the sources block
// beside it, when the hub has no job_metrics to read.
func (s *Service) AggregateMetrics(ctx context.Context, req MetricsRequest) (*MetricsResult, error) {
	if req.User == "" {
		return nil, errorf(http.StatusUnauthorized, "the caller's identity could not be established")
	}
	// The deadline covers the job's resolution as well as the aggregate,
	// and all of it reads one hub.
	ctx, cancel := context.WithTimeout(s.PinHub(ctx), MetricsTimeout)
	defer cancel()
	if src, off := s.MetricsOff(ctx); off {
		return &MetricsResult{Sources: src}, ErrMetricsNotFederated
	}
	schedd := req.Schedd
	var job *jobid.ID
	var clauses []string
	if req.Job != nil {
		id := *req.Job
		if !id.Complete() && schedd != "" {
			// ?schedd= settles which AP a bare cluster.proc is on.
			id = id.WithSchedd(schedd)
		}
		id, err := s.ResolveJob(ctx, req.User, id)
		if err != nil {
			return nil, err
		}
		if schedd != "" && !strings.EqualFold(schedd, id.Schedd) {
			return nil, errorf(http.StatusBadRequest, "job %s is not on %s", s.Codec.Format(id), schedd)
		}
		if m, ok := s.Registry.Get(id.Schedd); ok {
			// The member's own spelling, not the caller's.
			id.Schedd = m.Name
		}
		job, schedd = &id, id.Schedd
		// ScheddName is confined to the job's AP by Scope, below.
		clauses = append(clauses, fmt.Sprintf("ClusterId == %d && ProcId == %d", id.Cluster, id.Proc))
	}
	base, err := ownerscope.Constrain(AttrUser, req.User, req.Constraint)
	if err != nil {
		return nil, errorf(http.StatusBadRequest, "invalid constraint: %v", err)
	}
	for _, c := range req.Clauses {
		clauses = append(clauses, "("+c+")")
	}
	constraint := strings.Join(append([]string{base}, clauses...), " && ")
	scope, _, sources, err := s.Scope(ctx, req.User, constraint, schedd)
	if err != nil {
		return nil, err
	}
	res := &MetricsResult{Sources: s.TableSources(ctx, sources, TableJobMetrics), Job: job}
	dbc, closer, err := s.HubClient(ctx)
	if err != nil {
		return nil, err
	}
	defer closer()
	rows, err := dbc.ArchiveAggregateBucketed(ctx, TableJobMetrics, scope, req.Group, req.Aggs)
	if err != nil {
		if metricsMissing(err) {
			return res, ErrMetricsNotFederated
		}
		return nil, errorf(http.StatusServiceUnavailable, "aggregating the federation hub's job_metrics: %v", err)
	}
	res.Rows = rows
	return res, nil
}

// metricsMissing reports whether the hub has no job_metrics archive to
// aggregate (its sources list the table before it creates it), or is
// too old to aggregate archives by time bucket.
func metricsMissing(err error) bool {
	return errors.Is(err, dbrpc.ErrArchiveAggregateUnsupported) || errors.Is(err, dbrpc.ErrBucketedUnsupported) ||
		strings.Contains(err.Error(), "no such archive")
}
