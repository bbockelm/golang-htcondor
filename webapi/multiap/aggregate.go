package multiap

import (
	"context"
	"net/http"

	"github.com/PelicanPlatform/classad/dbrpc"
)

// Aggregate counts the caller's jobs (table "jobs") or history records
// ("history") on the hub, grouped by groupBy, under the same self-scope
// and AP filter as a listing. Group by ScheddName to count per AP.
func (s *Service) Aggregate(ctx context.Context, user, table, constraint string, groupBy []string, schedd string) ([]dbrpc.AggRow, Sources, error) {
	if user == "" {
		return nil, Sources{}, errorf(http.StatusUnauthorized, "the caller's identity could not be established")
	}
	if table == "" {
		table = TableJobs
	}
	if table != TableJobs && table != TableHistory {
		return nil, Sources{}, errorf(http.StatusBadRequest, "multi-AP mode aggregates %q or %q, not %q", TableJobs, TableHistory, table)
	}
	v := s.snapshot()
	schedds, err := s.allowed(v, schedd)
	if err != nil {
		return nil, v.sources, err
	}
	if len(schedds) == 0 {
		return nil, v.sources, nil
	}
	scope, err := scoped(user, constraint, schedds)
	if err != nil {
		return nil, v.sources, err
	}
	dbc, closer, err := s.Hub.Client(ctx)
	if err != nil {
		return nil, v.sources, errorf(http.StatusServiceUnavailable, "the federation hub is unavailable: %v", err)
	}
	defer closer()
	aggs := []dbrpc.AggSpec{{Func: dbrpc.AggCount, Arg: "*"}}
	var rows []dbrpc.AggRow
	if table == TableHistory {
		rows, err = dbc.ArchiveAggregate(ctx, table, scope, groupBy, aggs)
	} else {
		rows, err = dbc.AggregateTable(ctx, table, scope, groupBy, aggs)
	}
	if err != nil {
		return nil, v.sources, errorf(http.StatusServiceUnavailable, "aggregating on the federation hub: %v", err)
	}
	return rows, v.sources, nil
}
