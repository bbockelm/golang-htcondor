package multiap

import (
	"context"
	"net/http"
	"strings"

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
	ctx = s.PinHub(ctx)
	v := s.snapshot(ctx)
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
	dbc, closer, err := v.hub.Client(ctx)
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
	if s.noteRead(ctx, err) != nil {
		return nil, v.sources, errorf(http.StatusServiceUnavailable, "aggregating on the federation hub: %v", err)
	}
	return rows, v.sources, nil
}

// Scope is the hub constraint for a read of user's rows: constraint
// confined to user's jobs (User) and to the APs a read may return rows
// from -- schedd alone when it is set, else every member, less degraded
// APs under StaleExclude. It returns the APs and the sources block too.
// The hub has no row-level ACL; this clause is the scope. The sources
// block is the hub ctx is pinned to; pin ctx (PinHub) before calling
// this and then reading with HubClient, so both are one hub's.
func (s *Service) Scope(ctx context.Context, user, constraint, schedd string) (string, []string, Sources, error) {
	if user == "" {
		return "", nil, Sources{}, errorf(http.StatusUnauthorized, "the caller's identity could not be established")
	}
	v := s.snapshot(ctx)
	names, err := s.allowed(v, schedd)
	if err != nil {
		return "", nil, v.sources, err
	}
	if constraint == "" {
		constraint = "true"
	}
	scope, err := scoped(user, constraint, names)
	if err != nil {
		return "", nil, v.sources, err
	}
	return scope, names, v.sources, nil
}

// HubClient dials the hub ctx is pinned to (else the active one), as a
// 503 when it does not answer.
func (s *Service) HubClient(ctx context.Context) (*dbrpc.Client, func(), error) {
	dbc, closer, err := s.Hub.For(ctx).Client(ctx)
	if err != nil {
		return nil, nil, errorf(http.StatusServiceUnavailable, "the federation hub is unavailable: %v", err)
	}
	return dbc, closer, nil
}

// StateOf is an AP's state as a sources block reports it: fresh, or the
// state it is degraded in.
func (src Sources) StateOf(schedd string) string {
	for _, d := range src.Degraded {
		if strings.EqualFold(d.Schedd, schedd) {
			return d.State
		}
	}
	return StateFresh
}

// notKeptReason is why an AP keeps no copy of table.
func notKeptReason(table string, ts TableStatus) string {
	if ts.LastError != "" {
		return ts.LastError
	}
	return "this access point keeps no " + table
}

// optionalTables are the hub tables a spoke may lawfully not keep, so a
// <Table>Missing from the hub means "no rows here" rather than a fault.
// Every other table (jobs, history, syncstatus) is one a spoke must
// have: missing, it is degraded whatever the hub says.
var optionalTables = map[string]bool{TableJobMetrics: true, TableEpochHistory: true}

// TableSources adds to a sources block each AP whose stream of table
// into the hub cannot vouch for that table's rows -- not federated from
// it, disconnected, failing, or still catching up -- so a read of table
// says which APs' rows in it may be missing rather than returning them
// silently partial. An AP already degraded is left as it is.
//
// An AP the hub reports keeps no such table at all (<Table>Missing, for
// an optional table: a spoke without job_metrics or epoch history) has
// no rows to miss. It goes in NotKept instead, and still counts as fresh.
//
// An AP that is settling (the hub became active less than the settle
// window ago) stays degraded, settling: the new hub may lack its rows.
// If the hub also reports it keeps none of an optional table, it is
// listed in NotKept as well -- it has no such rows on any hub, so a read
// of that table finding none there is the answer, not the switch.
//
// The table states are the hub ctx is pinned to (else the active one's),
// which must be the hub src came from.
func (s *Service) TableSources(ctx context.Context, src Sources, table string) Sources {
	ep := s.Hub.For(ctx)
	out := Sources{Hub: src.Hub, APs: src.APs, Fresh: src.Fresh, Degraded: append([]Degraded{}, src.Degraded...),
		NotKept: append([]NotKept(nil), src.NotKept...)}
	degraded := map[string]bool{}
	settling := map[string]bool{}
	for _, d := range src.Degraded {
		degraded[strings.ToLower(d.Schedd)] = true
		settling[strings.ToLower(d.Schedd)] = d.State == StateSettling
	}
	for _, m := range s.Registry.Members() {
		key := strings.ToLower(m.Name)
		if degraded[key] && !settling[key] {
			continue
		}
		reason := ""
		hsrc, ok := ep.Source(m.Name)
		ts, federated := hsrc.TableStatus[table]
		if settling[key] {
			if ok && federated && ts.Missing && optionalTables[table] {
				out.NotKept = append(out.NotKept, NotKept{Schedd: m.Name, Table: table, Reason: notKeptReason(table, ts)})
			}
			continue
		}
		switch {
		case ok && federated && ts.Missing && optionalTables[table]:
			out.NotKept = append(out.NotKept, NotKept{Schedd: m.Name, Table: table, Reason: notKeptReason(table, ts)})
			continue
		case !ok || !federated:
			reason = "the federation hub does not federate " + table + " from this access point"
		case !ts.Connected:
			reason = "the federation hub's " + table + " stream from this access point is not connected"
		case ts.LastError != "":
			reason = "the federation hub's " + table + " stream from this access point is failing: " + ts.LastError
		case ts.SyncedKnown && !ts.Synced:
			reason = "the federation hub's " + table + " stream from this access point is catching up"
		default:
			continue
		}
		out.Fresh--
		out.Degraded = append(out.Degraded, Degraded{Schedd: m.Name, State: StateStale, Reason: reason})
	}
	return out
}
