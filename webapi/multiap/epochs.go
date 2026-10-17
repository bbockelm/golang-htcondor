package multiap

import (
	"context"
	"fmt"
	"net/http"
	"strings"

	"github.com/bbockelm/golang-htcondor/jobid"
	"github.com/bbockelm/golang-htcondor/webapi/apregistry"
	"github.com/bbockelm/golang-htcondor/webapi/dbmirror"
	"github.com/bbockelm/golang-htcondor/webapi/ownerscope"
)

// Run-attempt (epoch) and transfer history in multi-AP mode.
//
// Where the hub federates epoch_history, both are read from it: transfer
// history is the epoch_history records whose EpochAdType is a transfer
// (INPUT, OUTPUT, CHECKPOINT) -- HTCondor keeps no other transfer log.
// Where it does not, a read naming one job or one AP is routed to that
// AP's schedd (the caller does that; see RouteRead), and one naming
// neither is refused: it would be a history-file scan on every AP per
// request, with no order or page token across them, which is the load
// the hub exists to take off the APs.

// TransferAdTypes are the EpochAdType values of transfer records.
var TransferAdTypes = []string{"INPUT", "OUTPUT", "CHECKPOINT"}

const attrEpochWriteDate = "EpochWriteDate"

// EpochRequest is a read of run-attempt or transfer records.
type EpochRequest struct {
	// User is the caller's User value (UserFor). Required.
	User       string
	Constraint string
	// Projection nil or "*" reads whole records.
	Projection []string
	Limit      int
	// Schedd restricts the read to one AP.
	Schedd string
	// Job, when set, restricts it to one job; a complete id.
	Job *jobid.ID
	// AdTypes restricts it to records of these EpochAdTypes (transfer
	// history); empty reads every type.
	AdTypes []string
}

// ListEpochs reads the caller's epoch_history records from the hub,
// newest first when projected (TopK on EpochWriteDate), else in the
// archive's order. It fails with ErrEpochsNotFederated on a hub that
// does not federate epoch_history.
func (s *Service) ListEpochs(ctx context.Context, req EpochRequest) ([]Row, *ListResult, error) {
	ctx = s.PinHub(ctx)
	if !s.Hub.For(ctx).Federates(TableEpochHistory) {
		return nil, nil, ErrEpochsNotFederated
	}
	schedd := req.Schedd
	var clauses []string
	if req.Job != nil {
		if !req.Job.Complete() {
			return nil, nil, errorf(http.StatusBadRequest, "job %s does not name its access point", s.Codec.Format(*req.Job))
		}
		if schedd != "" && !strings.EqualFold(schedd, req.Job.Schedd) {
			return nil, nil, errorf(http.StatusBadRequest, "job %s is not on %s", s.Codec.Format(*req.Job), schedd)
		}
		schedd = req.Job.Schedd
		clauses = append(clauses, fmt.Sprintf("ClusterId == %d && ProcId == %d", req.Job.Cluster, req.Job.Proc))
	}
	if len(req.AdTypes) > 0 {
		var types []string
		for _, t := range req.AdTypes {
			types = append(types, "EpochAdType == "+strLit(strings.ToUpper(t)))
		}
		clauses = append(clauses, "("+strings.Join(types, " || ")+")")
	}
	// The caller's constraint is re-serialized on its own first, so it
	// cannot escape the job and type clauses ANDed beside it.
	base, err := ownerscope.Constrain(AttrUser, req.User, req.Constraint)
	if err != nil {
		return nil, nil, errorf(http.StatusBadRequest, "invalid constraint: %v", err)
	}
	constraint := strings.Join(append([]string{base}, clauses...), " && ")
	scope, _, sources, err := s.Scope(ctx, req.User, constraint, schedd)
	if err != nil {
		return nil, nil, err
	}
	res := &ListResult{Sources: s.TableSources(ctx, sources, TableEpochHistory)}
	dbc, closer, err := s.HubClient(ctx)
	if err != nil {
		return nil, nil, err
	}
	defer closer()
	limit := dbmirror.ClampLimit(req.Limit, dbmirror.Projected(req.Projection))
	proj := projectionWith(req.Projection, append([]string{attrEpochWriteDate}, keyAttrs...)...)
	var rows []Row
	collect := func(text string) bool {
		row, perr := rowFromText(text, "")
		if perr != nil {
			err = perr
			return false
		}
		row.Archived = true
		rows = append(rows, row)
		return true
	}
	if proj != nil {
		var texts []string
		texts, err = dbc.TopK(ctx, TableEpochHistory, scope, proj, attrEpochWriteDate, true, limit+1)
		if err == nil {
			for _, t := range texts {
				if !collect(t) {
					break
				}
			}
		}
	} else {
		qerr := dbc.QueryRawProjectStream(ctx, TableEpochHistory, scope, nil, limit+1, collect)
		if err == nil {
			err = qerr
		}
	}
	if s.noteRead(ctx, err) != nil {
		return nil, nil, errorf(http.StatusServiceUnavailable, "reading the federation hub's epoch_history: %v", err)
	}
	if len(rows) > limit {
		rows, res.HasMore = rows[:limit], true
	}
	res.Returned = len(rows)
	return rows, res, nil
}

// ResolveJob completes an id among the caller's jobs, live and archived,
// on every AP: unchanged when complete; the one AP holding it when
// exactly one does; else a 404, or a 409 with the candidates. For reads
// only -- an action never resolves (Route).
//
// A complete id is returned as given, without asking whose job it is:
// the hub read that follows is confined by Scope (User == the caller),
// and that clause is the only thing keeping the read to the caller's
// rows. Never widen Scope to admit rows without a User (samples or
// records the spoke never chained to their job) for a read naming a
// job: nobody can say whose those are.
func (s *Service) ResolveJob(ctx context.Context, user string, id jobid.ID) (jobid.ID, error) {
	if err := jobid.Valid(id); err != nil {
		return jobid.ID{}, errorf(http.StatusBadRequest, "invalid job id: %v", err)
	}
	if id.Complete() {
		return id, nil
	}
	ctx = s.PinHub(ctx)
	return s.resolve(ctx, s.snapshot(ctx), user, id)
}

// RouteRead is the AP a read naming one AP goes to, for a read the hub
// cannot serve: a member that can be reached now and admits the caller.
func (s *Service) RouteRead(ctx context.Context, user, schedd string) (apregistry.Member, error) {
	m, err := s.Member(schedd)
	if err != nil {
		return apregistry.Member{}, err
	}
	if err := s.AdmitTo(ctx, m, user); err != nil {
		return apregistry.Member{}, err
	}
	return m, nil
}
