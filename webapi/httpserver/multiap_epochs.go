package httpserver

import (
	"fmt"
	"net/http"
	"strings"

	htcondor "github.com/bbockelm/golang-htcondor"
	"github.com/bbockelm/golang-htcondor/jobid"
	"github.com/bbockelm/golang-htcondor/webapi/multiap"
)

// Run-attempt and transfer history in multi-AP mode: GET
// /api/v1/jobs/epochs and /api/v1/jobs/transfers.
//
// With the hub federating epoch_history, both are read from it, the
// caller's own records on every AP, or one AP (?schedd=) or one job
// (?job_id=, which may be a bare cluster.proc when exactly one AP has it
// among the caller's jobs). Without it, a read naming a job or an AP is
// routed to that AP's schedd and runs as in single-AP mode there; one
// naming neither is a 501 -- a history-file scan on every AP per request,
// with no order or page token across them, is the load the hub exists to
// keep off the APs.

// handleMultiEpochs serves both endpoints; opts.Source says which.
func (s *Handler) handleMultiEpochs(w http.ResponseWriter, r *http.Request, opts *htcondor.HistoryQueryOptions) {
	ctx, user, ok := s.multiAPCaller(w, r)
	if !ok {
		return
	}
	svc := s.multi.svc
	q := r.URL.Query()
	var id *jobid.ID
	if text := q.Get("job_id"); text != "" {
		parsed, err := s.multi.codec.Parse(text)
		if err != nil {
			s.writeError(w, http.StatusBadRequest, fmt.Sprintf("Invalid job_id: %v", err))
			return
		}
		resolved, err := svc.ResolveJob(ctx, user, parsed)
		if err != nil {
			s.multiAPError(w, err)
			return
		}
		id = &resolved
	}
	schedd := q.Get("schedd")
	if id != nil && schedd != "" && !strings.EqualFold(schedd, id.Schedd) {
		s.writeError(w, http.StatusBadRequest, fmt.Sprintf("job_id %s is not on %s", s.multi.codec.Format(*id), schedd))
		return
	}
	transfer := opts.Source == htcondor.HistorySourceTransfer
	var adTypes []string
	if transfer {
		adTypes = multiap.TransferAdTypes
		if v := strings.TrimSpace(q.Get("transfer_types")); v != "" {
			adTypes = nil
			for _, t := range strings.Split(v, ",") {
				switch t = strings.ToUpper(strings.TrimSpace(t)); t {
				case "INPUT", "OUTPUT", "CHECKPOINT":
					adTypes = append(adTypes, t)
				default:
					s.writeError(w, http.StatusBadRequest, fmt.Sprintf("Invalid transfer type: %s", t))
					return
				}
			}
		}
	}

	if svc.Hub.For(ctx).Federates(multiap.TableEpochHistory) {
		limit, err := parseLimit(r)
		if err != nil {
			s.writeError(w, http.StatusBadRequest, err.Error())
			return
		}
		projection := parseProjection(r)
		if projection == nil {
			projection = htcondor.DefaultEpochProjection()
			if transfer {
				projection = htcondor.DefaultTransferProjection()
			}
		}
		rows, res, err := svc.ListEpochs(ctx, multiap.EpochRequest{
			User: user, Constraint: q.Get("constraint"), Projection: projection, Limit: limit,
			Schedd: schedd, Job: id, AdTypes: adTypes,
		})
		if err != nil {
			s.multiAPError(w, err)
			return
		}
		out := &jsonRowStream{h: s, w: w, key: "ads"}
		for _, row := range rows {
			if !out.write(row) {
				break
			}
		}
		out.finish(res)
		return
	}

	target := schedd
	if id != nil {
		target = id.Schedd
	}
	if target == "" {
		s.multiAPError(w, &multiap.Error{Status: http.StatusNotImplemented, Reason: multiap.ReasonEpochsNotFederated,
			Msg: multiap.ErrEpochsNotFederated.Msg + "; name one job (job_id) or one access point (schedd) to read it from that access point"})
		return
	}
	t := multiap.Target{}
	var err error
	if id != nil {
		t.ID = *id
		t.Member, err = svc.Route(ctx, user, *id)
	} else {
		t.Member, err = svc.RouteRead(ctx, user, target)
	}
	if err != nil {
		s.multiAPError(w, err)
		return
	}
	// Run as in single-AP mode against the routed AP's schedd, with the
	// job named in the constraint and the routing parameters gone.
	routed := r.WithContext(multiap.WithTarget(ctx, t))
	u := *r.URL
	params := u.Query()
	params.Del("job_id")
	params.Del("schedd")
	if id != nil {
		job := fmt.Sprintf("ClusterId == %d && ProcId == %d", id.Cluster, id.Proc)
		if c := strings.TrimSpace(params.Get("constraint")); c != "" {
			// Balanced, so the caller's constraint cannot escape the job
			// clause; the owner scope is ANDed on later in the same way.
			safe, err := andScope(job, c)
			if err != nil {
				s.writeError(w, http.StatusBadRequest, fmt.Sprintf("invalid constraint: %v", err))
				return
			}
			job = safe
		}
		params.Set("constraint", job)
	}
	u.RawQuery = params.Encode()
	routed.URL = &u
	s.handleHistoryQuery(w, routed, opts)
}
