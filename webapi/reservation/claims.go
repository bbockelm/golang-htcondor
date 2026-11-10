package reservation

import (
	"context"
	"fmt"
	"sort"
	"strings"

	"github.com/PelicanPlatform/classad/classad"
)

// Holding permanent capacity with HTCondor's own persistent claims.
//
// Everything else in this package holds capacity by pushing attributes
// into machine ads and letting a sieve in each execute point's START
// decide what may run there. That exists because the claim is not held
// by HTCondor: a window has a bell, the bell needs a drain, and a drain
// needs the pool to be steered from outside.
//
// A permanent reservation has no bell. It wants capacity from now on,
// with no deadline to drain towards and no moment at which anything has
// to be evicted -- which is exactly what an OCU already is. So the
// always-on case can be held by asking the schedd for claims and
// counting them, with none of the machinery above: no deadline, no
// sieve, no stanza on each execute point, no prober, no estimate
// stamping, and no eviction.
//
// Two differences from the machine-attribute path are worth stating
// rather than discovering:
//
// A claim lives in one schedd's user record, so a reservation held this
// way serves the jobs of one access point. That is the intended model
// -- a reservation that silently spanned access points would hold
// capacity for jobs its owner cannot see -- but it is a real change
// from holding a machine by attribute, which serves anybody's jobs.
//
// A claim is acquired by waiting, not by draining. It is negotiated
// like an idle job and takes capacity as the pool frees it. For a
// reservation with no start time that is the right trade; for one with
// a bell it would not be, which is the other reason this is the
// always-on case only.

// claimPrefix marks the claims this subsystem owns.
//
// Claims are shared with whatever else uses the schedd's OCUs, and the
// reconciliation below removes what it does not want -- so it has to be
// able to tell its own claims from everybody else's. Anything without
// this prefix is left alone.
const claimPrefix = "reservation:"

// ClaimName is the label put on every claim held for one reservation.
//
// Every claim of a reservation carries the same name. The schedd does
// not require names to be unique and gives each claim an id of its own,
// so there is nothing to be gained by numbering them -- and a number
// would have to be parsed back out of a string an admin chose, which is
// a way to mistake one reservation for another.
func ClaimName(specID string) string { return claimPrefix + specID }

// claimReservation is the reservation a claim is held for, and whether
// the claim is one of ours at all.
func claimReservation(name string) (string, bool) {
	if !strings.HasPrefix(name, claimPrefix) {
		return "", false
	}
	return strings.TrimPrefix(name, claimPrefix), true
}

// Claim is one persistent claim the schedd is holding, as read back.
type Claim struct {
	ID      int64
	Name    string
	Owner   string
	Project string
}

// ClaimRequest is one claim to ask the schedd for.
type ClaimRequest struct {
	Name    string
	Owner   string
	Project string
	// Request is the shape to claim, rendered from the reservation's
	// submit file: the resource requests and the Requirements a job of
	// this reservation would carry. The claim is matched by the
	// negotiator the same way a job is, so giving it anything less
	// would claim machines the reservation's jobs cannot use.
	Request *classad.ClassAd
	// Reservation is which reservation this is for, carried for the
	// error message rather than for the schedd.
	Reservation string
}

// ClaimHolder is the schedd's persistent-claim interface.
//
// Separated from the schedd client so the reconciliation can be tested
// without a pool, in the same spirit as Actuator.
type ClaimHolder interface {
	// List returns every claim the schedd holds, for every owner. The
	// protocol carries no constraint, so this is unavoidably wider
	// than one reservation.
	List(ctx context.Context) ([]Claim, error)
	Create(ctx context.Context, req ClaimRequest) error
	Remove(ctx context.Context, id int64) error
}

// ClaimPlan is the difference between the claims the schedd holds and
// the claims the reservations want.
type ClaimPlan struct {
	Create []ClaimRequest
	Remove []int64
	// Shapes is why a reservation got no claims planned at all, keyed
	// by reservation ID. A submit file that will not render is an
	// operator problem and has to be said rather than silently
	// producing zero claims.
	Shapes map[string]error
}

// Empty reports whether the plan changes nothing.
func (p ClaimPlan) Empty() bool { return len(p.Create) == 0 && len(p.Remove) == 0 }

// PlanClaims works out what to create and what to remove so the schedd
// holds exactly the claims the always-on reservations want.
//
// It compares against what the schedd reports rather than against
// anything remembered, for the reason the rest of this package reads
// the pool every tick: a controller that trusted its own recollection
// would disagree with the schedd after a restart, a failed create, or a
// second controller, and the disagreement would be invisible.
//
// Three rules decide the answer:
//
// A reservation wants Seats claims and no more. Unlike the
// machine-attribute path there is nothing to subtract for the jobs
// already running: a claim running a job is still the same claim, so
// Seats claims are Seats seats whether anybody is using them or not.
// Standing does not apply either -- a claim with no job on it already
// is idle capacity kept for the project, which is what Standing asks
// for.
//
// A claim bearing this subsystem's prefix whose reservation is gone,
// disabled, or no longer always-on is removed. That is how a deleted
// reservation gives its capacity back, and it is also why the prefix
// has to be exact.
//
// A claim bearing no such prefix is left alone, whoever holds it.
func PlanClaims(specs []*Spec, held []Claim) ClaimPlan {
	plan := ClaimPlan{}

	// What each always-on reservation wants.
	want := make(map[string]*Spec)
	order := make([]string, 0, len(specs))
	for _, s := range specs {
		if s == nil || !s.Enabled || !s.alwaysOn() {
			continue
		}
		want[s.ID] = s
		order = append(order, s.ID)
	}

	// What is held, grouped by reservation. Highest id first, so a
	// reservation being shrunk gives up its newest claims and keeps the
	// ones most likely to have settled onto a machine.
	have := make(map[string][]Claim)
	for _, c := range held {
		id, mine := claimReservation(c.Name)
		if !mine {
			continue
		}
		have[id] = append(have[id], c)
	}
	for id := range have {
		claims := have[id]
		sort.Slice(claims, func(i, j int) bool { return claims[i].ID > claims[j].ID })
		have[id] = claims
	}

	// Claims held for something that is no longer asking.
	orphans := make([]string, 0, len(have))
	for id := range have {
		if _, ok := want[id]; !ok {
			orphans = append(orphans, id)
		}
	}
	sort.Strings(orphans)
	for _, id := range orphans {
		for _, c := range have[id] {
			plan.Remove = append(plan.Remove, c.ID)
		}
	}

	for _, id := range order {
		spec := want[id]
		claims := have[id]
		switch {
		case len(claims) > spec.Seats:
			for _, c := range claims[:len(claims)-spec.Seats] {
				plan.Remove = append(plan.Remove, c.ID)
			}
		case len(claims) < spec.Seats:
			ad, err := spec.SeatAd()
			if err != nil {
				// No shape, no claim. Asking for an unshaped claim
				// would match any machine at all, which is worse than
				// holding nothing.
				if plan.Shapes == nil {
					plan.Shapes = make(map[string]error)
				}
				plan.Shapes[id] = err
				continue
			}
			req := claimShape(ad)
			for i := len(claims); i < spec.Seats; i++ {
				plan.Create = append(plan.Create, ClaimRequest{
					Name:        ClaimName(id),
					Owner:       spec.Owner,
					Project:     spec.Project,
					Request:     req,
					Reservation: id,
				})
			}
		}
	}
	return plan
}

// claimAttrs are the attributes of a rendered seat that describe what
// to claim.
//
// The whole job ad is not sent. A claim is a request for a machine, not
// a job: the executable, the files and the environment say nothing
// about which machine fits, and sending them would put a copy of the
// reservation's submit file into the schedd's user record for every
// claim.
var claimAttrs = []string{
	"Requirements",
	"RequestCpus", "RequestMemory", "RequestDisk", "RequestGpus",
	"RequestGPUs",
}

// claimShape extracts the request a claim should carry from a rendered
// seat ad.
func claimShape(seat *classad.ClassAd) *classad.ClassAd {
	out := classad.New()
	if seat == nil {
		return out
	}
	for _, attr := range claimAttrs {
		if expr, ok := seat.Lookup(attr); ok && expr != nil {
			out.InsertExpr(attr, expr)
		}
	}
	return out
}

// ClaimResult is what one reconciliation did.
type ClaimResult struct {
	Created int
	Removed int
	// Errs are the individual failures. One schedd refusing a claim
	// should not stop the others being made, in the same way one
	// unreachable startd does not stop the rest being held.
	Errs []error
	// Shapes is carried through from the plan.
	Shapes map[string]error
}

// Err collects the failures into one error, or nil.
func (r ClaimResult) Err() error {
	if len(r.Errs) == 0 {
		return nil
	}
	parts := make([]string, 0, len(r.Errs))
	for _, e := range r.Errs {
		parts = append(parts, e.Error())
	}
	return fmt.Errorf("%s", strings.Join(parts, "; "))
}

// ReconcileClaims applies a plan.
//
// Removals go first, so a pool at its limit can give capacity back
// before more is asked for -- the mirror of the actuator releasing
// before it holds, and for the same reason.
func ReconcileClaims(ctx context.Context, holder ClaimHolder, plan ClaimPlan) ClaimResult {
	res := ClaimResult{Shapes: plan.Shapes}
	for _, id := range plan.Remove {
		if err := holder.Remove(ctx, id); err != nil {
			res.Errs = append(res.Errs, fmt.Errorf("releasing claim %d: %w", id, err))
			continue
		}
		res.Removed++
	}
	for _, req := range plan.Create {
		if err := holder.Create(ctx, req); err != nil {
			res.Errs = append(res.Errs, fmt.Errorf("claiming capacity for reservation %s: %w", req.Reservation, err))
			continue
		}
		res.Created++
	}
	return res
}
