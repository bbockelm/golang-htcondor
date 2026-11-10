package httpserver

import (
	"context"
	"time"

	htcondor "github.com/bbockelm/golang-htcondor"
	"github.com/bbockelm/golang-htcondor/logging"
	"github.com/bbockelm/golang-htcondor/webapi/reservation"
)

// claimTick is how often the always-on reservations are reconciled
// against the claims the schedd holds.
//
// Slower than the controller's tick because nothing here is urgent. A
// claim is acquired by waiting for the pool to free capacity, not by
// draining towards a deadline, so noticing a minute later that one more
// is wanted costs a minute on top of a wait measured in negotiation
// cycles.
const claimTick = 2 * time.Minute

// scheddClaims is reservation.ClaimHolder over this access point's
// schedd.
//
// One schedd, deliberately. A persistent claim lives in a schedd's user
// record, so a reservation held this way serves the jobs of one access
// point -- see the note at the top of the reservation package's
// claims.go. In multi-AP mode this is still the local schedd: the
// reservation belongs to this access point, not to whichever one a
// request happened to be routed to.
type scheddClaims struct {
	h *Handler
}

func (c scheddClaims) schedd() *htcondor.Schedd { return c.h.getSchedd() }

func (c scheddClaims) List(ctx context.Context) ([]reservation.Claim, error) {
	ocus, err := c.schedd().QueryOCUs(ctx)
	if err != nil {
		return nil, err
	}
	out := make([]reservation.Claim, 0, len(ocus))
	for _, o := range ocus {
		out = append(out, reservation.Claim{
			ID: o.ID, Name: o.Name, Owner: o.Owner, Project: o.Project,
		})
	}
	return out, nil
}

func (c scheddClaims) Create(ctx context.Context, req reservation.ClaimRequest) error {
	_, err := c.schedd().CreateOCU(ctx, &htcondor.OCURequest{
		Owner:   req.Owner,
		Project: req.Project,
		Name:    req.Name,
		// The claim is only offered for negotiation under a submitter
		// whose owners include it, so a claim created with no submitter
		// is never matched and waits for ever without saying why.
		Submitter: req.Owner,
		Request:   req.Request,
	})
	return err
}

func (c scheddClaims) Remove(ctx context.Context, id int64) error {
	return c.schedd().RemoveOCU(ctx, id)
}

// startReservationClaims reconciles the always-on reservations against
// the schedd's persistent claims, on a timer.
//
// Only runs when HTTP_API_RESERVATION_CLAIMS is on. It is opt-in rather
// than the default because turning it on changes where an always-on
// reservation's capacity comes from -- the claims below instead of the
// machine attributes the rest of the subsystem pushes -- and because
// the schedd it talks to has to be configured to let it: creating a
// claim needs the access point to be a queue super user there or named
// in OCU_SUPER_USERS.
func (h *Handler) startReservationClaims(ctx context.Context) {
	if !h.reservationsEnabled || !h.reservationClaims {
		return
	}

	// Marked for the same reason the rest of the subsystem's background
	// work is: this is the daemon acting on its own authority, with no
	// caller to act for, and creating a claim is an administrative act
	// the schedd only accepts from a super user. Without the mark it
	// would reach CEDAR unclassified and authenticate as this daemon by
	// falling through, which is the same outcome by accident.
	ctx = htcondor.WithDaemonCredential(ctx,
		"reservations: holding permanent capacity as persistent claims")

	holder := scheddClaims{h}
	go func() {
		ticker := time.NewTicker(claimTick)
		defer ticker.Stop()
		for {
			h.reconcileReservationClaims(ctx, holder)
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
			}
		}
	}()
}

// reconcileReservationClaims runs one pass.
func (h *Handler) reconcileReservationClaims(ctx context.Context, holder reservation.ClaimHolder) {
	store := h.reservationStore()
	if store == nil {
		return
	}
	specs, err := store.List(ctx)
	if err != nil {
		h.logger.Warnf(logging.DestinationCollector, "reservation claims: reading the reservations: %v", err)
		return
	}
	held, err := holder.List(ctx)
	if err != nil {
		h.logger.Warnf(logging.DestinationCollector, "reservation claims: reading the schedd's claims: %v", err)
		return
	}

	plan := reservation.PlanClaims(specs, held)
	for id, shapeErr := range plan.Shapes {
		// Nothing the reconciliation can do: the reservation's submit
		// file will not render, so there is no shape to claim.
		h.logger.Warnf(logging.DestinationCollector,
			"reservation %s holds nothing permanently: %v", id, shapeErr)
	}
	if plan.Empty() {
		return
	}

	res := reservation.ReconcileClaims(ctx, holder, plan)
	if res.Created > 0 || res.Removed > 0 {
		h.logger.Infof(logging.DestinationCollector,
			"reservation claims: asked for %d, released %d", res.Created, res.Removed)
	}
	if err := res.Err(); err != nil {
		h.logger.Warnf(logging.DestinationCollector, "reservation claims: %v", err)
	}
}
