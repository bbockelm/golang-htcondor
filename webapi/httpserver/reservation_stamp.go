package httpserver

import (
	"context"
	"fmt"
	"strconv"
	"time"

	htcondor "github.com/bbockelm/golang-htcondor"
	"github.com/bbockelm/golang-htcondor/logging"
	"github.com/bbockelm/golang-htcondor/webapi/reservation"
	"github.com/bbockelm/golang-htcondor/webapi/runtimeest"
)

// stampInterval is how often the idle queue is re-stamped.
//
// Slower than the controller's tick because nothing about it is urgent:
// a missing stamp costs a job its chance at a held machine, and a job
// that waits five more minutes for one loses nothing it would not have
// lost waiting for the next negotiation cycle anyway.
const stampInterval = 5 * time.Minute

// stampQueryLimit caps one read of the idle queue. A queue larger than
// this is stamped from what did come back; the next pass sees the rest.
const stampQueryLimit = 500_000

// scheddIdleQueue reads the idle queue and the stamps already on its
// cluster ads.
type scheddIdleQueue struct {
	h *Handler
}

// idleJobAttrs is what the estimator needs, plus the cluster id to
// group by. The bucket itself is deliberately NOT read here: a proc
// reports the value it inherits from its cluster, so reading it would
// make an unstamped cluster look stamped.
var idleJobAttrs = append(append([]string{}, runtimeest.QueryAttrs...), "ClusterId", "ProcId")

func (q scheddIdleQueue) IdleJobs(ctx context.Context) ([]reservation.JobView, error) {
	est := q.h.runtimeEst
	if est == nil {
		return nil, nil
	}
	ads, _, err := q.h.getSchedd().QueryWithOptions(ctx, "JobStatus == 1", &htcondor.QueryOptions{
		Projection: idleJobAttrs,
		Limit:      stampQueryLimit,
	})
	if err != nil {
		return nil, err
	}
	now := time.Now()
	out := make([]reservation.JobView, 0, len(ads))
	for _, ad := range ads {
		if ad == nil {
			continue
		}
		cluster, ok := ad.EvaluateAttrInt("ClusterId")
		if !ok {
			continue
		}
		view := reservation.JobView{Cluster: int(cluster)}
		// P90, not the estimate: the sieve's promise is that the job
		// will have finished by the bell, and the median would break it
		// half the time.
		if res := est.Estimate(runtimeest.QueryFromAd(ad, now)); res.Available && res.P90Seconds > 0 {
			view.Want = reservation.Bucket(time.Duration(res.P90Seconds) * time.Second)
		}
		out = append(out, view)
	}
	return out, nil
}

func (q scheddIdleQueue) Clusters(ctx context.Context) ([]reservation.ClusterView, error) {
	// Cluster ads only. A proc ad would report the inherited value,
	// which is exactly what must not be read back as "already written".
	ads, _, err := q.h.getSchedd().QueryWithOptions(ctx, "", &htcondor.QueryOptions{
		Projection: []string{"ClusterId", reservation.AttrBucket},
		Limit:      stampQueryLimit,
		FetchOpts:  htcondor.FetchNoProcAds | htcondor.FetchIncludeClusterAd,
	})
	if err != nil {
		return nil, err
	}
	out := make([]reservation.ClusterView, 0, len(ads))
	for _, ad := range ads {
		if ad == nil {
			continue
		}
		cluster, ok := ad.EvaluateAttrInt("ClusterId")
		if !ok {
			continue
		}
		have, _ := ad.EvaluateAttrInt(reservation.AttrBucket)
		out = append(out, reservation.ClusterView{Cluster: int(cluster), Have: have})
	}
	return out, nil
}

// scheddStampWriter writes cluster-ad attributes over qmgmt.
type scheddStampWriter struct {
	h *Handler
}

// Write sets the bucket on each cluster ad in one transaction.
//
// One transaction for the whole pass rather than one each: the schedd
// writes a job-queue record per attribute either way, but a single
// commit means the queue is consistent between passes and the log is
// fsynced once.
func (w scheddStampWriter) Write(ctx context.Context, stamps []reservation.Stamp) error {
	if len(stamps) == 0 {
		return nil
	}
	addr := w.h.getSchedd().Address()
	if addr == "" {
		return fmt.Errorf("no schedd address")
	}
	conn, err := htcondor.NewQmgmtConnection(ctx, addr)
	if err != nil {
		return fmt.Errorf("connecting to the schedd: %w", err)
	}
	defer func() { _ = conn.Close() }()

	for _, s := range stamps {
		// Proc -1 is the cluster ad. Every proc of the cluster reads
		// the attribute through it, including for matchmaking.
		if err := conn.SetAttribute(ctx, s.Cluster, -1, reservation.AttrBucket,
			strconv.FormatInt(s.Bucket, 10), 0); err != nil {
			_ = conn.AbortTransaction(ctx)
			return fmt.Errorf("stamping cluster %d: %w", s.Cluster, err)
		}
	}
	if err := conn.CommitTransaction(ctx); err != nil {
		return fmt.Errorf("committing %d stamps: %w", len(stamps), err)
	}
	return nil
}

// startReservationStamping keeps the idle queue stamped.
//
// Without it a held machine admits nothing but the reserved project, so
// a drain costs the whole machine for its whole lead instead of costing
// nothing. It runs with the rest of the subsystem and needs the runtime
// estimator, which is where the estimates come from.
func (h *Handler) startReservationStamping(ctx context.Context) {
	if !h.reservationsEnabled || h.runtimeEst == nil {
		return
	}
	h.reservationStamper = &reservation.Stamper{
		Queue:  scheddIdleQueue{h},
		Writer: scheddStampWriter{h},
		Budget: h.reservationStampBudget,
	}
	go h.reservationStamper.Run(ctx, stampInterval, func(res reservation.StampResult, err error) {
		if err != nil {
			h.logger.Warnf(logging.DestinationSchedd, "reservation stamping failed: %v", err)
			return
		}
		if res.Written > 0 {
			h.logger.Infof(logging.DestinationSchedd,
				"reservations: stamped %d cluster ads covering %d of %d idle jobs",
				res.Written, res.Covered, res.Idle)
		}
		if res.Deferred > 0 {
			// The budget is smaller than the queue needs. Nothing is
			// wrong, but the pool is not fully usable by a reservation
			// until it catches up.
			h.logger.Warnf(logging.DestinationSchedd,
				"reservations: %d clusters still need a runtime estimate written; raise HTTP_API_RESERVATION_STAMP_BUDGET",
				res.Deferred)
		}
	})
}
