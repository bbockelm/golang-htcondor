package httpserver

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/PelicanPlatform/classad/classad"

	"github.com/bbockelm/cedar/security"

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

// idleJobAttrs is what the estimator needs, the cluster id to group by,
// and the identity to write as. The bucket itself is deliberately NOT
// read here: a proc reports the value it inherits from its cluster, so
// reading it would make an unstamped cluster look stamped.
var idleJobAttrs = append(append([]string{}, runtimeest.QueryAttrs...),
	"ClusterId", "ProcId", "User", "Owner")

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
	horizon := q.h.reservationHorizon()
	out := make([]reservation.JobView, 0, len(ads))
	for _, ad := range ads {
		if ad == nil {
			continue
		}
		cluster, ok := ad.EvaluateAttrInt("ClusterId")
		if !ok {
			continue
		}
		view := reservation.JobView{Cluster: int(cluster), Owner: q.h.jobIdentity(ad)}
		// P90, not the estimate: the sieve's promise is that the job
		// will have finished by the bell, and the median would break it
		// half the time.
		if res := est.Estimate(runtimeest.QueryFromAd(ad, now)); res.Available && res.P90Seconds > 0 {
			view.Want = reservation.BucketCapped(
				time.Duration(res.P90Seconds)*time.Second, horizon)
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

// reservationHorizon is the furthest ahead any enabled reservation
// looks: the longest lead among them.
//
// Estimates are capped one grain beyond it. The sieve only asks whether
// a job finishes before the bell, and the bell is never further away
// than a lead, so every longer estimate is the same answer. Keeping
// them distinct would split autoclusters for the whole pool and buy
// nothing.
//
// Zero -- no reservations, or none enabled -- means no cap, which is
// right: nothing is being held, so nothing is being refused.
func (h *Handler) reservationHorizon() time.Duration {
	store := h.reservationStore()
	if store == nil {
		return 0
	}
	specs, err := store.List(context.Background())
	if err != nil {
		// Capping needs a number we trust. Without one, stamp
		// uncapped: a larger value is always safe for admission, it
		// only costs matchmaking.
		return 0
	}
	var longest time.Duration
	for _, s := range specs {
		if s != nil && s.Enabled && s.Lead > longest {
			longest = s.Lead
		}
	}
	return longest
}

// jobIdentity is the identity to act as for a job: the fully qualified
// name the schedd records as its owner.
//
// User is that name already; Owner is the bare account, which has to be
// qualified with the UID domain to mean anything to the schedd. An ad
// carrying neither is not stamped at all, rather than stamped as this
// process.
func (h *Handler) jobIdentity(ad *classad.ClassAd) string {
	if user, ok := ad.EvaluateAttrString("User"); ok {
		if user = strings.TrimSpace(user); strings.Contains(user, "@") {
			return user
		}
	}
	owner, ok := ad.EvaluateAttrString("Owner")
	if !ok {
		return ""
	}
	if owner = strings.TrimSpace(owner); owner == "" || h.uidDomain == "" {
		return ""
	}
	return owner + "@" + h.uidDomain
}

// scheddStampWriter writes cluster-ad attributes over qmgmt.
//
// Each write is made as the owner of the cluster it edits, not as this
// process. Stamping touches every user's jobs, and the alternative --
// one connection with queue-superuser rights over the whole queue --
// buys nothing: a job's own owner may already edit it, so acting as
// them needs no privilege on the queue at all, and a bug here can only
// mislabel a job with its owner's own estimate.
type scheddStampWriter struct {
	h *Handler
}

// ownerToken mints a short-lived credential naming one job owner.
//
// The lifetime covers a single pass and nothing more: the token is used
// immediately, on the connection opened for it, and never stored.
func (w scheddStampWriter) ownerToken(owner string) (string, error) {
	if w.h.signingKeyPath == "" || w.h.trustDomain == "" {
		return "", fmt.Errorf("no signing key or trust domain, so nothing can be written as %s", owner)
	}
	now := time.Now()
	return security.GenerateJWT(
		filepath.Dir(w.h.signingKeyPath), filepath.Base(w.h.signingKeyPath),
		owner, w.h.trustDomain, now.Unix(), now.Add(stampTokenLife).Unix(), nil)
}

// stampTokenLife is how long a stamping credential is good for. One
// pass, with room for a slow schedd.
const stampTokenLife = 5 * time.Minute

// Write sets the bucket on each cluster ad, one connection per owner.
//
// One transaction per owner rather than one per cluster: the schedd
// writes a job-queue record per attribute either way, but a single
// commit means that owner's clusters are consistent between passes and
// the log is fsynced once for all of them.
//
// One owner's failure does not stop the others. A user whose token the
// schedd will not accept, or whose jobs it will not let this process
// edit, costs that user's clusters their stamp and nothing else.
func (w scheddStampWriter) Write(ctx context.Context, stamps []reservation.Stamp) (int, error) {
	if len(stamps) == 0 {
		return 0, nil
	}
	addr := w.h.getSchedd().Address()
	if addr == "" {
		return 0, fmt.Errorf("no schedd address")
	}
	owners, byOwner := reservation.ByOwner(stamps)
	var errs []error
	written := 0
	for _, owner := range owners {
		if err := w.writeAs(ctx, addr, owner, byOwner[owner]); err != nil {
			errs = append(errs, fmt.Errorf("as %s: %w", owner, err))
			continue
		}
		written += len(byOwner[owner])
	}
	if len(errs) == len(owners) {
		// Every owner failed, which is a fact about this process --
		// the signing key, the trust domain, the schedd -- and not
		// about any one user.
		return 0, fmt.Errorf("no cluster ad could be stamped: %w", errors.Join(errs...))
	}
	return written, errors.Join(errs...)
}

// writeAs stamps one owner's clusters as that owner.
func (w scheddStampWriter) writeAs(ctx context.Context, addr, owner string, stamps []reservation.Stamp) error {
	token, err := w.ownerToken(owner)
	if err != nil {
		return err
	}
	secConfig, err := ConfigureSecurityForToken(token)
	if err != nil {
		return fmt.Errorf("configuring security: %w", err)
	}
	conn, err := htcondor.NewQmgmtConnection(htcondor.WithSecurityConfig(ctx, secConfig), addr)
	if err != nil {
		return fmt.Errorf("connecting to the schedd: %w", err)
	}
	defer func() { _ = conn.Close() }()

	// Name ourselves as the owner we authenticated as, which is what
	// the submit path does. It asks the schedd for no privilege it
	// would not give the user at a shell.
	if err := conn.SetEffectiveOwner(ctx, owner); err != nil {
		return fmt.Errorf("setting the effective owner: %w", err)
	}
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
	if h.signingKeyPath == "" || h.trustDomain == "" {
		// Each stamp is written as the owner of the job it edits, and
		// naming that owner to the schedd needs a credential this
		// process can only mint with the pool's signing key. Without
		// one there is no identity to write as, and writing as this
		// process instead would need superuser rights over everyone's
		// queue to do the same job.
		h.logger.Warnf(logging.DestinationSchedd,
			"reservations: no %s, so idle jobs cannot be stamped and a held machine will admit nothing",
			missingStampCredential(h.signingKeyPath, h.trustDomain))
		return
	}
	h.reservationStamper = &reservation.Stamper{
		Queue:   scheddIdleQueue{h},
		Writer:  scheddStampWriter{h},
		Budget:  h.reservationStampBudget,
		Horizon: h.reservationHorizon,
		// Ahead of the controller: the queue has to be stamped by the
		// time the first machine is held, which is the start of the
		// planning lead.
		Engaged: reservation.SpecGate(storeSpecs{h}, reservationForgiveDefault,
			reservation.SettleAfter, reservation.StampWarmup, nil),
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
		if res.Unowned > 0 {
			// Neither User nor Owner on the job ad, so there is nobody
			// to write as. Nothing here can fix it.
			h.logger.Warnf(logging.DestinationSchedd,
				"reservations: %d idle jobs carry no owner and cannot be stamped", res.Unowned)
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

// missingStampCredential names what is absent, so the warning says what
// to set rather than that something is unset.
func missingStampCredential(signingKey, trustDomain string) string {
	switch {
	case signingKey == "" && trustDomain == "":
		return "token signing key and no TRUST_DOMAIN"
	case signingKey == "":
		return "token signing key"
	default:
		return "TRUST_DOMAIN"
	}
}
