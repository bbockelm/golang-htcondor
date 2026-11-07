package htcondor

import (
	"context"
	"fmt"
	"log"
	"strings"
	"time"

	"github.com/PelicanPlatform/classad/classad"
)

// Restoring the submitter's hold reason after a spooling submission.
//
// configureRemoteJobAd has already done the part that matters: the job
// carries JobStatusOnRelease, so the schedd's post-spool release lands
// it in HELD rather than IDLE, atomically, with no window in which it
// could match. By the time anything here runs the job is already held
// and cannot start, whatever happens below.
//
// What is left is cosmetic, and is the part a client cannot do by
// writing attributes. The release moves HoldReason, HoldReasonCode and
// HoldReasonSubCode aside into their Last* counterparts, so the job
// arrives held with no reason at all -- `condor_q -hold` shows a blank,
// which reads like something went wrong rather than like what the
// submitter asked for. HoldReason is a protected attribute, so writing
// it back is refused for anyone but a queue superuser. A hold ACTION is
// not refused, and sets the reason as a side effect.
//
// The cost of that is the hold code: the schedd's hold action always
// records UserRequest (1), and SubmittedOnHold (15) can only be written
// at submit time, where the spooling hold has to live instead. So the
// code on the finished job is 1, not the 15 a local `hold = true` would
// leave. The reason text is the same.

// submitHoldRestoreTimeout bounds the wait for the schedd's release.
//
// The release happens in a reaper after the transfer thread exits, and
// that thread sleeps a deliberate second first, so a second or two is
// normal. Giving up leaves a job that is held with no reason on it,
// which is the same outcome as not trying -- never a job that runs.
const submitHoldRestoreTimeout = 30 * time.Second

// submitHoldPollInterval is how often the release is checked for.
const submitHoldPollInterval = 250 * time.Millisecond

// restoreSubmitHolds re-applies the submitter's hold reason to every job
// in ads that was submitted on hold, once the schedd's post-spool release
// has landed.
//
// Returns without talking to the schedd at all for ads that asked for no
// such thing, which is almost every submission.
//
// Errors are logged and never returned: the job is correctly held either
// way, and failing a submission that worked -- over the text in a status
// field -- would invite a retry that submits it twice.
func (s *Schedd) restoreSubmitHolds(ctx context.Context, ads []*classad.ClassAd) {
	for _, g := range groupHeldSubmissions(ads) {
		if err := s.restoreOneSubmitHold(ctx, g); err != nil {
			log.Printf("submit: cluster %d is held as requested, but its hold reason could not be set: %v",
				g.cluster, err)
		}
	}
}

// heldGroup is one cluster's worth of jobs that share a hold reason.
//
// Grouped rather than held one at a time because every job in a cluster
// is released by the same pass of the schedd's reaper, so one wait and
// one hold cover all of them. Per job, a `queue 100` submitted on hold
// would be a hundred waits and a hundred authenticated round trips.
type heldGroup struct {
	cluster int
	// proc is any one job in the group, the one whose release is waited
	// for. They are released together.
	proc   int
	reason string
}

// constraint selects this group's jobs.
//
// Scoped to the cluster, not to the reason alone: SubmitHoldReason is a
// durable attribute, so a bare match on it would also name jobs held by
// an earlier submission that happened to use the same words. A cluster
// is created fresh by each submission, so adding the cluster makes the
// constraint exactly this submission's jobs -- including procs this call
// did not spool, which belong to the same submission and want the same
// hold.
func (g heldGroup) constraint() string {
	return fmt.Sprintf("ClusterId == %d && %s == %s",
		g.cluster, attrSubmitHoldReason, classadQuoteString(g.reason))
}

// groupHeldSubmissions picks out the jobs configureRemoteJobAd marked,
// one group per cluster and reason.
func groupHeldSubmissions(ads []*classad.ClassAd) []heldGroup {
	type key struct {
		cluster int
		reason  string
	}
	seen := make(map[key]bool)
	var groups []heldGroup

	for _, ad := range ads {
		if ad == nil {
			continue
		}
		// The marker is the attribute that does the work, not a flag
		// set beside it: a job whose release will not land it in HELD
		// is not one of these, whatever else the ad says.
		if status, ok := ad.EvaluateAttrInt(attrJobStatusOnRelease); !ok || status != jobStatusHeld {
			continue
		}
		cluster, okC := ad.EvaluateAttrInt("ClusterId")
		proc, okP := ad.EvaluateAttrInt("ProcId")
		if !okC || !okP {
			continue
		}
		reason, ok := ad.EvaluateAttrString(attrSubmitHoldReason)
		if !ok || strings.TrimSpace(reason) == "" {
			reason = defaultSubmitHoldReason
		}
		k := key{cluster: int(cluster), reason: reason}
		if seen[k] {
			continue
		}
		seen[k] = true
		groups = append(groups, heldGroup{cluster: int(cluster), proc: int(proc), reason: reason})
	}
	return groups
}

// restoreOneSubmitHold waits for the spooling hold to end and then puts
// the submitter's reason on the group's jobs.
func (s *Schedd) restoreOneSubmitHold(ctx context.Context, g heldGroup) error {
	ctx, cancel := context.WithTimeout(ctx, submitHoldRestoreTimeout)
	defer cancel()

	if err := s.waitForSpoolRelease(ctx,
		fmt.Sprintf("ClusterId == %d && ProcId == %d", g.cluster, g.proc)); err != nil {
		return err
	}

	// A hold action rather than an attribute write, because HoldReason
	// is protected. Harmless if it loses a race and finds a job still
	// spooling: the schedd answers "already on hold" and the job stays
	// held, just without the reason.
	res, err := s.HoldJobs(ctx, g.constraint(), g.reason)
	if err != nil {
		return err
	}
	if res != nil && res.Success == 0 {
		return fmt.Errorf("the schedd accepted no hold for these jobs (%+v)", res)
	}
	return nil
}

// waitForSpoolRelease blocks until the schedd has ended the spooling
// hold, which is what makes the job's hold reason writable again.
//
// Waiting rather than holding straight away, because a hold action on a
// job still held for spooling is answered with "already on hold" and
// changes nothing -- and the release that follows would then move the
// reason aside anyway.
func (s *Schedd) waitForSpoolRelease(ctx context.Context, constraint string) error {
	projection := []string{"ClusterId", "ProcId", "JobStatus", "HoldReasonCode"}
	ticker := time.NewTicker(submitHoldPollInterval)
	defer ticker.Stop()

	for {
		ads, err := s.Query(ctx, constraint, projection)
		if err != nil {
			return fmt.Errorf("waiting for the spooling hold to end: %w", err)
		}
		if len(ads) == 0 {
			return fmt.Errorf("the job left the queue before its hold could be set")
		}
		status, _ := ads[0].EvaluateAttrInt("JobStatus")
		code, hasCode := ads[0].EvaluateAttrInt("HoldReasonCode")
		switch {
		case status == jobStatusRemoved:
			// The schedd aborts a job whose staging failed.
			return fmt.Errorf("the job was removed before its hold could be set")
		case !hasCode || code != holdCodeSpoolingInput:
			// The spooling hold is gone, so the release has landed and
			// JobStatusOnRelease has already decided the job is held.
			return nil
		}

		select {
		case <-ctx.Done():
			return fmt.Errorf("the spooling hold did not end within %s", submitHoldRestoreTimeout)
		case <-ticker.C:
		}
	}
}

// afterSpool runs what a completed spool still owes the submitter.
//
// Its own step rather than the tail of each spool function, because it
// has to happen after that function's connection to the schedd is
// closed: it opens connections of its own, and the deferred close in
// those functions runs last.
//
// Never returns an error. Everything it does is a repair to a submission
// that has already succeeded, and failing the call here would report a
// submit as failed for work that is done -- which invites a retry that
// submits the job a second time.
func (s *Schedd) afterSpool(ctx context.Context, jobAds []*classad.ClassAd) error {
	// A job submitted with `hold = true` is already held by now --
	// JobStatusOnRelease saw to that -- but the release has taken its
	// hold reason with it. Put the submitter's reason back. Does
	// nothing, and does not talk to the schedd, for every other
	// submission.
	s.restoreSubmitHolds(ctx, jobAds)
	return nil
}

// SubmittedOnHold reports whether a job ad is one that was submitted
// with `hold = true` and so will be held, not idle, once its input has
// spooled.
//
// Exported because the difference matters to whoever is told what to do
// next. Every other spooling submission becomes idle when the spool
// finishes and runs when it matches; this one sits held until somebody
// releases it, and a caller advised to wait for it to start is being
// advised to wait forever.
func SubmittedOnHold(ad *classad.ClassAd) bool {
	if ad == nil {
		return false
	}
	// JobStatusOnRelease while the job is still spooling, and
	// SubmitHoldReason afterwards: the release consumes the first and
	// leaves the second, so between them they answer the question at
	// either point in the job's life.
	if status, ok := ad.EvaluateAttrInt(attrJobStatusOnRelease); ok && status == jobStatusHeld {
		return true
	}
	reason, ok := ad.EvaluateAttrString(attrSubmitHoldReason)
	return ok && strings.TrimSpace(reason) != ""
}
