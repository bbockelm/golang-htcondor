package spool

import (
	"context"
	"fmt"

	"github.com/PelicanPlatform/classad/classad"
	htcondor "github.com/bbockelm/golang-htcondor"
)

// jobStatusHeld is HTCondor's JobStatus for a held job.
const jobStatusHeld = 5

// InputSpoolProjection is the projection to use when looking up the ads
// an input upload writes into. It must include every attribute
// htcondor.SpoolInputAllowSet reads -- that helper computes the
// allow-set of filenames the schedd will accept, and any name absent
// from the set is silently dropped on its way into the spool:
//
//   - TransferInput: the explicit user-listed inputs
//   - Cmd: the executable's path; its basename joins the allow-set when
//     the path is relative AND TransferExecutable is true
//   - TransferExecutable: gates the Cmd-basename inclusion above
//
// Dropping any of these leaves the executable out of the spool; the
// schedd then fails the input transfer at execute time with "errno 2 No
// such file or directory" and the job hold-loops on the missing file.
var InputSpoolProjection = []string{
	"ClusterId", "ProcId", "TransferInput", "Cmd", "TransferExecutable",
}

// InputShareProjection adds the state a share-URL mint or redeem has to
// decide on: whether the job is still held awaiting its input. That
// state, not the token's expiry, is what really bounds an upload URL --
// once the spool completes the job leaves it and the URL is inert.
var InputShareProjection = append(append([]string{}, InputSpoolProjection...),
	"JobStatus", "HoldReasonCode", "Owner")

// AwaitingInput reports whether a job is in the one state that can
// accept an input upload: held with the spooling hold code. The ad must
// have been fetched with InputShareProjection.
func AwaitingInput(ad *classad.ClassAd) bool {
	if ad == nil {
		return false
	}
	status, ok := ad.EvaluateAttrInt("JobStatus")
	if !ok || status != jobStatusHeld {
		return false
	}
	code, ok := ad.EvaluateAttrInt("HoldReasonCode")
	return ok && code == int64(SpoolingHoldCode)
}

// ProcIDOf reads a proc ad's cluster and proc. An ad it cannot read is
// skipped by callers rather than defaulted: a token or upload addressed
// to 0.0 would silently name the wrong job.
func ProcIDOf(ad *classad.ClassAd) (int, int, bool) {
	cluster, ok := ad.EvaluateAttrInt("ClusterId")
	if !ok {
		return 0, 0, false
	}
	proc, ok := ad.EvaluateAttrInt("ProcId")
	if !ok {
		return 0, 0, false
	}
	return int(cluster), int(proc), true
}

// OverlayClusterOntoProc copies cluster-ad attributes onto a proc ad
// wherever the proc does not define its own, matching HTCondor's
// "cluster as defaults, proc as overrides" semantics.
func OverlayClusterOntoProc(cluster, proc *classad.ClassAd) {
	if cluster == nil || proc == nil {
		return
	}
	for _, attr := range cluster.GetAttributes() {
		if _, ok := proc.Lookup(attr); ok {
			continue // proc has its own value; don't clobber
		}
		expr, ok := cluster.Lookup(attr)
		if !ok || expr == nil {
			continue
		}
		_ = proc.Set(attr, expr)
	}
}

// FetchProcAd returns the proc ad for (cluster, proc) with cluster-ad
// attributes overlaid, or (nil, nil) when no such proc is visible.
//
// The overlay is the reason this is not a plain query. The schedd stores
// attributes shared across all procs of a cluster (Cmd,
// TransferExecutable, …) on the cluster ad rather than duplicating them
// per-proc, so a `ClusterId == X && ProcId == Y` query alone returns
// only the proc-specific differences. Without the overlay the allow-set
// never sees Cmd and the executable is dropped in silence. Both ads come
// back in one query (ProcId == proc OR ProcId == -1) with
// FetchIncludeClusterAd.
//
// ownerScope, when set, wraps the whole id predicate with the caller's
// owner clause -- around the whole thing, because the cluster ad
// (ProcId == -1) must stay reachable.
func FetchProcAd(
	ctx context.Context,
	schedd *htcondor.Schedd,
	cluster, proc int,
	ownerScope func(string) (string, error),
	projection []string,
) (*classad.ClassAd, error) {
	constraint := fmt.Sprintf("ClusterId == %d && (ProcId == %d || ProcId == -1)", cluster, proc)
	if ownerScope != nil {
		scoped, err := ownerScope(constraint)
		if err != nil {
			return nil, err
		}
		constraint = scoped
	}
	ads, _, err := schedd.QueryWithOptions(ctx, constraint, &htcondor.QueryOptions{
		Projection: projection,
		FetchOpts:  htcondor.FetchIncludeClusterAd,
	})
	if err != nil {
		return nil, err
	}

	var procAd, clusterAd *classad.ClassAd
	for _, ad := range ads {
		pid, ok := ad.EvaluateAttrInt("ProcId")
		if !ok {
			continue
		}
		switch {
		case pid == int64(proc) && procAd == nil:
			procAd = ad
		case pid == -1 && clusterAd == nil:
			clusterAd = ad
		}
	}
	if procAd == nil {
		return nil, nil
	}
	OverlayClusterOntoProc(clusterAd, procAd)
	return procAd, nil
}

// FetchProcAdsAwaitingInput looks up every proc of a cluster that is
// held for input spooling, with the cluster ad's attributes overlaid.
//
// The projection is load-bearing: it must carry everything the caller's
// allow-set computation reads, or files go missing from the spool in
// silence. See InputSpoolProjection.
//
// It queries past the limit so the caller can report a remainder rather
// than presenting a truncated list as the whole cluster; the cluster ad
// is not a proc, hence the extra slot.
//
// The cluster-ad request and overlay are belt and braces. Against a 25.8
// schedd they do nothing measurable: QUERY_JOB_ADS merges chained
// cluster attributes into each proc ad, and the cluster ad itself does
// not come back even with FetchIncludeClusterAd and an explicit
// ProcId == -1 clause. They are kept because the single-proc path does
// the same and because a schedd that does not merge would otherwise fail
// in the silent way above. ownerScope wraps the whole predicate so the
// cluster ad stays reachable where it is returned.
func FetchProcAdsAwaitingInput(
	ctx context.Context,
	schedd *htcondor.Schedd,
	cluster int,
	limit int,
	ownerScope func(string) (string, error),
	projection []string,
) ([]*classad.ClassAd, error) {
	constraint := fmt.Sprintf(
		"ClusterId == %d && ((JobStatus == 5 && HoldReasonCode == %d) || ProcId == -1)",
		cluster, SpoolingHoldCode)
	if ownerScope != nil {
		scoped, err := ownerScope(constraint)
		if err != nil {
			return nil, err
		}
		constraint = scoped
	}
	// Past the limit so the caller can report a remainder rather than
	// presenting a truncated list as the whole cluster; the cluster ad is
	// not a proc, hence the extra slot.
	ads, _, err := schedd.QueryWithOptions(ctx, constraint, &htcondor.QueryOptions{
		Projection: projection,
		FetchOpts:  htcondor.FetchIncludeClusterAd,
		Limit:      limit + 2,
	})
	if err != nil {
		return nil, err
	}

	var clusterAd *classad.ClassAd
	procs := make([]*classad.ClassAd, 0, len(ads))
	for _, ad := range ads {
		pid, ok := ad.EvaluateAttrInt("ProcId")
		if !ok {
			continue
		}
		if pid == -1 {
			if clusterAd == nil {
				clusterAd = ad
			}
			continue
		}
		procs = append(procs, ad)
	}
	for _, proc := range procs {
		OverlayClusterOntoProc(clusterAd, proc)
	}
	SortByProc(procs)
	return procs, nil
}
