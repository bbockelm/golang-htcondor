package mcpserver

import (
	"context"
	"fmt"
	"sort"
	"strings"

	"github.com/PelicanPlatform/classad/classad"
	htcondor "github.com/bbockelm/golang-htcondor"
	"github.com/bbockelm/golang-htcondor/webapi/spool"
)

// Cluster-wide input upload for the MCP tool.
//
// HTCondor spools input per job, not per submission: a `queue 5` cluster
// leaves five procs held on HoldReasonCode 16, and each needs its own
// spool before it will run. Callers reasonably read "upload_job_input to
// complete the spooling step" as one call per submission and were
// surprised to find procs 1-4 still held (af-mcp-platform#268).
//
// A bare cluster id -- job_id="2954964" rather than "2954964.0" -- means
// "every proc of this cluster still waiting for input". The work is the
// same work; what changes is that one call does it and the result says
// what it cost.
//
// The fan-out itself lives in webapi/spool, shared with the REST upload
// endpoints, so both surfaces enforce the same limits and report the same
// accounting.

// procsAwaitingInput returns the cluster's procs that are held for
// spooling, oldest proc first, confined to the caller's own jobs.
func (s *Server) procsAwaitingInput(ctx context.Context, cluster int) ([]*classad.ClassAd, error) {
	lim := spool.DefaultLimits()
	constraint, ok := s.scopeToOwner(ctx, spool.AwaitingInputConstraint(cluster))
	if !ok {
		return nil, fmt.Errorf("authentication required")
	}
	// One past the limit, so the caller can say how many remain rather
	// than reporting a truncated list as the whole of it.
	opts, ok := s.selfScopedQueryOptions(ctx, &htcondor.QueryOptions{
		Projection: []string{"ClusterId", "ProcId", "TransferInput", "Cmd", "TransferExecutable"},
		Limit:      lim.MaxProcs + 1,
	})
	if !ok {
		return nil, fmt.Errorf("authentication required")
	}
	ads, _, err := s.getSchedd().QueryWithOptions(ctx, constraint, opts)
	if err != nil {
		return nil, fmt.Errorf("failed to query cluster %d: %w", cluster, err)
	}
	spool.SortByProc(ads)
	return ads, nil
}

// uploadNothingToDo is the answer when a cluster has no proc waiting for
// input. Not an error: the usual cause is that the input is already
// spooled, which is the state the caller was asking for.
func uploadNothingToDo(cluster int) map[string]interface{} {
	return map[string]interface{}{
		"content": []map[string]interface{}{
			{
				"type": "text",
				"text": fmt.Sprintf("Cluster %d has no procs waiting for input; nothing to upload.\n\n"+
					"A proc only needs an upload while it is HELD with HoldReasonCode 16 "+
					"(\"Spooling input data files\"). If the jobs are held for some other "+
					"reason, query_jobs will show HoldReason and uploading will not help.",
					cluster),
			},
		},
		"metadata": map[string]interface{}{
			"cluster_id":      cluster,
			"procs_spooled":   0,
			"procs_remaining": 0,
		},
	}
}

// uploadToCluster spools one tar to every proc of a cluster that is
// waiting for input, within the shared limits, and reports what it did
// and what is left.
func (s *Server) uploadToCluster(
	ctx context.Context,
	cluster int,
	ads []*classad.ClassAd,
	tarBytes []byte,
	uploadedFiles []string,
	sizeWarning string,
) (interface{}, error) {
	src := spool.Bytes(tarBytes)
	lim := spool.DefaultLimits()

	attempt, planned, err := spool.Plan(ads, src.Size(), lim)
	if err != nil {
		return nil, err
	}

	res := spool.FanOut(ctx, attempt, src, lim, s.getSchedd().SpoolJobFilesFromTar)
	res.NotAttempted = planned.NotAttempted
	res.Capped = planned.Capped

	perProc := src.Size()
	var b strings.Builder
	fmt.Fprintf(&b, "Uploaded %d file(s) to %d proc(s) of cluster %d: %s\n",
		len(uploadedFiles), len(res.Spooled), cluster, strings.Join(uploadedFiles, ", "))
	fmt.Fprintf(&b, "Cost: %d bytes per proc, %d bytes transferred in total.\n",
		perProc, perProc*int64(len(res.Spooled)))

	if len(res.Failed) > 0 {
		fmt.Fprintf(&b, "\n%d proc(s) failed:\n", len(res.Failed))
		for _, id := range sortedKeys(res.Failed) {
			fmt.Fprintf(&b, "  %s: %s\n", id, res.Failed[id])
		}
	}

	if remaining := res.Remaining(); remaining > 0 {
		fmt.Fprintf(&b, "\n%d proc(s) of this cluster are still waiting for input. "+
			"Call upload_job_input again with job_id=\"%d\" to continue", remaining, cluster)
		if res.Capped {
			fmt.Fprintf(&b, " (one call spools at most %d procs, or %d bytes in total)",
				lim.MaxProcs, lim.MaxVolume)
		}
		b.WriteString(".\n")
		b.WriteString("\nFor a fan-out of this size, HTTP/HTTPS URLs in transfer_input_files " +
			"are usually the better pattern: the execute nodes fetch the input themselves " +
			"and no per-proc upload is needed.\n")
	} else {
		b.WriteString("\nNEXT STEPS:\n" +
			"1. These procs should leave HELD and become IDLE (JobStatus=1).\n" +
			"2. To wait for them to finish, use watch_jobs (event=\"done\") and check_watches instead of polling query_jobs in a loop.\n" +
			"3. When JobStatus=4 (Completed), use get_job_output to retrieve output files.\n")
	}
	b.WriteString(sizeWarning)

	return map[string]interface{}{
		"content": []map[string]interface{}{
			{"type": "text", "text": b.String()},
		},
		"metadata": map[string]interface{}{
			"cluster_id":      cluster,
			"procs_awaiting":  len(ads),
			"procs_spooled":   len(res.Spooled),
			"procs_failed":    len(res.Failed),
			"procs_remaining": res.Remaining(),
			"spooled":         res.Spooled,
			"failed":          res.Failed,
			"file_count":      len(uploadedFiles),
			"files":           uploadedFiles,
			"bytes_per_proc":  perProc,
			"bytes_total":     perProc * int64(len(res.Spooled)),
		},
	}, nil
}

func sortedKeys(m map[string]string) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
