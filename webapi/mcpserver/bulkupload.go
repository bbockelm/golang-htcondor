package mcpserver

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"sort"
	"strconv"
	"strings"
	"sync"

	"github.com/PelicanPlatform/classad/classad"
	htcondor "github.com/bbockelm/golang-htcondor"
)

// Cluster-wide input upload.
//
// HTCondor spools input per job, not per submission: a `queue 5` cluster
// leaves five procs held on HoldReasonCode 16, and each one needs its own
// spool before it will run. Callers reasonably read "upload_job_input to
// complete the spooling step" as one call per submission and were
// surprised to find procs 1-4 still held.
//
// A bare cluster id -- job_id="2954964" rather than "2954964.0" -- means
// "every proc of this cluster that is still waiting for input". The work
// is the same work; what changes is that one call does it instead of N,
// and the result says what it cost.
//
// Deliberately not hidden behind a single opaque call: the uploads are
// bounded, the result reports how many procs were spooled and how many
// remain, and a fan-out too large to finish in one call says so rather
// than silently doing a fraction. An expensive operation that looks cheap
// is worse than one that states its price.

const (
	// maxBulkProcs bounds how many procs one call will spool. Past this
	// the answer is not a bigger upload -- it is HTTP/HTTPS URLs in
	// transfer_input_files, which the workers fetch themselves.
	maxBulkProcs = 1000

	// maxBulkVolume bounds payload x procs for one call. The per-proc
	// payload keeps the advisory limit the single-proc path has always
	// had (maxFileSize); this is the backstop on the product, which is
	// what a fan-out actually costs.
	maxBulkVolume = 1000 * 1024 * 1024

	// bulkUploadConcurrency is how many proc uploads are in flight at
	// once. Each is its own schedd session, so this is a deliberate
	// bound on load rather than an attempt to be fast: serial would be
	// needlessly slow, unbounded would be a way to hurt the schedd.
	bulkUploadConcurrency = 10
)

// uploadTarget is what a job_id argument asked for.
type uploadTarget struct {
	cluster int
	proc    int
	// allProcs is set when the caller gave a bare cluster id, meaning
	// every proc of the cluster still held for spooling.
	allProcs bool
}

// parseUploadTarget accepts "cluster.proc" or a bare "cluster".
//
// A bare cluster id is currently an error, so accepting it adds a meaning
// where there was none rather than changing one.
func parseUploadTarget(s string) (uploadTarget, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return uploadTarget{}, fmt.Errorf("job_id is required")
	}
	if !strings.Contains(s, ".") {
		cluster, err := strconv.Atoi(s)
		if err != nil || cluster <= 0 {
			return uploadTarget{}, fmt.Errorf(
				"job_id %q is neither a job id (\"123.0\") nor a cluster id (\"123\")", s)
		}
		return uploadTarget{cluster: cluster, allProcs: true}, nil
	}
	cluster, proc, err := parseJobID(s)
	if err != nil {
		return uploadTarget{}, err
	}
	return uploadTarget{cluster: cluster, proc: proc}, nil
}

// spoolingHoldCode is the hold a job sits in between submit and the end of
// input spooling. It is the only state a cluster-wide upload acts on: a
// proc that is running, finished, or held for a real reason is not waiting
// for this tar, and spooling into it would be wrong rather than merely
// wasteful.
const spoolingHoldCode = 16

// procsAwaitingInput returns the cluster's procs that are held for
// spooling, oldest proc first so partial progress is predictable.
func (s *Server) procsAwaitingInput(ctx context.Context, cluster int) ([]*classad.ClassAd, error) {
	idClause := fmt.Sprintf("ClusterId == %d && JobStatus == 5 && HoldReasonCode == %d",
		cluster, spoolingHoldCode)
	constraint, ok := s.scopeToOwner(ctx, idClause)
	if !ok {
		return nil, fmt.Errorf("authentication required")
	}
	// One past the limit, so the caller can say how many remain rather
	// than reporting a truncated list as the whole of it.
	opts, ok := s.selfScopedQueryOptions(ctx, &htcondor.QueryOptions{
		Projection: []string{"ClusterId", "ProcId", "TransferInput", "Cmd", "TransferExecutable"},
		Limit:      maxBulkProcs + 1,
	})
	if !ok {
		return nil, fmt.Errorf("authentication required")
	}
	ads, _, err := s.schedd.QueryWithOptions(ctx, constraint, opts)
	if err != nil {
		return nil, fmt.Errorf("failed to query cluster %d: %w", cluster, err)
	}
	sort.SliceStable(ads, func(i, j int) bool {
		pi, _ := ads[i].EvaluateAttrInt("ProcId")
		pj, _ := ads[j].EvaluateAttrInt("ProcId")
		return pi < pj
	})
	return ads, nil
}

// bulkUploadResult is the outcome of one cluster-wide upload.
type bulkUploadResult struct {
	// Spooled are the procs that took the files.
	Spooled []string
	// Failed are procs whose spool returned an error, with the reason.
	Failed map[string]string
	// NotAttempted is how many procs were still held for spooling but
	// outside this call's limits. Non-zero means "call again".
	NotAttempted int
	// Truncated says the cluster has more procs awaiting input than one
	// call will take.
	Truncated bool
}

// spoolToProcs uploads the same tar to each proc, bounded to
// bulkUploadConcurrency in flight.
//
// Each proc is its own SpoolJobFilesFromTar call with its own reader.
// That is not the only way -- the call takes a slice of ads, and a
// multi-job tar addresses procs by a "cluster.proc/" path prefix -- but
// per-proc keeps every upload in the single-job layout, where files sit at
// the tar root. In the multi-job layout an entry whose prefix does not
// match a job in the slice is silently skipped, so a mistake there leaves
// procs held with no error to explain it. It also makes partial progress
// exact: a failure names one proc.
// spoolFunc is one proc's spool. Injectable so the fan-out can be tested
// for the properties that matter about it -- that every proc is
// attempted, and that no more than the intended number are in flight --
// neither of which is observable through a real schedd. It is also the
// seam the REST path needs: the fan-out itself does not depend on the MCP
// server.
type spoolFunc func(ctx context.Context, ads []*classad.ClassAd, r io.Reader) error

func (s *Server) spoolToProcs(ctx context.Context, ads []*classad.ClassAd, tarBytes []byte) bulkUploadResult {
	return fanOutSpool(ctx, ads, tarBytes, bulkUploadConcurrency, s.schedd.SpoolJobFilesFromTar)
}

// fanOutSpool uploads the same tar to each proc, at most concurrency in
// flight at once.
func fanOutSpool(
	ctx context.Context,
	ads []*classad.ClassAd,
	tarBytes []byte,
	concurrency int,
	spool spoolFunc,
) bulkUploadResult {
	res := bulkUploadResult{Failed: map[string]string{}}
	if concurrency < 1 {
		concurrency = 1
	}

	var mu sync.Mutex
	sem := make(chan struct{}, concurrency)
	var wg sync.WaitGroup

	for _, ad := range ads {
		cl, _ := ad.EvaluateAttrInt("ClusterId")
		pr, _ := ad.EvaluateAttrInt("ProcId")
		id := fmt.Sprintf("%d.%d", cl, pr)

		wg.Add(1)
		go func(ad *classad.ClassAd, id string) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()

			// A fresh reader per proc: the tar is replayed, not shared.
			err := spool(ctx, []*classad.ClassAd{ad}, bytes.NewReader(tarBytes))

			mu.Lock()
			defer mu.Unlock()
			if err != nil {
				res.Failed[id] = err.Error()
				return
			}
			res.Spooled = append(res.Spooled, id)
		}(ad, id)
	}
	wg.Wait()

	sort.Strings(res.Spooled)
	return res
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
// waiting for input, within this call's limits, and reports what it did
// and what is left.
func (s *Server) uploadToCluster(
	ctx context.Context,
	cluster int,
	ads []*classad.ClassAd,
	tarBytes []byte,
	uploadedFiles []string,
	perProcSize int64,
	sizeWarning string,
) (interface{}, error) {
	awaiting := len(ads)
	truncated := awaiting > maxBulkProcs
	if truncated {
		ads = ads[:maxBulkProcs]
	}

	// The cost of a fan-out is payload x procs. Trim to what fits rather
	// than refusing outright: partial progress plus an accurate count of
	// what remains is more useful than an error, and the caller can
	// simply call again.
	volumeCapped := false
	if perProcSize > 0 {
		if affordable := int(maxBulkVolume / perProcSize); affordable < len(ads) {
			if affordable < 1 {
				return nil, fmt.Errorf(
					"a single proc's upload (%d bytes) exceeds the %d byte limit for one call; "+
						"use HTTP/HTTPS URLs in transfer_input_files instead",
					perProcSize, maxBulkVolume)
			}
			ads = ads[:affordable]
			volumeCapped = true
		}
	}

	res := s.spoolToProcs(ctx, ads, tarBytes)
	res.NotAttempted = awaiting - len(ads)
	res.Truncated = truncated || volumeCapped

	var b strings.Builder
	fmt.Fprintf(&b, "Uploaded %d file(s) to %d proc(s) of cluster %d: %s\n",
		len(uploadedFiles), len(res.Spooled), cluster, strings.Join(uploadedFiles, ", "))
	fmt.Fprintf(&b, "Cost: %d bytes per proc, %d bytes transferred in total.\n",
		perProcSize, perProcSize*int64(len(res.Spooled)))

	if len(res.Failed) > 0 {
		fmt.Fprintf(&b, "\n%d proc(s) failed:\n", len(res.Failed))
		for _, id := range sortedKeys(res.Failed) {
			fmt.Fprintf(&b, "  %s: %s\n", id, res.Failed[id])
		}
	}

	remaining := res.NotAttempted + len(res.Failed)
	if remaining > 0 {
		fmt.Fprintf(&b, "\n%d proc(s) of this cluster are still waiting for input. "+
			"Call upload_job_input again with job_id=\"%d\" to continue", remaining, cluster)
		if res.Truncated {
			fmt.Fprintf(&b, " (one call spools at most %d procs, or %d bytes in total)",
				maxBulkProcs, maxBulkVolume)
		}
		b.WriteString(".\n")
		fmt.Fprintf(&b, "\nFor a fan-out of this size, HTTP/HTTPS URLs in transfer_input_files "+
			"are usually the better pattern: the workers fetch the input themselves and no "+
			"per-proc upload is needed.\n")
	} else {
		b.WriteString("\nNEXT STEPS:\n" +
			"1. These procs should leave HELD and become IDLE (JobStatus=1).\n" +
			"2. Poll with query_jobs to monitor progress.\n" +
			"3. When JobStatus=4 (Completed), use get_job_output to retrieve output files.\n")
	}
	b.WriteString(sizeWarning)

	return map[string]interface{}{
		"content": []map[string]interface{}{
			{"type": "text", "text": b.String()},
		},
		"metadata": map[string]interface{}{
			"cluster_id":      cluster,
			"procs_awaiting":  awaiting,
			"procs_spooled":   len(res.Spooled),
			"procs_failed":    len(res.Failed),
			"procs_remaining": remaining,
			"spooled":         res.Spooled,
			"failed":          res.Failed,
			"file_count":      len(uploadedFiles),
			"files":           uploadedFiles,
			"bytes_per_proc":  perProcSize,
			"bytes_total":     perProcSize * int64(len(res.Spooled)),
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
