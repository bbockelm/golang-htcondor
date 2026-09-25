package mcpserver

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/PelicanPlatform/classad/classad"

	htcondor "github.com/bbockelm/golang-htcondor"
	"github.com/bbockelm/golang-htcondor/webapi/shareurl"
	"github.com/bbockelm/golang-htcondor/webapi/spool"
)

// toolCreateOutputDownloadURL mints a signed URL for downloading one
// job's output sandbox.
//
// The mirror image of create_input_upload_url, and it exists for the
// same reason read backwards. get_job_output returns the files through
// the conversation, so a job whose results are tens of megabytes -- or
// tens of thousands of tokens of text -- cannot be collected at all: the
// tool call that would carry them does not fit. Handing back a URL moves
// the data path onto an ordinary HTTP GET, and leaves MCP carrying only
// the capability.
//
// What comes back from the URL is a tar of the whole sandbox, streamed
// from the schedd, with no credentials required to fetch it. That makes
// it something an agent can hand to a local shell, or hand to the person
// to click -- which is the case get_job_output has no answer for.
func (s *Server) toolCreateOutputDownloadURL(ctx context.Context, args map[string]interface{}) (interface{}, error) {
	if s.shareSigner == nil {
		return nil, fmt.Errorf("download URLs are unavailable: this server has no pool signing key configured " +
			"(set SEC_TOKEN_POOL_SIGNING_KEY_FILE, or HTTP_API_SIGNING_KEY)")
	}
	base := strings.TrimRight(strings.TrimSpace(s.httpBaseURL), "/")
	if base == "" {
		return nil, fmt.Errorf("download URLs are unavailable: this server does not know the REST API's " +
			"public address (set HTTP_API_BASE_URL)")
	}

	jobID, ok := args["job_id"].(string)
	if !ok || strings.TrimSpace(jobID) == "" {
		return nil, fmt.Errorf("job_id is required")
	}
	// A bare cluster id mints one URL per proc. A sandbox is per proc,
	// so a `queue N` submission genuinely has N of them; there is no
	// single URL that would return them all.
	target, err := spool.ParseTarget(jobID)
	if err != nil {
		return nil, fmt.Errorf("invalid job_id %q: %w", jobID, err)
	}

	// Owner-scoped the way the live-job tools are, not the way the query
	// tools are. An MCP admin can READ another user's job ad, but a
	// download URL is a bearer capability that streams that user's files
	// to whoever holds it, and it outlives the call. The REST endpoint
	// that mints these makes the same check for the same reason.
	caller, err := s.liveJobCaller(ctx)
	if err != nil {
		return nil, err
	}
	ownerScope := func(c string) (string, error) {
		return fmt.Sprintf("(%s) && Owner == %s", c, classadStringLit(caller.Owner)), nil
	}

	ttl := shareurl.ClampTTL(shareurl.KindOutput, ttlSecondsArg(args))

	procAds, remaining, err := s.procAdsForDownload(ctx, target, ownerScope)
	if err != nil {
		return nil, fmt.Errorf("failed to look up %s: %w", jobID, err)
	}
	if len(procAds) == 0 {
		if target.AllProcs {
			return nil, fmt.Errorf("no proc of cluster %d owned by %s is in the queue; "+
				"a sandbox can only be fetched while the job is still there, and a job that "+
				"has left takes its sandbox with it", target.Cluster, caller.Owner)
		}
		return nil, fmt.Errorf("job %s was not found among jobs owned by %s; a sandbox can "+
			"only be fetched while the job is still in the queue", jobID, caller.Owner)
	}

	exp := time.Now().Add(ttl)
	downloads := make([]map[string]interface{}, 0, len(procAds))
	type mintedDL struct{ jobID, url string }
	minteds := make([]mintedDL, 0, len(procAds))
	for _, ad := range procAds {
		cluster, proc, ok := spool.ProcIDOf(ad)
		if !ok {
			continue
		}
		u, terr := mintOutputURL(s.shareSigner, base, cluster, proc, caller.Owner, exp)
		if terr != nil {
			return nil, terr
		}
		m := mintedDL{
			jobID: fmt.Sprintf("%d.%d", cluster, proc),
			url:   u,
		}
		minteds = append(minteds, m)
		downloads = append(downloads, map[string]interface{}{
			"job_id": m.jobID,
			"url":    m.url,
		})
	}

	var sb strings.Builder
	if len(minteds) == 1 {
		fmt.Fprintf(&sb, "Download URL for job %s (valid until %s, reads as %s):\n\n%s\n\n",
			minteds[0].jobID, exp.Format(time.RFC3339), caller.Owner, minteds[0].url)
	} else {
		fmt.Fprintf(&sb, "%d download URLs for cluster %d (valid until %s, read as %s). "+
			"A sandbox is per proc, so each proc has its own:\n\n",
			len(minteds), target.Cluster, exp.Format(time.RFC3339), caller.Owner)
		for _, m := range minteds {
			fmt.Fprintf(&sb, "  %s -> %s\n", m.jobID, m.url)
		}
		sb.WriteString("\n")
	}

	sb.WriteString("Each returns a tar of that job's output sandbox. Fetch it with a shell " +
		"command rather than reading it in, for example:\n")
	fmt.Fprintf(&sb, "  curl -fsSL '%s' | tar xv -C ./results\n\n", minteds[0].url)
	sb.WriteString("The URL needs no credentials, so it can be handed to whoever wants the " +
		"results -- including the person you are working for, to click. It stops working when " +
		"it expires, or when the job leaves the queue and its sandbox is cleaned up.")

	structured := map[string]interface{}{
		"cluster_id":  target.Cluster,
		"owner":       caller.Owner,
		"expires_at":  exp.Format(time.RFC3339),
		"ttl_seconds": int(ttl.Seconds()),
		"count":       len(downloads),
		"downloads":   downloads,
	}
	if remaining > 0 {
		note := fmt.Sprintf("%d more proc(s) of this cluster are in the queue; one call mints "+
			"at most %d. Call again for the rest.", remaining, maxMintedURLs)
		structured["procs_remaining"] = remaining
		structured["note"] = note
		sb.WriteString("\n\n" + note)
	}
	return structuredTextResult(sb.String(), structured), nil
}

// mintOutputURL signs one output-share token and builds the URL that
// redeems it.
//
// Split out of the handler so the two things that must be right can be
// tested without a schedd: the token is signed as KindOutput, and the
// URL points at the endpoint that redeems that kind. Get either wrong
// and nothing fails until somebody fetches the URL, where it surfaces
// as "invalid or expired token" -- a message that says nothing about
// the actual mistake.
func mintOutputURL(
	signer *shareurl.Signer,
	base string,
	cluster, proc int,
	owner string,
	exp time.Time,
) (string, error) {
	tok, err := signer.Sign(shareurl.Payload{
		Cluster: cluster,
		Proc:    proc,
		Owner:   owner,
		Exp:     exp.Unix(),
		Kind:    shareurl.KindOutput,
	})
	if err != nil {
		return "", fmt.Errorf("failed to sign download URL: %w", err)
	}
	return fmt.Sprintf("%s/api/v1/share/output?t=%s", base, tok), nil
}

// downloadShareProjection is everything a mint reads off a proc ad.
// Deliberately tiny: unlike the input side there is no allow-set to
// compute, only an identity to sign.
var downloadShareProjection = []string{"ClusterId", "ProcId", "Owner"}

// procAdsForDownload resolves a target to the proc ads a mint should
// cover: one for "cluster.proc", every proc in the queue for a bare
// cluster id. The second return is how many more procs exist than this
// call will mint for.
//
// No state filter, unlike the input side. Input can only be spooled into
// a job held for it, so minting for any other state would hand back a
// URL that cannot work. Output has no such window -- a running job's
// partial sandbox is a legitimate thing to fetch, and so is a completed
// one's, right up until the job leaves the queue.
func (s *Server) procAdsForDownload(
	ctx context.Context,
	target spool.Target,
	ownerScope func(string) (string, error),
) ([]*classad.ClassAd, int, error) {
	if !target.AllProcs {
		ad, err := spool.FetchProcAd(ctx, s.getSchedd(), target.Cluster, target.Proc,
			ownerScope, downloadShareProjection)
		if err != nil || ad == nil {
			return nil, 0, err
		}
		return []*classad.ClassAd{ad}, 0, nil
	}

	constraint := fmt.Sprintf("ClusterId == %d && ProcId >= 0", target.Cluster)
	scoped, err := ownerScope(constraint)
	if err != nil {
		return nil, 0, err
	}
	// One past the cap, so a truncated list can be reported as truncated
	// rather than presented as the whole cluster.
	ads, _, err := s.getSchedd().QueryWithOptions(ctx, scoped, &htcondor.QueryOptions{
		Projection: downloadShareProjection,
		Limit:      maxMintedURLs + 1,
	})
	if err != nil {
		return nil, 0, err
	}
	if len(ads) > maxMintedURLs {
		return ads[:maxMintedURLs], len(ads) - maxMintedURLs, nil
	}
	return ads, 0, nil
}
