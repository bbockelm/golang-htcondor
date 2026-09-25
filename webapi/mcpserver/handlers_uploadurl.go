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

// toolCreateInputUploadURL mints a signed URL for uploading one job's
// input files.
//
// The point of the tool is what it does NOT do: the bytes never enter
// the conversation. An MCP tool call carries its arguments through the
// model's context, which is why upload_job_input is capped at a size no
// real dataset fits in. Handing back a URL moves the data path onto an
// ordinary HTTP PUT the caller runs itself, and leaves MCP carrying only
// the capability.
//
// The URL is redeemed by the REST daemon, not by this server -- which is
// the case that decided where the signing lives. A standalone stdio MCP
// server has no listener of its own; it derives the same key from the
// same pool signing key, so the URL it mints verifies over there.
func (s *Server) toolCreateInputUploadURL(ctx context.Context, args map[string]interface{}) (interface{}, error) {
	if s.shareSigner == nil {
		return nil, fmt.Errorf("upload URLs are unavailable: this server has no pool signing key configured " +
			"(set SEC_TOKEN_POOL_SIGNING_KEY_FILE, or HTTP_API_SIGNING_KEY)")
	}
	base := strings.TrimRight(strings.TrimSpace(s.httpBaseURL), "/")
	if base == "" {
		// Minting a URL with no authority would produce something the
		// caller cannot use and cannot debug.
		return nil, fmt.Errorf("upload URLs are unavailable: this server does not know the REST API's " +
			"public address (set HTTP_API_BASE_URL)")
	}

	jobID, ok := args["job_id"].(string)
	if !ok || strings.TrimSpace(jobID) == "" {
		return nil, fmt.Errorf("job_id is required")
	}
	// A bare cluster id mints one URL per proc still awaiting input.
	// HTCondor spools per proc, so a `queue N` submission genuinely
	// needs N uploads -- upload_job_input fans out the same way.
	target, err := spool.ParseTarget(jobID)
	if err != nil {
		return nil, fmt.Errorf("invalid job_id %q: %w", jobID, err)
	}

	// Derived the way the live-job tools derive it, not the way the query
	// tools do: an upload URL writes into somebody's job, so an MCP admin
	// does not get one for another user's job by being an admin. This
	// also answers the stdio case, where there is no actor on the context
	// because the server IS the user.
	caller, err := s.liveJobCaller(ctx)
	if err != nil {
		return nil, err
	}
	ownerScope := func(c string) (string, error) {
		return fmt.Sprintf("(%s) && Owner == %s", c, classadStringLit(caller.Owner)), nil
	}

	ttl := shareurl.ClampTTL(shareurl.KindInput, ttlSecondsArg(args))

	procAds, remaining, err := s.procAdsToMintFor(ctx, target, ownerScope)
	if err != nil {
		return nil, fmt.Errorf("failed to look up %s: %w", jobID, err)
	}
	if len(procAds) == 0 {
		if target.AllProcs {
			return nil, fmt.Errorf("no proc of cluster %d owned by %s is awaiting input; "+
				"either the cluster does not exist or its input has already been spooled",
				target.Cluster, caller.Owner)
		}
		return nil, fmt.Errorf("job %s is not awaiting input among jobs owned by %s; "+
			"either it does not exist or its input has already been spooled -- only a job "+
			"held for input spooling accepts an upload", jobID, caller.Owner)
	}

	exp := time.Now().Add(ttl)
	uploads := make([]map[string]interface{}, 0, len(procAds))
	minteds := make([]minted, 0, len(procAds))
	for _, ad := range procAds {
		cluster, proc, ok := spool.ProcIDOf(ad)
		if !ok {
			continue
		}
		tok, terr := s.shareSigner.Sign(shareurl.Payload{
			Cluster: cluster,
			Proc:    proc,
			Owner:   caller.Owner,
			Exp:     exp.Unix(),
			Kind:    shareurl.KindInput,
		})
		if terr != nil {
			return nil, fmt.Errorf("failed to sign upload URL: %w", terr)
		}
		m := minted{
			jobID:    fmt.Sprintf("%d.%d", cluster, proc),
			url:      fmt.Sprintf("%s/api/v1/share/input?t=%s", base, tok),
			expected: htcondor.SpoolInputAllowSet(ad),
		}
		minteds = append(minteds, m)
		uploads = append(uploads, map[string]interface{}{
			"job_id":         m.jobID,
			"url":            m.url,
			"expected_files": m.expected,
		})
	}

	var sb strings.Builder
	if len(minteds) == 1 {
		fmt.Fprintf(&sb, "Upload URL for job %s (valid until %s, uploads as %s):\n\n%s\n\n",
			minteds[0].jobID, exp.Format(time.RFC3339), caller.Owner, minteds[0].url)
	} else {
		fmt.Fprintf(&sb, "%d upload URLs for cluster %d (valid until %s, upload as %s). "+
			"HTCondor spools per proc, so each proc needs its own upload:\n\n",
			len(minteds), target.Cluster, exp.Format(time.RFC3339), caller.Owner)
		for _, m := range minteds {
			fmt.Fprintf(&sb, "  %s -> %s\n", m.jobID, m.url)
		}
		sb.WriteString("\n")
	}

	sb.WriteString("PUT a tar of the input files to each, for example:\n")
	fmt.Fprintf(&sb, "  tar cf - %s | curl -T - '%s'\n\n",
		strings.Join(minteds[0].expected, " "), minteds[0].url)

	// The allow-set is per proc, so report it that way when the procs
	// disagree. Collapsing them would tell the caller a name is accepted
	// for a proc that will drop it.
	if uniformExpected(minteds[0].expected, minteds) {
		if len(minteds[0].expected) > 0 {
			fmt.Fprintf(&sb, "Each tar's entry names must be exactly: %s\n",
				strings.Join(minteds[0].expected, ", "))
			sb.WriteString("The schedd accepts only those names and silently drops anything else.\n")
		} else {
			sb.WriteString("These jobs list no input files, so an upload would have nothing to " +
				"accept. Check the submit file's transfer_input_files.\n")
		}
	} else {
		sb.WriteString("These procs expect different files; the schedd accepts only the names " +
			"listed for each and silently drops anything else:\n")
		for _, m := range minteds {
			fmt.Fprintf(&sb, "  %s: %s\n", m.jobID, strings.Join(m.expected, ", "))
		}
	}
	sb.WriteString("A URL stops working once its upload completes or its job leaves the " +
		"held-for-input state.")

	structured := map[string]interface{}{
		"cluster_id":  target.Cluster,
		"owner":       caller.Owner,
		"expires_at":  exp.Format(time.RFC3339),
		"ttl_seconds": int(ttl.Seconds()),
		"count":       len(uploads),
		"uploads":     uploads,
	}
	// Never let a cap read as "this is the whole cluster".
	if remaining > 0 {
		note := fmt.Sprintf("%d more proc(s) of this cluster are awaiting input; one call mints "+
			"at most %d. Call again for the rest.", remaining, maxMintedURLs)
		structured["procs_remaining"] = remaining
		structured["note"] = note
		sb.WriteString("\n\n" + note)
	}
	return structuredTextResult(sb.String(), structured), nil
}

// minted is one signed upload URL and the allow-set it goes with.
type minted struct {
	jobID    string
	url      string
	expected []string
}

// maxMintedURLs bounds one mint call, matching the REST endpoint and the
// spool fan-out's own ceiling: past it the answer is not a longer list of
// URLs but HTTP/HTTPS URLs in transfer_input_files, which the execute
// nodes fetch themselves.
var maxMintedURLs = spool.DefaultLimits().MaxProcs

// procAdsToMintFor resolves a target to the proc ads a mint should cover:
// one for "cluster.proc", every proc still awaiting input for a bare
// cluster id. The second return is how many more procs were awaiting
// input than this call will mint for.
func (s *Server) procAdsToMintFor(
	ctx context.Context,
	target spool.Target,
	ownerScope func(string) (string, error),
) ([]*classad.ClassAd, int, error) {
	if !target.AllProcs {
		ad, err := spool.FetchProcAd(ctx, s.getSchedd(), target.Cluster, target.Proc,
			ownerScope, spool.InputShareProjection)
		if err != nil || ad == nil {
			return nil, 0, err
		}
		if !spool.AwaitingInput(ad) {
			return nil, 0, nil
		}
		return []*classad.ClassAd{ad}, 0, nil
	}

	ads, err := spool.FetchProcAdsAwaitingInput(ctx, s.getSchedd(), target.Cluster,
		maxMintedURLs, ownerScope, spool.InputShareProjection)
	if err != nil {
		return nil, 0, err
	}
	if len(ads) > maxMintedURLs {
		return ads[:maxMintedURLs], len(ads) - maxMintedURLs, nil
	}
	return ads, 0, nil
}

// uniformExpected reports whether every minted upload shares one
// allow-set.
func uniformExpected(first []string, all []minted) bool {
	for _, m := range all {
		if len(m.expected) != len(first) {
			return false
		}
		for i := range first {
			if m.expected[i] != first[i] {
				return false
			}
		}
	}
	return true
}

// ttlSecondsArg reads the optional whole-second "ttl_seconds" argument
// every share-URL tool takes. JSON numbers arrive as float64 through the
// MCP transport, but an integer spelled as a string is common enough
// from a model to be worth accepting rather than refusing over.
//
// The key is fixed rather than a parameter: all three callers read the
// same one, and a parameter that only ever receives one value is a
// generalization nothing asked for. Take a key again when a second one
// exists.
func ttlSecondsArg(args map[string]interface{}) time.Duration {
	const key = "ttl_seconds"
	switch v := args[key].(type) {
	case float64:
		return time.Duration(v) * time.Second
	case int:
		return time.Duration(v) * time.Second
	case int64:
		return time.Duration(v) * time.Second
	case string:
		var n int64
		if _, err := fmt.Sscanf(strings.TrimSpace(v), "%d", &n); err == nil {
			return time.Duration(n) * time.Second
		}
	}
	return 0
}
