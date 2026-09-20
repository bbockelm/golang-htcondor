package mcpserver

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/bbockelm/golang-htcondor/webapi/jobwatch"
	"github.com/bbockelm/golang-htcondor/webapi/shareurl"
	"github.com/bbockelm/golang-htcondor/webapi/watchpoll"
)

// toolCreateWatchURL mints a signed URL that reports whether one watch
// has fired, and waits for it to.
//
// This exists because of what an agent cannot do: it is not a process,
// so between turns there is nothing of it running to wait on anything.
// check_watches solves that within a session by making the wait a
// bounded call. A watch URL solves the other half -- it hands the wait
// to something that IS always running. An agent framework points its
// poller at the URL, the poller blocks, and when the watch fires the
// framework wakes the agent. Nothing is spent while waiting.
//
// It is read-only and names exactly one watch: possession reports that
// watch's outcome and nothing else. It cannot register, cancel, or
// enumerate anything.
func (s *Server) toolCreateWatchURL(ctx context.Context, args map[string]interface{}) (interface{}, error) {
	if !s.jobWatchEnabled() {
		return nil, fmt.Errorf("job watches are not configured on this server")
	}
	if s.shareSigner == nil {
		return nil, fmt.Errorf("watch URLs are unavailable: this server has no pool signing key configured " +
			"(set SEC_TOKEN_POOL_SIGNING_KEY_FILE, or HTTP_API_SIGNING_KEY)")
	}
	base := strings.TrimRight(strings.TrimSpace(s.httpBaseURL), "/")
	if base == "" {
		return nil, fmt.Errorf("watch URLs are unavailable: this server does not know the REST API's " +
			"public address (set HTTP_API_BASE_URL)")
	}

	watchID, ok := args["watch_id"].(string)
	if !ok || strings.TrimSpace(watchID) == "" {
		return nil, fmt.Errorf("watch_id is required; register a watch with watch_jobs first")
	}
	watchID = strings.TrimSpace(watchID)

	owner, err := s.watchActor(ctx)
	if err != nil {
		return nil, err
	}

	// Confirm the watch is this caller's before signing. The URL is
	// redeemed as the owner in the token, so without this a caller could
	// mint one naming somebody else's watch id.
	all, err := s.jobWatch.ForOwner(ctx, owner, nil)
	if err != nil {
		return nil, fmt.Errorf("looking up the watch failed: %w", err)
	}
	var found *jobwatch.Watch
	for _, w := range all {
		if w.ID == watchID {
			found = w
			break
		}
	}
	if found == nil {
		return nil, fmt.Errorf("no live watch %q belongs to %s; register one with watch_jobs, "+
			"or it may have already expired", watchID, owner)
	}

	ttl := shareurl.ClampTTL(shareurl.KindWatch, argDuration(args, "ttl_seconds"))
	exp := time.Now().Add(ttl)
	tok, err := s.shareSigner.Sign(shareurl.Payload{
		Owner: owner,
		Exp:   exp.Unix(),
		Kind:  shareurl.KindWatch,
		Watch: watchID,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to sign watch URL: %w", err)
	}
	url := fmt.Sprintf("%s/api/v1/share/watch?t=%s", base, tok)

	maxWait := int(watchpoll.MaxWait.Seconds())
	defWait := int(watchpoll.DefaultWait.Seconds())

	var sb strings.Builder
	fmt.Fprintf(&sb, "Watch URL for %s (valid until %s, answers as %s):\n\n%s\n\n",
		watchID, exp.Format(time.RFC3339), owner, url)
	sb.WriteString("Give this to whatever does the waiting. A GET blocks until the watch fires, " +
		"then answers; add ?wait=<seconds> to choose how long it blocks ")
	fmt.Fprintf(&sb, "(default %d, maximum %d).\n\n", defWait, maxWait)
	sb.WriteString("The reply is JSON. poll_again tells a poller what to do next: true means " +
		"\"nothing yet, call again\", false means the question is settled and the URL is spent. " +
		"state is \"fired\", \"waiting\" or \"gone\", and waited_seconds is how long that call " +
		"blocked.\n\n")
	sb.WriteString("For a stream instead, send Accept: text/event-stream (or add &stream=sse): " +
		"a small heartbeat frame every 15s while it waits, then one frame with the answer.\n\n")
	sb.WriteString("Do not poll this yourself in a loop -- that is what check_watches is for " +
		"inside a turn. This URL is for handing the wait to something that runs while you do not.")

	return structuredTextResult(sb.String(), map[string]interface{}{
		"url":                  url,
		"watch_id":             watchID,
		"owner":                owner,
		"event":                string(found.Event),
		"label":                found.Label,
		"expires_at":           exp.Format(time.RFC3339),
		"ttl_seconds":          int(ttl.Seconds()),
		"max_wait_seconds":     maxWait,
		"default_wait_seconds": defWait,
	}), nil
}
