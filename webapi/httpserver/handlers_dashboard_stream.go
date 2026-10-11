package httpserver

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	htcondor "github.com/bbockelm/golang-htcondor"
	"github.com/bbockelm/golang-htcondor/webapi/jobwatch"
)

// The dashboard's live ticker.
//
// The activity lists on the page are a query: what happened in the last
// hour, answered when the page loads. This is the other half -- what is
// happening right now -- and it is not a query at all. The daemon
// already tails the mirror's jobs table for the MCP watch evaluator, so
// a second reader on that stream costs one subscription and no traffic
// to the database whatsoever.
//
// It therefore exists only where the mirror does. There is no schedd
// equivalent: watching the queue without a change log means polling it,
// and polling a busy access point often enough to look live is exactly
// the load this whole path exists to avoid. Where there is no mirror the
// endpoint says so and the page simply does not show a ticker.

// activityStreamHeartbeat keeps the connection open through proxies that
// drop idle ones. A quiet access point can go minutes without a
// transition, which is indistinguishable from a dead stream otherwise.
const activityStreamHeartbeat = 25 * time.Second

// activityStreamBuffer is how many events may queue for one browser.
// Large enough to ride out a burst, small enough that a tab left open on
// a laptop lid does not hold a thousand ads live.
const activityStreamBuffer = 128

// activityStreamEvent is the wire shape, deliberately flat: this is read
// by a ticker that renders one line per event.
type activityStreamEvent struct {
	Kind    string `json:"kind"`
	Cluster int64  `json:"cluster_id"`
	Proc    int64  `json:"proc_id"`
	Owner   string `json:"owner,omitempty"`
	At      int64  `json:"at"`
	Detail  string `json:"detail,omitempty"`
	// Skipped says how many events were lost before this one because
	// this browser was not reading fast enough. Reporting it keeps a
	// gap from looking like a quiet minute.
	Skipped int `json:"skipped,omitempty"`
}

// handleDashboardActivityStream handles GET /api/v1/dashboard/activity/stream.
func (s *Handler) handleDashboardActivityStream(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		s.writeError(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}
	ctx, release, ok := s.authenticateStream(w, r)
	if !ok {
		return
	}
	defer release()

	if s.jobWatchFeed == nil {
		// Not an error the caller can fix, and not a failure: this
		// deployment has no mirror to stream from.
		s.writeError(w, http.StatusNotImplemented,
			"The live activity stream needs an htcondordb mirror; this access point has none configured.")
		return
	}

	// Same scoping rule as the dashboard itself: everyone sees their own
	// by default, an administrator may ask for the whole access point.
	// The filter is applied inside the feed rather than here -- see
	// SubscribeActivity -- so there is no path on which a wider stream
	// is opened and narrowed afterwards. A caller nobody named gets no
	// stream at all; the feed refuses an empty owner too.
	owner, all := activityStreamScope(htcondor.GetAuthenticatedUserFromContext(ctx),
		r.URL.Query().Get("owned_by_me"), s.seesAllJobs(ctx, r, jobScopeRead))
	events, cancel, err := s.jobWatchFeed.SubscribeActivity(owner, all, activityStreamBuffer)
	if err != nil {
		s.writeError(w, http.StatusUnauthorized, "Authentication failed: "+errUnidentifiedCaller.Error())
		return
	}
	defer cancel()

	flusher, ok := sseSetup(w)
	if !ok {
		s.writeError(w, http.StatusInternalServerError, "Streaming unsupported")
		return
	}
	defer s.streamOpened()()

	// The feed goes cold across a reconnect to the mirror, and warm once
	// it is following again. Saying which lets the page show that the
	// ticker is live rather than that nothing is happening.
	if !s.jobWatchFeed.Warm() {
		if err := writeActivityComment(w, flusher, "waiting for the mirror"); err != nil {
			return
		}
	}

	streamActivity(r.Context(), w, flusher, events, activityStreamHeartbeat)
}

// activityStreamScope decides which jobs this connection may see: the
// Owner value of the caller's own jobs, or with all set, every job.
//
// Own jobs by default, for everyone. The pool-wide stream is an explicit
// ask and only an administrator gets it: a non-admin who sends
// owned_by_me=false is quietly given their own jobs rather than an
// error, which is the same rule the dashboard and the jobs list already
// apply to the same parameter.
//
// actor is the authenticated identity, which may be qualified
// ("alice@domain") where a job's Owner never is. An empty actor yields
// an empty owner and all unset -- never everyone.
func activityStreamScope(actor, requested string, isAdmin bool) (owner string, all bool) {
	owner = ownerFromActor(actor)
	if requested == "" || !isAdmin || actor == "" {
		return owner, false
	}
	ownedByMe, err := strconv.ParseBool(requested)
	if err != nil || ownedByMe {
		return owner, false
	}
	return "", true
}

// streamActivity is the response loop: events out as they arrive, a
// comment on the heartbeat so an idle connection is not reaped, and
// return when either side goes away.
func streamActivity(ctx context.Context, w http.ResponseWriter, flusher *http.ResponseController,
	events <-chan jobwatch.ActivityEvent, heartbeat time.Duration) {
	ticker := time.NewTicker(heartbeat)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if err := writeActivityComment(w, flusher, "keepalive"); err != nil {
				return
			}
		case ev, ok := <-events:
			if !ok {
				return
			}
			if err := writeActivityEvent(w, flusher, ev); err != nil {
				return
			}
		}
	}
}

func writeActivityEvent(w http.ResponseWriter, flusher *http.ResponseController, ev jobwatch.ActivityEvent) error {
	payload, err := json.Marshal(activityStreamEvent{
		Kind:    string(ev.Kind),
		Cluster: ev.Cluster,
		Proc:    ev.Proc,
		Owner:   ev.Owner,
		At:      ev.At,
		Detail:  ev.Detail,
		Skipped: ev.Skipped,
	})
	if err != nil {
		return err
	}
	var b strings.Builder
	// A named event type, so the page can add kinds later without the
	// handler changing: EventSource dispatches on this.
	b.WriteString("event: activity\n")
	b.WriteString("data: ")
	b.Write(payload)
	b.WriteString("\n\n")
	if _, err := w.Write([]byte(b.String())); err != nil {
		return err
	}
	return flusher.Flush()
}

// writeActivityComment sends an SSE comment: invisible to EventSource
// handlers but enough to keep an idle connection from being reaped.
func writeActivityComment(w http.ResponseWriter, flusher *http.ResponseController, text string) error {
	if _, err := fmt.Fprintf(w, ": %s\n\n", text); err != nil {
		return err
	}
	return flusher.Flush()
}
