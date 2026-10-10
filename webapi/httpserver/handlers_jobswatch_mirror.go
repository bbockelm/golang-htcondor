// Serving the job change stream from the htcondordb mirror.
//
// /api/v1/jobs/watch was written against a local job_queue.log, which
// an API server running in its own container cannot read. The mirror
// that most deployments do have is the htcondordb one, and following
// the queue is a large part of what it is for -- the dashboard's
// activity ticker has been streaming from it all along. This serves
// the same endpoint from the same feed, so a client gets a change
// stream wherever the access point is following its queue from.
//
// The wire format is the one the collection-backed path already
// emits, minus the cursor: the feed is a live subscription with no
// resumable position, so no `id:` frames are sent and a client has
// nothing stale to resume from. Clients re-read the queue on
// reconnect anyway, which is what the events tell them to do.

package httpserver

import (
	"context"
	"fmt"
	"net/http"
	"time"

	htcondor "github.com/bbockelm/golang-htcondor"
	"github.com/bbockelm/golang-htcondor/webapi/jobwatch"
)

// How many events to hold for a subscriber that is not reading fast
// enough. Past this the feed reports how many were dropped and the
// stream says so rather than quietly skipping them.
const jobsWatchMirrorBuffer = 256

// A comment every so often, so an idle connection is not reaped by
// something in between.
const jobsWatchMirrorHeartbeat = 25 * time.Second

// streamJobsWatchFromMirror answers GET /api/v1/jobs/watch out of the
// htcondordb mirror's feed.
func (h *Handler) streamJobsWatchFromMirror(ctx context.Context, w http.ResponseWriter, r *http.Request) {
	// The same scoping rule as the dashboard stream and the jobs list:
	// your own jobs unless you are an administrator and ask for more.
	// Applied inside the feed rather than here, so there is no path on
	// which a wider stream is opened and then narrowed. The feed
	// refuses a caller nobody named.
	owner, all := activityStreamScope(htcondor.GetAuthenticatedUserFromContext(ctx),
		r.URL.Query().Get("owned_by_me"), h.isWebUIAdmin(r))
	events, cancel, err := h.jobWatchFeed.SubscribeActivity(owner, all, jobsWatchMirrorBuffer)
	if err != nil {
		h.writeError(w, http.StatusUnauthorized, "authentication failed: "+errUnidentifiedCaller.Error())
		return
	}
	defer cancel()

	flusher, ok := sseSetup(w)
	if !ok {
		h.writeError(w, http.StatusInternalServerError, "server does not support streaming")
		return
	}
	defer h.streamOpened()()

	// Said once, up front. A client that has just connected has to
	// know whether what it is looking at is current: warm means the
	// mirror is caught up and every change from here is one this
	// stream will carry.
	if h.jobWatchFeed.Warm() {
		if err := writeWatchSSE(w, flusher, "synced", "", nil, nil, ""); err != nil {
			return
		}
	} else if err := writeWatchSSE(w, flusher, "resync", "", nil, nil, ""); err != nil {
		// Not synced: the mirror is still catching up, so the client
		// should re-read rather than assume this stream has told it
		// everything.
		return
	}

	ticker := time.NewTicker(jobsWatchMirrorHeartbeat)
	defer ticker.Stop()

	for {
		select {
		case <-r.Context().Done():
			return
		case <-ctx.Done():
			return
		case <-ticker.C:
			if _, err := w.Write([]byte(": keep-alive\n\n")); err != nil {
				return
			}
			_ = flusher.Flush()
		case ev, ok := <-events:
			if !ok {
				return
			}
			// A subscriber that fell behind has a gap. Saying so is
			// the difference between a client that re-reads the queue
			// and one that believes a stale picture: the events it
			// missed are exactly the ones it does not know about.
			if ev.Skipped > 0 {
				if err := writeWatchSSE(w, flusher, "resync", "", nil, nil, ""); err != nil {
					return
				}
			}
			if err := writeWatchSSE(w, flusher, jobsWatchEventName(ev.Kind), jobsWatchKey(ev), nil, nil, ""); err != nil {
				return
			}
		}
	}
}

// jobsWatchEventName maps a transition to the event names this
// endpoint already uses.
//
// A removal is a delete; everything else is an upsert. The two are the
// vocabulary the collection-backed path established, and a client that
// understands that path understands this one without being told which
// it is talking to.
func jobsWatchEventName(kind jobwatch.ActivityKind) string {
	if kind == jobwatch.ActivityRemoved {
		return "delete"
	}
	return "upsert"
}

// jobsWatchKey renders the job id the way the rest of the API does.
func jobsWatchKey(ev jobwatch.ActivityEvent) string {
	return fmt.Sprintf("%d.%d", ev.Cluster, ev.Proc)
}
