package httpserver

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/PelicanPlatform/classad/classad"
	"github.com/bbockelm/golang-htcondor/logging"
)

// GET /api/v1/jobs/{id}/watch -- Server-Sent Events for one job.
//
// Replaces the browser polling the job every couple of seconds. Events:
//
//	snapshot  the watched attributes as they are now (always first)
//	update    only the attributes that changed
//	gone      the job left the queue, and is on its way to the archive
//
// "gone" is not "finished". A submission carries a LeaveJobInQueue
// expression that keeps a completed job listed for days, so a job that
// finishes arrives as an update with JobStatus 4 and stays watchable; only
// a removal produces "gone".
//
// The stream is not resumable and holds no cursor. A client that
// reconnects gets a fresh snapshot, which is both the recovery path and
// the reason there is nothing to persist or reap.

// defaultWatchAttrs are the attributes the session pages actually render.
// Watching everything would emit an event for each of the schedd's
// periodic bookkeeping writes -- image size, disk usage, last-update
// timestamps -- which is most of a job's write traffic and none of its
// meaning.
var defaultWatchAttrs = []string{
	"JobStatus",
	"HoldReasonCode",
	"HoldReason",
	"ExitCode",
	"ExitBySignal",
	"ExitSignal",
	"RemoteHost",
	"JobCurrentStartDate",
	"CompletionDate",
	"EnteredCurrentStatus",
	"NumJobStarts",
	"TransferringInput",
}

const (
	jobWatchHeartbeat = 20 * time.Second
	// A watch is a held connection; without a ceiling a forgotten tab
	// keeps one for the life of the process. The browser's EventSource
	// reconnects on its own, so ending is cheap and bounds the leak.
	jobWatchMaxAge = 30 * time.Minute
)

func (s *Handler) handleJobWatch(w http.ResponseWriter, r *http.Request, jobID string) {
	if r.Method != http.MethodGet {
		s.writeError(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}
	ctx, needsRedirect, err := s.requireAuthentication(r)
	if err != nil {
		if needsRedirect {
			s.redirectToLogin(w, r)
			return
		}
		s.writeError(w, http.StatusUnauthorized, fmt.Sprintf("Authentication failed: %v", err))
		return
	}
	cluster, proc, err := parseJobID(jobID)
	if err != nil {
		s.writeError(w, http.StatusBadRequest, fmt.Sprintf("Invalid job ID: %v", err))
		return
	}

	// The same owner scope a plain GET of this job gets. A watch reads
	// job state continuously, so it is the last place to be laxer than
	// the one-shot read.
	constraint, err := s.jobOwnerScope(ctx, r, cluster, proc)
	if err != nil {
		s.writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	attrs := defaultWatchAttrs
	if v := strings.TrimSpace(r.URL.Query().Get("attrs")); v != "" {
		attrs = splitAttrs(v)
	}

	ctx, cancel := context.WithTimeout(ctx, jobWatchMaxAge)
	defer cancel()

	// Subscribe before the first read, not after.
	//
	// The feed only reports changes. Reading first and subscribing after
	// leaves a window in which a change lands between the two and is
	// never delivered -- the page would then sit on a stale value with a
	// live connection, which is worse than polling.
	var (
		feedCh  <-chan jobWatchUpdateSource
		feedOff func()
	)
	if s.jobWatchFeed != nil && s.jobWatchFeed.Warm() {
		feedCh, feedOff = subscribeFeed(s, int64(cluster), int64(proc))
		defer feedOff()
	}

	ad, err := s.scheddJobQuery(ctx, constraint)
	if err != nil {
		s.writeError(w, http.StatusBadGateway, fmt.Sprintf("Query failed: %v", err))
		return
	}
	if ad == nil {
		// Say so with a status code while we still can: once the stream
		// is open the only way to report this is an event nobody asked
		// for.
		s.writeError(w, http.StatusNotFound, "Job not found")
		return
	}

	// Commits the response, so everything that might still want a status
	// code -- the auth check, the scope, the 404 above -- has to be done.
	rc, ok := sseSetup(w)
	if !ok {
		s.writeError(w, http.StatusInternalServerError, "server does not support streaming")
		return
	}

	last := projectAttrs(ad, attrs)
	writeSSE(w, rc, "snapshot", last)

	// No mirror, or a feed that is not warm: poll, sharing one query per
	// constraint with every other watcher of the same job.
	var pollSrc jobWatchSource
	if feedCh == nil {
		pollSrc = s.jobPolls.Subscribe(constraint)
		defer pollSrc.Close()
	}

	heartbeat := time.NewTicker(jobWatchHeartbeat)
	defer heartbeat.Stop()

	for {
		var (
			next  *classad.ClassAd
			gone  bool
			stale bool
		)

		select {
		case <-ctx.Done():
			return
		case <-r.Context().Done():
			return
		case <-heartbeat.C:
			// A comment keeps intermediaries from dropping an idle
			// connection and tells us when the client has gone.
			if _, werr := w.Write([]byte(": ping\n\n")); werr != nil {
				return
			}
			_ = rc.Flush()
			continue
		case u, open := <-feedCh:
			if !open {
				return
			}
			next, gone, stale = u.Ad, u.Gone, u.Stale
		case u, open := <-pollChan(pollSrc):
			if !open {
				return
			}
			next, gone = u.Ad, u.Ad == nil
		}

		if stale {
			// The feed lost continuity, so it can no longer say what
			// changed -- only that it does not know. Re-read once, then
			// finish on the poller: a feed that just dropped may stay
			// down, and a connection that silently stops updating is the
			// failure this endpoint exists to remove.
			fresh, qerr := s.scheddJobQuery(ctx, constraint)
			if qerr != nil {
				s.logger.Debug(logging.DestinationHTTP,
					"job watch re-read failed after a stale feed", "job", jobID, "error", qerr)
				return
			}
			if feedOff != nil {
				feedOff()
				feedOff = nil
				feedCh = nil
			}
			if pollSrc == nil {
				pollSrc = s.jobPolls.Subscribe(constraint)
				defer pollSrc.Close()
			}
			next, gone = fresh, fresh == nil
		}

		if gone {
			writeSSE(w, rc, "gone", map[string]any{"job_id": jobID})
			return
		}
		if next == nil {
			continue
		}
		cur := projectAttrs(next, attrs)
		changed := diffAttrs(last, cur)
		if len(changed) == 0 {
			// Most writes to a job ad touch nothing this client asked
			// about. Staying quiet is the point of the projection.
			continue
		}
		last = cur
		if !writeSSE(w, rc, "update", changed) {
			return
		}
	}
}

// jobWatchUpdateSource is the shape both sources deliver in.
type jobWatchUpdateSource struct {
	Ad    *classad.ClassAd
	Gone  bool
	Stale bool
}

// pollChan adapts a possibly-nil poll source for use in a select. A nil
// channel blocks forever, which is what "this source is not in use" should
// mean in a select.
func pollChan(s jobWatchSource) <-chan jobWatchUpdate {
	if s == nil {
		return nil
	}
	return s.Updates()
}

func splitAttrs(v string) []string {
	parts := strings.Split(v, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

// projectAttrs renders the watched attributes to comparable strings.
// Attributes the ad does not carry are omitted rather than recorded as
// empty, so an attribute appearing for the first time reads as a change.
func projectAttrs(ad *classad.ClassAd, attrs []string) map[string]string {
	out := make(map[string]string, len(attrs))
	if ad == nil {
		return out
	}
	for _, a := range attrs {
		expr, ok := ad.Lookup(a)
		if !ok || expr == nil {
			continue
		}
		out[a] = expr.String()
	}
	return out
}

// diffAttrs returns what changed between two projections, including
// attributes that went away (as a JSON null) so a client can drop them.
func diffAttrs(prev, cur map[string]string) map[string]any {
	changed := map[string]any{}
	for k, v := range cur {
		if old, had := prev[k]; !had || old != v {
			changed[k] = v
		}
	}
	for k := range prev {
		if _, still := cur[k]; !still {
			changed[k] = nil
		}
	}
	return changed
}

func writeSSE(w http.ResponseWriter, rc *http.ResponseController, event string, payload any) bool {
	body, err := json.Marshal(payload)
	if err != nil {
		return false
	}
	if _, err := fmt.Fprintf(w, "event: %s\ndata: %s\n\n", event, body); err != nil {
		return false
	}
	_ = rc.Flush()
	return true
}

// subscribeFeed adapts jobwatch.Feed's per-job subscription to the shape
// this handler selects on.
func subscribeFeed(s *Handler, cluster, proc int64) (<-chan jobWatchUpdateSource, func()) {
	in, cancel := s.jobWatchFeed.Subscribe(cluster, proc)
	out := make(chan jobWatchUpdateSource, 1)
	go func() {
		defer close(out)
		for c := range in {
			out <- jobWatchUpdateSource{Ad: c.Ad, Gone: c.Gone, Stale: c.Stale}
		}
	}()
	return out, cancel
}
