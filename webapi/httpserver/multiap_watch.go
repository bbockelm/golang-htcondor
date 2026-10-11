package httpserver

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"

	htcondor "github.com/bbockelm/golang-htcondor"
	"github.com/bbockelm/golang-htcondor/jobid"
	"github.com/bbockelm/golang-htcondor/logging"
	"github.com/bbockelm/golang-htcondor/webapi/jobwatch"
	"github.com/bbockelm/golang-htcondor/webapi/multiap"
	"github.com/bbockelm/golang-htcondor/webapi/shareurl"
)

// Job watches in multi-AP mode.
//
// The same store, evaluator, feed and nudger single-AP mode runs, pointed
// at the federation hub: the evaluator reads each owner's jobs on every
// AP from the hub (multiap.WatchSource), and the feed follows the hub's
// jobs table -- one stream for every AP -- resuming from its cursor
// across a dropped connection. A tracked job's absence from the queue
// counts only on an AP the hub's federation_sources vouches for; see
// multiap.WatchSource and jobwatch.Coverage.
//
// A watch belongs to its owner across every AP: its constraint selects
// among the owner's jobs wherever they are, and each job it tracks or
// reports carries its AP. A watch share URL therefore names no one AP
// but all of them (shareurl.AllAccessPoints).

// multiAPWatchSource configures the feed for the hub and returns the
// evaluator's source.
func (h *Handler) multiAPWatchSource(feed *jobwatch.Feed) jobwatch.Source {
	svc := h.multi.svc
	// Hub rows are owned by User, owner@UID_DOMAIN; a watch's owner is
	// its local part, as in single-AP mode.
	feed.OwnerOf = svc.OwnerOfRow
	// A delete on the hub is also an AP retired or reconciled.
	feed.VouchDeparture = svc.VouchDeparture
	return multiap.WatchSource{Service: svc, Feed: feed}
}

// startMultiAPWatches runs the watch evaluator, the hub feed and the
// nudger.
func (h *Handler) startMultiAPWatches(ctx context.Context) {
	h.startJobWatchEvaluator(ctx)
	if h.jobWatchFeed == nil || h.jobWatchEval == nil || h.multi.svc.Hub == nil {
		return
	}
	h.wg.Add(1)
	go func() {
		defer h.wg.Done()
		h.logger.Info(logging.DestinationHTTP, "Job watch feed enabled; following the federation hub's jobs table")
		_ = h.jobWatchFeed.RunResumable(htcondor.WithDaemonCredential(ctx, "job watch feed"), h.watchHubJobsTable)
	}()
	nudger := jobwatch.NewNudger(h.jobWatchFeed, h.jobWatchEval.CheckOwner,
		func(format string, args ...any) {
			h.logger.Debug(logging.DestinationHTTP, fmt.Sprintf(format, args...))
		})
	nctx := htcondor.WithDaemonCredential(ctx, "job watch evaluation")
	h.wg.Add(1)
	go func() {
		defer h.wg.Done()
		nudger.Run(nctx)
	}()
}

// watchHubJobsTable opens a watch on the hub's jobs table: from its head
// with no cursor, else resuming after cursor. The hub answers a cursor it
// cannot resume from (it restarted, or its change log no longer reaches
// back) with a Reset and its whole table.
func (h *Handler) watchHubJobsTable(ctx context.Context, cursor []byte) (<-chan jobwatch.WatchEvent, func(), error) {
	dbc, closer, err := h.multi.svc.Hub.Client(ctx)
	if err != nil {
		return nil, nil, err
	}
	if cursor == nil {
		if cursor, err = dbc.WatchHead(ctx, multiap.TableJobs); err != nil {
			closer()
			return nil, nil, fmt.Errorf("reading the hub's jobs watch head: %w", err)
		}
	}
	raw, stop, err := dbc.WatchTable(ctx, multiap.TableJobs, cursor)
	if err != nil {
		closer()
		return nil, nil, fmt.Errorf("opening the hub's jobs watch: %w", err)
	}
	out := make(chan jobwatch.WatchEvent, 64)
	go func() {
		defer close(out)
		for ev := range raw {
			select {
			case out <- jobwatch.WatchEvent{Kind: ev.Kind, Key: ev.Key, AdText: ev.AdText, Cursor: ev.Cursor}:
			case <-ctx.Done():
				return
			}
		}
	}()
	return out, func() { stop(); closer() }, nil
}

// multiAPWatchAllowed is the watch half of the multi-AP allowlist: the
// share mint for one of the caller's watches, and its redemption.
// /api/v1/jobs/watch is in multiAPHubReadPaths.
func multiAPWatchAllowed(method, path string) bool {
	if path == "/api/v1/share/watch" {
		return method == http.MethodGet || method == http.MethodHead
	}
	if rest, ok := strings.CutPrefix(path, "/api/v1/watches/"); ok {
		parts := strings.Split(strings.Trim(rest, "/"), "/")
		return len(parts) == 2 && parts[0] != "" && parts[1] == "share" && method == http.MethodPost
	}
	return false
}

// multiAPHubReadPaths are the read routes multi-AP mode serves from the
// hub or by routing, beyond the job list and history: the jobs change
// stream, and the dashboard (multiap_dashboard.go).
var multiAPHubReadPaths = map[string]bool{
	"/api/v1/jobs/watch":                true,
	"/api/v1/dashboard":                 true,
	"/api/v1/dashboard/activity":        true,
	"/api/v1/dashboard/activity/stream": true,
}

// watchOwner is the owner a watch is stored against: the local part of
// the caller's identity. In multi-AP mode the identity must be in
// UID_DOMAIN -- alice@elsewhere is not the alice whose jobs the hub
// holds as alice@UID_DOMAIN, and is refused rather than narrowed to her.
func (h *Handler) watchOwner(actor string) (string, error) {
	owner := ownerFromActor(actor)
	if owner == "" {
		return "", errUnidentifiedCaller
	}
	if h.multi != nil {
		if _, err := h.multi.svc.UserFor(actor); err != nil {
			return "", err
		}
	}
	return owner, nil
}

// watchShareSchedd is the Schedd a watch token carries: every AP in
// multi-AP mode, none with one schedd.
func (h *Handler) watchShareSchedd() string {
	if h.multi != nil {
		return shareurl.AllAccessPoints
	}
	return ""
}

// errWatchShareScope is a watch token minted for the other mode.
var errWatchShareScope = errors.New("this watch URL was issued by a server with a different set of access points")

// checkWatchShareScope refuses a watch token whose access-point scope is
// not this server's: in multi-AP mode it must name every AP, with one
// schedd it must name none. The scope is inside the HMAC, so a URL
// cannot be moved between the two.
func (h *Handler) checkWatchShareScope(p *shareurl.Payload) error {
	if p.Schedd != h.watchShareSchedd() {
		return errWatchShareScope
	}
	return nil
}

// jobsWatchKeyFor renders an activity event's job id: cluster.proc with
// one schedd, the codec's complete id in multi-AP mode.
func (h *Handler) jobsWatchKeyFor(ev jobwatch.ActivityEvent) string {
	if h.multi != nil && ev.Schedd != "" {
		return h.multi.codec.Format(jobid.ID{Schedd: ev.Schedd, Cluster: ev.Cluster, Proc: ev.Proc})
	}
	return jobsWatchKey(ev)
}
