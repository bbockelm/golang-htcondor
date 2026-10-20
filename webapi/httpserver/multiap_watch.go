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
// across a dropped connection. With two hubs both follow the active one,
// and start over on the other when it changes (multiap.OpenJobsWatch). A tracked job's absence from the queue
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
		_ = h.jobWatchFeed.RunResumableFrom(htcondor.WithDaemonCredential(ctx, "job watch feed"), h.watchHubJobsTable)
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

// watchHubJobsTable opens a watch on the active hub's jobs table; see
// multiap.Service.OpenJobsWatch.
func (h *Handler) watchHubJobsTable(ctx context.Context, from jobwatch.Resume) (<-chan jobwatch.WatchEvent, func(), string, error) {
	return h.multi.svc.OpenJobsWatch(ctx, from)
}

// multiAPHubAllowed is the part of the multi-AP allowlist that is not a
// plain read path: job resource-usage samples (GET only), the share mint
// for one of the caller's watches and its redemption, and reads of the
// collector, which every AP shares (ads, ping, the pool summary, the ad
// change stream -- not advertise).
// The plain read paths it serves are multiAPHubReadPaths.
func multiAPHubAllowed(method, path string) bool {
	if path == multiAPMetricsPath {
		// Job resource-usage samples (multiap_metrics.go). The handler
		// answers GET alone, and no other metrics table is served.
		return method == http.MethodGet
	}
	if multiAPHubReadPaths[path] {
		return method == http.MethodGet || method == http.MethodHead
	}
	if rest, ok := strings.CutPrefix(path, "/api/v1/collector/"); ok {
		return (method == http.MethodGet || method == http.MethodHead) && rest != "" &&
			rest != "advertise" && !strings.HasPrefix(rest, "advertise/")
	}
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
// stream, the dashboard (multiap_dashboard.go), the issues view
// (multiap_issues.go), and run-attempt and transfer history
// (multiap_epochs.go).
var multiAPHubReadPaths = map[string]bool{
	"/api/v1/jobs/watch":                true,
	"/api/v1/dashboard":                 true,
	"/api/v1/dashboard/activity":        true,
	"/api/v1/dashboard/activity/stream": true,
	"/api/v1/issues":                    true,
	"/api/v1/jobs/epochs":               true,
	"/api/v1/jobs/transfers":            true,
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

// streamCallerInDomain refuses a change stream to an identity outside
// UID_DOMAIN: the feed names a job's owner by the local part of its User
// (or by its Owner, with one schedd), and alice@elsewhere is not the
// alice it would match. With one schedd only a placementd account is
// refused (placementOutsideUIDDomain). It writes the refusal and reports
// false.
func (h *Handler) streamCallerInDomain(ctx context.Context, w http.ResponseWriter) bool {
	if h.multi == nil {
		if h.placementOutsideUIDDomain(ctx, htcondor.GetAuthenticatedUserFromContext(ctx)) {
			h.writeError(w, http.StatusForbidden,
				"Live job updates are not available to accounts assigned by the placement service outside this access point's domain.")
			return false
		}
		return true
	}
	if _, err := h.watchOwner(htcondor.GetAuthenticatedUserFromContext(ctx)); err != nil {
		if errors.Is(err, errUnidentifiedCaller) {
			h.writeError(w, http.StatusUnauthorized, "authentication failed: "+err.Error())
			return false
		}
		h.multiAPError(w, err)
		return false
	}
	return true
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
