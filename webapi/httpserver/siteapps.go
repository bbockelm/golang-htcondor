package httpserver

import (
	"context"
	"net/http"
	"net/url"
	"time"

	"github.com/bbockelm/golang-htcondor/config"

	"github.com/bbockelm/golang-htcondor/logging"
	"github.com/bbockelm/golang-htcondor/webapi/siteapps"
)

// defaultSiteAppsReload is how often the bundle directory is rescanned
// when the operator did not say.
//
// A minute, because deploying a site app is a deliberate act somebody
// is standing in front of: they scp a bundle and then reload the page
// to see it. Longer makes that feel broken; shorter spends stat calls
// on a directory that changes a few times a year.
const defaultSiteAppsReload = time.Minute

// newSiteAppLibrary builds the library and scans it once.
//
// Called while the handler is being constructed, because setupRoutes
// decides whether to register /site/ on whether this returned
// anything, and that runs before there is a context to hand a
// goroutine. Returns nil when no directory is configured, which is how
// the whole feature stays out of a server that is not using it: no
// library, no timer, and no route.
//
// The first scan is synchronous so the first request after startup
// sees the apps, and so an operator's mistake is in the log before
// anybody tries the link.
func (h *Handler) newSiteAppLibrary(dir string, params *config.Config) *siteapps.Library {
	if dir == "" {
		return nil
	}
	// The configuration decides first; what an administrator uploaded
	// fills in the rest. Kept in that order deliberately -- see
	// siteapps.Chain.
	h.siteAppConfig = configPolicyFor(params)
	h.siteAppUploads = siteapps.NewUploadStore(h.db)
	var uploads siteapps.PolicySource
	if p := siteapps.NewDBPolicy(h.db); p != nil {
		uploads = p
	}
	lib := siteapps.NewLibrary(dir, siteapps.Chain{h.siteAppConfig, uploads})
	// What was served, and when. Absent a database -- the demo server,
	// most tests -- nothing is recorded and everything else works the
	// same.
	lib.SetRecorder(siteapps.NewSQLRecorder(h.db))
	h.logSiteAppReload(lib.Reload())
	return lib
}

// configPolicyFor builds the configuration-backed policy source.
//
// The nil check is load-bearing: a *config.Config that is nil put into
// a PolicySource interface makes an interface that is NOT nil, so
// every lookup would call a method on a nil pointer rather than
// finding no policy. A server with no HTCondor configuration -- demo
// mode, tests -- declares no apps instead.
func configPolicyFor(params *config.Config) *siteapps.ConfigPolicy {
	if params == nil {
		return siteapps.NewConfigPolicy(nil)
	}
	return siteapps.NewConfigPolicy(params)
}

// SetSiteAppPolicy installs policy read from a freshly-loaded
// configuration and rescans.
//
// Called on every reconfigure rather than when a parameter is seen to
// change, because an app's policy is spread over several parameters
// and a new app adds parameters that were not there to diff. The scan
// is what applies them, so it runs here rather than waiting out the
// reload interval: an operator who has just run condor_reconfig has
// said when they want this to take effect.
func (h *Handler) SetSiteAppPolicy(params *config.Config) {
	if h.siteApps == nil {
		return
	}
	h.siteAppConfig = configPolicyFor(params)
	var uploads siteapps.PolicySource
	if p := siteapps.NewDBPolicy(h.db); p != nil {
		uploads = p
	}
	h.siteApps.SetPolicySource(siteapps.Chain{h.siteAppConfig, uploads})
	h.logSiteAppReload(h.siteApps.Reload())
}

// runSiteAppReloads rescans the bundle directory until ctx is done.
//
// Started from Start, where there is a context whose cancellation is
// the server shutting down. Closing the library there is what releases
// the open (and already unlinked) bundle files.
func (h *Handler) runSiteAppReloads(ctx context.Context, interval time.Duration) {
	if h.siteApps == nil {
		return
	}
	if interval <= 0 {
		interval = defaultSiteAppsReload
	}
	lib := h.siteApps
	h.wg.Add(1)
	go func() {
		defer h.wg.Done()
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				_ = lib.Close()
				return
			case <-ticker.C:
				h.logSiteAppReload(lib.Reload())
			}
		}
	}()
}

// logSiteAppReload reports what a rescan found.
//
// Problems are logged individually at error level rather than summed,
// because each one names a bundle an operator deployed and is the only
// signal they get that it did not take: the app simply is not there,
// and a link that 404s looks the same whether the policy file is
// missing or the id was mistyped.
func (h *Handler) logSiteAppReload(published int, problems []error) {
	for _, err := range problems {
		h.logger.Error(logging.DestinationHTTP, "Site app not published", "error", err.Error())
	}
	h.logger.Debug(logging.DestinationHTTP, "Scanned site apps",
		"published", published, "problems", len(problems))
}

// siteAppCaller resolves the browser session for the site-app gate.
//
// Only the session cookie is consulted, deliberately. /site/ serves
// pages to a browser; a bearer token or an API key reaching these
// paths is a client doing something it has not been designed for, and
// treating one as a login would extend the group gate to credentials
// whose group membership is resolved on a different path.
func (h *Handler) siteAppCaller(r *http.Request) siteapps.Caller {
	session, ok := h.getSessionFromRequest(r)
	if !ok {
		return siteapps.Caller{}
	}
	return siteapps.Caller{Authenticated: true, Groups: session.Groups}
}

// siteAppLogin sends an unauthenticated browser to log in and come
// back to the page it asked for.
func (h *Handler) siteAppLogin(w http.ResponseWriter, r *http.Request) {
	target := r.URL.Path
	if r.URL.RawQuery != "" {
		target += "?" + r.URL.RawQuery
	}
	http.Redirect(w, r, "/login?return_to="+url.QueryEscape(target), http.StatusFound)
}

// SiteAppSummary is one app as /api/v1/auth/me reports it.
type SiteAppSummary struct {
	ID   string `json:"id"`
	Name string `json:"name"`
	URL  string `json:"url"`
	// Home reports that members land here instead of the dashboard.
	// More than one app may say so for the same caller, which is a
	// supported state and the reason the switcher exists.
	Home        bool   `json:"home,omitempty"`
	Description string `json:"description,omitempty"`
	Icon        string `json:"icon,omitempty"`
}

// siteAppsFor returns the apps a session may see.
//
// This is the only place app visibility is computed for the UI. The
// sidebar, the switcher and the app-only redirect all read it, so none
// of them can disagree with the gate on /site/ about who sees what.
func (h *Handler) siteAppsFor(groups []string) []SiteAppSummary {
	if h.siteApps == nil {
		return nil
	}
	entries := h.siteApps.VisibleTo(groups)
	if len(entries) == 0 {
		return nil
	}
	out := make([]SiteAppSummary, 0, len(entries))
	for _, e := range entries {
		out = append(out, SiteAppSummary{
			ID:          e.App.ID,
			Name:        e.App.Name,
			URL:         siteapps.MountPath(e.App.ID),
			Home:        e.App.Home,
			Description: e.App.Description,
			Icon:        e.App.Icon,
		})
	}
	return out
}
