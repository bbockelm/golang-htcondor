package httpserver

// Apps: long-lived servers running inside a job and reached through the
// job proxy.
//
//	POST   /api/v1/apps            submit one
//	GET    /api/v1/apps            the caller's
//	GET    /api/v1/apps/{id}       one, with a readiness probe
//	DELETE /api/v1/apps/{id}       remove its job
//
// Deliberately "apps" rather than "sessions": `interactive` already owns
// that word twice, for browser terminals and for MCP's named sessions,
// and a third meaning would be unreadable in condor_q output.
//
// Only code-server is implemented. The surface is app-shaped rather
// than code-server-shaped because what differs between a VS Code
// server, a JupyterLab and an RStudio is only the launch -- which image,
// which command, and how the app is told the URL prefix it is served
// under. Everything here (submit, spool, operator policy, discovery,
// state, teardown) is the same for all of them, and is where a third
// implementation of "run a server in a job" would otherwise appear:
// jupytertunnel and the interactive terminals are already two.
//
// There is no registry and nothing persisted. The queue is the record:
// an app is a job whose JobBatchName carries the prefix, so a restarted
// server finds them again with a query and nothing has to be adopted.

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"testing/fstest"
	"time"

	"github.com/PelicanPlatform/classad/classad"
	htcondor "github.com/bbockelm/golang-htcondor"
	"github.com/bbockelm/golang-htcondor/logging"
	"github.com/bbockelm/golang-htcondor/webapi/interactive"
	"github.com/bbockelm/golang-htcondor/webapi/jobssh"
	"github.com/bbockelm/golang-htcondor/webapi/vscode"
)

// AppTypeCodeServer is the only app type implemented.
const AppTypeCodeServer = "code-server"

// appReadyProbeTimeout bounds the readiness probe. It runs on a cached
// transport after the first call, so this only really bounds the first
// one -- which is also the one that pays for the whole handshake.
const appReadyProbeTimeout = 20 * time.Second

// App states, as reported to a caller.
//
// The distinction that matters is waiting/starting versus anything that
// reads as broken. A queued app and a dead one look identical through
// the proxy, which answers both with 502, and queue latency is the
// thing most likely to make somebody give up on this feature. It should
// not also look like a failure.
const (
	appStateWaiting  = "waiting"  // idle: no slot yet
	appStateStarting = "starting" // running, but the server is not listening yet
	appStateRunning  = "running"  // reachable
	appStateHeld     = "held"
	appStateEnded    = "ended"
)

// AppSummary is one app as reported to a caller.
type AppSummary struct {
	ID    string `json:"id"`
	Type  string `json:"type"`
	JobID string `json:"job_id"`
	Owner string `json:"owner,omitempty"`
	State string `json:"state"`
	// Detail says why, for a state a caller would otherwise have to
	// guess at: what it is waiting for, or why it is held.
	Detail string `json:"detail,omitempty"`
	// URL is where to open it, once there is something to open.
	URL string `json:"url,omitempty"`
	// Submitted is the queue date, so a caller can say how long a
	// wait has been going on.
	Submitted int64 `json:"submitted,omitempty"`
}

// AppCreateRequest is the body of POST /api/v1/apps.
type AppCreateRequest struct {
	Type        string `json:"type,omitempty"`
	Cpus        int    `json:"cpus,omitempty"`
	MemoryMB    int    `json:"memory_mb,omitempty"`
	DiskMB      int    `json:"disk_mb,omitempty"`
	Image       string `json:"image,omitempty"`
	Workdir     string `json:"workdir,omitempty"`
	SubmitLines string `json:"submit_lines,omitempty"`
}

// AppListResponse is the body of GET /api/v1/apps.
type AppListResponse struct {
	Apps []AppSummary `json:"apps"`
}

func (r *AppCreateRequest) applyDefaults() {
	if strings.TrimSpace(r.Type) == "" {
		r.Type = AppTypeCodeServer
	}
	if r.Cpus <= 0 {
		r.Cpus = 1
	}
	if r.MemoryMB <= 0 {
		r.MemoryMB = 4096
	}
	if r.DiskMB <= 0 {
		r.DiskMB = 10240
	}
}

func (r *AppCreateRequest) validate() error {
	if r.Type != AppTypeCodeServer {
		return fmt.Errorf("unknown app type %q; the only type implemented is %q", r.Type, AppTypeCodeServer)
	}
	if r.Cpus > 64 {
		return fmt.Errorf("cpus %d is more than an interactive app has any use for", r.Cpus)
	}
	// The user's own submit lines go into the submit file verbatim, so
	// they get the same validation the interactive terminals use --
	// which refuses the commands that would redefine what the job is.
	if err := interactive.ValidateCallerSubmitLines(r.SubmitLines); err != nil {
		return fmt.Errorf("submit_lines: %w", err)
	}
	return nil
}

// handleAppsPath dispatches /api/v1/apps and /api/v1/apps/{id}.
func (s *Handler) handleAppsPath(w http.ResponseWriter, r *http.Request) {
	const prefix = "/api/v1/apps"
	rest := strings.TrimPrefix(r.URL.Path, prefix)
	rest = strings.Trim(rest, "/")

	if rest == "" {
		switch r.Method {
		case http.MethodPost:
			s.handleAppCreate(w, r)
		case http.MethodGet:
			s.handleAppList(w, r)
		default:
			s.writeError(w, http.StatusMethodNotAllowed, "Method not allowed")
		}
		return
	}
	if strings.Contains(rest, "/") {
		s.writeError(w, http.StatusNotFound, "no such endpoint")
		return
	}
	switch r.Method {
	case http.MethodGet:
		s.handleAppGet(w, r, rest)
	case http.MethodDelete:
		s.handleAppDelete(w, r, rest)
	default:
		s.writeError(w, http.StatusMethodNotAllowed, "Method not allowed")
	}
}

// newAppID returns the identifier that ends up in the JobBatchName.
func newAppID() (string, error) {
	var b [8]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	return hex.EncodeToString(b[:]), nil
}

// appImage picks the image a code-server app runs.
//
// The operator's setting wins outright when there is one: a site that
// has pinned an image -- to its own build, or to a .sif staged on OSDF
// -- has decided, and this is the seam where that decision is enforced.
// Otherwise the caller may name one, which grants nothing new, since
// anyone who can create an app can already submit a job with any image
// through /api/v1/jobs. Failing those, the built-in recommendation.
func (s *Handler) appImage(requested string) string {
	if img := strings.TrimSpace(s.vscodeImage); img != "" {
		return img
	}
	if img := strings.TrimSpace(requested); img != "" {
		return img
	}
	return vscode.RecommendedImage
}

func (s *Handler) handleAppCreate(w http.ResponseWriter, r *http.Request) {
	ctx, needsRedirect, err := s.requireAuthentication(r)
	if err != nil {
		if needsRedirect {
			s.redirectToLogin(w, r)
			return
		}
		s.writeError(w, http.StatusUnauthorized, fmt.Sprintf("Authentication failed: %v", err))
		return
	}
	owner := htcondor.GetAuthenticatedUserFromContext(ctx)
	if owner == "" {
		s.writeError(w, http.StatusUnauthorized, "no authenticated user")
		return
	}

	var req AppCreateRequest
	if r.Body != nil {
		if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&req); err != nil && err.Error() != "EOF" {
			s.writeError(w, http.StatusBadRequest, fmt.Sprintf("invalid request body: %v", err))
			return
		}
	}
	req.applyDefaults()
	if err := req.validate(); err != nil {
		s.writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	id, err := newAppID()
	if err != nil {
		s.writeError(w, http.StatusInternalServerError, "could not generate an app id")
		return
	}

	submitFile, err := vscode.BuildSubmitFile(vscode.SubmitArgs{
		SessionID:         id,
		Universe:          "container",
		Image:             s.appImage(req.Image),
		Cpus:              req.Cpus,
		MemoryMB:          req.MemoryMB,
		DiskMB:            req.DiskMB,
		MaxLifetime:       s.appMaxLifetime(),
		ExtraRequirements: s.interactiveRequirements,
		CallerSubmitLines: req.SubmitLines,
		ExtraSubmitLines:  s.interactiveExtraSubmit,
	})
	if err != nil {
		s.writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	script := vscode.LaunchScript(vscode.ScriptArgs{Workdir: req.Workdir})

	clusterID, procAds, err := s.submitJob(ctx, submitFile)
	if err != nil {
		s.logger.Error(logging.DestinationHTTP, "app submit failed",
			"app", id, "owner", owner, "error", err)
		s.writeError(w, http.StatusBadGateway, fmt.Sprintf("schedd submit failed: %v", err))
		return
	}

	// Remote-submit then spool from an in-memory FS: no on-disk state
	// to clean up if the request fails partway through.
	stage := fstest.MapFS{
		vscode.ExecutableName: &fstest.MapFile{Data: []byte(script), Mode: 0o755},
	}
	if err := s.getSchedd().SpoolJobFilesFromFS(ctx, procAds, stage); err != nil {
		// The submit succeeded, so the job is sitting held with
		// SpoolingInput. Remove it rather than leaving a job that can
		// never run and that the caller has no handle on.
		s.removeAppJob(ctx, clusterID)
		s.logger.Error(logging.DestinationHTTP, "app spool failed",
			"app", id, "cluster", clusterID, "owner", owner, "error", err)
		s.writeError(w, http.StatusBadGateway,
			fmt.Sprintf("schedd accepted the submit but spooling the launcher failed: %v", err))
		return
	}

	s.logger.Info(logging.DestinationHTTP, "app submitted",
		"app", id, "type", req.Type, "cluster", clusterID, "owner", owner)

	s.writeJSON(w, http.StatusCreated, AppSummary{
		ID:        id,
		Type:      req.Type,
		JobID:     fmt.Sprintf("%d.0", clusterID),
		Owner:     owner,
		State:     appStateWaiting,
		Detail:    "submitted; waiting for a slot",
		Submitted: time.Now().Unix(),
	})
}

// appMaxLifetime is the ceiling the sandbox cannot talk its way out of.
//
// It reuses the Jupyter setting rather than adding a knob nobody asked
// for: both are "a browser app in a job", and an operator who has
// decided how long one may live has decided for the other.
func (s *Handler) appMaxLifetime() time.Duration {
	if s.jupyterMaxLifetimeSec <= 0 {
		return 0
	}
	return time.Duration(s.jupyterMaxLifetimeSec) * time.Second
}

func (s *Handler) handleAppList(w http.ResponseWriter, r *http.Request) {
	ctx, needsRedirect, err := s.requireAuthentication(r)
	if err != nil {
		if needsRedirect {
			s.redirectToLogin(w, r)
			return
		}
		s.writeError(w, http.StatusUnauthorized, fmt.Sprintf("Authentication failed: %v", err))
		return
	}
	owner := htcondor.GetAuthenticatedUserFromContext(ctx)
	if owner == "" {
		s.writeError(w, http.StatusUnauthorized, "no authenticated user")
		return
	}

	ads, err := s.queryAppAds(ctx, owner)
	if err != nil {
		s.writeError(w, http.StatusBadGateway, fmt.Sprintf("schedd query failed: %v", err))
		return
	}

	out := make([]AppSummary, 0, len(ads))
	for _, ad := range ads {
		if sum, ok := appSummaryFromAd(ad, owner); ok {
			out = append(out, sum)
		}
	}
	s.writeJSON(w, http.StatusOK, AppListResponse{Apps: out})
}

// queryAppAds returns the caller's app jobs.
//
// FetchMyJobs with the raw, unstripped identity: the schedd stores
// Owner with whatever the negotiation surfaced, typically the full
// user@TRUST_DOMAIN form, and an earlier handler that stripped the
// domain here silently matched zero rows. The batch-name filter is
// applied after the query rather than as a constraint, matching the
// interactive terminal list.
func (s *Handler) queryAppAds(ctx context.Context, owner string) ([]*classad.ClassAd, error) {
	return s.queryAppAdsWithConstraint(ctx, owner, appConstraint)
}

// appConstraint matches any of our app jobs. Equality on a custom
// attribute rather than a prefix match on JobBatchName: it is what
// every schedd understands, and it is evaluated by the SCHEDD, so a
// caller with hundreds of jobs in the queue still gets their apps back.
// Filtering here instead would lose them to the query limit.
var appConstraint = fmt.Sprintf("%s =?= %q", vscode.AppAttr, vscode.AppAttrValue)

func (s *Handler) queryAppAdsWithConstraint(ctx context.Context, owner, constraint string) ([]*classad.ClassAd, error) {
	ads, _, err := s.getSchedd().QueryWithOptions(ctx, constraint, &htcondor.QueryOptions{
		Limit: 200,
		Projection: []string{
			"ClusterId", "ProcId", "JobStatus", "JobBatchName",
			"HoldReason", "HoldReasonCode", "QDate", "Owner",
		},
		FetchOpts: htcondor.FetchMyJobs,
		Owner:     owner,
	})
	if err != nil {
		s.logger.Error(logging.DestinationHTTP, "app list query failed", "owner", owner, "error", err)
		return nil, err
	}
	return ads, nil
}

func (s *Handler) handleAppGet(w http.ResponseWriter, r *http.Request, id string) {
	ctx, needsRedirect, err := s.requireAuthentication(r)
	if err != nil {
		if needsRedirect {
			s.redirectToLogin(w, r)
			return
		}
		s.writeError(w, http.StatusUnauthorized, fmt.Sprintf("Authentication failed: %v", err))
		return
	}
	owner := htcondor.GetAuthenticatedUserFromContext(ctx)
	if owner == "" {
		s.writeError(w, http.StatusUnauthorized, "no authenticated user")
		return
	}

	sum, ok := s.findApp(ctx, owner, id)
	if !ok {
		s.writeError(w, http.StatusNotFound, "no such app")
		return
	}

	// Probe only here, never in the list. A running job is not the same
	// as a reachable one -- the server takes seconds to bind its socket
	// -- and this is the call a client polls after creating an app, so
	// it is where the distinction is worth paying for. The list would
	// pay it once per app.
	if sum.State == appStateRunning {
		sum.State, sum.Detail = s.probeApp(ctx, owner, sum.JobID)
		if sum.State != appStateRunning {
			sum.URL = ""
		}
	}
	s.writeJSON(w, http.StatusOK, sum)
}

// probeApp reports whether the app is actually listening yet.
func (s *Handler) probeApp(ctx context.Context, owner, jobID string) (state, detail string) {
	cluster, proc, err := parseJobID(jobID)
	if err != nil {
		return appStateRunning, ""
	}
	cache, err := s.getOrCreateJobSSHCache()
	if err != nil {
		return appStateRunning, ""
	}
	probeCtx, cancel := context.WithTimeout(ctx, appReadyProbeTimeout)
	defer cancel()
	conn, err := cache.DialJobUnix(probeCtx, jobssh.Key{Owner: owner, Cluster: cluster, Proc: proc}, vscode.SocketName)
	if err != nil {
		return appStateStarting, "the job is running; the editor is still starting up"
	}
	_ = conn.Close()
	return appStateRunning, ""
}

func (s *Handler) handleAppDelete(w http.ResponseWriter, r *http.Request, id string) {
	ctx, needsRedirect, err := s.requireAuthentication(r)
	if err != nil {
		if needsRedirect {
			s.redirectToLogin(w, r)
			return
		}
		s.writeError(w, http.StatusUnauthorized, fmt.Sprintf("Authentication failed: %v", err))
		return
	}
	owner := htcondor.GetAuthenticatedUserFromContext(ctx)
	if owner == "" {
		s.writeError(w, http.StatusUnauthorized, "no authenticated user")
		return
	}

	sum, ok := s.findApp(ctx, owner, id)
	if !ok {
		s.writeError(w, http.StatusNotFound, "no such app")
		return
	}
	cluster, _, err := parseJobID(sum.JobID)
	if err != nil {
		s.writeError(w, http.StatusInternalServerError, "app has an unparseable job id")
		return
	}
	s.removeAppJob(ctx, cluster)
	s.logger.Info(logging.DestinationHTTP, "app removed", "app", id, "cluster", cluster, "owner", owner)
	sum.State = appStateEnded
	sum.Detail = "removed"
	sum.URL = ""
	s.writeJSON(w, http.StatusOK, sum)
}

func (s *Handler) removeAppJob(ctx context.Context, cluster int) {
	constraint := fmt.Sprintf("ClusterId == %d", cluster)
	if _, err := s.getSchedd().RemoveJobs(ctx, constraint, "VS Code app removed"); err != nil {
		s.logger.Warn(logging.DestinationHTTP, "removing an app job failed",
			"cluster", cluster, "error", err)
	}
}

// findApp locates one of the caller's apps by id.
//
// Asks the schedd for that one job rather than for all of them: an app
// belonging to somebody with a busy queue would otherwise fall off the
// end of the limit and read as "no such app".
func (s *Handler) findApp(ctx context.Context, owner, id string) (AppSummary, bool) {
	want := vscode.BatchName(id)
	constraint := fmt.Sprintf("%s && JobBatchName =?= %q", appConstraint, want)
	ads, err := s.queryAppAdsWithConstraint(ctx, owner, constraint)
	if err != nil {
		return AppSummary{}, false
	}
	for _, ad := range ads {
		if name, ok := ad.EvaluateAttrString("JobBatchName"); !ok || name != want {
			continue
		}
		if sum, ok := appSummaryFromAd(ad, owner); ok {
			return sum, true
		}
	}
	return AppSummary{}, false
}

// appSummaryFromAd turns a job ad into an AppSummary, reporting false
// for a job that is not one of ours.
func appSummaryFromAd(ad *classad.ClassAd, owner string) (AppSummary, bool) {
	batchName, ok := ad.EvaluateAttrString("JobBatchName")
	if !ok {
		return AppSummary{}, false
	}
	id, ok := vscode.SessionIDFromBatchName(batchName)
	if !ok {
		return AppSummary{}, false
	}
	cluster, _ := ad.EvaluateAttrInt("ClusterId")
	proc, _ := ad.EvaluateAttrInt("ProcId")
	status, _ := ad.EvaluateAttrInt("JobStatus")
	qdate, _ := ad.EvaluateAttrInt("QDate")

	sum := AppSummary{
		ID:        id,
		Type:      AppTypeCodeServer,
		JobID:     fmt.Sprintf("%d.%d", cluster, proc),
		Owner:     owner,
		Submitted: qdate,
	}

	switch status {
	case 1:
		sum.State = appStateWaiting
		sum.Detail = "waiting for a slot"
	case 2:
		sum.State = appStateRunning
		sum.URL = appProxyPath(int(cluster), int(proc))
	case 5:
		sum.State = appStateHeld
		if reason, ok := ad.EvaluateAttrString("HoldReason"); ok {
			sum.Detail = reason
		} else {
			sum.Detail = "held"
		}
	default:
		sum.State = appStateEnded
	}
	return sum, true
}

// appProxyPath is where a browser opens the app.
//
// The trailing slash is not decoration: the app is served by stripping
// this prefix and emits relative URLs, so without it every asset
// resolves one path component too high. The proxy redirects to this
// form; handing it out already correct saves the round trip.
func appProxyPath(cluster, proc int) string {
	return fmt.Sprintf("/api/v1/jobs/%d.%d/proxy/unix/%s/", cluster, proc, vscode.SocketName)
}
