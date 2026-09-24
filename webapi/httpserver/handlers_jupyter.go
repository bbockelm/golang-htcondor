// HTTP routes for the JupyterLab reverse-tunnel feature.
//
// Routes (Phase 1: tunnel only — submit and SSE land in later phases):
//
//   POST   /api/v1/jupyter/instances/{id}/tunnel   websocket upgrade,
//                                                  helper-side connect-back.
//                                                  Bearer-token authenticated.
//   ANY    /api/v1/jupyter/instances/{id}/proxy/.. user-facing reverse proxy.
//                                                  Session-cookie authenticated;
//                                                  caller must own the instance.
//
// The actual yamux/UDS plumbing lives in
// github.com/bbockelm/golang-htcondor/webapi/jupytertunnel.

package httpserver

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"runtime"
	"strconv"
	"strings"
	"sync/atomic"
	"testing/fstest"
	"time"

	"github.com/PelicanPlatform/classad/classad"
	htcondor "github.com/bbockelm/golang-htcondor"
	"github.com/bbockelm/golang-htcondor/logging"
	"github.com/bbockelm/golang-htcondor/webapi/interactive"
	"github.com/bbockelm/golang-htcondor/webapi/jupytertunnel"
	"github.com/gorilla/websocket"

	"github.com/bbockelm/golang-htcondor/webapi/httpserver/jupyterhelperbin"
)

// jupyterUpgrader returns the websocket.Upgrader for the
// helper-side tunnel endpoint. The helper is bearer-token
// authenticated (the bearer token is the actual security boundary)
// and isn't a browser, so it sends no Origin header — the shared
// origin check accepts that case. Browser-originated connections
// from a third-party site WILL be rejected by the origin check,
// which is the correct behavior even though CSRF isn't the primary
// concern here.
func (s *Handler) jupyterUpgrader() websocket.Upgrader {
	return websocket.Upgrader{
		ReadBufferSize:  32 * 1024,
		WriteBufferSize: 32 * 1024,
		CheckOrigin:     s.checkWebSocketOrigin,
	}
}

// materializeJupyterHelper used to write the embedded helper to disk; it
// has been replaced by an in-memory fs.FS that's spooled directly to the
// schedd via SpoolJobFilesFromFS. Kept removed entirely so callers can't
// accidentally bring on-disk state back.

// getOrCreateJupyterRegistry lazily initializes the registry on first use.
// Errors here are unrecoverable (bad RNG); we crash the request and log.
func (s *Handler) getOrCreateJupyterRegistry() (*jupytertunnel.Registry, error) {
	s.jupyterRegistryMu.Lock()
	defer s.jupyterRegistryMu.Unlock()
	if s.jupyterRegistry != nil {
		return s.jupyterRegistry, nil
	}
	// A durable secret where there is a database to keep it in. Without
	// one every token stops verifying when this process ends, which is
	// what made a restart destroy every session: the job was still there,
	// the helper still held its token, and nothing left could check it.
	//
	// Falling back to a per-process secret rather than failing: a
	// deployment with no application database still gets working
	// JupyterLab, just not one that survives a restart, and that is the
	// behaviour it had before any of this.
	store := s.jupyterSessionStore()
	if store != nil {
		secret, err := store.SigningSecret(context.Background())
		if err == nil {
			reg, rerr := jupytertunnel.NewRegistryWithSecret(secret, store)
			if rerr == nil {
				s.jupyterRegistry = reg
				s.adoptJupyterSessions(context.Background(), reg, store)
				return reg, nil
			}
			err = rerr
		}
		s.logger.Warn(logging.DestinationHTTP,
			"jupyter: no durable signing secret; sessions will not survive a restart",
			"error", err)
	}

	reg, err := jupytertunnel.NewRegistry()
	if err != nil {
		return nil, err
	}
	s.jupyterRegistry = reg
	return reg, nil
}

// jupyterSessionStore is the durable session store, or nil when this
// deployment has no application database.
func (s *Handler) jupyterSessionStore() *jupyterStore {
	if s.db == nil {
		return nil
	}
	return newJupyterStore(s.db, s.sealer)
}

// adoptJupyterSessions puts back the sessions this process did not create.
//
// Their jobs are still running and their helpers are dialing back; without
// this the dial lands on a registry that has never heard of the instance and
// is refused, leaving a live JupyterLab unreachable until the job's ceiling
// reaps it.
//
// Best-effort and non-fatal: a session that cannot be adopted is one the user
// has to restart, which is where they already were.
func (s *Handler) adoptJupyterSessions(ctx context.Context, reg *jupytertunnel.Registry, store *jupyterStore) {
	rows, err := store.Live(ctx, time.Now())
	if err != nil {
		s.logger.Warn(logging.DestinationHTTP, "jupyter: could not read stored sessions", "error", err)
		return
	}
	var adopted int
	for _, row := range rows {
		if _, err := reg.AdoptInstance(row.InstanceID, row.Owner, row.CreatedAt, map[string]string{
			"cluster_id": strconv.Itoa(row.ClusterID),
			"proc_id":    strconv.Itoa(row.ProcID),
		}); err != nil {
			s.logger.Warn(logging.DestinationHTTP, "jupyter: could not adopt a stored session",
				"instance", row.InstanceID, "error", err)
			continue
		}
		adopted++
	}
	if adopted > 0 {
		s.logger.Info(logging.DestinationHTTP,
			"Adopted JupyterLab sessions that outlived the last process", "count", adopted)
	}
}

// handleJupyterPath dispatches /api/v1/jupyter/* paths. We register a single
// catch-all route to keep the mux setup tidy, then split here.
//
// Routes handled:
//
//	POST /api/v1/jupyter/instances                            create instance + submit job
//	GET  /api/v1/jupyter/instances/{id}/tunnel                websocket tunnel (helper-side)
//	ANY  /api/v1/jupyter/instances/{id}/proxy/{rest...}       browser-side reverse proxy
func (s *Handler) handleJupyterPath(w http.ResponseWriter, r *http.Request) {
	const prefix = "/api/v1/jupyter/instances"
	rest := strings.TrimPrefix(r.URL.Path, prefix)
	if rest == r.URL.Path {
		s.writeError(w, http.StatusNotFound, "Jupyter endpoint not found")
		return
	}
	// Bare /instances (no trailing slash): collection endpoint.
	// POST creates a new instance, GET lists the caller's instances.
	if rest == "" || rest == "/" {
		switch r.Method {
		case http.MethodPost:
			s.handleJupyterCreateInstance(w, r)
		case http.MethodGet:
			s.handleJupyterListInstances(w, r)
		default:
			s.writeError(w, http.StatusMethodNotAllowed, "Method not allowed")
		}
		return
	}
	rest = strings.TrimPrefix(rest, "/")

	// Split: <id>[/verb[/extra...]]
	id, after, hasVerb := strings.Cut(rest, "/")
	if id == "" {
		s.writeError(w, http.StatusNotFound, "missing instance id")
		return
	}
	if !hasVerb {
		// /instances/<id> with no verb — single-instance summary.
		if r.Method != http.MethodGet {
			s.writeError(w, http.StatusMethodNotAllowed, "Method not allowed")
			return
		}
		s.handleJupyterGetInstance(w, r, id)
		return
	}
	verb, extra, _ := strings.Cut(after, "/")
	switch verb {
	case "tunnel":
		if extra != "" {
			s.writeError(w, http.StatusNotFound, "tunnel endpoint takes no path suffix")
			return
		}
		s.handleJupyterTunnel(w, r, id)
	case "events":
		if extra != "" {
			s.writeError(w, http.StatusNotFound, "events endpoint takes no path suffix")
			return
		}
		s.handleJupyterEvents(w, r, id)
	case "proxy":
		// Forward the FULL request path, not just the bit after
		// /proxy/. JupyterLab is configured with --ServerApp.base_url
		// equal to that whole prefix (so its own links round-trip
		// through us cleanly). Stripping it would make every "/lab",
		// "/api/...", etc. miss in Jupyter's router and 404. The
		// downstream Registry.Proxy just plops r.URL.Path into the
		// outbound request unchanged.
		s.handleJupyterProxy(w, r, id, r.URL.Path)
	default:
		s.writeError(w, http.StatusNotFound, fmt.Sprintf("unknown jupyter verb %q", verb))
	}
}

// JupyterInstanceSummary is the SPA-facing shape returned by both
// GET /api/v1/jupyter/instances (list) and GET /api/v1/jupyter/instances/{id}
// (single). The proxy_path is what the iframe should mount; the events_path
// drives the SSE stream.
//
// The job_* fields are populated from a single bulk schedd query
// (handleJupyterListInstances) so the list view can run the same
// status-interpretation logic the detail page uses, without a
// round-trip per row. Empty when the schedd query failed or the
// cluster is gone — the SPA falls back to a "loading"/"connected only"
// view in that case.
type JupyterInstanceSummary struct {
	InstanceID                   string `json:"instance_id"`
	ClusterID                    string `json:"cluster_id,omitempty"`
	Image                        string `json:"image,omitempty"`
	Owner                        string `json:"owner"`
	CreatedAt                    string `json:"created_at"`
	Connected                    bool   `json:"connected"` // helper has dialed back
	ProxyPath                    string `json:"proxy_path"`
	EventsPath                   string `json:"events_path"`
	JobStatus                    int    `json:"job_status,omitempty"`
	JobCurrentStartExecutingDate int64  `json:"job_current_start_executing_date,omitempty"`
	HoldReasonCode               int    `json:"hold_reason_code,omitempty"`
	HoldReason                   string `json:"hold_reason,omitempty"`
}

// handleJupyterListInstances handles GET /api/v1/jupyter/instances and
// returns the caller's live instances. Instances live in process memory,
// so this list resets on every API server restart — that's documented
// in the SPA so users aren't surprised.
func (s *Handler) handleJupyterListInstances(w http.ResponseWriter, r *http.Request) {
	ctx, needsRedirect, err := s.requireAuthentication(r)
	if err != nil {
		if needsRedirect {
			s.redirectToLogin(w, r)
			return
		}
		s.writeError(w, http.StatusUnauthorized, fmt.Sprintf("Authentication failed: %v", err))
		return
	}
	username := htcondor.GetAuthenticatedUserFromContext(ctx)
	if username == "" {
		s.writeError(w, http.StatusUnauthorized, "no authenticated user")
		return
	}

	reg, err := s.getOrCreateJupyterRegistry()
	if err != nil {
		s.writeError(w, http.StatusInternalServerError, "registry unavailable")
		return
	}
	insts := reg.ListByOwner(username)

	// Enrich each summary with the underlying job's status, AND reap
	// instances whose underlying HTCondor job has gone away. A single
	// bulk schedd query covers every cluster we care about.
	//
	// Reaping rules (only when queriedOK is true — otherwise we don't
	// know whether the job is gone or the schedd is just unreachable):
	//   - job ad missing from the queue        → instance is dead, close it
	//   - JobStatus 3 (Removed) / 4 (Completed) → instance is dead, close it
	jobAdsByCluster, queriedOK := s.queryJupyterClusterAds(ctx, insts)
	out := make([]JupyterInstanceSummary, 0, len(insts))
	for _, inst := range insts {
		summary := instanceToSummary(inst)
		var ad *classad.ClassAd
		var cidInt int
		var haveCluster bool
		if cid := summary.ClusterID; cid != "" {
			if v, perr := strconv.Atoi(cid); perr == nil {
				cidInt = v
				haveCluster = true
				ad = jobAdsByCluster[v]
			}
		}
		if ad != nil {
			enrichJupyterSummaryFromAd(&summary, ad)
		}
		if queriedOK && haveCluster && jupyterInstanceIsDead(ad) {
			s.logger.Info(logging.DestinationHTTP, "jupyter list: reaping instance with terminal/missing job",
				"instance", inst.ID, "cluster", cidInt,
				"job_status", summary.JobStatus)
			reg.CloseInstance(inst.ID)
			continue
		}
		out = append(out, summary)
	}
	s.writeJSON(w, http.StatusOK, map[string]any{"instances": out})
}

// jupyterInstanceIsDead is the predicate that drives registry reaping
// in the list and detail handlers. Both treat:
//
//   - ad == nil           → cluster has fallen out of the queue (job
//     was condor_rm'd hard, or the schedd has
//     forgotten about it). The registry entry
//     is the only thing keeping the SPA from
//     cleaning up; drop it.
//   - JobStatus 3 / 4     → job was removed or completed. The
//     jupyter-lab process inside is gone, so
//     the helper's tunnel is dangling.
//
// Anything else (idle, running, held, transferring) is "still alive"
// and the SPA's status-interpretation surfaces the right state.
func jupyterInstanceIsDead(ad *classad.ClassAd) bool {
	if ad == nil {
		return true
	}
	if v, ok := ad.EvaluateAttrInt("JobStatus"); ok {
		switch v {
		case 3, 4:
			return true
		}
	}
	return false
}

// queryJupyterClusterAds fetches the proc.0 ad of every cluster the
// supplied instances reference, in one schedd query. Returns a map
// keyed by ClusterId plus a bool indicating whether the query
// itself succeeded — callers use that to distinguish "this cluster
// isn't in the queue (so the instance is dead)" from "the schedd
// query failed (so we don't know yet, leave instances alone)".
func (s *Handler) queryJupyterClusterAds(
	ctx context.Context,
	insts []*jupytertunnel.Instance,
) (map[int]*classad.ClassAd, bool) {
	out := map[int]*classad.ClassAd{}
	if len(insts) == 0 {
		return out, true
	}

	// Build "ClusterId == 1 || ClusterId == 2 || ..." rather than a
	// regexp / IN — older schedds and ClassAd dialects all understand
	// equality + boolean OR.
	parts := make([]string, 0, len(insts))
	for _, inst := range insts {
		cid := inst.Meta["cluster_id"]
		if cid == "" {
			continue
		}
		if _, perr := strconv.Atoi(cid); perr != nil {
			continue
		}
		parts = append(parts, fmt.Sprintf("ClusterId == %s", cid))
	}
	if len(parts) == 0 {
		return out, true
	}
	constraint := "(" + strings.Join(parts, " || ") + ") && ProcId == 0"

	ads, _, err := s.getSchedd().QueryWithOptions(ctx, constraint, &htcondor.QueryOptions{
		Projection: []string{
			"ClusterId", "ProcId", "JobStatus",
			"JobCurrentStartExecutingDate",
			"HoldReason", "HoldReasonCode",
		},
		Limit: len(parts) + 4,
	})
	if err != nil {
		s.logger.Warn(logging.DestinationHTTP, "jupyter list: schedd query failed",
			"error", err)
		return out, false
	}
	for _, ad := range ads {
		if cid, ok := ad.EvaluateAttrInt("ClusterId"); ok {
			out[int(cid)] = ad
		}
	}
	return out, true
}

// enrichJupyterSummaryFromAd copies the relevant job-status fields off
// the proc ad onto the SPA-facing summary. Missing fields stay zero;
// the SPA's status-interpretation function tolerates that.
func enrichJupyterSummaryFromAd(s *JupyterInstanceSummary, ad *classad.ClassAd) {
	if v, ok := ad.EvaluateAttrInt("JobStatus"); ok {
		s.JobStatus = int(v)
	}
	if v, ok := ad.EvaluateAttrInt("JobCurrentStartExecutingDate"); ok {
		s.JobCurrentStartExecutingDate = v
	}
	if v, ok := ad.EvaluateAttrInt("HoldReasonCode"); ok {
		s.HoldReasonCode = int(v)
	}
	if v, ok := ad.EvaluateAttrString("HoldReason"); ok {
		s.HoldReason = v
	}
}

// handleJupyterGetInstance handles GET /api/v1/jupyter/instances/{id}.
// Used by the per-instance detail page when the user navigates back to
// a session they previously launched.
func (s *Handler) handleJupyterGetInstance(w http.ResponseWriter, r *http.Request, id string) {
	ctx, needsRedirect, err := s.requireAuthentication(r)
	if err != nil {
		if needsRedirect {
			s.redirectToLogin(w, r)
			return
		}
		s.writeError(w, http.StatusUnauthorized, fmt.Sprintf("Authentication failed: %v", err))
		return
	}
	username := htcondor.GetAuthenticatedUserFromContext(ctx)

	reg, err := s.getOrCreateJupyterRegistry()
	if err != nil {
		s.writeError(w, http.StatusInternalServerError, "registry unavailable")
		return
	}
	inst, ok := reg.Lookup(id)
	if !ok || inst.Owner != username {
		// Don't leak existence to non-owners, mirroring the proxy/events
		// handlers' policy.
		s.writeError(w, http.StatusNotFound, "no such Jupyter instance")
		return
	}
	summary := instanceToSummary(inst)

	// Same reaping rules as the list handler: if the underlying
	// HTCondor job has gone terminal (or vanished from the queue), the
	// registry entry is just stale state — close it and tell the SPA
	// 404 so it transitions to a "gone" view instead of perpetually
	// showing "launching".
	if cid := summary.ClusterID; cid != "" {
		if cidInt, perr := strconv.Atoi(cid); perr == nil {
			adsByCluster, queriedOK := s.queryJupyterClusterAds(ctx,
				[]*jupytertunnel.Instance{inst})
			ad := adsByCluster[cidInt]
			if ad != nil {
				enrichJupyterSummaryFromAd(&summary, ad)
			}
			if queriedOK && jupyterInstanceIsDead(ad) {
				s.logger.Info(logging.DestinationHTTP, "jupyter detail: reaping instance with terminal/missing job",
					"instance", inst.ID, "cluster", cidInt,
					"job_status", summary.JobStatus)
				reg.CloseInstance(inst.ID)
				s.writeError(w, http.StatusNotFound, "Jupyter instance has ended")
				return
			}
		}
	}
	s.writeJSON(w, http.StatusOK, summary)
}

// instanceToSummary collapses the registry's Instance into the wire shape.
// Pulled out so list + single-get share the conversion.
func instanceToSummary(inst *jupytertunnel.Instance) JupyterInstanceSummary {
	return JupyterInstanceSummary{
		InstanceID: inst.ID,
		ClusterID:  inst.Meta["cluster_id"],
		Image:      inst.Meta["image"],
		Owner:      inst.Owner,
		CreatedAt:  inst.Created.UTC().Format(time.RFC3339),
		Connected:  inst.HasTunnel(),
		ProxyPath:  fmt.Sprintf("/api/v1/jupyter/instances/%s/proxy/", inst.ID),
		EventsPath: fmt.Sprintf("/api/v1/jupyter/instances/%s/events", inst.ID),
	}
}

// handleJupyterEvents streams instance lifecycle events to the browser via
// Server-Sent Events. The frontend uses these to flip from "submitting…"
// to "ready" (mounting the iframe). The stream stays open until the
// instance closes or the client disconnects.
func (s *Handler) handleJupyterEvents(w http.ResponseWriter, r *http.Request, id string) {
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
	username := htcondor.GetAuthenticatedUserFromContext(ctx)

	reg, err := s.getOrCreateJupyterRegistry()
	if err != nil {
		s.writeError(w, http.StatusInternalServerError, "registry unavailable")
		return
	}
	inst, ok := reg.Lookup(id)
	if !ok {
		s.writeError(w, http.StatusNotFound, "no such Jupyter instance")
		return
	}
	if inst.Owner != username {
		// Same 404 we use for proxy: don't leak existence to non-owners.
		s.writeError(w, http.StatusNotFound, "no such Jupyter instance")
		return
	}

	// Shared with the other SSE endpoints: sets the headers, clears the
	// server's write deadline (WriteTimeout otherwise kills the stream
	// mid-flight and the browser silently reconnects), and flushes so
	// EventSource opens.
	rc, ok := sseSetup(w)
	if !ok {
		s.writeError(w, http.StatusInternalServerError, "server does not support streaming")
		return
	}
	defer s.streamOpened()()

	events, cancel := inst.Subscribe(16)
	defer cancel()

	// Heartbeat so intermediate proxies don't drop the idle connection.
	ticker := time.NewTicker(15 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-r.Context().Done():
			return
		case <-ticker.C:
			if _, err := w.Write([]byte(": ping\n\n")); err != nil {
				return
			}
			_ = rc.Flush()
		case ev, ok := <-events:
			if !ok {
				return
			}
			payload, err := json.Marshal(ev)
			if err != nil {
				continue
			}
			_, _ = fmt.Fprintf(w, "event: %s\ndata: %s\n\n", ev.Kind, payload)
			_ = rc.Flush()
			if ev.Kind == jupytertunnel.EventClosed {
				return
			}
		}
	}
}

// JupyterCreateRequest is the optional JSON body of POST /jupyter/instances.
// All fields have sensible defaults so a bare {} is a valid request.
type JupyterCreateRequest struct {
	// Image is the Docker image to launch. Default
	// quay.io/jupyter/scipy-notebook:latest.
	Image string `json:"image"`
	// Cpus is the requested core count. Default 2.
	Cpus int `json:"cpus"`
	// MemoryMB is the requested RAM in mebibytes. Default 4096.
	MemoryMB int `json:"memory_mb"`
	// DiskMB is the requested scratch disk in mebibytes. Default 4096.
	DiskMB int `json:"disk_mb"`

	// GPU fields. Mirrored verbatim into request_gpus and the
	// gpus_minimum_* / cuda_version / require_gpus submit lines.
	// Gpus == 0 disables the entire GPU section in the submit file.
	Gpus                  int    `json:"gpus,omitempty"`
	GpusMinimumCapability string `json:"gpus_minimum_capability,omitempty"`
	GpusMinimumMemory     int    `json:"gpus_minimum_memory,omitempty"`
	GpusMinimumRuntime    string `json:"gpus_minimum_runtime,omitempty"`
	CudaVersion           string `json:"cuda_version,omitempty"`
	RequireGpus           string `json:"require_gpus,omitempty"`

	// SubmitLines are extra submit commands the user typed in the launch
	// form. Untrusted: validated with interactive.ValidateCallerSubmitLines,
	// which rejects anything that would redefine the job (executable,
	// universe, container_image, queue, ...). Merged before the operator's
	// extras so operator policy still wins.
	SubmitLines string `json:"submit_lines,omitempty"`
}

// JupyterCreateResponse is the JSON returned by POST /jupyter/instances.
type JupyterCreateResponse struct {
	InstanceID string `json:"instance_id"`
	ClusterID  string `json:"cluster_id"`
	// ProxyPath is where the browser should eventually point its iframe
	// (only useful once the helper has connected back; the SSE stream
	// from /events tells you when).
	ProxyPath string `json:"proxy_path"`
}

// handleJupyterCreateInstance accepts a JupyterCreateRequest, mints an
// instance + token, stages the helper binary and token file as
// transfer_input_files, generates a Docker-universe submit file, and submits
// it to the schedd.
func (s *Handler) handleJupyterCreateInstance(w http.ResponseWriter, r *http.Request) {
	ctx, needsRedirect, err := s.requireAuthentication(r)
	if err != nil {
		if needsRedirect {
			s.redirectToLogin(w, r)
			return
		}
		s.writeError(w, http.StatusUnauthorized, fmt.Sprintf("Authentication failed: %v", err))
		return
	}
	username := htcondor.GetAuthenticatedUserFromContext(ctx)
	if username == "" {
		s.writeError(w, http.StatusUnauthorized, "no authenticated user")
		return
	}

	// Pick the universe / helper combination based on what the API
	// server is running on. macOS lacks Docker universe support, so we
	// fall back to vanilla + an on-the-fly conda env there. (The user
	// can drive this from a Linux API server toward a macOS schedd by
	// setting `JUPYTER_FORCE_VANILLA=1` in the env if that ever
	// matters; not exposed yet.)
	universe := jupyterUniverseForGOOS(runtimeGOOS())
	helperGOOS := jupyterHelperGOOSForUniverse(universe)
	helperGOARCH := runtimeGOARCH()
	helperBytes, err := jupyterhelperbin.BytesFor(helperGOOS, helperGOARCH)
	if err != nil {
		if errors.Is(err, jupyterhelperbin.ErrNotEmbedded) {
			s.writeError(w, http.StatusServiceUnavailable,
				fmt.Sprintf("JupyterLab is not available in this build for %s/%s execute nodes. "+
					"The api binary is built with -tags embed_jupyter_helper but the helper for this "+
					"platform isn't in dist/. Add %q to JUPYTER_HELPER_TARGETS in the Makefile and "+
					"rebuild via `make build` (Go cross-compiles the helper for every listed target).",
					helperGOOS, helperGOARCH, helperGOOS+"/"+helperGOARCH))
			return
		}
		s.writeError(w, http.StatusInternalServerError,
			fmt.Sprintf("failed to load JupyterLab helper for %s/%s: %v", helperGOOS, helperGOARCH, err))
		return
	}

	// Parse the optional request body. Tolerate empty body / EOF.
	var req JupyterCreateRequest
	if r.Body != nil && r.ContentLength != 0 {
		dec := json.NewDecoder(r.Body)
		dec.DisallowUnknownFields()
		if err := dec.Decode(&req); err != nil {
			s.writeError(w, http.StatusBadRequest, fmt.Sprintf("invalid JSON: %v", err))
			return
		}
	}
	req.applyDefaults()
	if err := req.validate(); err != nil {
		s.writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	reg, err := s.getOrCreateJupyterRegistry()
	if err != nil {
		s.logger.Error(logging.DestinationHTTP, "jupyter registry init failed", "error", err)
		s.writeError(w, http.StatusInternalServerError, "registry unavailable")
		return
	}

	instID, token, err := reg.CreateInstance(jupytertunnel.CreateInstanceOptions{
		Owner: username,
		Meta: map[string]string{
			"image": req.Image,
		},
	})
	if err != nil {
		s.writeError(w, http.StatusInternalServerError, fmt.Sprintf("failed to create instance: %v", err))
		return
	}

	// Record the session before the job exists. A row with no job is
	// swept; a job with no row is a session nobody can ever re-adopt,
	// because the nonce it will present is only known here.
	if store := s.jupyterSessionStore(); store != nil {
		if nonce, ok := reg.PendingNonce(instID); ok {
			ttl := time.Duration(s.jupyterMaxLifetimeSec) * time.Second
			if ttl <= 0 {
				ttl = time.Duration(defaultJupyterSessionTTLSec) * time.Second
			}
			if err := store.Put(r.Context(), jupyterSessionRow{
				InstanceID: instID,
				Owner:      username,
				CreatedAt:  time.Now(),
				ExpiresAt:  time.Now().Add(ttl),
				NextNonce:  nonce,
			}); err != nil {
				// Not fatal: the session works, it just will not come
				// back after a restart. Better than refusing to start it.
				s.logger.Warn(logging.DestinationHTTP,
					"jupyter: could not record the session; it will not survive a restart",
					"instance", instID, "error", err)
			}
		}
	}

	// Resolve the upstream tunnel URL using the request's host. Production
	// deployments behind a reverse proxy should set X-Forwarded-Proto/Host
	// or rely on httpBaseURL (TODO: prefer httpBaseURL when set).
	upstream := buildJupyterTunnelURL(r, instID, s.httpBaseURL)
	proxyPath := fmt.Sprintf("/api/v1/jupyter/instances/%s/proxy/", instID)

	// If the API server has a TLS CA file configured (the demo's
	// auto-generated one, typically), ship it into the spool so the
	// helper can verify our wss:// upstream — the sandbox has no
	// system CAs that would cover a self-signed cert.
	var caCertBytes []byte
	if s.tlsCACertFile != "" {
		raw, readErr := os.ReadFile(s.tlsCACertFile) //nolint:gosec // operator-controlled path
		if readErr != nil {
			s.logger.Warn(logging.DestinationHTTP, "jupyter: could not read TLSCACertFile; helper will rely on system CAs",
				"path", s.tlsCACertFile, "error", readErr)
		} else {
			caCertBytes = raw
		}
	}

	// Generate the launcher script — keeps the messy quoting out of the
	// submit file's `arguments = ...` line and lets us put real bash
	// logic (conda fallback, daemonize-then-exec) in a single place.
	scriptArgs := jupyterLaunchScriptArgs{
		Universe:    universe,
		UpstreamURL: upstream,
		BaseURL:     proxyPath,
		AllowOrigin: buildAllowOrigin(r, s.httpBaseURL),
		CAFile:      "",
		// Auto-shutdown the helper if no traffic flows from the API
		// server for 30 minutes. Catches the failure mode where
		// jupyter-lab inside the sandbox failed at startup (e.g.
		// AF_UNIX path too long) but kept the slot held — without
		// this, the job would sit there until condor's own walltime
		// limit.
		//
		// This catches a CLOSED tab and nothing else. An open one
		// heartbeats its kernels every ~30s whether or not a human is
		// there, so traffic never stops and this timer never fires --
		// which is why an abandoned session could sit for hours. The
		// kernel-idle and lifetime limits below are what cover that.
		HelperIdleTimeoutSec: 30 * 60,
		// JupyterLab's own idleness, which it measures from kernel
		// execution rather than from HTTP traffic, so a tab polling in
		// the background does not look busy.
		KernelIdleTimeoutSec: s.jupyterKernelIdleSec,
	}
	if len(caCertBytes) > 0 {
		// The launcher passes this path (relative to the sandbox cwd)
		// to the helper's --ca-file flag.
		scriptArgs.CAFile = "ca.crt"
	}
	script := buildJupyterLaunchScript(scriptArgs)

	// Build the file list once and use it for both the submit file
	// and the in-memory FS so they can't drift. transfer_input_files
	// in the submit file is what the schedd actually ships to the
	// worker; staging a file in the FS without listing it here means
	// the worker never sees it (this was the ca.crt bug).
	transferInputFiles := []string{"htcondor-jupyter-helper", "jupyter-token"}
	if len(caCertBytes) > 0 {
		transferInputFiles = append(transferInputFiles, "ca.crt")
	}

	submitFile := buildJupyterSubmitFile(jupyterSubmitArgs{
		InstanceID:            instID,
		MaxLifetimeSec:        s.jupyterMaxLifetimeSec,
		Image:                 req.Image,
		Cpus:                  req.Cpus,
		MemoryMB:              req.MemoryMB,
		DiskMB:                req.DiskMB,
		Universe:              universe,
		HelperGOOS:            helperGOOS,
		HelperGOARCH:          runtimeGOARCH(),
		TransferInputFiles:    transferInputFiles,
		Gpus:                  req.Gpus,
		GpusMinimumCapability: req.GpusMinimumCapability,
		GpusMinimumMemory:     req.GpusMinimumMemory,
		GpusMinimumRuntime:    req.GpusMinimumRuntime,
		CudaVersion:           req.CudaVersion,
		RequireGpus:           req.RequireGpus,
		CallerSubmitLines:     req.SubmitLines,
		ExtraRequirements:     s.interactiveRequirements,
		ExtraSubmitLines:      s.interactiveExtraSubmit,
	})

	// Remote-submit + spool from an in-memory fs.FS. No on-disk state
	// to clean up if the request fails partway through.
	// Some access points hold every job submitted without particular OAuth
	// service credentials on file. Create them first, so a person using the
	// web UI does not get a held job for a reason unrelated to what they
	// asked for. Best effort: see ensureRequiredCredentials.
	s.ensureRequiredCredentials(ctx)

	clusterID, procAds, err := s.getSchedd().SubmitRemote(ctx, s.submitPolicy.Apply(submitFile))
	if err != nil {
		reg.CloseInstance(instID)
		s.logger.Error(logging.DestinationHTTP, "jupyter submit failed",
			"instance", instID, "owner", username, "error", err)
		s.writeError(w, http.StatusBadGateway, fmt.Sprintf("schedd submit failed: %v", err))
		return
	}

	stage := fstest.MapFS{
		"jupyter-launch.sh": &fstest.MapFile{
			Data: []byte(script),
			Mode: 0o755,
		},
		"htcondor-jupyter-helper": &fstest.MapFile{
			Data: helperBytes,
			Mode: 0o755,
		},
		"jupyter-token": &fstest.MapFile{
			Data: []byte(token),
			Mode: 0o600,
		},
	}
	if len(caCertBytes) > 0 {
		stage["ca.crt"] = &fstest.MapFile{
			Data: caCertBytes,
			Mode: 0o644,
		}
	}
	if err := s.getSchedd().SpoolJobFilesFromFS(ctx, procAds, stage); err != nil {
		// Submission succeeded but spooling failed; the jobs are stuck
		// in HELD with SpoolingInput. Best we can do is log and return
		// — the schedd will eventually time them out, and the user
		// can resubmit.
		reg.CloseInstance(instID)
		s.logger.Error(logging.DestinationHTTP, "jupyter spool failed",
			"instance", instID, "cluster", clusterID, "owner", username, "error", err)
		s.writeError(w, http.StatusBadGateway,
			fmt.Sprintf("schedd accepted the submit but spooling input files failed: %v", err))
		return
	}

	clusterIDStr := strconv.Itoa(clusterID)

	// Stash cluster id on the instance so callers (and SSE in Phase 3)
	// can correlate without holding the request open.
	if inst, ok := reg.Lookup(instID); ok {
		inst.Meta["cluster_id"] = clusterIDStr
	}

	s.logger.Info(logging.DestinationHTTP, "jupyter instance created",
		"instance", instID, "owner", username, "cluster", clusterIDStr,
		"universe", universe, "helper_goos", helperGOOS, "image", req.Image)

	s.writeJSON(w, http.StatusCreated, JupyterCreateResponse{
		InstanceID: instID,
		ClusterID:  clusterIDStr,
		ProxyPath:  proxyPath,
	})
}

func (req *JupyterCreateRequest) applyDefaults() {
	if req.Image == "" {
		req.Image = "quay.io/jupyter/scipy-notebook:latest"
	}
	if req.Cpus == 0 {
		req.Cpus = 2
	}
	if req.MemoryMB == 0 {
		req.MemoryMB = 4096
	}
	if req.DiskMB == 0 {
		req.DiskMB = 4096
	}
}

func (req *JupyterCreateRequest) validate() error {
	if req.Cpus < 1 || req.Cpus > 64 {
		return fmt.Errorf("cpus must be between 1 and 64, got %d", req.Cpus)
	}
	if req.MemoryMB < 256 || req.MemoryMB > 256*1024 {
		return fmt.Errorf("memory_mb must be between 256 and %d, got %d", 256*1024, req.MemoryMB)
	}
	if req.DiskMB < 256 || req.DiskMB > 1024*1024 {
		return fmt.Errorf("disk_mb must be between 256 and %d, got %d", 1024*1024, req.DiskMB)
	}
	if req.Gpus < 0 || req.Gpus > 16 {
		return fmt.Errorf("gpus must be between 0 and 16, got %d", req.Gpus)
	}
	// Light validation of image: no whitespace, no newlines (we paste it
	// verbatim into the submit file).
	if strings.ContainsAny(req.Image, " \t\r\n") {
		return fmt.Errorf("image contains whitespace")
	}
	// GPU submit strings need the same character whitelist applied
	// to the InteractiveCreateTerminalRequest path — both flow
	// into resourceRequestLines and would otherwise let a request
	// inject extra submit directives via embedded newlines.
	if err := validateGPUSubmitFields(req.GpusMinimumCapability, req.GpusMinimumRuntime, req.CudaVersion, req.RequireGpus); err != nil {
		return err
	}
	if err := interactive.ValidateCallerSubmitLines(req.SubmitLines); err != nil {
		return fmt.Errorf("submit_lines: %w", err)
	}
	return nil
}

// jupyterUniverseForGOOS picks the HTCondor universe a JupyterLab job
// should run in based on the API server's runtime GOOS. macOS lacks
// Docker universe support, so we silently fall back to vanilla there
// and rely on the launcher script's conda/pip path to provision an
// environment on the fly. Linux gets the standard Docker universe path.
func jupyterUniverseForGOOS(goos string) string {
	if goos == "darwin" {
		return "vanilla"
	}
	// Container universe rather than docker: it also matches execute
	// nodes that provide Apptainer/Singularity instead of Docker (the
	// requirements the submit parser emits for container_image are
	// HasDocker || HasSingularity || HasApptainer), which is the common
	// case on the OSPool.
	return "container"
}

// jupyterContainerImageRef renders an image for a container-universe
// container_image line. HTCondor's image_type_from_string treats a bare
// string as a sandbox directory unless it begins with a scheme
// (docker:/oras:) or ends in .sif; a Docker/quay repo image therefore
// has to be spelled docker://<image> to be pulled (by Docker or, on the
// OSPool, Apptainer). Anything already carrying a scheme, or a .sif /
// sandbox path, is passed through untouched.
func jupyterContainerImageRef(image string) string {
	img := strings.TrimSpace(image)
	switch {
	case strings.HasPrefix(img, "docker:"), strings.HasPrefix(img, "oras:"),
		strings.HasSuffix(img, ".sif"), strings.HasSuffix(img, "/"):
		return img
	default:
		return "docker://" + img
	}
}

// jupyterHelperGOOSForUniverse maps "vanilla"/"container" to the GOOS the
// helper binary needs to be built for. Container jobs always run inside a
// linux container; vanilla jobs run on the bare execute node, which on
// macOS pools means darwin. (On Linux pools we currently never fall
// back to vanilla, but if we ever do, the linux helper still applies.)
func jupyterHelperGOOSForUniverse(universe string) string {
	if universe == "vanilla" && runtimeGOOS() == "darwin" {
		return "darwin"
	}
	return "linux"
}

// jupyterSubmitArgs holds everything buildJupyterSubmitFile templates in.
type jupyterSubmitArgs struct {
	InstanceID   string
	Image        string // only used in container/docker universe
	Cpus         int
	MemoryMB     int
	DiskMB       int
	Universe     string // "docker" or "vanilla"
	HelperGOOS   string // "linux" or "darwin"; drives the requirements expr
	HelperGOARCH string // GOARCH; drives the Arch== requirement

	// GPU fields. Gpus == 0 omits the GPU section entirely.
	Gpus                  int
	GpusMinimumCapability string
	GpusMinimumMemory     int
	GpusMinimumRuntime    string
	CudaVersion           string
	RequireGpus           string

	// CallerSubmitLines are the user's own submit commands from the
	// launch form, merged in before the operator's block (so operator
	// policy still wins). Validated with ValidateCallerSubmitLines.
	CallerSubmitLines string

	// ExtraRequirements is an operator ClassAd expression ANDed into the
	// job's requirements (Handler.interactiveRequirements /
	// HTTP_API_INTERACTIVE_REQUIREMENTS), matching the interactive
	// terminal path. Empty adds nothing.
	ExtraRequirements string

	// ExtraSubmitLines is operator-supplied submit-file content
	// merged in just before the `queue` directive. Same source as
	// the interactive-terminal builder: Handler.interactiveExtraSubmit.
	ExtraSubmitLines string

	// TransferInputFiles is the list of files (in addition to the
	// executable) the schedd should ship from the spool to the worker.
	// Always includes the helper binary and token; conditionally
	// includes ca.crt when the API server has a TLS CA configured.
	// Must stay in lockstep with the in-memory FS the caller passes
	// to SpoolJobFilesFromFS — listing a file here that's not in the
	// FS makes the spool fail; staging a file in the FS that's not
	// here means it never reaches the worker.
	TransferInputFiles []string

	// MaxLifetimeSec, when > 0, is the wall-clock ceiling on the
	// session, enforced by the schedd rather than by anything inside
	// the sandbox. See jupyterPeriodicRemove.
	MaxLifetimeSec int
}

// buildJupyterSubmitFile produces the HTCondor submit file for a Jupyter
// instance. The actual command-line plumbing lives in the launcher
// script (see buildJupyterLaunchScript); this just declares resources,
// transfer rules, and the requirements expression.
func buildJupyterSubmitFile(a jupyterSubmitArgs) string {
	var sb strings.Builder
	fmt.Fprintf(&sb, "# Auto-generated by htcondor-api for Jupyter instance %s\n", a.InstanceID)

	switch a.Universe {
	case "container":
		fmt.Fprintf(&sb, "universe = container\n")
		// container_image needs an explicit scheme for a repo image, or
		// HTCondor classifies a bare "repo:tag" as a sandbox directory
		// (image_type_from_string). docker:// makes it a docker-repo
		// image, which Apptainer/Singularity can also pull.
		fmt.Fprintf(&sb, "container_image = %s\n\n", jupyterContainerImageRef(a.Image))
	case "docker":
		fmt.Fprintf(&sb, "universe = docker\n")
		fmt.Fprintf(&sb, "docker_image = %s\n", a.Image)
		fmt.Fprintf(&sb, "docker_pull_policy = missing\n\n")
	default:
		// Vanilla: the launcher script is responsible for provisioning
		// jupyter (conda or python -m venv).
		fmt.Fprintf(&sb, "universe = vanilla\n\n")
	}

	// The launcher script is the executable. transfer_executable=true
	// causes the schedd to pull it from the spool (where we put it via
	// SpoolJobFilesFromFS), so we never reference the API-server-local
	// path directly.
	fmt.Fprintf(&sb, "executable = jupyter-launch.sh\n")
	fmt.Fprintf(&sb, "transfer_executable = true\n\n")

	fmt.Fprintf(&sb, "should_transfer_files = YES\n")
	fmt.Fprintf(&sb, "when_to_transfer_output = ON_EXIT\n")
	inputs := a.TransferInputFiles
	if len(inputs) == 0 {
		// Backwards-compatible default for any caller that hasn't
		// migrated to the explicit TransferInputFiles slice.
		inputs = []string{"htcondor-jupyter-helper", "jupyter-token"}
	}
	fmt.Fprintf(&sb, "transfer_input_files = %s\n\n", strings.Join(inputs, ", "))

	sb.WriteString(resourceRequestLines(
		a.Cpus, a.MemoryMB, a.DiskMB,
		a.Gpus, a.GpusMinimumCapability, a.GpusMinimumMemory,
		a.GpusMinimumRuntime, a.CudaVersion, a.RequireGpus,
	))

	req := jupyterRequirementsExpr(a.HelperGOOS, a.HelperGOARCH)
	if extra := strings.TrimSpace(a.ExtraRequirements); extra != "" {
		// AND the operator's interactive-requirements expression, matching
		// the SSH-terminal path (HTTP_API_INTERACTIVE_REQUIREMENTS).
		req = fmt.Sprintf("(%s) && (%s)", req, extra)
	}
	fmt.Fprintf(&sb, "requirements = %s\n\n", req)

	// Name the batch so the jobs page and condor_q -batch say what this
	// job is. Without it a JupyterLab session shows up as a bare
	// jupyter-launch.sh among the user's real work, which is what made
	// them look strange.
	fmt.Fprintf(&sb, "batch_name = %s\n", jupyterBatchName(a.InstanceID))

	// A ceiling the sandbox cannot talk its way out of.
	//
	// The helper's idle timer measures traffic through the tunnel, and a
	// JupyterLab tab left open in a browser generates traffic forever --
	// it heartbeats its kernels every ~30s whether or not a human is
	// there. So the idle timer reaps a closed tab and never reaps an
	// abandoned one, which is how a session survives for hours with
	// nobody at it.
	//
	// periodic_remove is evaluated by the schedd, so it holds whatever
	// the sandbox, the helper or the browser are doing.
	if expr := jupyterPeriodicRemove(a.MaxLifetimeSec); expr != "" {
		fmt.Fprintf(&sb, "%s\n", expr)
	}

	fmt.Fprintf(&sb, "log    = jupyter.log\n")
	fmt.Fprintf(&sb, "output = jupyter.out\n")
	fmt.Fprintf(&sb, "error  = jupyter.err\n")

	// The user's own submit commands, then the operator's extras last so
	// operator policy overrides both the builder and the user. Same
	// precedence and validation as the interactive-terminal builder.
	interactive.AppendCallerSubmitLines(&sb, a.CallerSubmitLines)
	appendExtraSubmitLines(&sb, a.ExtraSubmitLines)

	fmt.Fprintf(&sb, "queue\n")
	return sb.String()
}

// jupyterRequirementsExpr builds the HTCondor `requirements = ...`
// expression for the given target GOOS/GOARCH. Choices reflect what
// HTCondor actually reports in slot ads:
//
//   - GOARCH=amd64 → Arch == "X86_64"  (universal)
//   - GOARCH=arm64 → Arch == "arm64" (macOS) || Arch == "AARCH64" (linux)
//   - GOOS=darwin  → also pin OpSys == "macOS" since the helper is darwin-only
//   - GOOS=linux   → no OpSys pin: docker handles the OS layer for us.
func jupyterRequirementsExpr(goos, goarch string) string {
	var arch string
	switch goarch {
	case "amd64":
		arch = `Arch == "X86_64"`
	case "arm64":
		// HTCondor on macOS reports lower-case "arm64"; on Linux it
		// reports "AARCH64". A single arm64 build runs on both, so
		// match either.
		arch = `(Arch == "arm64" || Arch == "AARCH64")`
	default:
		arch = fmt.Sprintf(`Arch == %q`, strings.ToUpper(goarch))
	}
	if goos == "darwin" {
		// HTCondor reports OpSys = "macOS" on Apple-silicon and Intel
		// Macs alike. The older "OSX" name shows up in the docs but
		// the schedd's actual ad uses "macOS"; pinning to OSX would
		// match no slots.
		return fmt.Sprintf(`(OpSys == "macOS") && (%s)`, arch)
	}
	return fmt.Sprintf(`(%s)`, arch)
}

// defaultJupyterSessionTTLSec bounds a stored session where the operator
// turned the job ceiling off. The row still has to expire: it is what the
// sweeper deletes on, and without a horizon the credential store grows for
// the life of the deployment.
const defaultJupyterSessionTTLSec = 24 * 60 * 60

// jupyterBatchPrefix marks a job as a JupyterLab session by
// JobBatchName. Also the beginning of putting the session's identity
// where it survives this process: the queue, rather than only the
// in-memory tunnel registry.
const jupyterBatchPrefix = "htcondor-api-jupyter-"

// jupyterBatchName names the batch after the instance it serves. The id
// is trimmed because a batch name is read at a glance in a queue
// listing, and the full hex is not.
func jupyterBatchName(instanceID string) string {
	short := instanceID
	if len(short) > 12 {
		short = short[:12]
	}
	if short == "" {
		return strings.TrimSuffix(jupyterBatchPrefix, "-")
	}
	return jupyterBatchPrefix + short
}

// jupyterPeriodicRemove is the schedd-side ceiling on a session.
//
// Measured from JobStartDate rather than QDate: the ceiling is on how
// long a session runs, and time spent idle in the queue waiting for a
// slot is not the user's session. Guarded on JobStartDate being set,
// because the expression is evaluated for a job that has not started
// and "time() - undefined" is undefined, not false.
//
// Returns "" for a non-positive limit, which is how an operator turns
// the ceiling off.
func jupyterPeriodicRemove(maxLifetimeSec int) string {
	if maxLifetimeSec <= 0 {
		return ""
	}
	return fmt.Sprintf(
		"periodic_remove = (JobStatus == 2) && (JobStartDate =!= UNDEFINED) && ((time() - JobStartDate) > %d)",
		maxLifetimeSec)
}

// jupyterIdleFlags are the JupyterLab options that make an abandoned
// session shut itself down.
//
// cull_connected is the load-bearing one. A tab left open holds a
// connection to its kernel, and culling skips connected kernels by
// default -- so without it the one case this is meant to catch, a
// browser nobody is sitting at, is exactly the case that survives.
//
// Culling turns on kernel idleness, which JupyterLab measures from
// execution state rather than from HTTP traffic, so the tab's own
// polling does not keep it alive. shutdown_no_activity_timeout then
// ends the server once the last kernel has gone.
func jupyterIdleFlags(idleSec int) string {
	if idleSec <= 0 {
		return ""
	}
	interval := idleSec / 4
	if interval < 60 {
		interval = 60
	}
	return fmt.Sprintf(` \
    --MappingKernelManager.cull_idle_timeout=%d \
    --MappingKernelManager.cull_interval=%d \
    --MappingKernelManager.cull_connected=True \
    --ServerApp.shutdown_no_activity_timeout=%d`, idleSec, interval, idleSec)
}

// runtimeGOARCH / runtimeGOOS are broken out so a test can override
// them. We use atomic.Value rather than reading runtime.* directly so
// the override path is race-safe.
var (
	goarchOverride atomic.Value
	goosOverride   atomic.Value
)

func runtimeGOARCH() string {
	if v, ok := goarchOverride.Load().(string); ok && v != "" {
		return v
	}
	return runtime.GOARCH
}

func runtimeGOOS() string {
	if v, ok := goosOverride.Load().(string); ok && v != "" {
		return v
	}
	return runtime.GOOS
}

// jupyterLaunchScriptArgs configures buildJupyterLaunchScript. The
// values land in a generated shell script that runs as the job's
// executable on the execute node.
type jupyterLaunchScriptArgs struct {
	Universe    string // "docker" or "vanilla"
	UpstreamURL string // wss://.../api/v1/jupyter/instances/<id>/tunnel
	BaseURL     string // ProxyPrefix; passed to jupyter --ServerApp.base_url
	AllowOrigin string // ServerApp.allow_origin (browser origin embedding the iframe)
	// CAFile, when non-empty, is the basename of a PEM CA bundle in
	// the sandbox the helper should pass to --ca-file. Set when the
	// API server is configured with TLSCACertFile (e.g. the demo's
	// auto-generated CA). Empty = rely on the sandbox's system CAs.
	CAFile string
	// KernelIdleTimeoutSec, when > 0, culls a kernel that has not
	// executed anything for that long and shuts the server down once no
	// kernels remain. See jupyterIdleFlags.
	KernelIdleTimeoutSec int

	// HelperIdleTimeoutSec, when > 0, makes the helper close the
	// tunnel (and exit) when no yamux stream has been accepted from
	// the API server within that many seconds. Used as an
	// auto-shutdown for jupyter-lab failures: if the user never opens
	// the iframe — or the iframe loads against a broken jupyter and
	// stops retrying — the helper times out and ends the job instead
	// of holding the slot indefinitely.
	//
	// "Ends the job" is now true. The helper is setsid'd and JupyterLab
	// is the exec'd main process, so the helper exiting used to free
	// nothing: the tunnel went and the slot stayed. It now signals the
	// job's process group. See endsession.go in the helper.
	HelperIdleTimeoutSec int
}

// buildJupyterLaunchScript writes a small bash script that:
//
//  1. (vanilla universe only) finds or builds a python env with jupyter:
//     - if `jupyter` is already on PATH, just use it;
//     - else if `conda` is available, `conda create -y -p ./jupyter-env`
//     and activate it;
//     - else fall back to `python3 -m venv ./jupyter-env` + pip install.
//  2. Runs the tunnel helper with --daemonize so it double-forks and
//     exits 0, leaving the tunnel running in the background.
//  3. exec's `jupyter lab` against a UDS at $(pwd)/jupyter.sock with
//     auth disabled — the websocket tunnel does the auth, the UDS keeps
//     peer-on-host attackers off.
//
// All quoting is done with normal POSIX rules; no HTCondor-specific
// `""` escaping needed because this lives in its own file.
func buildJupyterLaunchScript(a jupyterLaunchScriptArgs) string {
	var setup string
	if a.Universe == "vanilla" {
		// Packages we want in the on-the-fly env:
		//   - jupyterlab            : the user-facing IDE
		//   - jupyterlab-lsp        : language-server framework JL ships
		//   - python-lsp-server     : the actual Python LSP backend
		//                             (without it JL logs "Skipped non-installed
		//                             server(s): python-lsp-server, ..." and
		//                             code completion / hover don't work)
		// We deliberately skip language servers that need a separate
		// runtime (bash-language-server pulls npm; r-languageserver
		// needs R; etc.). Python is enough for "simple editing" per
		// the user's ask.
		setup = `
# Vanilla universe: provision an environment on the fly. We try, in
# order, jupyter-on-PATH (some pools pre-install it), conda (richest
# fallback), then plain python3 + venv. The created env lives in the
# sandbox and is reaped with the job.
if ! command -v jupyter >/dev/null 2>&1; then
    if command -v conda >/dev/null 2>&1; then
        echo "[jupyter-launch] using conda to create ./jupyter-env"
        conda create -y -p ./jupyter-env python=3.11 jupyterlab jupyterlab-lsp python-lsp-server >&2
        # shellcheck disable=SC1091
        source "$(conda info --base)/etc/profile.d/conda.sh"
        conda activate ./jupyter-env
    elif command -v python3 >/dev/null 2>&1; then
        echo "[jupyter-launch] using python3 -m venv at ./jupyter-env"
        python3 -m venv ./jupyter-env
        # shellcheck disable=SC1091
        source ./jupyter-env/bin/activate
        pip install --quiet --disable-pip-version-check \
            jupyterlab jupyterlab-lsp 'python-lsp-server[all]' >&2
    else
        echo "[jupyter-launch] neither jupyter, conda, nor python3 found on this execute node" >&2
        exit 1
    fi
fi
`
	}

	caFlag := ""
	if a.CAFile != "" {
		// Quoted with %q at format-time to keep the script literal-
		// safe regardless of what's in CAFile.
		caFlag = fmt.Sprintf(" \\\n    --ca-file %q", a.CAFile)
	}

	// AF_UNIX path-length cap is 104 on macOS, 108 on Linux. The
	// HTCondor scratch dir on macOS is something like
	// /private/var/folders/.../execute/dir_NNN/scratch/, which already
	// blows past that; appending "/jupyter.sock" pushed us over. Make
	// a fresh secure dir under /tmp (mktemp -d gives us mode 700) and
	// put the socket there. trap cleans it up regardless of how the
	// script exits.
	//
	// The same socket path is shared between jupyter-lab (which
	// creates the UDS) and the helper (which dials it on demand for
	// each yamux stream). Stage 1 of the helper already pre-flighted
	// the upstream TLS handshake and returned non-zero on failure;
	// if the daemonize line below succeeds we know the WS leg is
	// healthy.
	idleFlag := ""
	if a.HelperIdleTimeoutSec > 0 {
		idleFlag = fmt.Sprintf(" \\\n    --idle-timeout %ds", a.HelperIdleTimeoutSec)
	}

	return fmt.Sprintf(`#!/usr/bin/env bash
# Auto-generated by htcondor-api. See buildJupyterLaunchScript.
set -euo pipefail
%s
# Use /tmp for the UDS — the HTCondor scratch path on macOS exceeds
# the AF_UNIX 104-byte limit. mktemp -d gives us a unique mode-700
# directory; the trap cleans it up whether we exit normally or via
# signal, so the socket doesn't outlive the job.
#
# The template is spelled out rather than passed to -t: GNU mktemp
# requires at least three trailing X's and rejects a bare prefix
# ("too few X's in template"), while BSD mktemp accepts one. -t took
# the BSD reading, so this worked on a developer's Mac and failed on
# every Linux execute node. /tmp is named explicitly for the same
# reason the directory exists at all -- $TMPDIR on an execute node is
# the job scratch, which is the long path being avoided.
SOCK_DIR="$(mktemp -d /tmp/htcondor-jupyter.XXXXXX)"
trap 'rm -rf "$SOCK_DIR"' EXIT INT TERM
SOCK="$SOCK_DIR/j.sock"

# Daemonize the reverse-tunnel helper. It double-forks and exits 0;
# the tunnel keeps running in the background, picking up requests
# from the API server over the websocket. A non-zero exit here means
# stage 1's TLS pre-flight failed, so the wrapper bails out under
# set -e.
chmod +x ./htcondor-jupyter-helper
./htcondor-jupyter-helper \
    --upstream %q \
    --token-file ./jupyter-token \
    --socket "$SOCK" \
    --daemonize%s%s

# Resolve how to launch JupyterLab. In the vanilla path the setup above
# activated an env that puts jupyter on PATH. In a container the image
# provides it -- but under Apptainer the image ENTRYPOINT that would
# activate the image's environment (conda, on the jupyter/docker-stacks
# images) is not run, and /opt/conda/bin is not on the default PATH, so a
# bare "jupyter" is not found. Add the common conda/venv locations, then
# fall back to "python -m jupyterlab", before giving a clear error rather
# than the cryptic "exec: jupyter: not found".
if ! command -v jupyter >/dev/null 2>&1; then
    for d in /opt/conda/bin /opt/conda/condabin /srv/conda/bin /usr/local/bin /opt/conda/envs/*/bin; do
        if [ -x "$d/jupyter" ]; then PATH="$d:$PATH"; export PATH; break; fi
    done
fi
if command -v jupyter >/dev/null 2>&1; then
    set -- jupyter lab
elif command -v python3 >/dev/null 2>&1 && python3 -c 'import jupyterlab' >/dev/null 2>&1; then
    set -- python3 -m jupyterlab
elif command -v python >/dev/null 2>&1 && python -c 'import jupyterlab' >/dev/null 2>&1; then
    set -- python -m jupyterlab
else
    # Not found. Dump what we can see so the failure is diagnosable: most
    # importantly whether we are actually inside the container image at
    # all (a bare-node run has no /opt/conda and no *_CONTAINER var) or in
    # a container whose jupyter lives somewhere unexpected. errexit is off
    # here since we exit 127 regardless.
    set +e
    {
        echo "[jupyter-launch] JupyterLab not found in this environment."
        echo "[jupyter-launch] The image must provide 'jupyter' on PATH (e.g. /opt/conda/bin) or an importable 'jupyterlab' module."
        echo "[jupyter-launch] --- diagnostics ---"
        echo "[jupyter-launch] user=$(id -un 2>/dev/null || echo '?') cwd=$(pwd)"
        echo "[jupyter-launch] container=${APPTAINER_CONTAINER:-${SINGULARITY_CONTAINER:-none}}"
        echo "[jupyter-launch] os=$(. /etc/os-release 2>/dev/null; echo "${PRETTY_NAME:-unknown}") uname=$(uname -sm 2>/dev/null)"
        echo "[jupyter-launch] PATH=$PATH"
        echo "[jupyter-launch] python3=$(command -v python3 2>/dev/null || echo none) python=$(command -v python 2>/dev/null || echo none)"
        echo "[jupyter-launch] /opt/conda/bin: $(ls -1 /opt/conda/bin 2>&1 | head -n 8 | tr '\n' ' ')"
    } >&2
    exit 127
fi

# Run jupyter-lab against the same UDS. Jupyter creates the UDS at
# startup; the helper dials it on demand for each yamux stream the
# API server opens. Auth is disabled here because the websocket
# tunnel already enforced it; the UDS keeps any other user on this
# execute node off our notebooks.
exec "$@" \
    --ServerApp.sock="$SOCK" \
    --ServerApp.token='' \
    --ServerApp.password='' \
    --ServerApp.base_url=%q \
    --ServerApp.allow_origin=%q \
    --ServerApp.disable_check_xsrf=True \
    --ServerApp.allow_remote_access=True%s
`, setup, a.UpstreamURL, caFlag, idleFlag, a.BaseURL, a.AllowOrigin,
		jupyterIdleFlags(a.KernelIdleTimeoutSec))
}

// buildJupyterTunnelURL derives the wss://.../tunnel URL the helper should
// dial. Prefers the configured HTTPBaseURL; falls back to the request's host
// + scheme. WS scheme is mapped from HTTP/HTTPS.
func buildJupyterTunnelURL(r *http.Request, instanceID, baseURL string) string {
	scheme := "ws"
	host := r.Host
	if baseURL != "" {
		if u, err := url.Parse(baseURL); err == nil && u.Host != "" {
			host = u.Host
			if u.Scheme == "https" {
				scheme = "wss"
			}
		}
	}
	if r.TLS != nil && baseURL == "" {
		scheme = "wss"
	}
	return fmt.Sprintf("%s://%s/api/v1/jupyter/instances/%s/tunnel", scheme, host, instanceID)
}

// buildAllowOrigin returns the origin string Jupyter should accept. Prefers
// the configured HTTPBaseURL's origin.
func buildAllowOrigin(r *http.Request, baseURL string) string {
	if baseURL != "" {
		if u, err := url.Parse(baseURL); err == nil && u.Host != "" {
			return u.Scheme + "://" + u.Host
		}
	}
	scheme := "http"
	if r.TLS != nil {
		scheme = "https"
	}
	return scheme + "://" + r.Host
}

// handleJupyterTunnel accepts the helper's outbound websocket connect-back.
// Bearer-token authenticated against the registry; the URL's instance id
// must match the token's instance id.
func (s *Handler) handleJupyterTunnel(w http.ResponseWriter, r *http.Request, id string) {
	if r.Method != http.MethodGet {
		s.writeError(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}

	bearer := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
	if bearer == "" {
		s.writeError(w, http.StatusUnauthorized, "missing Authorization: Bearer token")
		return
	}

	reg, err := s.getOrCreateJupyterRegistry()
	if err != nil {
		s.logger.Error(logging.DestinationHTTP, "jupyter registry init failed", "error", err)
		s.writeError(w, http.StatusInternalServerError, "registry unavailable")
		return
	}

	// Upgrade first; if AcceptTunnel rejects we still need a websocket
	// channel to send a CLOSE frame so the helper sees a clean refusal
	// instead of a transport error.
	upgrader := s.jupyterUpgrader()
	ws, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		// Upgrader already wrote the HTTP error.
		return
	}

	inst, err := reg.AcceptTunnel(id, bearer, ws)
	if err != nil {
		s.logger.Warn(logging.DestinationHTTP, "jupyter tunnel rejected",
			"instance", id, "error", err)
		_ = ws.WriteMessage(websocket.CloseMessage,
			websocket.FormatCloseMessage(websocket.ClosePolicyViolation, "tunnel auth failed"))
		_ = ws.Close()
		return
	}

	s.logger.Info(logging.DestinationHTTP, "jupyter tunnel up", "instance", id, "owner", inst.Owner)

	// Hand the helper the token for its next dial. Best-effort: this
	// session is up and refusing it over a token the helper will not need
	// until the next reconnect would turn a future inconvenience into a
	// present outage. It is logged because a session that cannot come
	// back is worth knowing about before the restart that proves it.
	if next := inst.NextToken(); next != "" {
		if err := jupytertunnel.SendNextToken(inst, next); err != nil {
			s.logger.Warn(logging.DestinationHTTP,
				"jupyter: could not hand the helper its next token; this session will not survive a restart",
				"instance", id, "error", err)
		}
	}
	// Hold the upgraded request open until the tunnel closes; otherwise
	// the http server tears down the underlying TCP and yamux dies.
	inst.Wait()
	s.logger.Info(logging.DestinationHTTP, "jupyter tunnel down", "instance", id)
}

// handleJupyterProxy serves browser HTTP requests through the tunnel. The
// URL prefix /api/v1/jupyter/instances/{id}/proxy is stripped before the
// request is forwarded; what's left becomes the upstream path Jupyter sees.
func (s *Handler) handleJupyterProxy(w http.ResponseWriter, r *http.Request, id, upstreamPath string) {
	// Authenticate the caller. Same pattern as the rest of the API.
	ctx, needsRedirect, err := s.requireAuthentication(r)
	if err != nil {
		if needsRedirect {
			s.redirectToLogin(w, r)
			return
		}
		s.writeError(w, http.StatusUnauthorized, fmt.Sprintf("Authentication failed: %v", err))
		return
	}
	username := htcondor.GetAuthenticatedUserFromContext(ctx)

	reg, err := s.getOrCreateJupyterRegistry()
	if err != nil {
		s.writeError(w, http.StatusInternalServerError, "registry unavailable")
		return
	}
	inst, ok := reg.Lookup(id)
	if !ok {
		s.writeError(w, http.StatusNotFound, "no such Jupyter instance (or it is not yet connected)")
		return
	}
	if inst.Owner != username {
		// We do NOT leak instance existence to non-owners; this is the same
		// as a 404 from their perspective.
		s.writeError(w, http.StatusNotFound, "no such Jupyter instance")
		return
	}

	reg.Proxy(inst, upstreamPath, w, r)
}
