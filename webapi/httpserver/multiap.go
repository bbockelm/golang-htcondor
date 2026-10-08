package httpserver

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"github.com/PelicanPlatform/classad/dbrpc"

	htcondor "github.com/bbockelm/golang-htcondor"
	"github.com/bbockelm/golang-htcondor/jobid"
	"github.com/bbockelm/golang-htcondor/logging"
	"github.com/bbockelm/golang-htcondor/webapi/apregistry"
	"github.com/bbockelm/golang-htcondor/webapi/dbmirror"
	"github.com/bbockelm/golang-htcondor/webapi/multiap"
)

// Multi-AP mode: one API server in front of every access point whose
// schedd ad matches HTTP_API_SCHEDD_CONSTRAINT.
//
// This is the read-only first step. Reads of the caller's own jobs and
// history are served from the federation hub; everything else -- every
// action, submit, credentials, watches, the SSH gateway -- answers 501
// until it has been taught which AP it is about. The refusal is an
// ALLOWLIST (multiAPAllowed): a route nobody has looked at is refused,
// not served against whichever schedd happens to be handy. There is no
// such schedd: Handler.schedd is nil in this mode, and getSchedd counts
// and logs any call that reaches it.

// MultiAPConfig configures multi-AP mode. ScheddConstraint set enables it.
type MultiAPConfig struct {
	// ScheddConstraint is HTTP_API_SCHEDD_CONSTRAINT: the AP set, over
	// ScheddAds.
	ScheddConstraint string
	// HubName and HubAddress are HTTP_API_HUB_NAME / _ADDRESS: pin the
	// federation hub instead of discovering the HTCondorDB ad that
	// carries FederationConstraint.
	HubName    string
	HubAddress string
	// Stale is HTTP_API_MULTI_AP_STALE: include (default) or exclude a
	// degraded AP's rows from unscoped reads.
	Stale string
	// JobIDCodec is HTTP_API_JOB_ID_CODEC; empty selects jobid's default.
	JobIDCodec string

	// service replaces the hub, registry and spokes built from the
	// collector. Tests only.
	service *multiap.Service
	// registry is the registry behind service, for the readiness and AP
	// endpoints. Tests only.
	registry *apregistry.Registry
}

// Enabled reports whether multi-AP mode is configured.
func (c MultiAPConfig) Enabled() bool {
	return strings.TrimSpace(c.ScheddConstraint) != "" || c.service != nil
}

// multiAPMode is the multi-AP state a Handler holds.
type multiAPMode struct {
	svc        *multiap.Service
	registry   *apregistry.Registry // nil in tests that supply a service
	hubLoc     *dbmirror.Locator    // nil in tests
	spokeLoc   *dbmirror.Locator    // nil in tests
	constraint string
	codec      jobid.Codec
	// scheddCalls counts calls to the single-schedd accessor, which has
	// no answer in this mode. Any non-zero value is a route or background
	// task that escaped the allowlist.
	scheddCalls atomic.Int64
}

func newMultiAPMode(cfg HandlerConfig, logger *logging.Logger) (*multiAPMode, error) {
	mc := cfg.MultiAP
	if cfg.ScheddName != "" || cfg.ScheddAddr != "" {
		return nil, errors.New("HTTP_API_SCHEDD_CONSTRAINT selects multi-AP mode and cannot be combined with a single schedd " +
			"(-schedd, -schedd-addr or SCHEDD_NAME); unset one of them")
	}
	if strings.TrimSpace(cfg.UIDDomain) == "" {
		return nil, errors.New("multi-AP mode needs UID_DOMAIN: jobs are matched to their owner on the User attribute, owner@UID_DOMAIN")
	}
	codec, err := jobid.Lookup(mc.JobIDCodec)
	if err != nil {
		return nil, fmt.Errorf("HTTP_API_JOB_ID_CODEC: %w", err)
	}
	stale, err := multiap.ParseStaleMode(mc.Stale)
	if err != nil {
		return nil, err
	}
	m := &multiAPMode{constraint: strings.TrimSpace(mc.ScheddConstraint), codec: codec}
	if mc.service != nil {
		m.svc, m.registry = mc.service, mc.registry
		if m.svc.Codec == nil {
			m.svc.Codec = codec
		}
		return m, nil
	}
	if cfg.Collector == nil {
		return nil, errors.New("multi-AP mode needs a collector (COLLECTOR_HOST) to find the access points")
	}
	if cfg.HTCondorConfig == nil {
		return nil, errors.New("multi-AP mode needs the HTCondor configuration to authenticate to the federation hub")
	}
	reg, err := apregistry.New(cfg.Collector, m.constraint, apregistry.Options{})
	if err != nil {
		return nil, err
	}
	hubOpts := dbmirror.Options{Name: mc.HubName, Address: mc.HubAddress}
	if mc.HubName == "" {
		hubOpts.Constraint = dbmirror.HubConstraint
	}
	// The database on this host is a spoke, not the hub, unless the
	// operator pinned the hub's address -- then asking that address
	// directly is the right fallback.
	hubOpts.NoLocalFallback = mc.HubAddress == ""
	m.hubLoc = dbmirror.NewLocatorWithOptions(cfg.Collector, cfg.HTCondorConfig, hubOpts)
	m.spokeLoc = dbmirror.NewLocatorWithOptions(cfg.Collector, cfg.HTCondorConfig, dbmirror.Options{})
	hubLoc := m.hubLoc
	m.registry = reg
	m.svc = &multiap.Service{
		Registry: reg,
		Hub: multiap.NewHub(func(ctx context.Context) (*dbrpc.Client, func(), error) {
			c, closer, _, err := hubLoc.Client(ctx)
			return c, closer, err
		}, 0),
		Spokes:    m.spokeLoc,
		Codec:     codec,
		Stale:     stale,
		UIDDomain: cfg.UIDDomain,
	}
	logger.Info(logging.DestinationHTTP, "Multi-AP mode enabled",
		"schedd_constraint", m.constraint, "hub_name", mc.HubName, "hub_address", mc.HubAddress,
		"stale", string(stale), "job_id_codec", strings.ToLower(strings.TrimSpace(mc.JobIDCodec)))
	return m, nil
}

// setTokenSource gives the hub and spoke connections the IDTOKEN the
// single-AP mirror would use.
func (m *multiAPMode) setTokenSource(src func(ctx context.Context) (string, error)) {
	if m == nil || src == nil {
		return
	}
	if m.hubLoc != nil {
		m.hubLoc.SetTokenSource(src)
	}
	if m.spokeLoc != nil {
		m.spokeLoc.SetTokenSource(src)
	}
}

// singleAPMirror is the single-AP mirror locator. In multi-AP mode it is
// a disabled locator: the hub and the spokes replace it, and the
// single-mirror paths that consult it are not reachable.
func singleAPMirror(cfg HandlerConfig, schedd *htcondor.Schedd) *dbmirror.Locator {
	if schedd == nil {
		return dbmirror.NewLocator(nil, nil)
	}
	return dbmirror.NewLocatorWithOptions(cfg.Collector, cfg.HTCondorConfig, dbmirror.Options{
		Name:     cfg.DBMirrorName,
		Address:  cfg.DBMirrorAddress,
		Required: cfg.DBMirrorRequired,
		// Which schedd this daemon serves, so discovery can tell
		// this access point's mirror from another's.
		ScheddAddress: schedd.Address,
	})
}

// startMultiAP runs the registry and hub pollers.
func (h *Handler) startMultiAP(ctx context.Context) {
	m := h.multi
	if m.registry != nil {
		h.wg.Add(1)
		go func() {
			defer h.wg.Done()
			var lastErr string
			m.registry.Run(ctx, func(err error) {
				msg := ""
				if err != nil {
					msg = err.Error()
				}
				if msg != lastErr {
					if err != nil {
						h.logger.Warn(logging.DestinationSchedd, "Access point registry poll failed; keeping the last known set", "error", err)
					} else {
						st := m.registry.Status()
						h.logger.Info(logging.DestinationSchedd, "Access point registry updated", "members", st.Members, "present", st.Present)
					}
					lastErr = msg
				}
			})
		}()
	}
	if m.svc.Hub != nil && m.hubLoc != nil {
		h.wg.Add(1)
		go func() {
			defer h.wg.Done()
			var lastErr string
			m.svc.Hub.Run(ctx, func(err error) {
				msg := ""
				if err != nil {
					msg = err.Error()
				}
				if msg != lastErr {
					if err != nil {
						h.logger.Warn(logging.DestinationHTTP, "Federation hub is not answering", "error", err)
					} else {
						h.logger.Info(logging.DestinationHTTP, "Federation hub is answering", "sources", m.svc.Hub.Status().Sources)
					}
					lastErr = msg
				}
			})
		}()
	}
}

// multiAPScheddMisuse records a call to the single-schedd accessor in
// multi-AP mode. There is no right schedd to return, and a real one would
// act on another AP's job; the handle it returns cannot connect anywhere,
// so the escaped call fails with an error instead of a nil dereference
// in some goroutine that would take the daemon down.
func (h *Handler) multiAPScheddMisuse() *htcondor.Schedd {
	n := h.multi.scheddCalls.Add(1)
	if n <= 10 || n%1000 == 0 {
		h.logger.Error(logging.DestinationHTTP, "BUG: the single-schedd accessor was called in multi-AP mode; refusing", "calls", n)
	}
	return multiap.NoSchedd
}

// identitySchedds returns the schedds to try when a call needs any
// schedd to identify a caller: the one schedd in single-AP mode, else up
// to three registry members (all members trust one signing key in v1).
func (h *Handler) identitySchedds() []*htcondor.Schedd {
	if h.multi == nil {
		if s := h.getSchedd(); s != nil {
			return []*htcondor.Schedd{s}
		}
		return nil
	}
	if h.multi.registry == nil {
		return nil
	}
	var out []*htcondor.Schedd
	for _, m := range h.multi.registry.Healthy(3) {
		out = append(out, m.Schedd)
	}
	return out
}

// identitySchedd is the first of identitySchedds, or nil.
func (h *Handler) identitySchedd() *htcondor.Schedd {
	if s := h.identitySchedds(); len(s) > 0 {
		return s[0]
	}
	return nil
}

// multiAPReadPaths are the API routes multi-AP mode serves to a GET.
var multiAPReadPaths = map[string]bool{
	"/api/v1/jobs":         true,
	"/api/v1/jobs/archive": true,
	"/api/v1/aps":          true,
	"/api/v1/whoami":       true,
	"/api/v1/auth/me":      true,
	"/api/v1/version":      true,
	"/api/v1/chat/info":    true,
}

// multiAPJobSubroutes are the registered /api/v1/jobs/<name> routes that
// are NOT a job id.
var multiAPJobSubroutes = map[string]bool{"archive": true, "epochs": true, "transfers": true, "watch": true}

// multiAPAdminPaths are admin pages that read and write only this
// server's own database (OAuth2 clients and tokens, API keys, logs,
// usage, configuration) and never a schedd. Admin-gated in the handlers.
var multiAPAdminPaths = []string{
	"/api/v1/admin/oauth2/",
	"/api/v1/admin/api-keys",
	"/api/v1/admin/logs",
	"/api/v1/admin/usage",
	"/api/v1/admin/condor-config",
}

// multiAPAllowed is the allowlist of routes multi-AP mode serves.
//
// Outside /api/ are the web UI's static files, login and OAuth2, MCP
// (which carries its own tool allowlist), metrics and health -- none of
// which reaches a schedd. Under /api/ only the routes named here are
// served; every other one is a 501.
func multiAPAllowed(method, path string) bool {
	if !strings.HasPrefix(path, "/api/") {
		return true
	}
	read := method == http.MethodGet || method == http.MethodHead
	if multiAPReadPaths[path] {
		return read
	}
	if path == "/api/v1/auth/logout" {
		return true
	}
	if seg, ok := strings.CutPrefix(path, "/api/v1/jobs/"); ok {
		return read && seg != "" && !strings.Contains(seg, "/") && !multiAPJobSubroutes[seg]
	}
	for _, p := range multiAPAdminPaths {
		if path == p || strings.HasPrefix(path, strings.TrimSuffix(p, "/")+"/") {
			return true
		}
	}
	return false
}

// refuseMultiAP writes the 501 for a route multi-AP mode does not serve.
func (h *Handler) refuseMultiAP(w http.ResponseWriter, r *http.Request) {
	h.writeError(w, http.StatusNotImplemented,
		fmt.Sprintf("%s %s is not available in multi-AP mode yet", r.Method, r.URL.Path))
}

// multiAPError writes a multiap error with its status, adding the
// candidate ids to a 409.
func (h *Handler) multiAPError(w http.ResponseWriter, err error) {
	status := multiap.StatusOf(err)
	if cands, ok := multiap.IsAmbiguous(err); ok {
		h.writeJSON(w, status, map[string]any{
			"error":      http.StatusText(status),
			"message":    err.Error(),
			"code":       status,
			"candidates": cands,
		})
		return
	}
	h.writeError(w, status, err.Error())
}

// multiAPCaller authenticates the request and returns its context and
// the caller's User attribute value, or writes the error.
func (h *Handler) multiAPCaller(w http.ResponseWriter, r *http.Request) (context.Context, string, bool) {
	ctx, needsRedirect, err := h.requireAuthentication(r)
	if err != nil {
		if needsRedirect {
			h.redirectToLogin(w, r)
			return nil, "", false
		}
		h.writeError(w, http.StatusUnauthorized, fmt.Sprintf("Authentication failed: %v", err))
		return nil, "", false
	}
	// The hub has no row-level ACL and skips the schedd handshake, so a
	// read is served only to a caller whose identity is established:
	// trusted session or header, or a bearer a schedd has vouched for.
	actor := htcondor.GetAuthenticatedUserFromContext(ctx)
	if actor == "" {
		h.writeError(w, http.StatusUnauthorized,
			"Authentication required: this listing returns only your own jobs, and the caller's identity could not be established")
		return nil, "", false
	}
	user, err := h.multi.svc.UserFor(actor)
	if err != nil {
		h.multiAPError(w, err)
		return nil, "", false
	}
	return ctx, user, true
}

func parseLimit(r *http.Request) (int, error) {
	limit := 50
	if v := r.URL.Query().Get("limit"); v != "" {
		if v == "*" {
			return -1, nil
		}
		n, err := strconv.Atoi(v)
		if err != nil {
			return 0, fmt.Errorf("invalid limit parameter: %w", err)
		}
		limit = n
	}
	return limit, nil
}

func parseProjection(r *http.Request) []string {
	v := r.URL.Query().Get("projection")
	if v == "" {
		return nil
	}
	if v == "*" {
		return []string{"*"}
	}
	parts := strings.Split(v, ",")
	for i := range parts {
		parts[i] = strings.TrimSpace(parts[i])
	}
	return parts
}

// handleMultiListJobs serves GET /api/v1/jobs in multi-AP mode: the
// caller's live jobs on every AP, from the hub.
func (h *Handler) handleMultiListJobs(w http.ResponseWriter, r *http.Request) {
	ctx, user, ok := h.multiAPCaller(w, r)
	if !ok {
		return
	}
	limit, err := parseLimit(r)
	if err != nil {
		h.writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	q := r.URL.Query()
	req := multiap.ListRequest{
		User: user, Constraint: q.Get("constraint"), Projection: parseProjection(r),
		Limit: limit, PageToken: q.Get("page_token"), Schedd: q.Get("schedd"),
	}
	out := &jsonRowStream{h: h, w: w, key: "jobs"}
	res, err := h.multi.svc.ListJobs(ctx, req, out.write)
	if err != nil {
		h.multiAPError(w, err)
		return
	}
	out.finish(res)
}

// handleMultiHistory serves GET /api/v1/jobs/archive in multi-AP mode.
// The single-AP before_cluster/before_proc keyset is not unique across
// APs, so it is refused; pages continue with page_token.
func (h *Handler) handleMultiHistory(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	if q.Get("before_cluster") != "" || q.Get("before_proc") != "" {
		h.writeError(w, http.StatusBadRequest,
			"before_cluster/before_proc do not identify a position across access points; continue with the response's next_page_token")
		return
	}
	ctx, user, ok := h.multiAPCaller(w, r)
	if !ok {
		return
	}
	limit, err := parseLimit(r)
	if err != nil {
		h.writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	rows, res, err := h.multi.svc.ListHistory(ctx, multiap.ListRequest{
		User: user, Constraint: q.Get("constraint"), Projection: parseProjection(r),
		Limit: limit, PageToken: q.Get("page_token"), Schedd: q.Get("schedd"),
	})
	if err != nil {
		h.multiAPError(w, err)
		return
	}
	out := &jsonRowStream{h: h, w: w, key: "ads"}
	for _, row := range rows {
		if !out.write(row) {
			break
		}
	}
	out.finish(res)
}

// handleMultiGetJob serves GET /api/v1/jobs/{id} in multi-AP mode. The
// id is the codec's text form; an incomplete one is resolved among the
// caller's jobs.
func (h *Handler) handleMultiGetJob(w http.ResponseWriter, r *http.Request, idText string) {
	ctx, user, ok := h.multiAPCaller(w, r)
	if !ok {
		return
	}
	id, err := h.multi.codec.Parse(idText)
	if err != nil {
		h.writeError(w, http.StatusBadRequest, fmt.Sprintf("Invalid job ID: %v", err))
		return
	}
	res, err := h.multi.svc.GetJob(ctx, user, id, nil)
	if err != nil {
		h.multiAPError(w, err)
		return
	}
	evaluateUsageAttrs(res.Row.Ad)
	body, err := h.multi.svc.RowJSON(res.Row)
	if err != nil {
		h.writeError(w, http.StatusInternalServerError, "could not encode the job")
		return
	}
	// The ad's own members plus where it came from: "source" names the
	// tier, and "degraded" the AP's state when the hub's copy is not
	// fresh.
	var out map[string]any
	dec := json.NewDecoder(bytes.NewReader(body))
	dec.UseNumber() // job ads carry 64-bit integers
	if err := dec.Decode(&out); err != nil {
		h.writeError(w, http.StatusInternalServerError, "could not encode the job")
		return
	}
	out["source"] = res.Source
	if res.Degraded != nil {
		out["degraded"] = res.Degraded
	}
	h.writeJSON(w, http.StatusOK, out)
}

// jsonRowStream writes {"<key>":[rows...], footer} as rows arrive.
type jsonRowStream struct {
	h       *Handler
	w       http.ResponseWriter
	key     string
	started bool
	n       int
	failed  error
}

func (s *jsonRowStream) begin() {
	if s.started {
		return
	}
	s.started = true
	s.w.Header().Set("Content-Type", "application/json")
	s.w.WriteHeader(http.StatusOK)
	_, _ = fmt.Fprintf(s.w, `{%q:[`, s.key)
}

func (s *jsonRowStream) write(row multiap.Row) bool {
	evaluateUsageAttrs(row.Ad)
	b, err := s.h.multi.svc.RowJSON(row)
	if err != nil {
		s.failed = err
		return false
	}
	s.begin()
	if s.n > 0 {
		if _, err := s.w.Write([]byte(",")); err != nil {
			s.failed = err
			return false
		}
	}
	if _, err := s.w.Write(b); err != nil {
		s.failed = err
		return false
	}
	s.n++
	_ = http.NewResponseController(s.w).Flush()
	return true
}

func (s *jsonRowStream) finish(res *multiap.ListResult) {
	s.begin()
	tail := map[string]any{
		"total_returned": s.n,
		"has_more":       res.HasMore,
		"source":         "hub",
		"sources":        res.Sources,
	}
	if res.NextPageToken != "" {
		tail["next_page_token"] = res.NextPageToken
	}
	switch {
	case s.failed != nil:
		tail["error"] = s.failed.Error()
		delete(tail, "next_page_token")
		tail["has_more"] = false
	case res.Err != nil:
		tail["error"] = res.Err.Error()
	}
	b, err := json.Marshal(tail)
	if err != nil {
		b = []byte(`{"source":"hub"}`)
	}
	_, _ = s.w.Write(append([]byte("],"), b[1:]...))
}

// APsResponse is GET /api/v1/aps.
type APsResponse struct {
	Constraint string           `json:"constraint"`
	APs        []multiap.APInfo `json:"aps"`
	Sources    multiap.Sources  `json:"sources"`
	Registry   *APRegistryState `json:"registry,omitempty"`
	Hub        APHubReach       `json:"hub"`
}

// APRegistryState is the AP registry's polling state.
type APRegistryState struct {
	LastSuccess string `json:"last_success,omitempty"`
	LastError   string `json:"last_error,omitempty"`
}

// APHubReach is whether the federation hub is answering.
type APHubReach struct {
	Reachable   bool   `json:"reachable"`
	LastSuccess string `json:"last_success,omitempty"`
	LastError   string `json:"last_error,omitempty"`
}

func timeOrEmpty(t time.Time) string {
	if t.IsZero() {
		return ""
	}
	return t.UTC().Format(time.RFC3339)
}

// handleAPs serves GET /api/v1/aps: the AP set, with the registry's and
// the hub's view of each member.
func (h *Handler) handleAPs(w http.ResponseWriter, r *http.Request) {
	if h.multi == nil {
		h.writeError(w, http.StatusNotFound, "this server is not in multi-AP mode")
		return
	}
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		h.writeError(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}
	if _, _, ok := h.multiAPCaller(w, r); !ok {
		return
	}
	hs := h.multi.svc.Hub.Status()
	resp := APsResponse{
		Constraint: h.multi.constraint,
		APs:        h.multi.svc.APs(),
		Sources:    h.multi.svc.Sources(),
		Hub:        APHubReach{Reachable: hs.Reachable, LastSuccess: timeOrEmpty(hs.LastSuccess), LastError: hs.LastError},
	}
	if h.multi.registry != nil {
		st := h.multi.registry.Status()
		resp.Registry = &APRegistryState{LastSuccess: timeOrEmpty(st.LastSuccess), LastError: st.LastError}
	}
	h.writeJSON(w, http.StatusOK, resp)
}

// multiAPReadiness is /readyz in multi-AP mode: ready when the hub
// answers and the AP set is non-empty. One AP being down never makes the
// server unready -- at fifty, one always is; the per-AP map says which.
func (h *Handler) multiAPReadiness() (bool, map[string]any) {
	hs := h.multi.svc.Hub.Status()
	members := h.multi.svc.Registry.Members()
	aps := map[string]any{}
	for _, info := range h.multi.svc.APs() {
		aps[info.Schedd] = map[string]any{
			"in_collector": info.InCollector,
			"hub_state":    info.Hub.State,
		}
	}
	body := map[string]any{
		"mode": "multi-ap",
		"hub": map[string]any{
			"reachable":    hs.Reachable,
			"last_success": timeOrEmpty(hs.LastSuccess),
			"last_error":   hs.LastError,
		},
		"aps":       aps,
		"ap_count":  len(members),
		"sources":   h.multi.svc.Sources(),
		"timestamp": time.Now().UTC().Format(time.RFC3339),
	}
	ready := hs.Reachable && len(members) > 0
	switch {
	case !hs.Reachable:
		body["reason"] = "the federation hub is not answering"
	case len(members) == 0:
		body["reason"] = "no access point matches HTTP_API_SCHEDD_CONSTRAINT yet"
	}
	return ready, body
}

// pingAsCaller asks a schedd who the request's credential authenticates
// as. In multi-AP mode any member can answer -- every member trusts the
// same signing key in v1 -- so an unreachable member is skipped; a
// refusal is the answer and is not retried elsewhere.
func (h *Handler) pingAsCaller(ctx context.Context) (*htcondor.PingResult, error) {
	schedds := h.identitySchedds()
	if len(schedds) == 0 {
		return nil, errors.New("no schedd is available to identify the caller")
	}
	var lastErr error
	for _, s := range schedds {
		res, err := s.Ping(ctx)
		if err == nil {
			return res, nil
		}
		lastErr = err
		if isAuthenticationError(err) {
			break
		}
	}
	return nil, lastErr
}

// startMultiAPHandler is Start for multi-AP mode: the schedd-independent
// half of startup, plus the registry and hub pollers. Everything that
// polls or acts on "the" schedd -- address and credd updaters, periodic
// pings, the queue-superuser poll, the job_queue.log tail, watches,
// Jupyter -- does not start.
func (h *Handler) startMultiAPHandler(ctx context.Context, ln net.Listener, protocol string) error {
	if h.sshGatewayAddress != "" {
		return errors.New("HTTP_API_SSH_GATEWAY_ADDRESS is set, but the SSH gateway is not available in multi-AP mode yet")
	}
	if err := h.initializeIDP(ln, protocol); err != nil {
		return err
	}
	h.initializeOAuth2(ln, protocol)
	h.warnIfMCPCannotMintCredentials()
	if h.oauth2StateStore != nil {
		h.oauth2StateStore.Start(ctx)
	}
	if h.oauth2Provider != nil && h.tokenRetentionFor >= 0 {
		go h.runTokenRetention(ctx)
	}
	h.startSessionCleanup(ctx)
	h.startMultiAP(h.ctx)
	return nil
}
