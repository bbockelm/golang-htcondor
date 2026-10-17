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

	htcondor "github.com/bbockelm/golang-htcondor"
	"github.com/bbockelm/golang-htcondor/jobid"
	"github.com/bbockelm/golang-htcondor/logging"
	"github.com/bbockelm/golang-htcondor/webapi/apassign"
	"github.com/bbockelm/golang-htcondor/webapi/apregistry"
	"github.com/bbockelm/golang-htcondor/webapi/dbmirror"
	"github.com/bbockelm/golang-htcondor/webapi/multiap"
)

// Multi-AP mode: one API server in front of every access point whose
// schedd ad matches HTTP_API_SCHEDD_CONSTRAINT.
//
// Reads of the caller's own jobs and history are served from the
// federation hub, and so are job watches (multiap_watch.go) and job
// resource-usage samples (multiap_metrics.go). Actions on
// one job are routed to the schedd of the AP its complete id names
// (multiap_actions.go); bulk actions fan out to every member
// (multiap_bulk.go). A submission goes to the AP the caller's assignment
// names, and credentials to that AP's credd (multiap_submit.go).
// Interactive work -- browser terminals, named sessions, JupyterLab,
// apps -- is placed the same way and then reached on the AP its record
// names (multiap_interactive.go). Everything else answers 501 until it
// has been taught which AP it is about. The refusal is an ALLOWLIST
// (multiAPAllowed): a route nobody has looked at is refused, not served
// against whichever schedd happens to be handy. There is no such schedd:
// Handler.schedd is nil in this mode, and getSchedd counts and logs any
// call that reaches it.

// MultiAPConfig configures multi-AP mode. ScheddConstraint set enables it.
type MultiAPConfig struct {
	// ScheddConstraint is HTTP_API_SCHEDD_CONSTRAINT: the AP set, over
	// ScheddAds.
	ScheddConstraint string
	// HubName and HubAddress are HTTP_API_HUB_NAME / _ADDRESS: name the
	// federation hubs (one, or several separated by commas or spaces),
	// or dial one at a fixed address, instead of discovering every
	// HTCondorDB ad that carries FederationConstraint.
	HubName    string
	HubAddress string
	// HubSwitchAfter, HubSwitchMargin and HubFailAfter are
	// HTTP_API_HUB_SWITCH_SECONDS, _SWITCH_MARGIN and _FAIL_AFTER: how
	// the active hub is chosen among several (multiap.HubPolicy). Zero
	// takes the default.
	HubSwitchAfter  time.Duration
	HubSwitchMargin int
	HubFailAfter    int
	// Stale is HTTP_API_MULTI_AP_STALE: include (default) or exclude a
	// degraded AP's rows from unscoped reads.
	Stale string
	// JobIDCodec is HTTP_API_JOB_ID_CODEC; empty selects jobid's default.
	JobIDCodec string
	// BulkFresh is HTTP_API_BULK_FRESH_SECONDS: how fresh the hub's copy
	// of an AP must be for a bulk action to skip that AP on the hub's
	// word that nothing there matches. Zero (the default) or negative
	// never skips: every usable AP is contacted.
	BulkFresh time.Duration
	// Assignment is HTTP_API_AP_ASSIGNMENT and its knobs: which AP a
	// user's new work goes to.
	Assignment apassign.Config

	// service replaces the hub, registry and spokes built from the
	// collector. Tests only.
	service *multiap.Service
	// registry is the registry behind service, for the readiness and AP
	// endpoints. Tests only.
	registry *apregistry.Registry
	// queueSuperUser replaces the per-AP QUEUE_SUPER_USERS polled from
	// each member. Tests only.
	queueSuperUser func(ap, actor string) bool
	// creddFor replaces per-AP credd discovery: the credd for an AP.
	// Tests only.
	creddFor func(ap string) htcondor.CreddClient
}

// Enabled reports whether multi-AP mode is configured.
func (c MultiAPConfig) Enabled() bool {
	return strings.TrimSpace(c.ScheddConstraint) != "" || c.service != nil
}

// multiAPMode is the multi-AP state a Handler holds.
type multiAPMode struct {
	svc        *multiap.Service
	registry   *apregistry.Registry // nil in tests that supply a service
	hubLocs    *hubLocators         // nil in tests
	spokeLoc   *dbmirror.Locator    // nil in tests
	constraint string
	codec      jobid.Codec
	// scheddCalls counts calls to the single-schedd accessor, which has
	// no answer in this mode. Any non-zero value is a route or background
	// task that escaped the allowlist.
	scheddCalls atomic.Int64
	// superusers is each member's QUEUE_SUPER_USERS; queueSuperUser,
	// when set, replaces it (tests).
	superusers     *apSuperusers
	queueSuperUser func(ap, actor string) bool
	// bulkFresh is HTTP_API_BULK_FRESH_SECONDS.
	bulkFresh time.Duration
	// observeBulkLeg, when set, sees the AP and scoped constraint of each
	// bulk leg before it runs. Tests only.
	observeBulkLeg func(ap, constraint string)
	// assign is the AP assignment chain (also svc.Assign).
	assign *apassign.Chain
	// credds is each AP's credd.
	credds *apCredds
}

func newMultiAPMode(cfg HandlerConfig, logger *logging.Logger) (*multiAPMode, error) {
	mc := cfg.MultiAP
	if cfg.ScheddName != "" || cfg.ScheddAddr != "" {
		return nil, errors.New("HTTP_API_SCHEDD_CONSTRAINT selects multi-AP mode and cannot be combined with a single schedd " +
			"(-schedd, -schedd-addr or SCHEDD_NAME); unset one of them")
	}
	if strings.TrimSpace(cfg.CreddAddress) != "" {
		return nil, errors.New("HTTP_API_CREDD_ADDRESS names one credd, and in multi-AP mode each access point uses its own " +
			"(the CredDIpAddr its schedd advertises); a credential stored in another AP's credd is accepted and never used. Unset it")
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
	m := &multiAPMode{constraint: strings.TrimSpace(mc.ScheddConstraint), codec: codec, bulkFresh: mc.BulkFresh,
		credds: &apCredds{clientConfig: cfg.ClientConfig, override: mc.creddFor}}
	if mc.service != nil {
		m.svc, m.registry, m.queueSuperUser = mc.service, mc.registry, mc.queueSuperUser
		if m.svc.Codec == nil {
			m.svc.Codec = codec
		}
		m.superusers = newAPSuperusers(m.svc.Registry, cfg.UIDDomain, logger)
		m.svc.QueueSuperUser = m.apQueueSuperUser
		m.svc.BulkFresh = m.bulkFresh
		if err := m.setupAssignment(mc.Assignment, logger); err != nil {
			return nil, err
		}
		return m, nil
	}
	if cfg.Collector == nil {
		return nil, errors.New("multi-AP mode needs a collector (COLLECTOR_HOST) to find the access points")
	}
	if cfg.HTCondorConfig == nil {
		return nil, errors.New("multi-AP mode needs the HTCondor configuration to authenticate to the federation hub")
	}
	reg, err := apregistry.New(cfg.Collector, m.constraint, apregistry.Options{ClientConfig: cfg.ClientConfig})
	if err != nil {
		return nil, err
	}
	m.hubLocs = &hubLocators{collector: cfg.Collector, cfg: cfg.HTCondorConfig}
	hub, err := newHubSet(mc, m.hubLocs, logger)
	if err != nil {
		return nil, err
	}
	// Hubs are ranked on the access points this server serves.
	hub.SetMembership(func(schedd string) bool {
		_, ok := reg.Get(schedd)
		return ok
	})
	m.spokeLoc = dbmirror.NewLocatorWithOptions(cfg.Collector, cfg.HTCondorConfig, dbmirror.Options{})
	m.registry = reg
	m.svc = &multiap.Service{
		Registry:  reg,
		Hub:       hub,
		Spokes:    m.spokeLoc,
		Codec:     codec,
		Stale:     stale,
		UIDDomain: cfg.UIDDomain,
	}
	m.superusers = newAPSuperusers(reg, cfg.UIDDomain, logger)
	m.svc.QueueSuperUser = m.apQueueSuperUser
	m.svc.BulkFresh = m.bulkFresh
	if err := m.setupAssignment(mc.Assignment, logger); err != nil {
		return nil, err
	}
	logger.Info(logging.DestinationHTTP, "Multi-AP mode enabled",
		"schedd_constraint", m.constraint, "hub_name", mc.HubName, "hub_address", mc.HubAddress,
		"stale", string(stale), "job_id_codec", strings.ToLower(strings.TrimSpace(mc.JobIDCodec)),
		"bulk_fresh", m.bulkFresh)
	return m, nil
}

// setupAssignment builds the AP assignment chain, unless a test service
// brought its own. A chain that cannot be built -- an unknown backend, a
// mapfile that does not parse -- refuses to start the server.
func (m *multiAPMode) setupAssignment(cfg apassign.Config, logger *logging.Logger) error {
	if m.svc.Assign != nil {
		if c, ok := m.svc.Assign.(*apassign.Chain); ok {
			m.assign = c
		}
		return nil
	}
	chain, err := newAssignment(cfg, m.svc, logger)
	if err != nil {
		return err
	}
	m.assign, m.svc.Assign = chain, chain
	logger.Info(logging.DestinationHTTP, "Access point assignment configured",
		"backends", chain.Backends(), "default", chain.Default())
	return nil
}

// setTokenSource gives the hub and spoke connections the IDTOKEN the
// single-AP mirror would use.
func (m *multiAPMode) setTokenSource(src func(ctx context.Context) (string, error)) {
	if m == nil || src == nil {
		return
	}
	if m.hubLocs != nil {
		m.hubLocs.setTokenSource(src)
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
	// Finding the access points and following their mirrors is this
	// daemon's own work.
	ctx = htcondor.WithDaemonCredential(ctx, "multi-AP discovery")
	m := h.multi
	if m.superusers != nil && m.queueSuperUser == nil {
		h.wg.Add(1)
		go func() {
			defer h.wg.Done()
			// Reading each AP's QUEUE_SUPER_USERS is this daemon's own work.
			m.superusers.run(htcondor.WithDaemonCredential(ctx, "per-AP queue superuser refresh"))
		}()
	}
	if m.assign != nil {
		// The assignment's files (the mapfile) are watched off the
		// request path.
		h.wg.Add(1)
		go func() {
			defer h.wg.Done()
			m.assign.Run(ctx)
		}()
	}
	if m.registry != nil {
		// Each member is probed for trust as it joins, and periodically.
		m.registry.SetProbe(h.probeMemberTrust)
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
	if m.svc.Hub != nil && m.hubLocs != nil {
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
						st := m.svc.Hub.Status()
						h.logger.Info(logging.DestinationHTTP, "Federation hub is answering", "hub", st.Name, "sources", st.Sources)
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
// to three registry members (all members trust one signing key in v1)
// that have PASSED the trust probe. A member not yet probed -- or one
// whose probe could not run -- is not trusted to say who anybody is: an
// identity it reports may come from a different key, trust domain or
// mapfile than the ones the probe would have checked.
func (h *Handler) identitySchedds() []*htcondor.Schedd {
	if h.multi == nil {
		if s := h.getSchedd(); s != nil {
			return []*htcondor.Schedd{s}
		}
		return nil
	}
	var out []*htcondor.Schedd
	for _, m := range h.multi.svc.Registry.Members() {
		if len(out) == 3 {
			break
		}
		if m.Present && m.Schedd != nil && m.Trust.State == apregistry.TrustTrusted {
			out = append(out, m.Schedd)
		}
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
	"/api/v1/jobs":                 true,
	"/api/v1/jobs/archive":         true,
	"/api/v1/utilization":          true,
	"/api/v1/utilization/jobs":     true,
	"/api/v1/utilization/workflow": true,
	"/api/v1/aps":                  true,
	"/api/v1/whoami":               true,
	"/api/v1/auth/me":              true,
	"/api/v1/version":              true,
	"/api/v1/chat/info":            true,
}

// multiAPJobSubroutes are the registered /api/v1/jobs/<name> routes that
// are NOT a job id.
var multiAPJobSubroutes = map[string]bool{"archive": true, "epochs": true, "transfers": true, "watch": true}

// multiAPSharePaths are the share-URL redemption routes multi-AP mode
// serves for one job. /api/v1/share/watch is in multiAPWatchAllowed.
var multiAPSharePaths = map[string]bool{
	"/api/v1/share/output": true,
	"/api/v1/share/input":  true,
}

// multiAPSSHPaths serve the SSH gateway's device-flow approval screen
// and its certificate authority. In multi-AP mode the approval creates
// an interactive session through the session manager, on the AP the
// caller's assignment names; approving a job login runs the revocation
// oracles' scope check over the trusted members, and the certificate
// endpoint identifies its caller with a trusted member.
var multiAPSSHPaths = map[string]bool{
	sshConsentReadPath:        true,
	sshConsentApprovePath:     true,
	"/api/v1/ssh/ca":          true,
	"/api/v1/ssh/certificate": true,
}

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
	if path == "/api/v1/jobs" && (method == http.MethodDelete || method == http.MethodPatch || method == http.MethodPost) {
		// Bulk remove and edit fan out to every member; a submission goes
		// to the AP the caller's assignment names.
		return true
	}
	if multiAPCredentialPath(path) {
		// The credd of the caller's home AP, or of ?schedd=.
		return true
	}
	if multiAPReadPaths[path] {
		return read
	}
	if multiAPHubAllowed(method, path) {
		return true
	}
	if path == "/api/v1/auth/logout" {
		return true
	}
	if seg, ok := strings.CutPrefix(path, "/api/v1/jobs/"); ok {
		first, rest, sub := strings.Cut(seg, "/")
		switch {
		case first == "":
			return false
		case sub:
			// /api/v1/jobs/{id}/...: an action on one job.
			return !multiAPJobSubroutes[first] && first != "hold" && first != "release" &&
				multiAPJobActionAllowed(method, rest)
		case first == "hold" || first == "release":
			// Bulk hold and release.
			return method == http.MethodPost
		case multiAPJobSubroutes[first]:
			return false
		}
		// One job: read, remove, edit.
		return read || method == http.MethodDelete || method == http.MethodPatch
	}
	if multiAPSSHPaths[path] {
		return true
	}
	if multiAPSharePaths[path] {
		// Redeeming a share URL acts on the AP the URL names.
		return true
	}
	if multiAPInteractivePath(method, path) {
		// Terminals, JupyterLab and apps: placed by AP assignment,
		// then reached on the AP their record names.
		return true
	}
	if path == "/api/v1/templates" || strings.HasPrefix(path, "/api/v1/templates/") {
		// Submit templates: each user's own, in this server's database,
		// never a schedd. The submit page reads and saves them.
		return true
	}
	for _, p := range multiAPAdminPaths {
		if path == p || strings.HasPrefix(path, strings.TrimSuffix(p, "/")+"/") {
			return true
		}
	}
	return false
}

// multiAPCredentialPath reports whether path is a credential endpoint.
func multiAPCredentialPath(path string) bool {
	return path == "/api/v1/creds/user" || path == "/api/v1/creds/service" ||
		strings.HasPrefix(path, "/api/v1/creds/service/")
}

// refuseMultiAP writes the 501 for a route multi-AP mode does not serve.
func (h *Handler) refuseMultiAP(w http.ResponseWriter, r *http.Request) {
	h.writeError(w, http.StatusNotImplemented,
		fmt.Sprintf("%s %s is not available in multi-AP mode yet", r.Method, r.URL.Path))
}

// multiAPError writes a multiap error with its status, adding its
// machine-readable reason and, for an ambiguous or incomplete job id,
// the candidate jobs.
func (h *Handler) multiAPError(w http.ResponseWriter, err error) {
	status := multiap.StatusOf(err)
	reason := multiap.ReasonOf(err)
	cands, ambiguous := multiap.IsAmbiguous(err)
	if !ambiguous {
		cands = multiap.CandidatesOf(err)
	}
	if reason == "" && !ambiguous && cands == nil {
		h.writeError(w, status, err.Error())
		return
	}
	body := map[string]any{
		"error":   http.StatusText(status),
		"message": err.Error(),
		"code":    status,
	}
	if reason != "" {
		body["reason"] = reason
	}
	if ambiguous || reason == multiap.ReasonIncompleteID {
		if cands == nil {
			cands = []multiap.JobRef{}
		}
		body["candidates"] = cands
	}
	h.writeJSON(w, status, body)
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
	// One federation hub for the whole request: every read it makes, and
	// every freshness it reports, is that hub's.
	return h.multi.svc.PinHub(ctx), user, true
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

// multiWholeAd reports whether a multi-AP read returns whole ads: the hub
// reads every attribute when there is no projection or it names "*".
func multiWholeAd(projection []string) bool {
	return len(projection) == 0 || isWholeAdProjection(projection)
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
	out := &jsonRowStream{h: h, w: w, key: "jobs", wholeAd: multiWholeAd(req.Projection)}
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
	projection := parseProjection(r)
	rows, res, err := h.multi.svc.ListHistory(ctx, multiap.ListRequest{
		User: user, Constraint: q.Get("constraint"), Projection: projection,
		Limit: limit, PageToken: q.Get("page_token"), Schedd: q.Get("schedd"),
	})
	if err != nil {
		h.multiAPError(w, err)
		return
	}
	out := &jsonRowStream{h: h, w: w, key: "ads", wholeAd: multiWholeAd(projection)}
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
	annotateEvaluatedRequests(res.Row.Ad) // no projection: the whole ad
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
	h   *Handler
	w   http.ResponseWriter
	key string
	// wholeAd: the rows carry every attribute, so their requests can be
	// evaluated (see annotateEvaluatedRequests).
	wholeAd bool
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
	if s.wholeAd {
		annotateEvaluatedRequests(row.Ad)
	}
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
	// Hub is the federation hub this answer comes from; Hubs every hub
	// this server knows, the one reads go to now marked active.
	Hub       APHubReach   `json:"hub"`
	Hubs      []APHubReach `json:"hubs,omitempty"`
	HubSwitch *APHubSwitch `json:"hub_switch,omitempty"`
	// Assignment is where the caller's new work goes; each AP's submit
	// says whether the caller may submit there.
	Assignment *APAssignmentInfo `json:"assignment,omitempty"`
}

// APRegistryState is the AP registry's polling state.
type APRegistryState struct {
	LastSuccess string `json:"last_success,omitempty"`
	LastError   string `json:"last_error,omitempty"`
}

// APHubReach is whether a federation hub is answering.
type APHubReach struct {
	// Name is the hub's collector ad Name, Address where it was found.
	Name    string `json:"name,omitempty"`
	Address string `json:"address,omitempty"`
	// Active is whether reads go to this hub now.
	Active      bool   `json:"active"`
	Reachable   bool   `json:"reachable"`
	LastSuccess string `json:"last_success,omitempty"`
	LastError   string `json:"last_error,omitempty"`
	// FreshAPs is how many access points this hub holds fresh, which is
	// what hub selection ranks on.
	FreshAPs int `json:"fresh_aps"`
}

// APHubSwitch is the last change of active hub.
type APHubSwitch struct {
	From   string `json:"from,omitempty"`
	To     string `json:"to,omitempty"`
	Reason string `json:"reason"`
	At     string `json:"at"`
}

// hubReach reports a hub's status.
func (m *multiAPMode) hubReach(st multiap.HubStatus) APHubReach {
	return APHubReach{Name: st.Name, Address: m.hubAddress(st), Active: st.Active, Reachable: st.Reachable,
		LastSuccess: timeOrEmpty(st.LastSuccess), LastError: st.LastError, FreshAPs: st.FreshAPs}
}

// hubReport is the hub ctx is pinned to, every known hub, and the last
// switch, for /api/v1/aps and /readyz.
func (m *multiAPMode) hubReport(ctx context.Context) (APHubReach, []APHubReach, *APHubSwitch) {
	pinned := m.svc.Hub.For(ctx)
	var cur APHubReach
	var all []APHubReach
	for _, st := range m.svc.Hub.Statuses() {
		r := m.hubReach(st)
		all = append(all, r)
		if strings.EqualFold(st.Name, pinned.Name()) {
			cur = r
		}
	}
	if len(all) == 0 {
		cur = m.hubReach(m.svc.Hub.Status())
	}
	var sw *APHubSwitch
	if last := m.svc.Hub.LastSwitch(); last != nil {
		sw = &APHubSwitch{From: last.From, To: last.To, Reason: last.Reason, At: timeOrEmpty(last.At)}
	}
	return cur, all, sw
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
	ctx, user, ok := h.multiAPCaller(w, r)
	if !ok {
		return
	}
	cur, all, sw := h.multi.hubReport(ctx)
	resp := APsResponse{
		Constraint: h.multi.constraint,
		APs:        h.multi.svc.APs(ctx),
		Sources:    h.multi.svc.Sources(ctx),
		Hub:        cur,
		Hubs:       all,
		HubSwitch:  sw,
	}
	if h.multi.registry != nil {
		st := h.multi.registry.Status()
		resp.Registry = &APRegistryState{LastSuccess: timeOrEmpty(st.LastSuccess), LastError: st.LastError}
	}
	// ?kind= asks where that kind of work would go (the web UI's
	// interactive page asks for "interactive" and "jupyter"); a site's
	// assignment may differ by kind.
	areq := h.jobAssignRequest(ctx, r, user)
	switch k := r.URL.Query().Get("kind"); k {
	case "", apassign.KindJob:
	case apassign.KindDAG, apassign.KindInteractive, apassign.KindJupyter, apassign.KindContainerBuild:
		areq.Kind = k
	default:
		h.writeError(w, http.StatusBadRequest, fmt.Sprintf("unknown kind %q", k))
		return
	}
	resp.Assignment = h.assignmentInfo(ctx, areq)
	if a := resp.Assignment; a != nil && a.Schedd != "" {
		allowed := apassign.Assignment{Schedd: a.Schedd, Alternates: a.Alternates}
		for i := range resp.APs {
			_, resp.APs[i].Submit = allowed.Allows(resp.APs[i].Schedd)
			resp.APs[i].Home = strings.EqualFold(resp.APs[i].Schedd, a.Schedd)
		}
	}
	h.writeJSON(w, http.StatusOK, resp)
}

// multiAPReadiness is /readyz in multi-AP mode: ready when some
// federation hub answers and the AP set is non-empty. One AP being down
// never makes the server unready -- at fifty, one always is; the per-AP
// map says which. Nor does one of two hubs: reads fail over to the other.
func (h *Handler) multiAPReadiness() (bool, map[string]any) {
	ctx := h.multi.svc.PinHub(context.Background())
	cur, all, sw := h.multi.hubReport(ctx)
	reachable := 0
	for _, hub := range all {
		if hub.Reachable {
			reachable++
		}
	}
	anyReachable := reachable > 0
	members := h.multi.svc.Registry.Members()
	aps := map[string]any{}
	for _, info := range h.multi.svc.APs(ctx) {
		aps[info.Schedd] = map[string]any{
			"in_collector": info.InCollector,
			"hub_state":    info.Hub.State,
			"trust":        info.Trust.State,
		}
	}
	body := map[string]any{
		"mode": "multi-ap",
		"hub": map[string]any{
			"name":         cur.Name,
			"reachable":    cur.Reachable,
			"last_success": cur.LastSuccess,
			"last_error":   cur.LastError,
		},
		"hubs":           all,
		"hubs_reachable": reachable,
		"aps":            aps,
		"ap_count":       len(members),
		"sources":        h.multi.svc.Sources(ctx),
		"timestamp":      time.Now().UTC().Format(time.RFC3339),
	}
	if sw != nil {
		body["hub_switch"] = sw
	}
	if e := h.multi.svc.Hub.DiscoveryError(); e != "" {
		body["hub_discovery_error"] = e
	}
	ready := anyReachable && len(members) > 0
	switch {
	case !anyReachable:
		body["reason"] = "no federation hub is answering"
	case len(members) == 0:
		body["reason"] = "no access point matches HTTP_API_SCHEDD_CONSTRAINT yet"
	}
	return ready, body
}

// pingAsCaller asks a schedd who the request's credential authenticates
// as. In multi-AP mode any member can answer -- every member trusts the
// same signing key in v1 -- so an unreachable member is skipped; a
// refusal is the answer and is not retried elsewhere.
//
// The ping is DC_NOP_READ, which DaemonCore registers at READ, so the
// schedd refuses the handshake for a credential it would not let run
// QUERY_JOB_ADS: an identity resolved here is one the schedd accepts at
// READ. DC_NOP is registered at ALLOW and would answer for anything the
// schedd can authenticate. ctx must carry the request's SecurityConfig.
//
// A request routed to an AP asks that AP and no other: the identity an
// action runs as is the one the AP it runs on reports.
func (h *Handler) pingAsCaller(ctx context.Context) (*htcondor.PingResult, error) {
	schedds := h.identitySchedds()
	if h.multi != nil {
		if t, ok := multiap.TargetFrom(ctx); ok {
			m, err := h.multi.svc.Member(t.Member.Name)
			if err != nil {
				return nil, err
			}
			schedds = []*htcondor.Schedd{m.Schedd}
		}
	}
	if len(schedds) == 0 {
		return nil, errors.New("no schedd is available to identify the caller")
	}
	var lastErr error
	for _, s := range schedds {
		res, err := s.PingWithOptions(ctx, &htcondor.PingOptions{Command: htcondor.DCNopRead})
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
// half of startup, the registry and hub pollers, and job watches over
// the hub. Everything that polls or acts on "the" schedd -- address and
// credd updaters, periodic pings, the queue-superuser poll, the
// job_queue.log tail -- does not start. What does start runs on h.ctx,
// which Stop cancels, never on Start's context.
func (h *Handler) startMultiAPHandler(ln net.Listener, protocol string) error {
	if err := h.initializeIDP(ln, protocol); err != nil {
		return err
	}
	h.initializeOAuth2(ln, protocol)
	h.warnIfMCPCannotMintCredentials()
	// The gateway reaches jobs by complete id, and sessions on the AP
	// their record names (sshGatewayResolveMultiAP).
	if h.oauth2Provider != nil {
		if err := h.startSSHGateway(h.ctx, h.oauth2Provider.config.AccessTokenIssuer); err != nil {
			return fmt.Errorf("starting the SSH gateway: %w", err)
		}
	} else if h.sshGatewayAddress != "" {
		return errors.New("HTTP_API_SSH_GATEWAY_ADDRESS is set but OAuth2 is not configured; " +
			"the gateway authenticates with the device flow and cannot run without it")
	}
	if h.oauth2StateStore != nil {
		h.oauth2StateStore.Start(h.ctx)
	}
	if h.oauth2Provider != nil {
		go h.runTokenRetention(h.ctx)
	}
	h.startSessionCleanup(h.ctx)
	h.startMultiAP(h.ctx)
	h.startMultiAPWatches(h.ctx)
	return nil
}
