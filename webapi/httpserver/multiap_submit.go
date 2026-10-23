package httpserver

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"sync"

	htcondor "github.com/bbockelm/golang-htcondor"
	"github.com/bbockelm/golang-htcondor/config"
	"github.com/bbockelm/golang-htcondor/jobid"
	"github.com/bbockelm/golang-htcondor/logging"
	"github.com/bbockelm/golang-htcondor/webapi/apassign"
	"github.com/bbockelm/golang-htcondor/webapi/apregistry"
	"github.com/bbockelm/golang-htcondor/webapi/multiap"
	"github.com/bbockelm/golang-htcondor/webapi/submitlint"
)

// Submission and credentials in multi-AP mode.
//
// A new submission goes to the AP the assignment chain (webapi/apassign)
// names for the caller: their home AP, or an alternate they name with
// ?schedd=. It is asked once, here. The response carries complete job
// ids, and every later step -- the input upload of a two-step submit
// above all -- addresses the job by that id and is routed by it, never
// assigned again.
//
// Credentials follow the assignment: each AP's schedd says which credd
// it uses (CredDIpAddr), and a credential is only useful there. The
// submit-time credential bootstrap runs against the target AP's credd,
// and the credential endpoints act on the caller's home AP's credd
// unless ?schedd= names another AP in the set.

// apassignLogger hands the assignment chain this server's logger.
type apassignLogger struct{ l *logging.Logger }

func (a apassignLogger) Error(msg string, args ...any) {
	if a.l != nil {
		a.l.Error(logging.DestinationHTTP, msg, args...)
	}
}

func (a apassignLogger) Warn(msg string, args ...any) {
	if a.l != nil {
		a.l.Warn(logging.DestinationHTTP, msg, args...)
	}
}

func (a apassignLogger) Info(msg string, args ...any) {
	if a.l != nil {
		a.l.Info(logging.DestinationHTTP, msg, args...)
	}
}

// newAssignment builds the assignment chain for svc's AP set. The static
// backend assigns HTTP_API_AP_ASSIGNMENT_DEFAULT: in multi-AP mode there
// is no single schedd for it to name.
func newAssignment(cfg apassign.Config, svc *multiap.Service, logger *logging.Logger) (*apassign.Chain, error) {
	cfg.Static = cfg.Default
	return apassign.Build(cfg, apassign.Options{InSet: svc.InSet, Usable: svc.Usable, Logger: apassignLogger{logger}})
}

// callerClaims is what the request says about its caller beyond the
// HTCondor identity: the principal it authenticated as and the groups
// recorded at login. From the browser session, or from the OAuth2 grant
// behind an opaque bearer; anything else (an HTCondor token, a trusted
// header) carries no groups, and its subject is the identity itself.
func (h *Handler) callerClaims(ctx context.Context, r *http.Request) apassign.Caller {
	if c, ok := apassign.CallerFrom(ctx); ok {
		return c
	}
	actor := htcondor.GetAuthenticatedUserFromContext(ctx)
	if tok, err := extractBearerToken(r); err != nil {
		if sess, ok := h.getSessionFromRequest(r); ok && sess.Username != "" {
			return apassign.Caller{Subject: sess.Username, Groups: append([]string(nil), sess.Groups...)}
		}
	} else if h.oauth2Provider != nil {
		if ar, err := h.oauth2Provider.IntrospectAccessToken(r.Context(), tok); err == nil {
			return claimsFromSession(ar.GetSession())
		}
	}
	return apassign.Caller{Subject: actor}
}

// claimsFromSession reads the subject and groups an OAuth2 grant was
// issued with.
func claimsFromSession(sess interface{ GetSubject() string }) apassign.Caller {
	c := apassign.Caller{Subject: sess.GetSubject()}
	if s, ok := sess.(*Session); ok {
		c.Groups = append([]string(nil), s.Groups...)
	}
	return c
}

// jobAssignRequest is the assignment question for this caller's jobs:
// every REST submission, and the home AP a report or a credential
// endpoint names, is for kind "job".
func (h *Handler) jobAssignRequest(ctx context.Context, r *http.Request, user string) apassign.Request {
	c := h.callerClaims(ctx, r)
	return apassign.Request{User: user, Subject: c.Subject, Groups: c.Groups, Kind: apassign.KindJob}
}

// handleMultiSubmitJob serves POST /api/v1/jobs in multi-AP mode: the
// job is submitted, as the caller, to the AP their assignment names.
func (h *Handler) handleMultiSubmitJob(w http.ResponseWriter, r *http.Request) {
	ctx, user, ok := h.multiAPCaller(w, r)
	if !ok {
		return
	}
	var req JobSubmitRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.writeError(w, http.StatusBadRequest, fmt.Sprintf("Invalid request body: %v", err))
		return
	}
	if req.SubmitFile == "" {
		h.writeError(w, http.StatusBadRequest, "submit_file is required")
		return
	}
	// Same read of the submit file as the single-AP path. Done before an
	// access point is chosen: a submit file with no working outcome is
	// refused wherever it would have gone, and choosing first would
	// charge the caller's assignment for a submission that never happens.
	insp := submitlint.Inspect(req.SubmitFile)
	if insp.Fatal != nil {
		h.writeError(w, http.StatusBadRequest, insp.Fatal.Error())
		return
	}
	m, a, err := h.multi.svc.SubmitTarget(ctx, h.jobAssignRequest(ctx, r, user), r.URL.Query().Get("schedd"))
	if err != nil {
		h.multiAPError(w, err)
		return
	}
	ctx = multiap.WithTarget(ctx, multiap.Target{Member: m})
	// The job is owned by whoever the AP says this credential is.
	if v := h.multi.svc.VerifyCaller; v != nil {
		if err := v(ctx, m, user); err != nil {
			h.multiAPError(w, err)
			return
		}
	}
	h.multi.svc.NoteWrite(m.Name)
	defer h.multi.svc.NoteWrite(m.Name)

	clusterID, procAds, err := h.submitJob(ctx, req.SubmitFile)
	if err != nil {
		// An AP that left the collector or turned untrusted since it was
		// chosen is refused by scheddFor; say that, not "submission
		// failed".
		if _, merr := h.multi.svc.Member(m.Name); merr != nil {
			h.multiAPError(w, merr)
			return
		}
		h.writeSubmitFailure(ctx, w, err)
		return
	}
	resp := JobSubmitResponse{ClusterID: clusterID, Schedd: m.Name, Assignment: &a, Warnings: insp.Warnings}
	for _, ad := range procAds {
		cluster, _ := ad.EvaluateAttrInt("ClusterId")
		proc, _ := ad.EvaluateAttrInt("ProcId")
		id := jobid.ID{Schedd: m.Name, Cluster: cluster, Proc: proc}
		text := h.multi.codec.Format(id)
		resp.JobIDs = append(resp.JobIDs, text)
		resp.Jobs = append(resp.Jobs, multiap.JobRef{Schedd: m.Name, Cluster: cluster, Proc: proc, JobID: text})
	}
	if resp.JobIDs == nil {
		resp.JobIDs = []string{}
	}
	h.logger.Info(logging.DestinationHTTP, "Submitted to the assigned access point",
		"user", user, "access_point", m.Name, "cluster", clusterID, "procs", len(procAds),
		"assignment_source", a.Source, "submit_warnings", len(insp.Warnings))
	h.writeJSON(w, http.StatusCreated, resp)
}

// --- per-AP credds -----------------------------------------------------------

// apCredds holds a credd client per AP, built from the address the AP's
// schedd advertises and replaced when it changes.
type apCredds struct {
	clientConfig *config.Config
	// override replaces discovery (tests): the credd for an AP.
	override func(ap string) htcondor.CreddClient

	mu   sync.Mutex
	byAP map[string]apCredd // by lower-cased AP name
}

type apCredd struct {
	addr   string
	client htcondor.CreddClient
}

// forMember returns m's credd and the key the required-credential cache
// keeps its answers under (the credd's address), or nil when the AP
// advertises no credd.
func (c *apCredds) forMember(m apregistry.Member) (htcondor.CreddClient, string) {
	if c.override != nil {
		cl := c.override(m.Name)
		if cl == nil {
			return nil, ""
		}
		return cl, "ap:" + strings.ToLower(m.Name)
	}
	addr := strings.TrimSpace(m.CreddAddress)
	if addr == "" {
		return nil, ""
	}
	key := strings.ToLower(m.Name)
	c.mu.Lock()
	defer c.mu.Unlock()
	if e, ok := c.byAP[key]; ok && e.addr == addr {
		return e.client, addr
	}
	if c.byAP == nil {
		c.byAP = map[string]apCredd{}
	}
	cl := htcondor.NewCedarCredd(addr).WithConfig(c.clientConfig)
	c.byAP[key] = apCredd{addr: addr, client: cl}
	return cl, addr
}

// creddFor returns the credd an operation on ctx uses, and the scope the
// required-credential cache keys its answers by. Single-AP: this
// server's credd, scope "". Multi-AP: the credd of the AP ctx was routed
// to, and nothing without a route -- there is no pool-wide credd to fall
// back on, and a credential stored in the wrong one is accepted and
// never used.
func (h *Handler) creddFor(ctx context.Context) (htcondor.CreddClient, string) {
	if h.multi == nil {
		c := h.getCredd()
		if c == nil || !h.creddAvailable.Load() {
			return nil, ""
		}
		return c, ""
	}
	t, ok := multiap.TargetFrom(ctx)
	if !ok {
		h.logger.Error(logging.DestinationHTTP, "BUG: a credd was asked for with no access point routed")
		return nil, ""
	}
	m, err := h.multi.svc.Member(t.Member.Name)
	if err != nil {
		return nil, ""
	}
	return h.multi.credds.forMember(m)
}

// creddForContext is creddFor without the cache scope, for MCP.
func (h *Handler) creddForContext(ctx context.Context) htcondor.CreddClient {
	c, _ := h.creddFor(ctx)
	return c
}

// multiCredContext routes a credential request to an AP: ?schedd= when
// given (any AP in the set), else the caller's home AP. It returns the
// routed context and that AP's credd, or writes the error.
func (h *Handler) multiCredContext(w http.ResponseWriter, r *http.Request) (context.Context, htcondor.CreddClient, bool) {
	ctx, user, ok := h.multiAPCaller(w, r)
	if !ok {
		return nil, nil, false
	}
	m, err := h.multi.svc.CredentialTarget(ctx, h.jobAssignRequest(ctx, r, user), r.URL.Query().Get("schedd"))
	if err != nil {
		h.multiAPError(w, err)
		return nil, nil, false
	}
	ctx = multiap.WithTarget(ctx, multiap.Target{Member: m})
	credd, _ := h.creddFor(ctx)
	if credd == nil {
		h.writeError(w, http.StatusServiceUnavailable,
			fmt.Sprintf("access point %s advertises no credential service (credd)", m.Name))
		return nil, nil, false
	}
	w.Header().Set("X-HTCondor-Access-Point", m.Name)
	return ctx, credd, true
}

// --- reporting the assignment -----------------------------------------------

// APAssignmentInfo is the caller's AP assignment as /api/v1/auth/me,
// /api/v1/whoami and /api/v1/aps report it: where new work goes, or why
// it cannot be submitted.
type APAssignmentInfo struct {
	// Schedd is the home AP.
	Schedd string `json:"schedd,omitempty"`
	// Alternates are the other APs the caller may submit to by name.
	Alternates []string `json:"alternates,omitempty"`
	// Source names what decided it: a backend, or "default".
	Source string `json:"source,omitempty"`
	// Stale is set when the answer is a last known good one.
	Stale bool `json:"stale,omitempty"`
	// Error and Reason say why there is no assignment.
	Error  string `json:"error,omitempty"`
	Reason string `json:"reason,omitempty"`
}

// assignmentInfo resolves user's assignment for a report. Nil outside
// multi-AP mode.
func (h *Handler) assignmentInfo(ctx context.Context, req apassign.Request) *APAssignmentInfo {
	if h.multi == nil || req.User == "" {
		return nil
	}
	a, err := h.multi.svc.Assignment(ctx, req)
	if err != nil {
		return &APAssignmentInfo{Error: err.Error(), Reason: multiap.ReasonOf(err)}
	}
	return &APAssignmentInfo{Schedd: a.Schedd, Alternates: a.Alternates, Source: a.Source, Stale: a.Stale}
}

// sessionAssignment is the browser session's assignment, for
// /api/v1/auth/me.
func (h *Handler) sessionAssignment(r *http.Request, sess *SessionData) *APAssignmentInfo {
	if h.multi == nil || sess == nil {
		return nil
	}
	user, err := h.multi.svc.UserFor(sess.Username)
	if err != nil {
		return &APAssignmentInfo{Error: err.Error(), Reason: multiap.ReasonOf(err)}
	}
	return h.assignmentInfo(r.Context(), apassign.Request{
		User: user, Subject: sess.Username, Groups: append([]string(nil), sess.Groups...), Kind: apassign.KindJob,
	})
}
