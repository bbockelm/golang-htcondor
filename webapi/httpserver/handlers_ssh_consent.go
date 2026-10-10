// Copyright 2026 Morgridge Institute for Research
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package httpserver

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"sync"

	"github.com/ory/fosite"
	"golang.org/x/time/rate"

	"github.com/bbockelm/golang-htcondor/logging"
	"github.com/bbockelm/golang-htcondor/webapi/interactive"
	"github.com/bbockelm/golang-htcondor/webapi/sshgateway"
)

// sshApprovePath is the SPA route that approves an SSH login.
//
// A route in the single-page app rather than another server-rendered
// page, because the screen it has to show is the interactive page's
// resource form -- CPUs, memory, disk, GPUs, extra submit lines -- and
// that form already exists in the SPA. Rebuilding it in Go string
// concatenation would be a second copy of validation, layout and
// defaults that would drift from the first within a release.
const sshApprovePath = "/ssh/approve"

// API endpoints the SPA approval screen drives.
const (
	sshConsentReadPath    = "/api/v1/ssh/device"
	sshConsentApprovePath = "/api/v1/ssh/device/approve"
)

// sshConsentRedirect says where handleOAuth2DeviceVerify should send a
// browser, or "" to render the server-side consent page as before.
//
// A function rather than an inline condition so both answers can be
// tested: a test binary has no frontend compiled in, so `embedded` is
// false in every test in this package and an inline check would only
// ever exercise the fallback -- a test of it could not fail.
//
// The server-rendered page stays the answer for an MCP-only
// deployment and for every device code that is not an SSH login. That
// is not a legacy path kept out of politeness: it is the only consent
// surface a build without the web UI has.
func sshConsentRedirect(sshSession, userCode string, embedded bool) string {
	if sshSession == "" || !embedded {
		return ""
	}
	return sshApprovePath + "?user_code=" + url.QueryEscape(userCode)
}

// sshSessionFromRequester reads the SSH workspace a device code was
// started for, or "" when it was not started by the SSH gateway.
//
// Re-validated on the way out as well as on the way in. What is in the
// row was written by an endpoint that authenticates no client, and the
// row may predate whatever the validator says today; a name that would
// not be accepted now must not be rendered or submitted now either.
func sshSessionFromRequester(request fosite.Requester) string {
	if request == nil {
		return ""
	}
	name := strings.TrimSpace(request.GetRequestForm().Get(sshgateway.SessionFormField))
	if name == "" {
		return ""
	}
	if err := interactive.ValidateSessionName(name); err != nil {
		return ""
	}
	return name
}

// sshConsentView is what the approval screen is told about a pending
// login.
//
// Deliberately nothing about who started the flow, because nothing is
// known: the device-authorize endpoint authenticates no client. Every
// field here is either the approving user's own data or something the
// server-rendered consent page already displays.
type sshConsentView struct {
	UserCode string `json:"user_code"`
	// Username is who the browser is signed in as -- the account the
	// session would be created as and the grant issued to. On screen
	// so somebody signed in as the wrong person sees it before they
	// approve rather than after.
	Username string   `json:"username"`
	ClientID string   `json:"client_id"`
	Scopes   []string `json:"scopes"`
	// Session is the workspace the SSH client asked to reach.
	Session string `json:"session"`
	// Exists reports whether the approving user already has a session
	// by that name; when they do, there is nothing to configure and
	// the screen offers the login alone.
	Exists bool `json:"session_exists"`
	// CanCreate is false where this server runs no interactive
	// manager, which makes the resource form pointless to show.
	CanCreate      bool   `json:"can_create"`
	JobID          string `json:"job_id,omitempty"`
	Status         string `json:"status,omitempty"`
	HoldReason     string `json:"hold_reason,omitempty"`
	HoldReasonCode int    `json:"hold_reason_code,omitempty"`
	// Defaults are what this deployment would submit if nobody chose,
	// so the form opens showing what it is about to do rather than
	// something the server will silently replace.
	Defaults InteractiveCreateTerminalRequest `json:"defaults"`
	// ApprovalToken must come back on the approve request. See
	// sshApprovalToken.
	ApprovalToken string `json:"approval_token"`
}

// sshConsentDecision is the body of the approve request.
type sshConsentDecision struct {
	UserCode string `json:"user_code"`
	// Action is "approve" or "deny", matching the server-rendered
	// form's own field rather than inventing a second vocabulary.
	Action        string `json:"action"`
	ApprovalToken string `json:"approval_token"`
	// Create, when set, asks for the workspace to be submitted as part
	// of approving. Ignored when the session already exists -- see
	// handleSSHConsentApprove for why that is a silent no-op and not
	// an error.
	Create *InteractiveCreateTerminalRequest `json:"create,omitempty"`
}

// sshConsentResult is what the screen shows after the decision.
type sshConsentResult struct {
	Approved bool   `json:"approved"`
	Session  string `json:"session,omitempty"`
	JobID    string `json:"job_id,omitempty"`
	// Created distinguishes "your workspace was submitted" from "the
	// one you already had is being used", which is the difference
	// between waiting for the queue and not.
	Created bool `json:"created"`
}

// sshConsentNotFound is the single answer to every user code that does
// not resolve to a pending login of this kind.
//
// One message for absent, expired, already-approved, already-denied
// and not-an-SSH-login on purpose. The user code is eight characters a
// human types, and an endpoint that distinguishes those cases is an
// oracle for walking the space: "expired" tells you a code existed.
const sshConsentNotFound = "That code is not waiting for approval. Check the code in your terminal, or reconnect to get a new one."

// handleSSHConsentRead describes the pending login behind a user code.
//
// GET rather than POST because it changes nothing, and the user code
// travels in the query string the same way it already does on the
// verification page a browser was redirected from.
func (h *Handler) handleSSHConsentRead(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		h.writeError(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}
	ctx := r.Context()

	username, _, ok := h.sshConsentIdentity(w, r)
	if !ok {
		return
	}
	userCode, request, ok := h.sshConsentLookup(w, r, username, r.URL.Query().Get("user_code"))
	if !ok {
		return
	}
	session := sshSessionFromRequester(request)

	view := sshConsentView{
		UserCode:      userCode,
		Username:      username,
		ClientID:      request.GetClient().GetID(),
		Scopes:        request.GetRequestedScopes(),
		Session:       session,
		Defaults:      h.sshConsentDefaults(),
		ApprovalToken: h.sshApprovalToken(userCode, username),
	}

	mgr := h.interactiveManagerOrNil()
	view.CanCreate = mgr != nil
	if mgr != nil {
		owner := ownerFromActor(username)
		cctx, err := h.withCondorCredential(ctx, owner, sshGatewayScopes, nil)
		if err != nil {
			// Not fatal to the page. The login half of this screen
			// works without ever reaching the queue, and refusing to
			// render would take away the only way in rather than the
			// part that is broken.
			h.logger.Warn(logging.DestinationHTTP,
				"Could not look up interactive sessions for an SSH approval screen",
				"username", owner, "error", err)
		} else if info, err := findInteractiveSession(cctx, mgr, interactive.Caller{Actor: owner, Owner: owner}, session); err != nil {
			h.logger.Warn(logging.DestinationHTTP,
				"Could not look up interactive sessions for an SSH approval screen",
				"username", owner, "error", err)
		} else if info != nil {
			view.Exists = true
			view.JobID = info.JobID
			view.Status = info.Status
			view.HoldReason = info.HoldReason
			view.HoldReasonCode = info.HoldReasonCode
		}
	}

	h.writeJSON(w, http.StatusOK, view)
}

// handleSSHConsentApprove records the browser user's decision, and on
// approval submits the workspace they consented to first.
//
// The order is deliberate and is the whole point of this design. The
// gateway is polling, and the poll returns the moment the device code
// flips to approved; it then looks for the session and attaches to
// what it finds. Approving first and submitting second would hand the
// gateway a grant for a workspace that does not exist yet, and it
// would create a second one.
func (h *Handler) handleSSHConsentApprove(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		h.writeError(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}
	ctx := r.Context()

	if err := h.requireSameOrigin(r); err != nil {
		h.writeError(w, http.StatusForbidden, err.Error())
		return
	}
	// A cross-site form POST cannot set this content type without a
	// CORS preflight, and a preflight to this origin is refused. It is
	// the cheap half of the pair; sshApprovalToken is the half that
	// does not depend on the browser.
	if ct := r.Header.Get("Content-Type"); !strings.HasPrefix(ct, "application/json") {
		h.writeError(w, http.StatusUnsupportedMediaType, "Send application/json")
		return
	}

	username, groups, ok := h.sshConsentIdentity(w, r)
	if !ok {
		return
	}

	var decision sshConsentDecision
	setBodyLimit(w, r, 1<<16)
	if err := json.NewDecoder(r.Body).Decode(&decision); err != nil {
		h.writeError(w, http.StatusBadRequest, "Could not read the request body")
		return
	}

	userCode, request, ok := h.sshConsentLookup(w, r, username, decision.UserCode)
	if !ok {
		return
	}
	if !h.checkSSHApprovalToken(decision.ApprovalToken, userCode, username) {
		// Deliberately the same shape of refusal as a stale page
		// rather than an accusation: the honest way to arrive here is
		// to leave the screen open past a restart, which rolls the
		// key.
		h.writeError(w, http.StatusForbidden,
			"This approval is no longer valid. Reload the page and try again.")
		return
	}

	if decision.Action == "deny" {
		if err := h.oauth2Provider.GetStorage().DenyDeviceCodeSession(ctx, userCode); err != nil {
			if errors.Is(err, fosite.ErrNotFound) {
				h.writeError(w, http.StatusNotFound, sshConsentNotFound)
				return
			}
			h.logger.Error(logging.DestinationHTTP, "Failed to deny an SSH device code", "error", err)
			h.writeError(w, http.StatusInternalServerError, "Could not record the refusal")
			return
		}
		h.logger.Info(logging.DestinationHTTP, "SSH login denied", "username", username)
		h.writeJSON(w, http.StatusOK, sshConsentResult{Approved: false})
		return
	}
	if decision.Action != "approve" {
		h.writeError(w, http.StatusBadRequest, `action must be "approve" or "deny"`)
		return
	}

	session := sshSessionFromRequester(request)
	result := sshConsentResult{Approved: true, Session: session}

	if decision.Create != nil {
		info, created, err := h.sshConsentCreateSession(ctx, username, session, *decision.Create)
		if err != nil {
			h.writeError(w, http.StatusBadRequest, err.Error())
			return
		}
		result.Created = created
		if info != nil {
			result.JobID = info.JobID
		}
	}

	// The same narrowing the server-rendered approval performs, minus
	// the per-scope checkboxes. There are none on this screen on
	// purpose: the scopes an SSH login asks for are the ones a shell
	// needs, and a user who declines condor:/WRITE gets a terminal
	// that cannot reach their job and no explanation of why. What the
	// user consents to here is the login and the workspace; what the
	// policy allows is still the ceiling.
	accepted := h.getScopesForGroups(groups, request.GetRequestedScopes())
	accepted = h.scopesAllowedByScheddACL(ctx, username, accepted)

	oidcSession := DefaultOpenIDConnectSession(username).WithGroups(groups)
	oidcSession.WithAuthorizedScopes(accepted)
	if err := h.oauth2Provider.GetStorage().ApproveDeviceCodeSessionWithScopes(
		ctx, userCode, username, oidcSession, accepted); err != nil {
		if errors.Is(err, fosite.ErrNotFound) {
			// The row stopped being pending between the lookup above
			// and here -- it expired, or a second tab decided first.
			// The same answer as a code that was never pending, for
			// the same reason.
			h.writeError(w, http.StatusNotFound, sshConsentNotFound)
			return
		}
		h.logger.Error(logging.DestinationHTTP, "Failed to approve an SSH device code", "error", err)
		h.writeError(w, http.StatusInternalServerError, "Could not record the approval")
		return
	}

	h.logger.Info(logging.DestinationHTTP, "SSH login approved",
		"username", username, "client_id", request.GetClient().GetID(),
		"session", session, "created", result.Created, "job", result.JobID,
		"accepted_scopes", accepted)

	h.writeJSON(w, http.StatusOK, result)
}

// sshConsentCreateSession submits the workspace the user consented to.
//
// Returns created=false when they already had one by that name, which
// is a success and not a conflict: the session the SSH client is about
// to attach to exists either way, and two browser tabs or a reloaded
// page must not turn into two jobs.
func (h *Handler) sshConsentCreateSession(ctx context.Context, username, session string, req InteractiveCreateTerminalRequest) (*interactive.Info, bool, error) {
	if session == "" {
		return nil, false, errors.New("this login is not for a workspace, so there is nothing to create")
	}
	// Validated before anything else is consulted, so the refusal
	// names the field the user got wrong rather than whatever this
	// deployment happens to be missing.
	req.applyDefaults()
	if err := req.validate(); err != nil {
		return nil, false, err
	}

	mgr := h.interactiveManagerOrNil()
	if mgr == nil {
		return nil, false, errors.New("this access point does not run interactive sessions")
	}

	owner := ownerFromActor(username)
	caller := interactive.Caller{Actor: owner, Owner: owner}
	cctx, err := h.withCondorCredential(ctx, owner, sshGatewayScopes, nil)
	if err != nil {
		return nil, false, fmt.Errorf("could not act as %s: %w", owner, err)
	}

	info, err := mgr.Create(cctx, caller, interactive.CreateSpec{
		Name:                  session,
		Cpus:                  req.Cpus,
		MemoryMB:              req.MemoryMB,
		DiskMB:                req.DiskMB,
		Gpus:                  req.Gpus,
		GpusMinimumCapability: req.GpusMinimumCapability,
		GpusMinimumMemory:     req.GpusMinimumMemory,
		GpusMinimumRuntime:    req.GpusMinimumRuntime,
		CudaVersion:           req.CudaVersion,
		RequireGpus:           req.RequireGpus,
		SubmitLines:           req.SubmitLines,
	})
	switch {
	case err == nil:
		h.logger.Info(logging.DestinationHTTP, "Created an interactive session from an SSH approval",
			"username", owner, "session", session, "job", info.JobID)
		return info, true, nil
	case errors.Is(err, interactive.ErrSessionExists):
		var exists *interactive.SessionExistsError
		if errors.As(err, &exists) {
			return &exists.Info, false, nil
		}
		return nil, false, nil
	default:
		return nil, false, err
	}
}

// sshConsentDefaults is what the approval form opens with.
//
// The operator's HTTP_API_SSH_GATEWAY_SESSION_* numbers where they set
// any, so the form shows what `ssh` would have submitted on its own;
// the interactive package's defaults otherwise. Showing one thing and
// submitting another is the failure this exists to avoid.
func (h *Handler) sshConsentDefaults() InteractiveCreateTerminalRequest {
	req := InteractiveCreateTerminalRequest{
		Cpus:     h.sshGatewaySessionSpec.Cpus,
		MemoryMB: h.sshGatewaySessionSpec.MemoryMB,
		DiskMB:   h.sshGatewaySessionSpec.DiskMB,
	}
	req.applyDefaults()
	return req
}

func (h *Handler) interactiveManagerOrNil() *interactive.Manager {
	if h.mcpServer == nil {
		return nil
	}
	return h.mcpServer.InteractiveManager()
}

// sshConsentIdentity resolves the human at the browser, or answers the
// request and reports false.
//
// deviceApprovalIdentity and nothing else, which is the same set the
// server-rendered approval accepts: a trusted proxy's header, a
// browser session, or the built-in IDP's session. Bearer tokens and
// API keys are deliberately not accepted even though the rest of
// /api/v1 takes them. Approving a device code mints a NEW grant, so a
// token that could approve one would be a token that can extend
// itself to a shell, and a stolen token would no longer need a human
// anywhere. An approval has to be an act of a person at a browser,
// and this is the list of ways this server knows one.
func (h *Handler) sshConsentIdentity(w http.ResponseWriter, r *http.Request) (string, []string, bool) {
	if h.oauth2Provider == nil {
		h.writeError(w, http.StatusServiceUnavailable, "OAuth2 is not configured on this server")
		return "", nil, false
	}
	username, groups := h.deviceApprovalIdentity(r.Context(), r)
	if username == "" {
		h.writeError(w, http.StatusUnauthorized, "Sign in to approve a login")
		return "", nil, false
	}
	return username, groups, true
}

// sshConsentLookup resolves a user code to a pending SSH login, or
// answers the request and reports false.
//
// Every refusal is the same message and the same status, and every
// attempt -- successful or not -- spends rate-limit budget. See
// sshConsentNotFound and sshConsentAllow.
func (h *Handler) sshConsentLookup(w http.ResponseWriter, r *http.Request, username, raw string) (string, fosite.Requester, bool) {
	userCode := strings.ToUpper(strings.TrimSpace(raw))
	if userCode == "" {
		h.writeError(w, http.StatusBadRequest, "user_code is required")
		return "", nil, false
	}
	if !h.sshConsentAllow(r, username) {
		h.logger.Warn(logging.DestinationSecurity,
			"Rate-limiting device code lookups", "username", username)
		h.writeError(w, http.StatusTooManyRequests,
			"Too many attempts. Wait a moment and try again.")
		return "", nil, false
	}

	storage := h.oauth2Provider.GetStorage()
	// Pending and nothing else. The shared lookup below answers for a
	// code in any state, which would let this pair of endpoints
	// confirm that an approved, denied or used code once existed --
	// and existing is the expensive half of guessing one.
	if !storage.DeviceCodeIsPending(r.Context(), userCode) {
		h.writeError(w, http.StatusNotFound, sshConsentNotFound)
		return "", nil, false
	}
	_, request, err := storage.GetDeviceCodeSessionByUserCode(r.Context(), userCode)
	if err != nil {
		h.writeError(w, http.StatusNotFound, sshConsentNotFound)
		return "", nil, false
	}
	// Not an SSH login: the generic consent page owns that code, and
	// answering for it here would let this pair of endpoints approve
	// any device code at all while skipping the per-scope choices that
	// page offers.
	if sshSessionFromRequester(request) == "" {
		h.writeError(w, http.StatusNotFound, sshConsentNotFound)
		return "", nil, false
	}
	return userCode, request, true
}

// Rate limits on the user code.
//
// Two limiters, both consulted, because they stop different things. By
// source address is the classic one. By authenticated user matters
// more here: signing in is cheap at most sites, and without it one
// account could sweep from a botnet. A user code is eight characters
// of a 32-symbol alphabet and lives ten minutes, so the space is far
// too large to walk at these rates -- the limits exist so that stays
// true however many codes are outstanding. The server-rendered device
// verification page spends the same budgets.
const (
	sshConsentAttemptsPerMinute = 20
	sshConsentBurst             = 20
)

func (h *Handler) sshConsentLimiters() (byIP, byUser *LoginRateLimiter) {
	h.sshConsentLimiterOnce.Do(func() {
		h.sshConsentByIP = NewLoginRateLimiter(rate.Limit(sshConsentAttemptsPerMinute/60.0), sshConsentBurst)
		h.sshConsentByUser = NewLoginRateLimiter(rate.Limit(sshConsentAttemptsPerMinute/60.0), sshConsentBurst)
	})
	return h.sshConsentByIP, h.sshConsentByUser
}

// sshConsentAllow spends one attempt from both budgets.
//
// Both are charged even when one has already refused, so a caller
// cannot use a fresh address to keep a user budget full, or the
// reverse.
func (h *Handler) sshConsentAllow(r *http.Request, username string) bool {
	byIP, byUser := h.sshConsentLimiters()
	ipOK := byIP.Allow(clientIP(r, h.trustedProxies))
	userOK := byUser.Allow(username)
	return ipOK && userOK
}

// sshApprovalToken binds an approval to the code and the person who
// was shown it.
//
// This is the CSRF defence that does not depend on the browser. The
// existing server-rendered consent form has none at all: it is a plain
// POST whose only authentication is a cookie, and in the deployments
// that authenticate with a proxy-set header there is not even a cookie
// whose SameSite could save it. Here the token is handed out only in
// the body of the read endpoint, which a cross-site page cannot read
// because the browser will not show it a cross-origin response. So an
// approval requires having loaded the screen, as the person
// approving, which is exactly the deliberate act the grant is supposed
// to represent.
//
// Keyed per process. The key is unrecoverable across a restart, which
// invalidates screens left open across one -- acceptable, because the
// page reloads and the device code outlives neither by much -- and
// costs nothing to hold.
func (h *Handler) sshApprovalToken(userCode, username string) string {
	mac := hmac.New(sha256.New, h.sshApprovalKey())
	// Length-prefixed rather than concatenated: with a separator
	// alone, a crafted username could borrow part of a code.
	_, _ = fmt.Fprintf(mac, "%d:%s%d:%s", len(userCode), userCode, len(username), username)
	return base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
}

func (h *Handler) checkSSHApprovalToken(presented, userCode, username string) bool {
	want := h.sshApprovalToken(userCode, username)
	return subtle.ConstantTimeCompare([]byte(presented), []byte(want)) == 1
}

func (h *Handler) sshApprovalKey() []byte {
	return h.purposeKey(sshApprovalInfo, &h.sshApprovalKeyOnce, &h.sshApprovalKeyBytes,
		"the SSH approval token")
}

// purposeKey resolves one purpose's key: derived from the application
// master when this deployment has one, and otherwise minted for this
// process alone.
//
// Derived is what we want. The master is wrapped in master_keys under
// each pool signing key, so it survives a restart and is identical on
// every replica reading that database -- which is how secrets are
// managed here, and what a per-process key silently was not. A key that
// rotates on every restart invalidates whatever it signed, and a key
// that differs per replica means a form rendered by one pod cannot be
// verified by another.
//
// The fallback exists because a deployment with no pool signing keys has
// no master to derive from, and the alternative there is a consent page
// that cannot work at all. It is logged at warn, once, naming the
// consequence rather than the mechanism.
func (h *Handler) purposeKey(label string, once *sync.Once, cached *[]byte, what string) []byte {
	// Nil-tolerant: a Handler built field-by-field in a test has no
	// logger, and a key accessor is the wrong place to insist on one.
	warn := func(msg string, args ...any) {
		if h.logger != nil {
			h.logger.Warn(logging.DestinationSecurity, msg, args...)
		}
	}
	once.Do(func() {
		if key, err := h.masterSubkey(label); err != nil {
			warn("Could not derive "+what+" from the application master key; "+
				"it will not survive a restart and will differ between replicas",
				"error", err)
		} else if len(key) > 0 {
			*cached = key
			return
		} else {
			warn("No pool signing keys, so "+what+" cannot be derived from the application "+
				"master key; it will not survive a restart and will differ between replicas",
				"hint", "SEC_PASSWORD_DIRECTORY")
		}
		key := make([]byte, 32)
		if _, err := rand.Read(key); err != nil {
			// A Handler that cannot read randomness cannot issue a
			// token anybody can verify, and carrying on with a zero
			// key would silently accept a forged one.
			panic("httpserver: no randomness for " + what + ": " + err.Error())
		}
		*cached = key
	})
	return *cached
}

// requireSameOrigin refuses a state-changing request that a page on
// another site made.
//
// Only when the browser said where it came from. Origin is sent on
// every cross-origin request and on every POST from a modern browser,
// but a reverse proxy that strips it would otherwise make approving a
// login impossible -- and the approval token already covers the case
// this is a second opinion on.
func (h *Handler) requireSameOrigin(r *http.Request) error {
	origin := r.Header.Get("Origin")
	if origin == "" {
		return nil
	}
	parsed, err := url.Parse(origin)
	if err != nil || parsed.Host == "" {
		return errors.New("that request did not come from this site")
	}
	if parsed.Host == r.Host {
		return nil
	}
	if h.httpBaseURL != "" {
		if base, err := url.Parse(h.httpBaseURL); err == nil &&
			base.Host == parsed.Host && base.Scheme == parsed.Scheme {
			return nil
		}
	}
	return errors.New("that request did not come from this site")
}

// sshConsentState is the per-Handler state the helpers above build on
// demand, embedded in Handler.
//
// Built lazily rather than in NewHandler so each Handler owns its own
// -- limiters shared between Handlers make one test's exhausted budget
// another test's mysterious 429 -- and so nothing has to be remembered
// at construction for a feature that may never be reached.
type sshConsentState struct {
	sshConsentLimiterOnce sync.Once
	sshConsentByIP        *LoginRateLimiter
	sshConsentByUser      *LoginRateLimiter

	sshApprovalKeyOnce  sync.Once
	sshApprovalKeyBytes []byte

	consentCSRFKeyOnce  sync.Once
	consentCSRFKeyBytes []byte
}

// csrfSafeMethod reports whether a method is read-only by definition and
// so needs no cross-site check.
//
// The list is RFC 9110's safe methods. OPTIONS is here because a CORS
// preflight is exactly a cross-origin OPTIONS and refusing it would
// refuse the request it precedes before the real check ever ran.
func csrfSafeMethod(method string) bool {
	switch method {
	case http.MethodGet, http.MethodHead, http.MethodOptions, http.MethodTrace:
		return true
	default:
		return false
	}
}

// hasBearerCredential reports whether the request carries a Bearer
// token, which exempts it from the cross-site check.
//
// Not "is it valid" -- that is the handler's job and happens later.
// The question here is only whether a browser could have attached this
// by itself, and for a Bearer token it could not: cookies and proxy-set
// headers ride along automatically, a Bearer token is put there by
// whoever built the request. A forged one simply fails to authenticate.
//
// Any other Authorization scheme is not exempt. A browser does attach
// Basic credentials by itself once the user has entered them, cross-site
// included, and a reverse proxy that authenticates with Basic and sets
// the trusted user header is exactly the deployment this check protects.
func hasBearerCredential(r *http.Request) bool {
	token, err := extractBearerToken(r)
	return err == nil && token != ""
}
