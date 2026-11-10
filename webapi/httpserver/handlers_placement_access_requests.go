package httpserver

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	htcondor "github.com/bbockelm/golang-htcondor"
	"github.com/bbockelm/golang-htcondor/logging"
	"golang.org/x/time/rate"
)

// The access request endpoints; see placement_access_requests.go.
//
//	GET|POST|DELETE /api/v1/placement/me/request      the session's own
//	GET  /api/v1/placement/admin/requests[?status=]    admins
//	GET  /api/v1/placement/admin/requests/count
//	POST /api/v1/placement/admin/requests/{id}/approve
//	POST /api/v1/placement/admin/requests/{id}/deny
//	POST /api/v1/placement/admin/requests/{id}/resolve
//
// Whose request it is comes from the session and nothing else: the request
// body names no identity (an unknown field is refused), and no query
// parameter or header is consulted.

// Rate limits on filing a request: per identity, and per client address so
// that many sign-ins from one place cannot flood the queue.
var (
	accessRequestIdentityRate  = rate.Every(10 * time.Minute)
	accessRequestIdentityBurst = 3
	accessRequestAddressRate   = rate.Every(time.Minute)
	accessRequestAddressBurst  = 10
)

// placementMeRequestBody is POST /api/v1/placement/me/request.
type placementMeRequestBody struct {
	Projects []string `json:"projects"`
	Note     string   `json:"note"`
}

// placementMeRequestJSON is a request as its requester sees it.
type placementMeRequestJSON struct {
	ID        int64      `json:"id"`
	Status    string     `json:"status"`
	Projects  []string   `json:"projects"`
	Note      string     `json:"note,omitempty"`
	CreatedAt time.Time  `json:"created_at"`
	UpdatedAt time.Time  `json:"updated_at"`
	DecidedAt *time.Time `json:"decided_at,omitempty"`
	// Reason is the administrator's reason, on a denial.
	Reason string `json:"reason,omitempty"`
	// Account is the account access was granted as, on an approval.
	Account string `json:"account,omitempty"`
}

// placementMeRequestResponse is GET /api/v1/placement/me/request: who the
// session is, as a request would record it, and their latest request.
type placementMeRequestResponse struct {
	Identity    string                  `json:"identity"`
	DisplayName string                  `json:"display_name,omitempty"`
	Email       string                  `json:"email,omitempty"`
	Request     *placementMeRequestJSON `json:"request"`
}

func meRequestJSON(req *placementAccessRequest) *placementMeRequestJSON {
	if req == nil {
		return nil
	}
	status := req.Status
	if status == accessRequestApproving {
		// Not decided until the directory change commits.
		status = accessRequestPending
	}
	out := &placementMeRequestJSON{
		ID:        req.ID,
		Status:    status,
		Projects:  nonNilStrings(req.Projects),
		Note:      req.Note,
		CreatedAt: req.CreatedAt,
		UpdatedAt: req.UpdatedAt,
		DecidedAt: optionalTime(req.DecidedAt),
	}
	switch req.Status {
	case accessRequestDenied:
		out.Reason = req.DecisionNote
	case accessRequestApproved:
		out.Account = req.Account
	}
	return out
}

// handlePlacementMeRequest serves /api/v1/placement/me/request. The caller
// has authenticated the session and checked the CSRF header.
func (s *Handler) handlePlacementMeRequest(w http.ResponseWriter, r *http.Request, session *SessionData) {
	store := s.placementOnboard.requests
	if store == nil {
		s.writeError(w, http.StatusServiceUnavailable, "Access requests are not available on this server.")
		return
	}
	identity := session.PlacementIdentity
	if identity == "" {
		s.writeError(w, http.StatusForbidden, "Your sign-in did not provide an identity the placement service knows.")
		return
	}
	switch r.Method {
	case http.MethodGet:
		req, err := store.latest(r.Context(), identity)
		if err != nil {
			s.logger.Error(logging.DestinationHTTP, "Failed to read an access request", "identity", identity, "error", err)
			s.writeError(w, http.StatusInternalServerError, "Could not read your request.")
			return
		}
		w.Header().Set("Cache-Control", "no-store")
		s.writeJSON(w, http.StatusOK, placementMeRequestResponse{
			Identity:    identity,
			DisplayName: session.DisplayName,
			Email:       session.Email,
			Request:     meRequestJSON(req),
		})
	case http.MethodPost:
		s.createPlacementAccessRequest(w, r, session)
	case http.MethodDelete:
		req, err := store.withdraw(r.Context(), identity)
		if err != nil {
			s.logger.Error(logging.DestinationHTTP, "Failed to withdraw an access request", "identity", identity, "error", err)
			s.writeError(w, http.StatusInternalServerError, "Could not withdraw your request.")
			return
		}
		if req == nil {
			// An approval in progress holds the request.
			if cur, err := store.latest(r.Context(), identity); err == nil && cur != nil && cur.Status == accessRequestApproving {
				s.writeError(w, http.StatusConflict, "Your request is being approved.")
				return
			}
			s.writeError(w, http.StatusNotFound, "You have no pending request.")
			return
		}
		s.logger.Info(logging.DestinationHTTP, "Access request withdrawn", "identity", identity, "request", req.ID)
		s.writeJSON(w, http.StatusOK, placementMeRequestResponse{
			Identity: identity, DisplayName: session.DisplayName, Email: session.Email, Request: meRequestJSON(req),
		})
	default:
		s.writeError(w, http.StatusMethodNotAllowed, "Method not allowed")
	}
}

func (s *Handler) createPlacementAccessRequest(w http.ResponseWriter, r *http.Request, session *SessionData) {
	po := &s.placementOnboard
	// The only identity this request can ever be for.
	identity := session.PlacementIdentity

	// Charged before anything else is done for the caller, refusals
	// included: the limit is on attempts.
	if !po.requestIdentityLimiter.Allow(identity) || !s.allowAccessRequestFrom(r) {
		w.Header().Set("Retry-After", "600")
		s.writeError(w, http.StatusTooManyRequests, "Too many requests. Try again later.")
		return
	}

	setBodyLimit(w, r, 1<<14)
	var body placementMeRequestBody
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(&body); err != nil {
		s.writeError(w, http.StatusBadRequest, fmt.Sprintf("Invalid request body: %v", err))
		return
	}
	projects, err := cleanAccessRequestProjects(body.Projects)
	if err != nil {
		s.writeError(w, http.StatusBadRequest, capitalize(err.Error())+".")
		return
	}
	note, err := cleanAccessRequestText("note", body.Note)
	if err != nil {
		s.writeError(w, http.StatusBadRequest, capitalize(err.Error())+".")
		return
	}

	// Only somebody without access may ask for it.
	self, err := s.lookupPlacementSelf(r, identity)
	if err != nil {
		s.writePlacementError(w, "look up your placement identity", err)
		return
	}
	if self.authorized {
		s.writeError(w, http.StatusConflict, "You already have access to this access point.")
		return
	}
	// An expired mapping is still in the directory, where an approval
	// cannot create it again: it needs its expiry extended.
	if self.expired {
		s.writeError(w, http.StatusConflict,
			"Your access to this access point has expired. Ask an administrator of this access point to extend it.")
		return
	}

	req, err := po.requests.create(r.Context(), placementAccessRequest{
		Identity:    identity,
		IDPSubject:  session.IDPSubject,
		DisplayName: session.DisplayName,
		Email:       session.Email,
		Projects:    projects,
		Note:        note,
	})
	if errors.Is(err, errAccessRequestPending) {
		s.writeError(w, http.StatusConflict, "You already have a pending request.")
		return
	}
	if err != nil {
		s.logger.Error(logging.DestinationHTTP, "Failed to store an access request", "identity", identity, "error", err)
		s.writeError(w, http.StatusInternalServerError, "Could not store your request.")
		return
	}
	s.logger.Info(logging.DestinationHTTP, "Access request filed",
		"identity", identity, "request", req.ID, "projects", projects)
	s.writeJSON(w, http.StatusCreated, placementMeRequestResponse{
		Identity: identity, DisplayName: session.DisplayName, Email: session.Email, Request: meRequestJSON(req),
	})
}

// allowAccessRequestFrom charges the per-address limit on filing requests.
//
// The address is only worth limiting when it is the client's. With no
// trusted proxies configured, a loopback or private peer is most likely a
// proxy or ingress in front of this server, and every user would share
// its one budget; the per-identity limit still applies then.
func (s *Handler) allowAccessRequestFrom(r *http.Request) bool {
	po := &s.placementOnboard
	if len(s.trustedProxies) == 0 {
		host, _, err := net.SplitHostPort(r.RemoteAddr)
		if err != nil {
			host = r.RemoteAddr
		}
		if ip := net.ParseIP(host); ip != nil && (ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast()) {
			po.requestAddressOff.Do(func() {
				s.logger.Info(logging.DestinationHTTP,
					"Access requests from a private address are limited per identity only; set HTTP_API_TRUSTED_PROXIES to limit them per client address",
					"peer", host)
			})
			return true
		}
	}
	return po.requestAddressLimiter.Allow(clientIP(r, s.trustedProxies))
}

// capitalize upper-cases the first letter of an error message used as a
// sentence.
func capitalize(s string) string {
	if s == "" {
		return s
	}
	return strings.ToUpper(s[:1]) + s[1:]
}

// --- Admin ---

// placementAccessRequestJSON is a request as administrators see it.
type placementAccessRequestJSON struct {
	ID           int64      `json:"id"`
	Identity     string     `json:"identity"`
	IDPSubject   string     `json:"idp_subject,omitempty"`
	DisplayName  string     `json:"display_name,omitempty"`
	Email        string     `json:"email,omitempty"`
	Projects     []string   `json:"projects"`
	Note         string     `json:"note,omitempty"`
	Status       string     `json:"status"`
	CreatedAt    time.Time  `json:"created_at"`
	UpdatedAt    time.Time  `json:"updated_at"`
	DecidedBy    string     `json:"decided_by,omitempty"`
	DecidedAt    *time.Time `json:"decided_at,omitempty"`
	DecisionNote string     `json:"decision_note,omitempty"`
	Account      string     `json:"account,omitempty"`
	ChangesetID  int64      `json:"changeset_id,omitempty"`
	// SuggestedAccount is the account a map file line with "*" would give
	// this identity: its part before the last "@", in UID_DOMAIN.
	SuggestedAccount string `json:"suggested_account,omitempty"`
}

// placementAccessRequestList is GET /api/v1/placement/admin/requests.
type placementAccessRequestList struct {
	Requests []placementAccessRequestJSON `json:"requests"`
	// Pending counts every pending request, whatever the filter.
	Pending int `json:"pending"`
	// CanApprove is whether the placementd serves the directory edits an
	// approval needs. Without them the requests are read-only.
	CanApprove bool `json:"can_approve"`
}

// placementApproveBody is POST .../requests/{id}/approve.
type placementApproveBody struct {
	Account        string   `json:"account"`
	Authorizations []string `json:"authorizations"`
	Projects       []string `json:"projects"`
	DefaultProject string   `json:"default_project"`
	// ExpiresAt is an RFC 3339 time, Unix seconds, or null for never.
	ExpiresAt   json.RawMessage `json:"expires_at,omitempty"`
	DisplayName string          `json:"display_name"`
	Comment     string          `json:"comment"`
	DryRun      bool            `json:"dry_run"`
	// AttachToExisting confirms mapping the identity to an account that
	// already exists, and that other identities may share. Without it,
	// an existing account is refused with what it holds. Attaching never
	// changes the account: its grants stay as they are, and the
	// authorizations and projects given are not used.
	AttachToExisting bool `json:"attach_to_existing"`
}

// placementAccountExistsBody is the 409 an approval answers when the
// account exists and attaching was not confirmed.
type placementAccountExistsBody struct {
	Error         string                `json:"error"`
	Message       string                `json:"message"`
	Code          int                   `json:"code"`
	AccountExists bool                  `json:"account_exists"`
	Account       *placementAccountJSON `json:"account"`
}

// placementApproveResponse answers an approval: the batch's outcome and,
// once committed, the request as recorded.
type placementApproveResponse struct {
	placementBatchResponse
	Request *placementAccessRequestJSON `json:"request,omitempty"`
}

// suggestedPlacementAccount is what the map file's "*" gives identity: the
// part before its last "@", in UID_DOMAIN. It is suggested only for an
// identity in a domain listed in HTTP_API_PLACEMENT_PREFILL_DOMAINS: the
// part before the "@" is chosen by whoever controls the identity, and only
// the operator knows for which domains that is the person's own name.
func (s *Handler) suggestedPlacementAccount(identity string) string {
	at := strings.LastIndex(identity, "@")
	if at <= 0 || s.uidDomain == "" ||
		!s.placementOnboard.prefillDomains[strings.ToLower(identity[at+1:])] {
		return ""
	}
	account := identity[:at] + "@" + s.uidDomain
	if s.checkPlacementAccountName(account) != nil {
		return ""
	}
	return account
}

// reservedPlacementAccounts is the set of account names, lower-cased and
// without a domain, an approval may never create or attach to: root,
// condor and condor_pool, and every name in QUEUE_SUPER_USERS (a group's
// name too, without its "%"), whatever its domain. The schedd qualifies a
// super-user name with its own UID_DOMAIN, which need not be the
// placementd's, so the name alone decides.
func reservedPlacementAccounts(queueSuperUsers string) map[string]bool {
	out := map[string]bool{"root": true, "condor": true, "condor_pool": true}
	for _, f := range strings.FieldsFunc(queueSuperUsers, func(r rune) bool { return r == ',' || unicode.IsSpace(r) }) {
		f = strings.TrimPrefix(f, "%")
		if at := strings.Index(f, "@"); at >= 0 {
			f = f[:at]
		}
		if f != "" {
			out[strings.ToLower(f)] = true
		}
	}
	return out
}

// checkPlacementAccountName refuses an account name the placementd would
// not hold, or that would act as a super user: it must be user@domain,
// one "@" with something on both sides, no whitespace, control or format
// characters, and no double quote, backslash or comma.
func (s *Handler) checkPlacementAccountName(account string) error {
	if len(account) > 256 || !utf8.ValidString(account) {
		return fmt.Errorf("account %q is not a valid account name", account)
	}
	if strings.IndexFunc(account, func(r rune) bool {
		return unicode.IsSpace(r) || isControlOrFormat(r) || r == '"' || r == '\\' || r == ','
	}) >= 0 {
		return fmt.Errorf("account %q contains a character an account name cannot", account)
	}
	user, domain, ok := strings.Cut(account, "@")
	if !ok || user == "" || domain == "" || strings.Contains(domain, "@") {
		return fmt.Errorf("account %q must be user@domain", account)
	}
	if s.placementOnboard.reservedAccounts[strings.ToLower(user)] {
		return fmt.Errorf("account %q is reserved for the access point itself", account)
	}
	return nil
}

func (s *Handler) accessRequestJSON(req *placementAccessRequest) *placementAccessRequestJSON {
	if req == nil {
		return nil
	}
	return &placementAccessRequestJSON{
		ID:               req.ID,
		Identity:         req.Identity,
		IDPSubject:       req.IDPSubject,
		DisplayName:      req.DisplayName,
		Email:            req.Email,
		Projects:         nonNilStrings(req.Projects),
		Note:             req.Note,
		Status:           req.Status,
		CreatedAt:        req.CreatedAt,
		UpdatedAt:        req.UpdatedAt,
		DecidedBy:        req.DecidedBy,
		DecidedAt:        optionalTime(req.DecidedAt),
		DecisionNote:     req.DecisionNote,
		Account:          req.Account,
		ChangesetID:      req.ChangesetID,
		SuggestedAccount: s.suggestedPlacementAccount(req.Identity),
	}
}

// handlePlacementAccessRequestsAdmin serves /api/v1/placement/admin/requests
// and below; rest is the path after "requests".
func (s *Handler) handlePlacementAccessRequestsAdmin(w http.ResponseWriter, r *http.Request, rest string) {
	if !s.requireAdmin(w, r) {
		return
	}
	store := s.placementOnboard.requests
	if store == nil {
		s.writeError(w, http.StatusServiceUnavailable, "Access requests are not available on this server.")
		return
	}
	rest = strings.Trim(rest, "/")
	switch rest {
	case "":
		if !placementMethod(s, w, r, http.MethodGet) {
			return
		}
		s.listPlacementAccessRequests(w, r)
		return
	case "count":
		if !placementMethod(s, w, r, http.MethodGet) {
			return
		}
		n, err := store.countPending(r.Context())
		if err != nil {
			s.writeError(w, http.StatusInternalServerError, "Could not count the requests.")
			return
		}
		s.writeJSON(w, http.StatusOK, map[string]int{"pending": n})
		return
	}

	parts := strings.Split(rest, "/")
	id, err := strconv.ParseInt(parts[0], 10, 64)
	if err != nil || id <= 0 || len(parts) > 2 {
		s.writeError(w, http.StatusNotFound, "Placement admin endpoint not found")
		return
	}
	if len(parts) == 1 {
		if !placementMethod(s, w, r, http.MethodGet) {
			return
		}
		req, err := store.get(r.Context(), id)
		if err != nil {
			s.writeError(w, http.StatusInternalServerError, "Could not read the request.")
			return
		}
		if req == nil {
			s.writeError(w, http.StatusNotFound, fmt.Sprintf("No access request #%d.", id))
			return
		}
		s.writeJSON(w, http.StatusOK, s.accessRequestJSON(req))
		return
	}
	if !placementMethod(s, w, r, http.MethodPost) {
		return
	}
	switch parts[1] {
	case "approve":
		s.approvePlacementAccessRequest(w, r, id)
	case "deny":
		s.denyPlacementAccessRequest(w, r, id)
	case "resolve":
		s.resolvePlacementAccessRequest(w, r, id)
	default:
		s.writeError(w, http.StatusNotFound, "Placement admin endpoint not found")
	}
}

func (s *Handler) listPlacementAccessRequests(w http.ResponseWriter, r *http.Request) {
	store := s.placementOnboard.requests
	status := r.URL.Query().Get("status")
	switch status {
	case "":
		status = accessRequestPending
	case "all":
		status = ""
	case accessRequestPending, accessRequestApproving, accessRequestApproved, accessRequestDenied, accessRequestWithdrawn:
	default:
		s.writeError(w, http.StatusBadRequest, "status must be pending, approving, approved, denied, withdrawn or all")
		return
	}
	// An approval interrupted mid-way gives its request back.
	if _, err := store.releaseStaleApprovals(r.Context()); err != nil {
		s.logger.Warn(logging.DestinationHTTP, "Could not release interrupted approvals", "error", err)
	}
	reqs, err := store.list(r.Context(), status)
	if err != nil {
		s.logger.Error(logging.DestinationHTTP, "Failed to list access requests", "error", err)
		s.writeError(w, http.StatusInternalServerError, "Could not list the requests.")
		return
	}
	pending, err := store.countPending(r.Context())
	if err != nil {
		s.writeError(w, http.StatusInternalServerError, "Could not count the requests.")
		return
	}
	out := placementAccessRequestList{Requests: make([]placementAccessRequestJSON, 0, len(reqs)), Pending: pending}
	for i := range reqs {
		out.Requests = append(out.Requests, *s.accessRequestJSON(&reqs[i]))
	}
	out.CanApprove = s.placementdReady(r.Context()) &&
		s.placementAPIVersion(r.Context()) >= htcondor.PlacementdAPIVersionDirectory
	w.Header().Set("Cache-Control", "no-store")
	s.writeJSON(w, http.StatusOK, out)
}

// pendingAccessRequest loads request id for a decision, writing the error
// response when it does not exist or is no longer pending.
func (s *Handler) pendingAccessRequest(w http.ResponseWriter, r *http.Request, id int64) (*placementAccessRequest, bool) {
	req, err := s.placementOnboard.requests.get(r.Context(), id)
	if err != nil {
		s.writeError(w, http.StatusInternalServerError, "Could not read the request.")
		return nil, false
	}
	if req == nil {
		s.writeError(w, http.StatusNotFound, fmt.Sprintf("No access request #%d.", id))
		return nil, false
	}
	if req.Status != accessRequestPending {
		s.writeError(w, http.StatusConflict, fmt.Sprintf("Access request #%d is already %s.", id, req.Status))
		return nil, false
	}
	return req, true
}

// sessionAdmin is the signed-in admin's username. requireAdmin has already
// checked there is a session.
func (s *Handler) sessionAdmin(r *http.Request) string {
	if session, ok := s.getSessionFromRequest(r); ok {
		return session.Username
	}
	return ""
}

// accessRequestComment is the directory change comment for an approval of
// request id, with the admin's own comment after it.
func accessRequestComment(id int64, comment string) string {
	c := fmt.Sprintf("access request #%d", id)
	if comment != "" {
		c += ": " + comment
	}
	return c
}

// placementIdentityExistsBody is the 409 an approval answers when the
// identity is already in the directory; the UI offers "mark resolved".
type placementIdentityExistsBody struct {
	Error          string `json:"error"`
	Message        string `json:"message"`
	Code           int    `json:"code"`
	IdentityExists bool   `json:"identity_exists"`
}

func (s *Handler) writeIdentityExists(w http.ResponseWriter, identity string) {
	s.writeJSON(w, http.StatusConflict, placementIdentityExistsBody{
		Error:          http.StatusText(http.StatusConflict),
		Message:        fmt.Sprintf("The identity %s is already in the directory.", identity),
		Code:           http.StatusConflict,
		IdentityExists: true,
	})
}

func (s *Handler) approvePlacementAccessRequest(w http.ResponseWriter, r *http.Request, id int64) {
	if !s.placementdReady(r.Context()) {
		s.writeError(w, http.StatusServiceUnavailable,
			"No condor_placementd is available. Set PLACEMENTD_ADDRESS_FILE or run one in the pool.")
		return
	}
	if v := s.placementAPIVersion(r.Context()); v < htcondor.PlacementdAPIVersionDirectory {
		s.writeError(w, http.StatusNotImplemented, fmt.Sprintf(
			"This placementd does not support directory management (API version %d; %d is required).",
			v, htcondor.PlacementdAPIVersionDirectory))
		return
	}

	body, in, comment, ok := s.decodeApproval(w, r)
	if !ok {
		return
	}
	account := in.account

	req, ok := s.pendingAccessRequest(w, r, id)
	if !ok {
		return
	}
	ctx := placementContext(r)

	// An identity already in the directory (onboarded some other way) is
	// not created again; the admin marks the request resolved instead.
	found, err := s.placementd.Query(ctx, htcondor.PlacementQuery{
		TargetType: htcondor.PlacementTargetIdentity, Key: req.Identity, Limit: 1,
	})
	if err != nil {
		s.writePlacementAdminError(w, "look up the identity", err, nil)
		return
	}
	for _, o := range found {
		if o.Identity != nil {
			s.writeIdentityExists(w, req.Identity)
			return
		}
	}
	accounts, err := s.placementd.Query(ctx, htcondor.PlacementQuery{
		TargetType: htcondor.PlacementTargetAccount, Key: account, Limit: 1,
	})
	if err != nil {
		s.writePlacementAdminError(w, "look up the account", err, nil)
		return
	}
	var existing *htcondor.PlacementAccount
	for _, o := range accounts {
		if o.Account != nil {
			existing = o.Account
		}
	}
	// Another identity's account is shared from now on; that takes the
	// admin's say-so, given with what the account holds in front of them.
	if existing != nil && !body.AttachToExisting {
		acct, _ := placementObjectJSON(htcondor.PlacementObject{Account: existing}).(placementAccountJSON)
		s.writeJSON(w, http.StatusConflict, placementAccountExistsBody{
			Error: http.StatusText(http.StatusConflict),
			Message: fmt.Sprintf("The account %s already exists, with %d identities. Confirm attaching this identity to it.",
				existing.Name, len(existing.Identities)),
			Code:          http.StatusConflict,
			AccountExists: true,
			Account:       &acct,
		})
		return
	}

	ops := accessRequestApproveOps(req, in, existing != nil)

	admin := s.sessionAdmin(r)
	dryRun := body.DryRun || placementDryRun(r)
	store := s.placementOnboard.requests
	// Held while the directory changes, so it cannot be withdrawn or
	// denied under the admin. A dry run changes nothing and holds nothing.
	if !dryRun {
		if _, err := store.beginApproval(r.Context(), id, admin); !s.writeDecisionError(w, id, err) {
			return
		}
	}
	opts := htcondor.PlacementEditOptions{
		DryRun:     dryRun,
		OnBehalfOf: admin,
		Comment:    accessRequestComment(id, comment),
	}
	results, err := s.placementd.Edit(ctx, ops, opts)
	out := make([]placementEditResultJSON, 0, len(results))
	for _, res := range results {
		out = append(out, placementEditResultJSON{
			Index: res.Index, ID: res.ID, Version: res.Version,
			Warning: res.Warning, ErrorCode: res.ErrorCode, Error: res.ErrorString,
		})
	}
	s.logger.Info(logging.DestinationSecurity, "Access request approval",
		"admin", admin, "request", id, "identity", req.Identity, "account", account,
		"operations", len(ops), "dry_run", dryRun, "error", err)
	if err != nil {
		// Nothing was granted: the request is pending again.
		if !dryRun {
			if aerr := store.abandonApproval(context.WithoutCancel(r.Context()), id); aerr != nil {
				s.logger.Error(logging.DestinationHTTP, "Could not return an access request to pending", "request", id, "error", aerr)
			}
		}
		var perr *htcondor.PlacementError
		identityOp := len(ops) - 1
		if errors.As(err, &perr) && perr.Code == htcondor.PlacementErrDuplicate &&
			identityOp < len(results) && results[identityOp].ErrorCode == htcondor.PlacementErrDuplicate {
			s.writeIdentityExists(w, req.Identity)
			return
		}
		s.writePlacementAdminError(w, "approve the request", err, out)
		return
	}
	resp := placementApproveResponse{
		placementBatchResponse: placementBatchResponse{Committed: !dryRun, DryRun: dryRun, Results: out},
	}
	if dryRun {
		s.writeJSON(w, http.StatusOK, resp)
		return
	}

	decided, err := store.finishApproval(context.WithoutCancel(r.Context()), id, placementAccessDecision{
		By:          admin,
		Note:        comment,
		Account:     account,
		ChangesetID: s.placementChangesetID(r, results, len(ops)-1),
	})
	if err != nil {
		// The directory change committed; only the bookkeeping is off.
		s.logger.Warn(logging.DestinationHTTP, "Approved an access request the directory now reflects, but could not record it",
			"request", id, "error", err)
	}
	resp.Request = s.accessRequestJSON(decided)
	s.writeJSON(w, http.StatusOK, resp)
}

// decodeApproval reads and checks an approval's body, writing the error
// response when it is refused.
func (s *Handler) decodeApproval(w http.ResponseWriter, r *http.Request) (placementApproveBody, approveInput, string, bool) {
	setBodyLimit(w, r, 1<<16)
	var body placementApproveBody
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(&body); err != nil {
		s.writeError(w, http.StatusBadRequest, fmt.Sprintf("Invalid request body: %v", err))
		return body, approveInput{}, "", false
	}
	account := strings.TrimSpace(body.Account)
	if account == "" {
		s.writeError(w, http.StatusBadRequest, "account is required")
		return body, approveInput{}, "", false
	}
	if err := s.checkPlacementAccountName(account); err != nil {
		s.writeError(w, http.StatusBadRequest, capitalize(err.Error())+".")
		return body, approveInput{}, "", false
	}
	comment, err := cleanAccessRequestText("comment", body.Comment)
	if err != nil {
		s.writeError(w, http.StatusBadRequest, capitalize(err.Error())+".")
		return body, approveInput{}, "", false
	}
	var expires any
	if len(body.ExpiresAt) > 0 && strings.TrimSpace(string(body.ExpiresAt)) != "null" {
		expires, err = placementFieldValue(placementFieldSpec{attr: "ExpiresAt", kind: placementFieldTime}, body.ExpiresAt)
		if err != nil {
			s.writeError(w, http.StatusBadRequest, "expires_at "+err.Error())
			return body, approveInput{}, "", false
		}
		if t, ok := expires.(time.Time); ok && !t.After(time.Now()) {
			s.writeError(w, http.StatusBadRequest, "expires_at is in the past")
			return body, approveInput{}, "", false
		}
	}
	return body, approveInput{
		account:        account,
		authorizations: trimmedStrings(body.Authorizations),
		projects:       trimmedStrings(body.Projects),
		defaultProject: strings.TrimSpace(body.DefaultProject),
		expires:        expires,
		displayName:    strings.TrimSpace(body.DisplayName),
	}, comment, true
}

// approveInput is an approval's account and grants.
type approveInput struct {
	account        string
	authorizations []string
	projects       []string
	defaultProject string
	expires        any
	displayName    string
}

// accessRequestApproveOps is the batch that onboards req's identity: the
// account created when it does not exist, then the identity, keyed by the
// request's identity, mapped to it. An existing account is never changed:
// its grants are those of every identity mapped to it, and they are
// changed on the directory page, where that is visible. The identity is
// always the last operation.
func accessRequestApproveOps(req *placementAccessRequest, in approveInput, accountExists bool) []htcondor.PlacementOp {
	var ops []htcondor.PlacementOp
	if !accountExists {
		fields := map[string]any{
			"Name":           in.account,
			"Authorizations": nonNilStrings(in.authorizations),
			"Projects":       nonNilStrings(in.projects),
		}
		if in.defaultProject != "" {
			fields["DefaultProject"] = in.defaultProject
		}
		ops = append(ops, htcondor.PlacementOp{
			Operation: htcondor.PlacementOpCreate, TargetType: htcondor.PlacementTargetAccount, Fields: fields,
		})
	}
	identity := map[string]any{
		"Identity": req.Identity,
		"Account":  in.account,
	}
	if in.expires != nil {
		identity["ExpiresAt"] = in.expires
	}
	if in.displayName != "" {
		identity["DisplayName"] = in.displayName
	}
	ops = append(ops, htcondor.PlacementOp{
		Operation: htcondor.PlacementOpCreate, TargetType: htcondor.PlacementTargetIdentity, Fields: identity,
	})
	return ops
}

func trimmedStrings(in []string) []string {
	out := make([]string, 0, len(in))
	for _, v := range in {
		if v = strings.TrimSpace(v); v != "" {
			out = append(out, v)
		}
	}
	return out
}

// placementChangesetID is the change set a committed approval made, or 0
// when it cannot be told: a ChangesetId on a result, else the identity's
// newest history entry, provided that entry is the one the batch wrote.
func (s *Handler) placementChangesetID(r *http.Request, results []htcondor.PlacementEditResult, identityOp int) int64 {
	for _, res := range results {
		if res.Ad == nil {
			continue
		}
		if v, ok := res.Ad.EvaluateAttrInt("ChangesetId"); ok && v > 0 {
			return v
		}
	}
	if identityOp < 0 || identityOp >= len(results) || results[identityOp].ID == "" {
		return 0
	}
	created := results[identityOp]
	objs, err := s.placementd.Query(placementContext(r), htcondor.PlacementQuery{
		TargetType: htcondor.PlacementTargetModification, EntityID: created.ID, Limit: 1,
	})
	if err != nil {
		s.logger.Debug(logging.DestinationHTTP, "Could not read the approval's change set", "error", err)
		return 0
	}
	for _, o := range objs {
		if m := o.Modification; m != nil && m.EntityID == created.ID && (created.Version == 0 || m.ID == created.Version) {
			return m.ChangesetID
		}
	}
	return 0
}

func (s *Handler) denyPlacementAccessRequest(w http.ResponseWriter, r *http.Request, id int64) {
	setBodyLimit(w, r, 1<<14)
	var body struct {
		Reason string `json:"reason"`
	}
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(&body); err != nil {
		s.writeError(w, http.StatusBadRequest, fmt.Sprintf("Invalid request body: %v", err))
		return
	}
	reason, err := cleanAccessRequestText("reason", body.Reason)
	if err != nil {
		s.writeError(w, http.StatusBadRequest, capitalize(err.Error())+".")
		return
	}
	if reason == "" {
		s.writeError(w, http.StatusBadRequest, "A reason is required.")
		return
	}
	if _, ok := s.pendingAccessRequest(w, r, id); !ok {
		return
	}
	admin := s.sessionAdmin(r)
	req, err := s.placementOnboard.requests.decide(r.Context(), id, placementAccessDecision{
		Status: accessRequestDenied, By: admin, Note: reason,
	})
	if !s.writeDecisionError(w, id, err) {
		return
	}
	s.logger.Info(logging.DestinationSecurity, "Access request denied",
		"admin", admin, "request", id, "identity", req.Identity)
	s.writeJSON(w, http.StatusOK, s.accessRequestJSON(req))
}

// resolvePlacementAccessRequest marks a request approved without changing
// the directory, for an identity that was given access some other way. It
// checks the placementd: the identity must have access now.
func (s *Handler) resolvePlacementAccessRequest(w http.ResponseWriter, r *http.Request, id int64) {
	if !s.placementdReady(r.Context()) {
		s.writeError(w, http.StatusServiceUnavailable,
			"No condor_placementd is available. Set PLACEMENTD_ADDRESS_FILE or run one in the pool.")
		return
	}
	setBodyLimit(w, r, 1<<14)
	var body struct {
		Comment string `json:"comment"`
	}
	raw, ok := s.decodeOptionalPlacementObject(w, r)
	if !ok {
		return
	}
	if c, present := raw["comment"]; present {
		if err := json.Unmarshal(c, &body.Comment); err != nil {
			s.writeError(w, http.StatusBadRequest, "comment must be a string")
			return
		}
		delete(raw, "comment")
	}
	if len(raw) > 0 {
		s.writeError(w, http.StatusBadRequest, "resolving takes only comment")
		return
	}
	comment, err := cleanAccessRequestText("comment", body.Comment)
	if err != nil {
		s.writeError(w, http.StatusBadRequest, capitalize(err.Error())+".")
		return
	}
	req, ok := s.pendingAccessRequest(w, r, id)
	if !ok {
		return
	}
	users, err := s.placementd.QueryUsers(placementContext(r), req.Identity)
	if err != nil {
		s.writePlacementError(w, "look up the identity", err)
		return
	}
	var user *htcondor.PlacementUser
	for i := range users {
		if users[i].UserName == req.Identity {
			user = &users[i]
		}
	}
	if user == nil || !user.Authorized ||
		(!user.MappingExpiration.IsZero() && user.MappingExpiration.Before(time.Now())) {
		s.writeError(w, http.StatusConflict, fmt.Sprintf("The identity %s does not have access yet.", req.Identity))
		return
	}
	admin := s.sessionAdmin(r)
	decided, err := s.placementOnboard.requests.decide(r.Context(), id, placementAccessDecision{
		Status: accessRequestApproved, By: admin, Note: comment, Account: user.APUserID,
	})
	if !s.writeDecisionError(w, id, err) {
		return
	}
	s.logger.Info(logging.DestinationSecurity, "Access request marked resolved",
		"admin", admin, "request", id, "identity", req.Identity, "account", user.APUserID)
	s.writeJSON(w, http.StatusOK, s.accessRequestJSON(decided))
}

// writeDecisionError writes the response for a failed decide and reports
// whether there was no failure.
func (s *Handler) writeDecisionError(w http.ResponseWriter, id int64, err error) bool {
	switch {
	case err == nil:
		return true
	case errors.Is(err, sql.ErrNoRows):
		s.writeError(w, http.StatusNotFound, fmt.Sprintf("No access request #%d.", id))
	case errors.Is(err, errAccessRequestNotPending):
		s.writeError(w, http.StatusConflict, fmt.Sprintf("Access request #%d was decided or withdrawn meanwhile.", id))
	default:
		s.logger.Error(logging.DestinationHTTP, "Failed to record an access request decision", "request", id, "error", err)
		s.writeError(w, http.StatusInternalServerError, "Could not record the decision.")
	}
	return false
}

// sweepPlacementAccessRequests gives back requests whose approval was
// interrupted, and deletes approved, denied and withdrawn requests older
// than the retention: they hold the requester's provider subject, name,
// email and note, which are not needed once the request is settled.
func (s *Handler) sweepPlacementAccessRequests(ctx context.Context) {
	store := s.placementOnboard.requests
	if store == nil {
		return
	}
	if n, err := store.releaseStaleApprovals(ctx); err != nil {
		s.logger.Warn(logging.DestinationHTTP, "Could not release interrupted approvals", "error", err)
	} else if n > 0 {
		s.logger.Info(logging.DestinationHTTP, "Released interrupted access request approvals", "count", n)
	}
	n, err := store.deleteClosedBefore(ctx, store.now().Add(-s.placementOnboard.requestRetention))
	if err != nil {
		s.logger.Warn(logging.DestinationHTTP, "Could not delete old access requests", "error", err)
		return
	}
	if n > 0 {
		s.logger.Info(logging.DestinationHTTP, "Deleted old access requests", "count", n,
			"retention", s.placementOnboard.requestRetention)
	}
}
