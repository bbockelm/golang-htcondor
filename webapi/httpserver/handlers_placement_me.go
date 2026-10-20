package httpserver

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	htcondor "github.com/bbockelm/golang-htcondor"
	"github.com/bbockelm/golang-htcondor/logging"
)

// The user-facing placement endpoints, /api/v1/placement/me*. Any signed-in
// session reaches them, placement-only sessions included. See
// placement_onboarding.go for the invariant they keep: the identity sent
// to the placementd is the session's, never the request's.

// placementMeAuthorization is one authorization the person may request,
// with the operator's display metadata.
type placementMeAuthorization struct {
	Name        string `json:"name"`
	Label       string `json:"label,omitempty"`
	Color       string `json:"color,omitempty"`
	Description string `json:"description,omitempty"`
}

// placementMeProject is one project the person may bind a token to.
type placementMeProject struct {
	Name string `json:"name"`
	// Default is the first project on the person's map file line.
	Default bool `json:"default"`
	// Enabled is false when the schedd's project record is disabled. No
	// record counts as enabled: nobody has disabled it.
	Enabled bool `json:"enabled"`
}

// placementMeResponse is GET /api/v1/placement/me.
type placementMeResponse struct {
	Identity    string `json:"identity"`
	DisplayName string `json:"display_name,omitempty"`
	// Authorized is whether the placementd will issue this identity a
	// token at all.
	Authorized bool `json:"authorized"`
	// Expired is whether the identity's mapping has passed its expiry.
	Expired           bool       `json:"expired"`
	MappingExpiration *time.Time `json:"mapping_expiration,omitempty"`
	// Account is the AP account tokens are issued for.
	Account        string                     `json:"account,omitempty"`
	Authorizations []placementMeAuthorization `json:"authorizations"`
	Projects       []placementMeProject       `json:"projects"`
	// AccountEnabled is false when the schedd's record for Account is
	// disabled: a token still issues, but jobs will not be accepted.
	AccountEnabled bool `json:"account_enabled"`
	// RecordsAvailable is false when the schedd could not be asked about
	// account and project records; the enabled flags then say nothing.
	RecordsAvailable bool `json:"records_available"`
}

// placementTokenRequest is POST /api/v1/placement/me/token. It names no
// user: the token is always for the session's own identity, and a body
// carrying any other field is refused.
type placementTokenRequest struct {
	Project        string   `json:"project"`
	Authorizations []string `json:"authorizations"`
	// UserCode, when set, binds the token to that pending device request
	// instead of returning it.
	UserCode string `json:"user_code,omitempty"`
}

// placementMeTokenResponse is the 201 answer to a token request.
type placementMeTokenResponse struct {
	// Token is absent when it was bound to a device request.
	Token          string     `json:"token,omitempty"`
	APUserID       string     `json:"ap_user_id,omitempty"`
	IssuedAt       *time.Time `json:"issued_at,omitempty"`
	ExpiresAt      *time.Time `json:"expires_at,omitempty"`
	Project        string     `json:"project"`
	Authorizations []string   `json:"authorizations"`
	// UserConfig is the ~/.condor/user_config lines that point an
	// HTCondor client at this access point.
	UserConfig string `json:"user_config,omitempty"`
	// Device names the request the token went to, when it did.
	Device *placementDeviceInfo `json:"device,omitempty"`
}

// handlePlacementMePath dispatches /api/v1/placement/me and below. rest is
// the path after "me", without leading slash.
func (s *Handler) handlePlacementMePath(w http.ResponseWriter, r *http.Request, rest string) {
	// A bearer access token holding the placement scope acts for
	// the identity recorded on its grant, and may use only /me and
	// /me/token.
	session, isBearer, err := s.placementBearerIdentity(r)
	if isBearer {
		if err != nil {
			s.writeOAuthError(w, http.StatusUnauthorized, "invalid_token",
				"A token holding the placement scope is required")
			return
		}
		if !placementBearerAllowed(r.Method, r.URL.Path) {
			s.writeError(w, http.StatusForbidden, "A placement token can only request a placement token.")
			return
		}
	} else {
		var ok bool
		session, ok = s.getAnySessionFromRequest(r)
		if !ok {
			s.writeError(w, http.StatusUnauthorized, "Authentication required")
			return
		}
	}
	// State-changing calls from a browser carry a header a cross-site
	// form cannot set. A bearer token is not attached by a browser.
	if !isBearer && r.Method != http.MethodGet && r.Method != http.MethodHead && r.Header.Get("X-Requested-With") == "" {
		s.writeError(w, http.StatusForbidden, "Missing X-Requested-With header")
		return
	}
	if !s.placementOnboardingEnabled(r.Context()) {
		s.writeError(w, http.StatusServiceUnavailable, "Placement tokens are not available on this server.")
		return
	}

	switch {
	case rest == "":
		if r.Method != http.MethodGet {
			s.writeError(w, http.StatusMethodNotAllowed, "Method not allowed")
			return
		}
		s.handlePlacementMe(w, r, session)
	case rest == "token":
		if r.Method != http.MethodPost {
			s.writeError(w, http.StatusMethodNotAllowed, "Method not allowed")
			return
		}
		s.handlePlacementMeToken(w, r, session)
	case rest == "request":
		s.handlePlacementMeRequest(w, r, session)
	case rest == "project":
		if r.Method != http.MethodPost {
			s.writeError(w, http.StatusMethodNotAllowed, "Method not allowed")
			return
		}
		s.handlePlacementMeProject(w, r, session)
	case strings.HasPrefix(rest, "device/"):
		parts := strings.Split(strings.TrimPrefix(rest, "device/"), "/")
		code, err := url.PathUnescape(parts[0])
		if err != nil || code == "" {
			s.writeError(w, http.StatusNotFound, "Placement endpoint not found")
			return
		}
		switch {
		case len(parts) == 1:
			s.placementDeviceLookup(w, r, code)
		case len(parts) == 2 && parts[1] == "deny":
			if r.Method != http.MethodPost {
				s.writeError(w, http.StatusMethodNotAllowed, "Method not allowed")
				return
			}
			s.placementDeviceDeny(w, r, code)
		default:
			s.writeError(w, http.StatusNotFound, "Placement endpoint not found")
		}
	default:
		s.writeError(w, http.StatusNotFound, "Placement endpoint not found")
	}
}

// placementSelf is what the placementd says about the session's identity.
type placementSelf struct {
	user       *htcondor.PlacementUser
	authorized bool
	expired    bool
}

// lookupPlacementSelf asks the placementd about identity, which the caller
// took from the session.
func (s *Handler) lookupPlacementSelf(r *http.Request, identity string) (placementSelf, error) {
	users, err := s.placementd.QueryUsers(placementUserContext(r), identity)
	if err != nil {
		return placementSelf{}, err
	}
	var out placementSelf
	for i := range users {
		if users[i].UserName == identity {
			out.user = &users[i]
			break
		}
	}
	if out.user == nil {
		return out, nil
	}
	out.expired = !out.user.MappingExpiration.IsZero() && out.user.MappingExpiration.Before(time.Now())
	out.authorized = out.user.Authorized && !out.expired
	return out, nil
}

func (s *Handler) handlePlacementMe(w http.ResponseWriter, r *http.Request, session *SessionData) {
	resp := placementMeResponse{
		Identity:       session.PlacementIdentity,
		DisplayName:    session.DisplayName,
		Authorizations: []placementMeAuthorization{},
		Projects:       []placementMeProject{},
		AccountEnabled: true,
	}
	if session.PlacementIdentity == "" {
		s.writeJSON(w, http.StatusOK, resp)
		return
	}

	self, err := s.lookupPlacementSelf(r, session.PlacementIdentity)
	if err != nil {
		s.writePlacementUserError(w, "look up your placement identity", err)
		return
	}
	resp.Authorized, resp.Expired = self.authorized, self.expired
	if self.user != nil {
		resp.Account = self.user.APUserID
		resp.MappingExpiration = optionalTime(self.user.MappingExpiration)
	}
	if !resp.Authorized {
		s.writeJSON(w, http.StatusOK, resp)
		return
	}

	authz, err := s.placementd.QueryAuthorizations(placementUserContext(r), session.PlacementIdentity)
	if err != nil {
		var perr *htcondor.PlacementError
		if !errors.As(err, &perr) || (perr.Code != htcondor.PlacementErrUserNotAuthorized &&
			perr.Code != htcondor.PlacementErrUserMappingExpired) {
			s.writePlacementUserError(w, "list your authorizations", err)
			return
		}
		// The mapping went away between the two calls.
		resp.Authorized = false
		s.writeJSON(w, http.StatusOK, resp)
		return
	}
	for _, a := range authz {
		resp.Authorizations = append(resp.Authorizations, placementMeAuthorization(a))
	}
	for i, p := range self.user.Projects {
		resp.Projects = append(resp.Projects, placementMeProject{Name: p, Default: i == 0, Enabled: true})
	}

	resp.RecordsAvailable = s.fillPlacementRecordFlags(r, &resp)
	s.writeJSON(w, http.StatusOK, resp)
}

// fillPlacementRecordFlags sets the account and project Enabled flags from
// the schedd's records, and reports whether it could ask. A missing record
// is enabled, as pdwebapp treats it: a disable needs a record to write to.
func (s *Handler) fillPlacementRecordFlags(r *http.Request, resp *placementMeResponse) bool {
	records := s.placementRecords()
	if records == nil {
		return false
	}
	ctx := htcondor.WithDaemonCredential(r.Context(), "placement onboarding: schedd record flags")
	ok := true
	if resp.Account != "" {
		recs, err := records.QueryUserRecords(ctx, &htcondor.UserRecordQueryOptions{
			Constraint: "User == " + classadString(resp.Account),
			Projection: []string{"User", "Name", "Enabled"},
		})
		if err != nil {
			s.logger.Warn(logging.DestinationHTTP, "Could not read the schedd's user record", "account", resp.Account, "error", err)
			ok = false
		}
		for i := range recs {
			if recs[i].IsDisabled() {
				resp.AccountEnabled = false
			}
		}
	}
	if len(resp.Projects) > 0 {
		clauses := make([]string, 0, len(resp.Projects))
		for _, p := range resp.Projects {
			clauses = append(clauses, "Name == "+classadString(p.Name))
		}
		recs, err := records.QueryProjectRecords(ctx, &htcondor.UserRecordQueryOptions{
			Constraint: strings.Join(clauses, " || "),
			Projection: []string{"Name", "Enabled"},
		})
		if err != nil {
			s.logger.Warn(logging.DestinationHTTP, "Could not read the schedd's project records", "error", err)
			ok = false
		}
		for i := range resp.Projects {
			for j := range recs {
				if strings.EqualFold(recs[j].User, resp.Projects[i].Name) && recs[j].IsDisabled() {
					resp.Projects[i].Enabled = false
				}
			}
		}
	}
	return ok
}

func (s *Handler) handlePlacementMeToken(w http.ResponseWriter, r *http.Request, session *SessionData) {
	identity := session.PlacementIdentity
	if identity == "" {
		s.writeError(w, http.StatusForbidden, "Your sign-in did not provide an identity the placement service knows.")
		return
	}

	setBodyLimit(w, r, 1<<16)
	var req placementTokenRequest
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(&req); err != nil {
		s.writeError(w, http.StatusBadRequest, fmt.Sprintf("Invalid request body: %v", err))
		return
	}
	project := sanitizePlacementProject(req.Project)
	if project == "" {
		s.writeError(w, http.StatusBadRequest, "Select a project.")
		return
	}
	if len(req.Authorizations) == 0 {
		s.writeError(w, http.StatusBadRequest, "Select at least one permission.")
		return
	}

	var userCode string
	if req.UserCode != "" && s.bearerRequest(r) {
		s.writeError(w, http.StatusBadRequest, "user_code is for the browser confirmation page.")
		return
	}
	if req.UserCode != "" {
		userCode = normalizePlacementUserCode(req.UserCode)
		if userCode == "" {
			s.writeError(w, http.StatusBadRequest, "The code must look like XXXX-XXXX.")
			return
		}
		if s.placementOnboard.devices == nil {
			s.writeError(w, http.StatusServiceUnavailable, "Device requests are not available on this server.")
			return
		}
		// Checked before minting, so a stale code does not leave a token
		// nobody can collect.
		grant, err := s.placementOnboard.devices.byUserCode(r.Context(), userCode)
		if err != nil {
			s.writeError(w, http.StatusInternalServerError, "Could not read the device request.")
			return
		}
		if grant == nil {
			s.writeError(w, http.StatusNotFound, "That code was not recognized.")
			return
		}
		if grant.State != placementDeviceStatePending || grant.expired(s.placementOnboard.devices.now().Unix()) {
			s.writeError(w, http.StatusConflict, "That device request has already been answered or has expired.")
			return
		}
	}

	self, err := s.lookupPlacementSelf(r, identity)
	if err != nil {
		s.writePlacementUserError(w, "look up your placement identity", err)
		return
	}
	if !self.authorized {
		s.writeError(w, http.StatusForbidden, "Your identity is not authorized to receive a token on this access point.")
		return
	}

	// Only the authorizations offered to this person may be asked for,
	// as on pdwebapp's form: grants the operator did not make requestable
	// (INSTRUCTOR, say) are not for a self-service token.
	offered, err := s.placementd.QueryAuthorizations(placementUserContext(r), identity)
	if err != nil {
		s.writePlacementUserError(w, "list your authorizations", err)
		return
	}
	authz := make([]string, 0, len(req.Authorizations))
	for _, want := range req.Authorizations {
		found := ""
		for _, a := range offered {
			if strings.EqualFold(a.Name, want) {
				found = a.Name
				break
			}
		}
		if found == "" {
			s.writeError(w, http.StatusBadRequest, fmt.Sprintf("The permission %q is not available to you.", want))
			return
		}
		authz = append(authz, found)
	}

	result, err := s.placementd.Login(placementUserContext(r), htcondor.PlacementLoginRequest{
		UserName:       identity,
		Requester:      identity,
		Authorizations: authz,
		Project:        project,
	})
	if err != nil {
		s.writePlacementUserError(w, "issue a token", err)
		return
	}

	resp := placementMeTokenResponse{
		APUserID:       self.user.APUserID,
		Project:        project,
		Authorizations: authz,
		UserConfig:     s.placementUserConfig(),
	}
	claims := decodePlacementTokenClaims(result.Token)
	var expUnix int64
	if v, ok := jsonNumberClaim(claims, "iat"); ok {
		t := time.Unix(v, 0).UTC()
		resp.IssuedAt = &t
	}
	if v, ok := jsonNumberClaim(claims, "exp"); ok {
		expUnix = v
		t := time.Unix(v, 0).UTC()
		resp.ExpiresAt = &t
	}
	if sub, ok := claims["sub"].(string); ok && sub != "" {
		resp.APUserID = sub
	}

	jti, _ := claims["jti"].(string)
	if userCode != "" {
		if err := s.placementOnboard.devices.approve(r.Context(), userCode, identity, result.Token, expUnix); err != nil {
			if errors.Is(err, errPlacementDeviceGrantGone) {
				s.writeError(w, http.StatusConflict, "That device request has already been answered or has expired.")
				return
			}
			s.logger.Error(logging.DestinationHTTP, "Failed to bind a placement token to a device request", "error", err)
			s.writeError(w, http.StatusInternalServerError, "Could not complete the device request.")
			return
		}
		grant, _ := s.placementOnboard.devices.byUserCode(r.Context(), userCode)
		if grant != nil {
			resp.Device = &placementDeviceInfo{
				UserCode:   grant.UserCode,
				ClientID:   grant.ClientID,
				ClientName: placementDeviceClientName(grant.ClientID),
				State:      grant.State,
				ExpiresAt:  time.Unix(grant.ExpiresAt, 0).UTC(),
			}
		}
	} else {
		resp.Token = result.Token
	}

	s.logger.Info(logging.DestinationSecurity, "Placement token issued",
		"identity", identity, "account", resp.APUserID, "project", project,
		"authorizations", authz, "token_id", jti, "device", userCode != "")
	w.Header().Set("Cache-Control", "no-store")
	s.writeJSON(w, http.StatusCreated, resp)
}

// sanitizePlacementProject is pdwebapp's util.sanitize_project:
// re.sub(r"[^\w_-]+", "_", project.strip())[:64].
func sanitizePlacementProject(project string) string {
	project = strings.TrimFunc(project, pythonIsSpace)
	if project == "" {
		return ""
	}
	var b strings.Builder
	inRun := false
	for _, r := range project {
		if r == '-' || pythonIsWord(r) {
			b.WriteRune(r)
			inRun = false
			continue
		}
		if !inRun {
			b.WriteByte('_')
			inRun = true
		}
	}
	out := []rune(b.String())
	if len(out) > 64 {
		out = out[:64]
	}
	return string(out)
}

func jsonUnmarshalUseNumber(data []byte, v any) error {
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.UseNumber()
	return dec.Decode(v)
}

// jsonNumberClaim reads an integer claim decoded with UseNumber.
func jsonNumberClaim(claims map[string]any, name string) (int64, bool) {
	n, ok := claims[name].(json.Number)
	if !ok {
		return 0, false
	}
	if v, err := n.Int64(); err == nil {
		return v, true
	}
	if f, err := n.Float64(); err == nil {
		return int64(f), true
	}
	return 0, false
}

// handlePlacementMeProject is POST /api/v1/placement/me/project {project}:
// selects the project a placementd session's tokens name. Only a project the
// account has.
func (s *Handler) handlePlacementMeProject(w http.ResponseWriter, r *http.Request, session *SessionData) {
	if !session.IsPlacementd() {
		s.writeError(w, http.StatusConflict, "This sign-in has no account whose project can be selected.")
		return
	}
	setBodyLimit(w, r, 1<<12)
	var req struct {
		Project string `json:"project"`
	}
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(&req); err != nil {
		s.writeError(w, http.StatusBadRequest, fmt.Sprintf("Invalid request body: %v", err))
		return
	}
	chosen := ""
	for _, p := range session.Placement.Projects {
		if strings.EqualFold(p, strings.TrimSpace(req.Project)) {
			chosen = p
		}
	}
	if chosen == "" {
		s.writeError(w, http.StatusBadRequest, fmt.Sprintf("%q is not one of your projects.", req.Project))
		return
	}
	sid, err := getSessionCookie(r)
	if err != nil {
		s.writeError(w, http.StatusUnauthorized, "Authentication required")
		return
	}
	info := *session.Placement
	info.Project = chosen
	if err := s.sessionStore.UpdatePlacement(sid, &info, session.ExpiresAt); err != nil {
		s.writeError(w, http.StatusInternalServerError, "Could not select the project.")
		return
	}
	updated := *session
	updated.Placement = &info
	if err := s.recordPlacementSubject(r.Context(), &updated); err != nil {
		s.logger.Warn(logging.DestinationHTTP, "Could not record the selected project for OAuth2 grants",
			"account", info.Account, "error", err)
	}
	s.logger.Info(logging.DestinationHTTP, "Selected a project for a placementd session",
		"account", info.Account, "project", chosen)
	s.writeJSON(w, http.StatusOK, map[string]string{"project": chosen})
}

// bearerRequest reports whether the request authenticated with a bearer.
func (s *Handler) bearerRequest(r *http.Request) bool {
	tok, err := extractBearerToken(r)
	return err == nil && tok != ""
}
