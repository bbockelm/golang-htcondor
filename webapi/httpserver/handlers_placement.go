package httpserver

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	htcondor "github.com/bbockelm/golang-htcondor"
)

// The placement endpoints are a thin, JSON-shaped view of condor_placementd.
//
// Every one of them is admin-gated. The placementd registers all four of its
// commands at ADMINISTRATOR, and this server talks to it as the AP's own
// identity — so an endpoint reachable by any signed-in user would let that
// user mint a bearer token for any identity in the placementd's map file.
// requireAdmin is what keeps the API's authorization at least as strict as
// the daemon's.

// placementUserResponse is one row of the users view.
type placementUserResponse struct {
	UserName string `json:"username"`
	// APUserID is the local AP account the foreign identity maps to.
	APUserID string `json:"ap_user_id,omitempty"`
	// TokenExpiration is when this user's newest live token runs out.
	// Absent when they hold no unexpired token.
	TokenExpiration *time.Time `json:"token_expiration,omitempty"`
	// MappingExpiration is when the map-file entry stops being honored.
	// Absent means it never does.
	MappingExpiration *time.Time `json:"mapping_expiration,omitempty"`
	Projects          []string   `json:"projects,omitempty"`
	Authorizations    []string   `json:"authorizations,omitempty"`
	// Authorized is false for a user who still holds a live token but is
	// no longer in the map file: their existing tokens work, but they
	// cannot log in again.
	Authorized bool `json:"authorized"`
}

// placementTokenResponse is one issued token. The token itself is not stored
// by the daemon and is never returned here — only its jti and claims.
type placementTokenResponse struct {
	TokenID        string     `json:"token_id"`
	UserName       string     `json:"username"`
	APUserID       string     `json:"ap_user_id,omitempty"`
	Requester      string     `json:"requester,omitempty"`
	Authorizations []string   `json:"authorizations,omitempty"`
	Project        string     `json:"project,omitempty"`
	Expiration     *time.Time `json:"expiration,omitempty"`
	// Expired is computed server-side so a UI does not have to agree with
	// us about the current time.
	Expired bool `json:"expired"`
}

// placementAuthorizationResponse is one grantable authorization, including the
// display metadata the placementd's authorizations map file carries.
type placementAuthorizationResponse struct {
	Name        string `json:"name"`
	Label       string `json:"label,omitempty"`
	Color       string `json:"color,omitempty"`
	Description string `json:"description,omitempty"`
}

// placementLoginRequest is the POST body for minting a token.
type placementLoginRequest struct {
	// Username is the foreign identity to log in. Required.
	Username string `json:"username"`
	// Authorizations narrows the token's bounding set. Every entry must be
	// one the user is entitled to or the whole request is refused. Empty
	// means the user's full set.
	Authorizations []string `json:"authorizations,omitempty"`
	// Project ties the token to an AP project the user is authorized for.
	Project string `json:"project,omitempty"`
	// Requester is the identity asking on the user's behalf; it needs the
	// INSTRUCTOR authorization. Empty means the user asks for themselves.
	Requester string `json:"requester,omitempty"`
}

// placementLoginResponse carries the minted token. The token is a bearer
// credential for the AP identity it names, so it is returned exactly once and
// never logged.
type placementLoginResponse struct {
	Token string `json:"token"`
}

// placementStatusResponse tells a UI whether the placement feature is usable
// before it renders navigation for it.
type placementStatusResponse struct {
	Available bool   `json:"available"`
	Address   string `json:"address,omitempty"`
	// Reason explains an Available=false, so an operator sees why in the
	// UI rather than only in the server log.
	Reason string `json:"reason,omitempty"`
}

// handlePlacementPath dispatches /api/v1/placement/* to the handler for each
// sub-resource.
func (s *Handler) handlePlacementPath(w http.ResponseWriter, r *http.Request) {
	path := strings.Trim(strings.TrimPrefix(r.URL.Path, "/api/v1/placement"), "/")

	switch path {
	case "status":
		// Admin-gated like the rest — the address of an internal daemon
		// is not something to hand out — but it is the one endpoint that
		// answers when no placementd was found, which is the point of
		// asking.
		s.handlePlacementStatus(w, r)
	case "users":
		s.handlePlacementUsers(w, r)
	case "tokens":
		s.handlePlacementTokens(w, r)
	case "authorizations":
		s.handlePlacementAuthorizations(w, r)
	case "login":
		s.handlePlacementLogin(w, r)
	default:
		s.writeError(w, http.StatusNotFound, "Placement endpoint not found")
	}
}

func (s *Handler) handlePlacementStatus(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		s.writeError(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}
	if !s.requireAdmin(w, r) {
		return
	}

	resp := placementStatusResponse{Available: s.placementdAvailable.Load()}
	if resp.Available {
		if p, ok := s.placementd.(*htcondor.Placementd); ok {
			resp.Address = p.Address()
		}
	} else {
		resp.Reason = "No condor_placementd was found. Set PLACEMENTD_ADDRESS_FILE, " +
			"or run one and let it advertise to the collector."
	}
	s.writeJSON(w, http.StatusOK, resp)
}

// requirePlacementd runs the admin gate and reports whether a placementd is
// available, writing the appropriate error response when either check fails.
func (s *Handler) requirePlacementd(w http.ResponseWriter, r *http.Request) bool {
	if !s.requireAdmin(w, r) {
		return false
	}
	if s.placementd == nil || !s.placementdAvailable.Load() {
		s.writeError(w, http.StatusServiceUnavailable,
			"No condor_placementd is available. Set PLACEMENTD_ADDRESS_FILE or run one in the pool.")
		return false
	}
	return true
}

func (s *Handler) handlePlacementUsers(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		s.writeError(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}
	if !s.requirePlacementd(w, r) {
		return
	}

	users, err := s.placementd.QueryUsers(r.Context(), r.URL.Query().Get("username"))
	if err != nil {
		s.writePlacementError(w, "query users", err)
		return
	}

	out := make([]placementUserResponse, 0, len(users))
	for _, u := range users {
		out = append(out, placementUserResponse{
			UserName:          u.UserName,
			APUserID:          u.APUserID,
			TokenExpiration:   optionalTime(u.TokenExpiration),
			MappingExpiration: optionalTime(u.MappingExpiration),
			Projects:          u.Projects,
			Authorizations:    u.Authorizations,
			Authorized:        u.Authorized,
		})
	}
	s.writeJSON(w, http.StatusOK, map[string]any{"users": out})
}

func (s *Handler) handlePlacementTokens(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		s.writeError(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}
	if !s.requirePlacementd(w, r) {
		return
	}

	q := r.URL.Query()
	query := htcondor.PlacementTokenQuery{
		UserName: q.Get("username"),
		TokenID:  q.Get("token_id"),
	}
	// Any of the usual spellings of true; anything else (including an
	// absent parameter) means "include expired tokens".
	switch strings.ToLower(q.Get("valid_only")) {
	case "1", "true", "yes":
		query.ValidOnly = true
	}

	tokens, err := s.placementd.QueryTokens(r.Context(), query)
	if err != nil {
		s.writePlacementError(w, "query tokens", err)
		return
	}

	now := time.Now()
	out := make([]placementTokenResponse, 0, len(tokens))
	for _, t := range tokens {
		out = append(out, placementTokenResponse{
			TokenID:        t.TokenID,
			UserName:       t.UserName,
			APUserID:       t.APUserID,
			Requester:      t.Requester,
			Authorizations: t.Authorizations,
			Project:        t.Project,
			Expiration:     optionalTime(t.Expiration),
			// A token with no expiration at all never expires; only a
			// set expiration in the past counts as expired.
			Expired: !t.Expiration.IsZero() && t.Expiration.Before(now),
		})
	}
	s.writeJSON(w, http.StatusOK, map[string]any{"tokens": out})
}

func (s *Handler) handlePlacementAuthorizations(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		s.writeError(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}
	if !s.requirePlacementd(w, r) {
		return
	}

	authz, err := s.placementd.QueryAuthorizations(r.Context(), r.URL.Query().Get("username"))
	if err != nil {
		s.writePlacementError(w, "query authorizations", err)
		return
	}

	out := make([]placementAuthorizationResponse, 0, len(authz))
	for _, a := range authz {
		out = append(out, placementAuthorizationResponse{
			Name:        a.Name,
			Label:       a.Label,
			Color:       a.Color,
			Description: a.Description,
		})
	}
	s.writeJSON(w, http.StatusOK, map[string]any{"authorizations": out})
}

func (s *Handler) handlePlacementLogin(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		s.writeError(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}
	if !s.requirePlacementd(w, r) {
		return
	}

	var req placementLoginRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.writeError(w, http.StatusBadRequest, fmt.Sprintf("Invalid request body: %v", err))
		return
	}
	if strings.TrimSpace(req.Username) == "" {
		s.writeError(w, http.StatusBadRequest, "username is required")
		return
	}

	result, err := s.placementd.Login(r.Context(), htcondor.PlacementLoginRequest{
		UserName:       req.Username,
		Authorizations: req.Authorizations,
		Project:        req.Project,
		Requester:      req.Requester,
	})
	if err != nil {
		s.writePlacementError(w, "login", err)
		return
	}

	// The token is a credential: keep it out of caches and shared proxies
	// even though the response already requires an admin session.
	w.Header().Set("Cache-Control", "no-store")
	s.writeJSON(w, http.StatusCreated, placementLoginResponse{Token: result.Token})
}

// writePlacementError turns a placementd failure into an HTTP response,
// distinguishing the daemon's own policy decisions (which the caller can act
// on) from transport failures (which they cannot).
func (s *Handler) writePlacementError(w http.ResponseWriter, op string, err error) {
	var perr *htcondor.PlacementError
	if !errors.As(err, &perr) {
		// Not a reply from the daemon: we could not reach it, the
		// connection broke, or the reply did not parse.
		s.writeError(w, http.StatusBadGateway, fmt.Sprintf("Failed to %s: %v", op, err))
		return
	}
	s.writeError(w, placementErrorStatus(perr.Code), perr.Message)
}

// placementErrorStatus maps a placementd error code to an HTTP status.
// Unknown codes are the ones the daemon forwards verbatim from the schedd, so
// they read as an upstream failure rather than a client mistake.
func placementErrorStatus(code int) int {
	switch code {
	case htcondor.PlacementErrMissingUserName:
		return http.StatusBadRequest
	case htcondor.PlacementErrUserNotAuthorized,
		htcondor.PlacementErrAuthorizationDenied,
		htcondor.PlacementErrUserMappingExpired,
		htcondor.PlacementErrRequesterUnknown,
		htcondor.PlacementErrRequesterNotInstructor,
		htcondor.PlacementErrRequesterMappingExpired,
		htcondor.PlacementErrProjectNotAuthorized:
		return http.StatusForbidden
	case htcondor.PlacementErrNotEncrypted, htcondor.PlacementErrDatabase:
		// Both are failures on our side of the conversation, not the
		// API caller's: a security configuration that let an
		// unencrypted connection through, or the daemon's database.
		return http.StatusInternalServerError
	default:
		return http.StatusBadGateway
	}
}

// optionalTime renders the zero time — which is how the placementd client
// spells "no expiration" — as an absent JSON field rather than as the Unix
// epoch or year 1.
func optionalTime(t time.Time) *time.Time {
	if t.IsZero() {
		return nil
	}
	return &t
}
