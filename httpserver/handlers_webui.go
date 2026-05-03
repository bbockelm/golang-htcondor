package httpserver

import (
	"fmt"
	"net/http"

	htcondor "github.com/bbockelm/golang-htcondor"
	"github.com/bbockelm/golang-htcondor/logging"
	"github.com/bbockelm/golang-htcondor/ratelimit"
)

// AuthMeResponse describes the currently-authenticated browser session.
//
// The Web UI uses this as its single source of truth for "is the user logged
// in", who they are, and whether to render admin pages. It is intentionally
// looser than /api/v1/whoami: it always returns 200 (with Authenticated=false
// when there is no session) so the SPA can render a landing page without
// going through error-handling.
type AuthMeResponse struct {
	Authenticated bool     `json:"authenticated"`
	Username      string   `json:"username,omitempty"`
	Groups        []string `json:"groups,omitempty"`
	IsAdmin       bool     `json:"is_admin"`
}

// handleAuthMe handles GET /api/v1/auth/me. Resolves the browser session
// cookie (only) — bearer tokens and the user-header path are deliberately
// NOT consulted, because this endpoint is meant to describe the SPA's
// session, not the API caller's identity.
func (s *Handler) handleAuthMe(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		s.writeError(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}

	resp := AuthMeResponse{Authenticated: false}

	if session, ok := s.getSessionFromRequest(r); ok {
		resp.Authenticated = true
		resp.Username = session.Username
		resp.Groups = session.Groups
		if s.webuiAdminGroup != "" {
			resp.IsAdmin = hasGroup(session.Groups, s.webuiAdminGroup)
		}
	}

	s.writeJSON(w, http.StatusOK, resp)
}

// handleAuthLogout is the JSON/REST counterpart to /logout. It exists so
// the SPA can call a stable /api/v1/* path with a JSON response instead of
// the redirect-flavored form-style /logout.
func (s *Handler) handleAuthLogout(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		s.writeError(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}
	// Reuse the existing handler — it already deletes the session row,
	// clears cookies, and returns JSON for non-browser requests.
	s.handleLogout(w, r)
}

// DashboardResponse summarizes the user's queue at the AP. It is a minimal
// shape on purpose; we'll grow it (transfer history, recent completions,
// user-level quota) in PR (b)/(c) once the SPA has the basics.
type DashboardResponse struct {
	Username     string         `json:"username"`
	JobsByStatus map[string]int `json:"jobs_by_status"`
	JobsTotal    int            `json:"jobs_total"`
}

// statusName maps an HTCondor JobStatus integer to a stable lower-case
// string suitable for JSON keys. Keep in sync with the schedd:
//
//	1 = idle, 2 = running, 3 = removed, 4 = completed,
//	5 = held, 6 = transferring_output, 7 = suspended
func statusName(code int64) string {
	switch code {
	case 1:
		return "idle"
	case 2:
		return "running"
	case 3:
		return "removed"
	case 4:
		return "completed"
	case 5:
		return "held"
	case 6:
		return "transferring_output"
	case 7:
		return "suspended"
	default:
		return fmt.Sprintf("status_%d", code)
	}
}

// handleDashboard handles GET /api/v1/dashboard. Returns counts of the
// authenticated user's jobs by status.
//
// We stream the queue with a projection of just JobStatus (no Cmd/Args/etc.)
// to keep this cheap even for large user queues. Limit=-1 (unlimited)
// because the point is to count.
func (s *Handler) handleDashboard(w http.ResponseWriter, r *http.Request) {
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

	owner := htcondor.GetAuthenticatedUserFromContext(ctx)

	opts := &htcondor.QueryOptions{
		Limit:      -1,
		Projection: []string{"JobStatus"},
		FetchOpts:  htcondor.FetchMyJobs,
		Owner:      owner,
	}
	streamOpts := &htcondor.StreamOptions{
		BufferSize:   s.streamBufferSize,
		WriteTimeout: s.streamWriteTimeout,
	}
	resultCh, err := s.getSchedd().QueryStreamWithOptions(ctx, "true", opts, streamOpts)
	if err != nil {
		switch {
		case ratelimit.IsRateLimitError(err):
			s.writeError(w, http.StatusTooManyRequests, err.Error())
		case isAuthenticationError(err):
			s.writeError(w, http.StatusUnauthorized, "Authentication failed")
		default:
			s.writeError(w, http.StatusBadGateway, fmt.Sprintf("Failed to query schedd: %v", err))
		}
		return
	}

	counts := make(map[string]int)
	total := 0
	for result := range resultCh {
		if result.Err != nil {
			// Streaming error mid-flight — log and surface what we have.
			// We don't fail the whole dashboard for a partial result; the
			// SPA shows a stale-counts banner in that case (PR (a) just
			// returns what we got).
			s.logger.Warn(logging.DestinationHTTP, "Dashboard query stream error", "error", result.Err)
			break
		}
		if result.Ad == nil {
			continue
		}
		var js int64
		if v, ok := result.Ad.EvaluateAttrInt("JobStatus"); ok {
			js = v
		}
		counts[statusName(js)]++
		total++
	}

	s.writeJSON(w, http.StatusOK, DashboardResponse{
		Username:     owner,
		JobsByStatus: counts,
		JobsTotal:    total,
	})
}
