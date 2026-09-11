package httpserver

import (
	"context"

	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"time"

	"github.com/PelicanPlatform/classad/classad"

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
	// SuperuserAllowed reports that this session MAY arm superuser mode --
	// the feature is configured and the session is in the superuser group.
	// It says nothing about whether the mode is currently on.
	SuperuserAllowed bool `json:"superuser_allowed"`
	// SuperuserActive reports that the mode is armed right now. The SPA
	// shows its warning banner on this, so every page can tell the user
	// that their next action may land on somebody else's job.
	SuperuserActive bool `json:"superuser_active"`
	// SuperuserExpiresAt is when the mode disarms itself. Surfaced so the
	// banner can say how long is left rather than have the mode silently
	// lapse mid-task.
	SuperuserExpiresAt *time.Time `json:"superuser_expires_at,omitempty"`
	// SuperuserIdentity is what actions will be attributed to on the schedd
	// while the mode is armed, and SuperuserNote explains it if that is not
	// the operator themselves.
	SuperuserIdentity string `json:"superuser_identity,omitempty"`
	SuperuserNote     string `json:"superuser_note,omitempty"`
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
		resp.SuperuserAllowed = s.mayUseSuperuserMode(r)
		if resp.SuperuserAllowed {
			if sessionID, err := getSessionCookie(r); err == nil {
				if armed, ok := s.superuserArmed.Armed(sessionID); ok {
					resp.SuperuserActive = true
					until := armed.until
					resp.SuperuserExpiresAt = &until
					resp.SuperuserIdentity = armed.identity
					resp.SuperuserNote = armed.note
				}
			}
		}
	}

	s.writeJSON(w, http.StatusOK, resp)
}

// SuperuserModeRequest toggles superuser mode for the calling session.
type SuperuserModeRequest struct {
	Enabled bool `json:"enabled"`
}

// SuperuserModeResponse reports the resulting state.
type SuperuserModeResponse struct {
	Active    bool       `json:"active"`
	ExpiresAt *time.Time `json:"expires_at,omitempty"`
	// Identity is what the server will authenticate to the schedd as while
	// the mode is on, and ActorIsQueueSuperUser whether that is the caller
	// themselves. Surfaced because the two differ in how well the action
	// can be attributed: as themselves, the schedd records the human; via
	// the shared account, only this server and the job's reason string do.
	Identity              string `json:"identity,omitempty"`
	ActorIsQueueSuperUser bool   `json:"actor_is_queue_superuser,omitempty"`
	// Note explains a fallback when one happened, including how to fix it.
	// Empty when the operator is acting as themselves.
	Note string `json:"note,omitempty"`
}

// handleSuperuserMode handles POST /api/v1/admin/superuser.
//
// Arming is an explicit act with an explicit expiry rather than a standing
// property of being an admin. The mode changes what an ordinary-looking click
// does -- a remove button starts landing on other people's jobs -- so it
// should be something the operator turned on moments ago and can see they
// turned on, not a capability they have forgotten they hold.
func (s *Handler) handleSuperuserMode(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		s.writeError(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}
	if !s.superuserModeAvailable() {
		s.writeError(w, http.StatusServiceUnavailable,
			"Superuser mode is not enabled on this server. It requires HTTP_API_SUPERUSER_GROUP and a pool signing key.")
		return
	}
	session, ok := s.getSessionFromRequest(r)
	if !ok {
		s.writeError(w, http.StatusUnauthorized, "Authentication required")
		return
	}
	if !s.mayUseSuperuserMode(r) {
		s.writeError(w, http.StatusForbidden,
			fmt.Sprintf("Superuser mode requires membership in group %q", s.superuserGroup))
		return
	}
	sessionID, err := getSessionCookie(r)
	if err != nil {
		s.writeError(w, http.StatusUnauthorized, "Authentication required")
		return
	}

	r.Body = http.MaxBytesReader(w, r.Body, 1<<16)
	var req SuperuserModeRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.writeError(w, http.StatusBadRequest, "Invalid request body")
		return
	}

	resp := SuperuserModeResponse{}
	if req.Enabled {
		armed := s.resolveImpersonationIdentity(r.Context(), session.Username)
		until := s.superuserArmed.Arm(sessionID, armed)
		resp.Active = true
		resp.ExpiresAt = &until
		resp.Identity = armed.identity
		resp.ActorIsQueueSuperUser = armed.actorIsSuperUser
		resp.Note = armed.note
		identity, isSuper := armed.identity, armed.actorIsSuperUser
		// Arming is itself worth an audit record: it is the moment an
		// operator took on the ability to act as anyone, and it may be
		// the only entry if they then do nothing.
		s.logger.Info(logging.DestinationSecurity, "Superuser mode armed",
			"actor", session.Username,
			"authenticated_as", identity,
			"actor_is_queue_superuser", isSuper,
			"expires_at", until,
			"remote_addr", r.RemoteAddr)
	} else {
		s.superuserArmed.Disarm(sessionID)
		s.logger.Info(logging.DestinationSecurity, "Superuser mode disarmed",
			"actor", session.Username, "remote_addr", r.RemoteAddr)
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
	// Activity is the "how is this access point doing" half: why jobs
	// are held, and what changed recently. Computed from the same walk
	// as the counts.
	Activity DashboardActivity `json:"activity"`
}

// holdReasonCodeSpoolingInput is HTCondor's "Spooling input data files"
// hold. A job sits here between submit and the input transfer finishing;
// it is not a failure and resolves on its own. Mirrors
// HOLD_REASON_CODE_SPOOLING_INPUT in the frontend's lib/api.ts.
const holdReasonCodeSpoolingInput = 16

// dashboardStatusName is statusName plus the one presentation override
// the jobs page makes: held-because-spooling is its own bucket rather
// than part of "held". The wire value of JobStatus is untouched.
func dashboardStatusName(status, holdReasonCode int64) string {
	if status == 5 && holdReasonCode == holdReasonCodeSpoolingInput {
		return "uploading"
	}
	return statusName(status)
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

	// Admins may opt into a pool-wide view via ?owned_by_me=false.
	// Non-admins (and the default for everyone) get the my-jobs view.
	// Security boundary lives in handleListJobs; we mirror the same
	// rule here so the dashboard counts match what /api/v1/jobs would
	// return for the same caller.
	ownedByMe := true
	if v := r.URL.Query().Get("owned_by_me"); v != "" {
		if parsed, perr := strconv.ParseBool(v); perr == nil {
			ownedByMe = parsed
		}
	}
	if !ownedByMe && !s.isWebUIAdmin(r) {
		ownedByMe = true
	}

	// HoldReasonCode rides along so a job held purely because its input
	// is still spooling can be counted separately from a real hold. The
	// jobs page already draws that distinction (displayJobStatus in
	// lib/api.ts); without it the dashboard's HELD tile makes a routine
	// submit look like a failure.
	//
	// The rest of the projection pays for the activity view out of the
	// walk this was already doing: the identity to name a job, the three
	// timestamps the recent lists sort on, the hold text, and one detail
	// each. Six more attributes on a read of the whole queue is a far
	// better trade than a second query -- and none of it is worth
	// anything without the walk, which is why it goes here rather than
	// into an endpoint of its own.
	opts := &htcondor.QueryOptions{
		Limit: -1,
		Projection: []string{
			"JobStatus", "HoldReasonCode", "HoldReason", "ExitCode", "CompletionDate",
			"ClusterId", "ProcId", "Owner",
			"QDate", "JobCurrentStartDate", "JobStartDate", "EnteredCurrentStatus",
			"Cmd", "RemoteHost",
		},
	}
	if ownedByMe {
		opts.FetchOpts = htcondor.FetchMyJobs
		opts.Owner = owner
	}
	// One walk per interval for the whole deployment, not one per page
	// load. The key is the scope, so an admin's pool-wide view and a
	// user's own view are cached apart; everyone sharing a scope shares
	// the answer, which is what makes the cost independent of how many
	// people have the page open.
	key := dashboardCacheKey(owner, ownedByMe)
	snap, err := s.dashboards().get(key, func() (*dashboardSnapshot, error) {
		return s.walkQueueForDashboard(ctx, opts, owner, ownedByMe)
	})
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

	s.writeJSON(w, http.StatusOK, DashboardResponse{
		Username:     owner,
		JobsByStatus: snap.Counts,
		JobsTotal:    snap.Total,
		Activity:     snap.Activity,
	})
}

// walkQueueForDashboard reads the queue once and folds it into counts
// and the activity view.
//
// It is the expensive thing the dashboard does, which is why the caller
// runs it behind a cache: on a busy access point this reads tens of
// thousands of ads, and it used to do so on every open of the page.
func (s *Handler) walkQueueForDashboard(ctx context.Context, opts *htcondor.QueryOptions, owner string, ownedByMe bool) (*dashboardSnapshot, error) {
	streamOpts := &htcondor.StreamOptions{
		BufferSize:   s.streamBufferSize,
		WriteTimeout: s.streamWriteTimeout,
	}
	resultCh, err := s.getSchedd().QueryStreamWithOptions(ctx, "true", opts, streamOpts)
	if err != nil {
		return nil, err
	}

	counts := make(map[string]int)
	activity := newActivityCollector()
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
		var hrc int64
		if v, ok := result.Ad.EvaluateAttrInt("HoldReasonCode"); ok {
			hrc = v
		}
		counts[dashboardStatusName(js, hrc)]++
		activity.observe(result.Ad)
		total++
	}

	act := activity.result(time.Now())

	// The queue's completed list only reaches back as far as the reaper
	// has not got to. Ask the archive for the rest, when there is one:
	// this is the mirror doing what it is for, and a failure here leaves
	// the queue's shorter answer in place rather than emptying it.
	if archived, aerr := s.recentlyCompletedFromArchive(ctx, owner, ownedByMe); aerr != nil {
		s.logger.Debug(logging.DestinationHTTP,
			"dashboard: no archive for recently-completed; showing what the queue still holds", "error", aerr)
	} else {
		act.mergeArchivedCompletions(archived)
		act.Source = "schedd + htcondordb archive"
	}

	return &dashboardSnapshot{Counts: counts, Total: total, Activity: act}, nil
}

// recentlyCompletedFromArchive reads the newest finished jobs from the
// mirror's history table.
//
// Errors rather than returning empty when there is no mirror, so the
// caller can tell "nothing finished" from "nothing could answer" -- the
// distinction the dashboard shows the viewer.
func (s *Handler) recentlyCompletedFromArchive(ctx context.Context, owner string, ownedByMe bool) ([]RecentJob, error) {
	if !s.dbMirror.Enabled() {
		return nil, fmt.Errorf("no htcondordb mirror is configured")
	}
	constraint := "true"
	if ownedByMe {
		constraint = fmt.Sprintf("Owner == %s", classadStringLit(owner))
	}
	dbc, closer, _, err := s.dbMirror.Client(ctx)
	if err != nil {
		return nil, err
	}
	defer closer()

	// The archive returns newest first with the limit pushed down, which
	// is exactly this question -- no sort and no over-fetch.
	rows, err := dbc.QueryRawProject(ctx, "history", constraint,
		[]string{"ClusterId", "ProcId", "Owner", "CompletionDate", "EnteredCurrentStatus", "ExitCode", "ExitBySignal"},
		recentPerList)
	if err != nil {
		return nil, err
	}
	out := make([]RecentJob, 0, len(rows))
	for _, row := range rows {
		ad, perr := classad.ParseOld(row)
		if perr != nil {
			// One unreadable row is not worth failing the dashboard for;
			// the rest of the list is still an answer.
			s.logger.Debug(logging.DestinationHTTP, "dashboard: skipping an unreadable history row", "error", perr)
			continue
		}
		e := RecentJob{At: completionTime(ad)}
		e.ClusterID, _ = ad.EvaluateAttrInt("ClusterId")
		e.ProcID, _ = ad.EvaluateAttrInt("ProcId")
		e.Owner, _ = ad.EvaluateAttrString("Owner")
		if bySignal, ok := ad.EvaluateAttrBool("ExitBySignal"); ok && bySignal {
			e.Detail = "killed by a signal"
		} else if code, ok := ad.EvaluateAttrInt("ExitCode"); ok {
			e.Detail = fmt.Sprintf("exit %d", code)
		}
		out = append(out, e)
	}
	return out, nil
}
