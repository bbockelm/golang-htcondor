package httpserver

// GET /api/v1/calendar?days=<n>&owned_by_me=<bool>
//
// Per-day submitted / completed / removed / in-queue counts over the
// last n days. The queries, and why they are shaped the way they are,
// are in calendar.go; this file is the endpoint, the window parameter,
// and the cache every viewer with the same scope shares.

import (
	"context"
	"fmt"
	"net/http"
	"strconv"

	htcondor "github.com/bbockelm/golang-htcondor"
)

// handleCalendar handles GET /api/v1/calendar.
func (s *Handler) handleCalendar(w http.ResponseWriter, r *http.Request) {
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

	// Multi-AP mode has its own scope machinery (multiap.Service.Scope)
	// and its own sources block, and a calendar that silently charted one
	// access point out of several would be worse than no calendar. The
	// route is not on multi-AP's allowlist, so a request there is already
	// a 501 and this is not normally reached; it stays as the guard that
	// makes allowlisting the path later a deliberate act rather than an
	// accidental one-AP chart.
	if s.multi != nil {
		s.writeJSON(w, http.StatusOK, CalendarResponse{
			Note: "The calendar is not available in multi-AP mode.",
		})
		return
	}

	// Validated before the availability check below: a malformed window
	// is the caller's own bug, and answering it with "the feature is
	// off" would hide that from a deployment that later gains a mirror.
	days, err := calendarDaysParam(r.URL.Query().Get("days"))
	if err != nil {
		s.writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	// No mirror, no calendar: the schedd cannot answer this at all --
	// it has no history older than the reaper and no way to group by
	// anything. Report the feature off rather than erroring, the same
	// way handlers_metrics.go reports an absent sampler.
	if !s.dbMirror.Enabled() {
		s.writeJSON(w, http.StatusOK, CalendarResponse{
			Note: "This access point has no htcondordb mirror, so there is no history to chart.",
		})
		return
	}

	// The Owner value of the caller's jobs: a bearer's actor is
	// qualified ("alice@domain") and a job's Owner is not. A placementd
	// account is keyed and scoped by its full name.
	owner := ownerKey(ctx, htcondor.GetAuthenticatedUserFromContext(ctx))
	// Same rule as every other listing: a caller that is not an
	// administrator is confined to its own jobs whatever it asked for.
	// The scope is built server-side from the authenticated identity
	// (mirrorScope -> ownerKeyClause); the query parameter only ever
	// narrows, and cannot widen.
	ownedByMe := true
	if v := r.URL.Query().Get("owned_by_me"); v != "" {
		if parsed, perr := strconv.ParseBool(v); perr == nil {
			ownedByMe = parsed
		}
	}
	if !ownedByMe && !s.seesAllJobs(ctx, r, jobScopeRead) {
		ownedByMe = true
	}

	// The mirror is dialed with this daemon's credential, so it may only
	// answer a caller the schedd itself accepts at READ. There is no
	// schedd fallback for this view.
	if !s.mirrorReadVerified(ctx, r) {
		s.writeError(w, http.StatusForbidden, errMirrorNotVerified.Error())
		return
	}

	resp, err := s.calendars().get(ctx, calendarCacheKey(owner, ownedByMe, days),
		func(cctx context.Context) (*CalendarResponse, error) {
			return s.calendarFromMirror(cctx, owner, ownedByMe, days)
		})
	if err != nil {
		s.writeError(w, http.StatusBadGateway, fmt.Sprintf("Could not read the job calendar: %v", err))
		return
	}
	s.writeJSON(w, http.StatusOK, resp)
}

// calendarDaysParam reads and caps the window.
//
// Capped rather than refused above the cap, like every other window
// parameter here: a caller asking for five years gets the longest answer
// this can give, and window_days in the response says what it got.
func calendarDaysParam(v string) (int, error) {
	if v == "" {
		return calendarDefaultDays, nil
	}
	n, err := strconv.Atoi(v)
	if err != nil {
		return 0, fmt.Errorf("invalid days (want a whole number of days): %w", err)
	}
	if n < 1 {
		return 0, fmt.Errorf("days must be at least 1")
	}
	if n > calendarMaxDays {
		n = calendarMaxDays
	}
	return n, nil
}

// calendarCacheKey names the calendar a viewer may be served.
//
// The owner is in the key for the reason dashboardCacheKey gives: a
// snapshot holds that owner's counts, and leaving the owner out would
// not waste a query, it would serve one user's calendar to another with
// nothing downstream to notice. The window is in it because a 30-day and
// a 90-day answer are different answers, not a prefix of one another --
// the archive-submitted series is windowed, so the shorter one is not a
// slice of the longer.
func calendarCacheKey(owner string, ownedByMe bool, days int) string {
	if !ownedByMe {
		return fmt.Sprintf("all|%d", days)
	}
	return fmt.Sprintf("mine:%s|%d", owner, days)
}

// calendars returns the handler's calendar cache, built on first use so
// a Handler constructed directly in a test still has one.
func (s *Handler) calendars() *sharedCache[*CalendarResponse] {
	s.calendarCacheOnce.Do(func() {
		s.calendarCacheVal = newSharedCache[*CalendarResponse](calendarRefresh, calendarComputeTimeout)
	})
	return s.calendarCacheVal
}
