package httpserver

import (
	"encoding/json"
	"errors"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/bbockelm/golang-htcondor/logging"
	"github.com/bbockelm/golang-htcondor/webapi/reservation"
)

// reservationJSON is a reservation as the admin UI sends and receives it.
//
// Durations are seconds rather than Go duration strings: the form has
// number inputs, and a client that has to parse "6h0m0s" to put 6 in a box
// will get it wrong eventually.
type reservationJSON struct {
	ID              string `json:"id"`
	Owner           string `json:"owner"`
	Project         string `json:"project"`
	Submit          string `json:"submit"`
	Seats           int    `json:"seats"`
	Standing        int    `json:"standing"`
	DurationSeconds int64  `json:"duration_seconds"`
	LeadSeconds     int64  `json:"lead_seconds"`
	HoldSeconds     int64  `json:"hold_seconds"`
	Schedule        string `json:"schedule"`
	Timezone        string `json:"timezone"`
	// StartsAt and EndsAt bound the recurrence, RFC3339, empty for
	// unbounded. Strings rather than times because "no end date" has to
	// be expressible, and an omitted JSON time decodes to the zero year
	// rather than to nothing.
	StartsAt string `json:"starts_at"`
	EndsAt   string `json:"ends_at"`
	// Occurrences ends the recurrence after a number of scheduled
	// starts instead of on a date. Zero is unlimited.
	Occurrences int  `json:"occurrences"`
	Enabled     bool `json:"enabled"`
}

// windowJSON is one upcoming hold.
type windowJSON struct {
	Start       time.Time `json:"start"`
	End         time.Time `json:"end"`
	PlanFrom    time.Time `json:"plan_from"`
	Occurrences int       `json:"occurrences"`
}

func toReservationJSON(s *reservation.Spec) reservationJSON {
	out := reservationJSON{
		ID: s.ID, Owner: s.Owner, Project: s.Project, Submit: s.Submit,
		Seats: s.Seats, Standing: s.Standing,
		DurationSeconds: int64(s.Duration / time.Second),
		LeadSeconds:     int64(s.Lead / time.Second),
		HoldSeconds:     int64(s.Hold / time.Second),
		Occurrences:     s.Occurrences,
		Enabled:         s.Enabled,
	}
	loc := time.Local
	if s.Schedule != nil {
		out.Schedule = s.Schedule.String()
		if l := s.Schedule.Location(); l != nil {
			loc, out.Timezone = l, l.String()
		}
	}
	// The bounds go out in the schedule's zone. They are instants
	// either way, but a term that starts on the 26th should not read as
	// the 25th to an admin whose class is in another zone from the
	// browser they are reading it in.
	out.StartsAt = formatBound(s.Starts, loc)
	out.EndsAt = formatBound(s.Ends, loc)
	return out
}

// formatBound renders an absent bound as the empty string: a form with
// no end date has to be able to say so.
func formatBound(t time.Time, loc *time.Location) string {
	if t.IsZero() {
		return ""
	}
	return t.In(loc).Format(time.RFC3339)
}

// parseBound reads one bound, naming the field so a mistyped date comes
// back to the box it was typed in.
func parseBound(field, raw string) (time.Time, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return time.Time{}, nil
	}
	t, err := time.Parse(time.RFC3339, raw)
	if err != nil {
		return time.Time{}, errors.New(field + " must be an RFC3339 time such as 2026-09-01T00:00:00Z, got " + strconv.Quote(raw))
	}
	return t, nil
}

// toSpec builds a Spec, reporting a bad schedule or zone as a client error
// rather than a 500: the admin mistyped something and should be told what.
func (j reservationJSON) toSpec() (*reservation.Spec, error) {
	loc := time.Local
	if tz := strings.TrimSpace(j.Timezone); tz != "" && tz != "Local" {
		l, err := time.LoadLocation(tz)
		if err != nil {
			return nil, errors.New("unknown time zone " + strconv.Quote(tz))
		}
		loc = l
	}
	sched, err := reservation.ParseSchedule(j.Schedule, loc)
	if err != nil {
		return nil, err
	}
	starts, err := parseBound("starts_at", j.StartsAt)
	if err != nil {
		return nil, err
	}
	ends, err := parseBound("ends_at", j.EndsAt)
	if err != nil {
		return nil, err
	}
	return &reservation.Spec{
		ID: strings.TrimSpace(j.ID), Owner: strings.TrimSpace(j.Owner),
		Project: strings.TrimSpace(j.Project), Submit: j.Submit,
		Seats: j.Seats, Standing: j.Standing,
		Duration: time.Duration(j.DurationSeconds) * time.Second,
		Lead:     time.Duration(j.LeadSeconds) * time.Second,
		Hold:     time.Duration(j.HoldSeconds) * time.Second,
		Schedule: sched, Enabled: j.Enabled,
		Starts: starts, Ends: ends, Occurrences: j.Occurrences,
	}, nil
}

// handleAdminReservations serves the collection: GET lists, POST creates or
// replaces.
func (s *Handler) handleAdminReservations(w http.ResponseWriter, r *http.Request) {
	if !s.requireReservations(w) || !s.requireAdmin(w, r) {
		return
	}
	store := s.reservationStore()
	if store == nil {
		s.writeError(w, http.StatusServiceUnavailable, "Reservations are not available: the application database is not open")
		return
	}
	switch r.Method {
	case http.MethodGet:
		specs, err := store.List(r.Context())
		if err != nil {
			s.logger.Error(logging.DestinationHTTP, "Failed to list reservations", "error", err)
			s.writeError(w, http.StatusInternalServerError, "Failed to list reservations")
			return
		}
		out := make([]reservationJSON, 0, len(specs))
		for _, spec := range specs {
			out = append(out, toReservationJSON(spec))
		}
		s.writeJSON(w, http.StatusOK, map[string]any{"reservations": out})
	case http.MethodPost:
		var body reservationJSON
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			s.writeError(w, http.StatusBadRequest, "Invalid JSON: "+err.Error())
			return
		}
		spec, err := body.toSpec()
		if err != nil {
			s.writeError(w, http.StatusBadRequest, err.Error())
			return
		}
		// Put validates and renders the submit file, so everything wrong
		// with the reservation comes back to the form at once.
		if err := store.Put(r.Context(), spec); err != nil {
			s.writeError(w, http.StatusBadRequest, err.Error())
			return
		}
		s.writeJSON(w, http.StatusOK, toReservationJSON(spec))
	default:
		s.writeError(w, http.StatusMethodNotAllowed, "Method not allowed")
	}
}

// handleAdminReservation serves one reservation by ID, and its upcoming
// windows at .../windows.
func (s *Handler) handleAdminReservation(w http.ResponseWriter, r *http.Request) {
	if !s.requireReservations(w) || !s.requireAdmin(w, r) {
		return
	}
	store := s.reservationStore()
	if store == nil {
		s.writeError(w, http.StatusServiceUnavailable, "Reservations are not available: the application database is not open")
		return
	}
	rest := strings.TrimPrefix(r.URL.Path, "/api/v1/admin/reservations/")
	id, tail, _ := strings.Cut(rest, "/")
	if id == "" {
		s.writeError(w, http.StatusBadRequest, "Reservation ID is required")
		return
	}
	if tail == "windows" {
		s.serveReservationWindows(w, r, store, id)
		return
	}
	switch r.Method {
	case http.MethodGet:
		spec, err := store.Get(r.Context(), id)
		if errors.Is(err, reservation.ErrNotFound) {
			s.writeError(w, http.StatusNotFound, "No such reservation")
			return
		}
		if err != nil {
			s.logger.Error(logging.DestinationHTTP, "Failed to read reservation", "id", id, "error", err)
			s.writeError(w, http.StatusInternalServerError, "Failed to read reservation")
			return
		}
		s.writeJSON(w, http.StatusOK, toReservationJSON(spec))
	case http.MethodDelete:
		if err := store.Delete(r.Context(), id); err != nil {
			s.logger.Error(logging.DestinationHTTP, "Failed to delete reservation", "id", id, "error", err)
			s.writeError(w, http.StatusInternalServerError, "Failed to delete reservation")
			return
		}
		w.WriteHeader(http.StatusNoContent)
	default:
		s.writeError(w, http.StatusMethodNotAllowed, "Method not allowed")
	}
}

// defaultWindowHorizon is how far ahead the preview looks when the caller
// does not say. Two weeks covers a fortnightly timetable.
const defaultWindowHorizon = 14 * 24 * time.Hour

// serveReservationWindows previews when a reservation will actually hold
// seats. A cron expression is hard to read, so the form shows what it
// means rather than asking the admin to trust it.
func (s *Handler) serveReservationWindows(w http.ResponseWriter, r *http.Request, store *reservation.Store, id string) {
	if r.Method != http.MethodGet {
		s.writeError(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}
	spec, err := store.Get(r.Context(), id)
	if errors.Is(err, reservation.ErrNotFound) {
		s.writeError(w, http.StatusNotFound, "No such reservation")
		return
	}
	if err != nil {
		s.logger.Error(logging.DestinationHTTP, "Failed to read reservation", "id", id, "error", err)
		s.writeError(w, http.StatusInternalServerError, "Failed to read reservation")
		return
	}
	horizon := defaultWindowHorizon
	if raw := r.URL.Query().Get("days"); raw != "" {
		days, err := strconv.Atoi(raw)
		if err != nil || days < 1 || days > 365 {
			s.writeError(w, http.StatusBadRequest, "days must be between 1 and 365")
			return
		}
		horizon = time.Duration(days) * 24 * time.Hour
	}
	now := time.Now()
	windows := spec.Windows(now, horizon, reservationForgive)
	out := make([]windowJSON, 0, len(windows))
	for _, win := range windows {
		out = append(out, windowJSON{
			Start: win.Start, End: win.End, Occurrences: win.Occurrences,
			PlanFrom: win.Start.Add(-spec.Lead),
		})
	}
	s.writeJSON(w, http.StatusOK, map[string]any{"windows": out})
}

// reservationForgive is the age below which evicting a job is treated as
// free. It decides whether two occurrences are one hold: a gap shorter
// than this is free either way, because anything started in it is still
// cheap to evict at the next bell.
const reservationForgive = 30 * time.Minute

// reservationHealthJSON is what the admin page reads to decide whether
// to warn.
type reservationHealthJSON struct {
	// Running is false when no prober is wired up, which is not the same
	// as healthy: nothing has been checked.
	Running bool `json:"running"`
	reservation.Health
}

// handleAdminReservationHealth answers whether this access point can
// still do what a reservation needs.
//
// The failure worth surfacing is an access point that may not update
// machine ads. Nothing errors, no reservation complains, and every class
// starts on a pool that was never drained -- so the only place it can
// show up is here.
func (s *Handler) handleAdminReservationHealth(w http.ResponseWriter, r *http.Request) {
	if !s.requireReservations(w) || !s.requireAdmin(w, r) {
		return
	}
	if r.Method != http.MethodGet {
		s.writeError(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}
	out := reservationHealthJSON{}
	if s.reservationProber != nil {
		out.Running, out.Health = true, s.reservationProber.Health()
	}
	s.writeJSON(w, http.StatusOK, out)
}

// requireReservations refuses when the subsystem is switched off. The
// check comes before the admin check so an operator who has not enabled
// reservations is told that, rather than being told they are not an
// admin.
func (s *Handler) requireReservations(w http.ResponseWriter) bool {
	if !s.reservationsEnabled {
		s.writeError(w, http.StatusServiceUnavailable,
			"Reservations are disabled. Set HTTP_API_RESERVATIONS = true to enable.")
		return false
	}
	return true
}

// reservationStore is the reservation table on the application database.
// Store holds no state beyond the handle, so building one per request is
// free and avoids another field to initialise in the right order.
func (s *Handler) reservationStore() *reservation.Store {
	if s.db == nil {
		return nil
	}
	return reservation.NewStore(s.db)
}
