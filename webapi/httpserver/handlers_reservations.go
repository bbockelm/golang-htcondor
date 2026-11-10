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
	// ScheduleKind says which timing is authoritative: "cron" for the
	// expression in Schedule, "recurrence" for the structure in
	// Recurrence, "always" for a reservation that holds its capacity
	// continuously. Empty is "cron", which is what every reservation
	// stored before the recurrence existed is.
	ScheduleKind string `json:"schedule_kind"`
	// Recurrence is the structured timing. It goes out as null for a
	// reservation that does not use one, so the form can tell "no
	// recurrence" from an empty one.
	Recurrence *reservation.Recurrence `json:"recurrence"`
	Timezone   string                  `json:"timezone"`
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

// windowsJSON is what both window previews answer with -- the saved
// reservation's and the draft's -- so the page renders either with one
// component.
//
// ScheduleKind goes with the list because an empty list has two
// meanings: an always-on reservation has no windows because it never
// stops holding, and a finished one has none because it is over. A
// preview that could not tell them apart would show "nothing upcoming"
// for a reservation holding capacity right now.
type windowsJSON struct {
	Windows      []windowJSON `json:"windows"`
	ScheduleKind string       `json:"schedule_kind"`
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
		ScheduleKind:    string(s.ScheduleKind()),
		Recurrence:      s.Recurrence,
	}
	if s.Schedule != nil {
		out.Schedule = s.Schedule.String()
	}
	// The zone comes from whichever timing the reservation uses, so an
	// always-on one still reports the zone its dates were typed in.
	loc := s.Location()
	out.Timezone = loc.String()
	// The bounds go out in the schedule's zone. They are instants
	// either way, but a reservation that starts on the 26th should not
	// read as the 25th to an admin whose reservation is in another zone
	// from the browser they are reading it in.
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
	var err error
	loc := time.Local
	if tz := strings.TrimSpace(j.Timezone); tz != "" && tz != "Local" {
		l, err := time.LoadLocation(tz)
		if err != nil {
			return nil, errors.New("unknown time zone " + strconv.Quote(tz))
		}
		loc = l
	}
	kind := reservation.ScheduleKind(strings.TrimSpace(j.ScheduleKind))
	var (
		sched *reservation.Schedule
		recur *reservation.Recurrence
	)
	switch kind {
	case reservation.KindAlways:
		// Nothing to parse: an always-on reservation is timed by being
		// enabled. Whatever the form was holding in its cron box is
		// deliberately dropped rather than stored, so a reservation
		// cannot come back from the database timed by text nothing
		// displayed.
	case reservation.KindRecurrence:
		if j.Recurrence == nil {
			return nil, errors.New("a recurrence is required when schedule_kind is \"recurrence\"")
		}
		if recur, err = reservation.NewRecurrence(*j.Recurrence, loc); err != nil {
			return nil, err
		}
	case reservation.KindCron, "":
		kind = reservation.KindCron
		if sched, err = reservation.ParseSchedule(j.Schedule, loc); err != nil {
			return nil, err
		}
	default:
		return nil, errors.New("schedule_kind " + strconv.Quote(j.ScheduleKind) + " is not one of cron, recurrence or always")
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
		Kind:     kind, Schedule: sched, Recurrence: recur, Zone: loc,
		Enabled: j.Enabled,
		Starts:  starts, Ends: ends, Occurrences: j.Occurrences,
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

// serveReservationWindows previews when a saved reservation will
// actually hold capacity. Neither a cron expression nor a recurrence is
// easy to read back, so the form shows what it means rather than asking
// the admin to trust it.
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
	horizon, ok := s.windowHorizon(w, r)
	if !ok {
		return
	}
	s.writeJSON(w, http.StatusOK, previewWindows(spec, horizon))
}

// handleAdminReservationWindowsPreview previews the windows of a
// reservation that has not been saved.
//
// It takes a whole draft in the body rather than the recurrence alone
// because the windows depend on more than the recurrence: the duration
// decides where each one ends, the lead decides when draining would
// start, and the bounds decide which occurrences exist at all. POST
// rather than GET for the same reason -- the draft is a document, not a
// query string -- and it writes nothing.
//
// The enumeration is spec.Windows, the same call the saved preview and
// the controller itself make. A second implementation for the form is
// how a preview comes to show an operator a schedule that is not the
// one that will run.
func (s *Handler) handleAdminReservationWindowsPreview(w http.ResponseWriter, r *http.Request) {
	if !s.requireReservations(w) || !s.requireAdmin(w, r) {
		return
	}
	if r.Method != http.MethodPost {
		s.writeError(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}
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
	// Only the timing is checked. A draft is previewed while it is
	// still being written, so refusing one for an empty submit file or
	// a missing owner would withhold the preview exactly when the admin
	// is working out whether the recurrence is right.
	if err := spec.ValidateTiming(); err != nil {
		s.writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	if spec.ScheduleKind() != reservation.KindAlways && spec.Duration <= 0 {
		// Windows yields nothing without a duration, and "no upcoming
		// windows" would read as a mistake in the recurrence rather
		// than an empty box further up the form.
		s.writeError(w, http.StatusBadRequest, "duration_seconds must be positive to preview windows")
		return
	}
	horizon, ok := s.windowHorizon(w, r)
	if !ok {
		return
	}
	s.writeJSON(w, http.StatusOK, previewWindows(spec, horizon))
}

// previewWindows renders a spec's upcoming windows. Shared so the saved
// reservation and the draft cannot drift apart in either the enumeration
// or the shape it comes back in.
func previewWindows(spec *reservation.Spec, horizon time.Duration) windowsJSON {
	windows := spec.Windows(time.Now(), horizon, reservationForgive)
	out := make([]windowJSON, 0, len(windows))
	for _, win := range windows {
		out = append(out, windowJSON{
			Start: win.Start, End: win.End, Occurrences: win.Occurrences,
			PlanFrom: win.Start.Add(-spec.Lead),
		})
	}
	return windowsJSON{Windows: out, ScheduleKind: string(spec.ScheduleKind())}
}

// windowHorizon reads how far ahead to preview, writing the error itself
// so both previews refuse a bad one identically.
func (s *Handler) windowHorizon(w http.ResponseWriter, r *http.Request) (time.Duration, bool) {
	raw := r.URL.Query().Get("days")
	if raw == "" {
		return defaultWindowHorizon, true
	}
	days, err := strconv.Atoi(raw)
	if err != nil || days < 1 || days > 365 {
		s.writeError(w, http.StatusBadRequest, "days must be between 1 and 365")
		return 0, false
	}
	return time.Duration(days) * 24 * time.Hour, true
}

// reservationForgive is the age below which evicting a job is treated as
// free. It decides whether two occurrences are one hold: a gap shorter
// than this is free either way, because anything started in it is still
// cheap to evict when the next window opens.
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
// machine ads. Nothing errors, no reservation complains, and every
// window opens on a pool that was never drained -- so the only place it
// can show up is here.
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
