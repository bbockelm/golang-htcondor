package httpserver

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/bbockelm/golang-htcondor/webapi/reservation"

	"github.com/bbockelm/golang-htcondor/logging"
	"github.com/bbockelm/golang-htcondor/webapi/httpserver/appdb"
)

const testSeatSubmit = "executable = /usr/bin/jupyter\nrequest_cpus = 4\nrequest_gpus = 1\nrequest_memory = 16384\nqueue\n"

type resEnv struct {
	h     *Handler
	admin string
	user  string
}

func newResEnv(t *testing.T) *resEnv {
	t.Helper()
	logger, err := logging.New(&logging.Config{
		OutputPath: filepath.Join(t.TempDir(), "audit.log"), SkipGlobalInstall: true,
	})
	if err != nil {
		t.Fatalf("logger: %v", err)
	}
	db, err := appdb.Open(filepath.Join(t.TempDir(), "app.db"))
	if err != nil {
		t.Fatalf("appdb.Open: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	if err := appdb.Migrate(context.Background(), db); err != nil {
		t.Fatalf("appdb.Migrate: %v", err)
	}
	h := &Handler{
		logger:           logger,
		db:               db,
		sessionStore:     createTestSessionStore(t, time.Hour),
		webuiAdminGroups: newGroupSet("web-admins"),
		// The subsystem is off unless configured; these tests are about
		// what it does when an operator has turned it on.
		reservationsEnabled: true,
	}
	env := &resEnv{h: h}
	var mkErr error
	if env.admin, _, mkErr = h.sessionStore.Create("alice", []string{"web-admins"}); mkErr != nil {
		t.Fatalf("admin session: %v", mkErr)
	}
	if env.user, _, mkErr = h.sessionStore.Create("bob", []string{"students"}); mkErr != nil {
		t.Fatalf("user session: %v", mkErr)
	}
	return env
}

func (e *resEnv) do(t *testing.T, method, target, sid string, body any) *httptest.ResponseRecorder {
	t.Helper()
	var buf bytes.Buffer
	if body != nil {
		if err := json.NewEncoder(&buf).Encode(body); err != nil {
			t.Fatalf("encode body: %v", err)
		}
	}
	r := httptest.NewRequestWithContext(context.Background(), method, target, &buf)
	r.Header.Set("Content-Type", "application/json")
	if sid != "" {
		r.AddCookie(&http.Cookie{Name: sessionCookieName, Value: sid}) //nolint:gosec
	}
	w := httptest.NewRecorder()
	// Routed through a mux registered exactly as routes.go does, so the
	// precedence that makes "health" a route rather than a reservation
	// ID is what these tests actually exercise.
	e.mux().ServeHTTP(w, r)
	return w
}

// mux mirrors the reservation registrations in routes.go.
func (e *resEnv) mux() *http.ServeMux {
	m := http.NewServeMux()
	m.HandleFunc("/api/v1/admin/reservations", e.h.handleAdminReservations)
	m.HandleFunc("/api/v1/admin/reservations/health", e.h.handleAdminReservationHealth)
	m.HandleFunc("/api/v1/admin/reservations/windows", e.h.handleAdminReservationWindowsPreview)
	m.HandleFunc("/api/v1/admin/reservations/", e.h.handleAdminReservation)
	return m
}

func goodReservation() reservationJSON {
	return reservationJSON{
		ID: "cs301", Owner: "prof-moriarty", Project: "cs301-f26", Submit: testSeatSubmit,
		Seats: 35, Standing: 4,
		DurationSeconds: 3600, LeadSeconds: 21600, HoldSeconds: 900,
		Schedule: "0 14 * * 1,3", Timezone: "UTC", Enabled: true,
	}
}

func TestReservationsCRUD(t *testing.T) {
	env := newResEnv(t)

	if w := env.do(t, http.MethodGet, "/api/v1/admin/reservations", env.admin, nil); w.Code != http.StatusOK {
		t.Fatalf("empty list: status %d, body %s", w.Code, w.Body)
	}

	w := env.do(t, http.MethodPost, "/api/v1/admin/reservations", env.admin, goodReservation())
	if w.Code != http.StatusOK {
		t.Fatalf("create: status %d, body %s", w.Code, w.Body)
	}

	w = env.do(t, http.MethodGet, "/api/v1/admin/reservations", env.admin, nil)
	var list struct {
		Reservations []reservationJSON `json:"reservations"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &list); err != nil {
		t.Fatalf("decode list: %v", err)
	}
	if len(list.Reservations) != 1 || list.Reservations[0].ID != "cs301" {
		t.Fatalf("list = %+v", list.Reservations)
	}
	got := list.Reservations[0]
	if got.Seats != 35 || got.Standing != 4 || got.LeadSeconds != 21600 || got.Schedule != "0 14 * * 1,3" {
		t.Errorf("round-tripped as %+v", got)
	}

	w = env.do(t, http.MethodGet, "/api/v1/admin/reservations/cs301", env.admin, nil)
	if w.Code != http.StatusOK {
		t.Errorf("get one: status %d, body %s", w.Code, w.Body)
	}

	w = env.do(t, http.MethodDelete, "/api/v1/admin/reservations/cs301", env.admin, nil)
	if w.Code != http.StatusNoContent {
		t.Errorf("delete: status %d, body %s", w.Code, w.Body)
	}
	if w := env.do(t, http.MethodGet, "/api/v1/admin/reservations/cs301", env.admin, nil); w.Code != http.StatusNotFound {
		t.Errorf("get after delete: status %d", w.Code)
	}
}

// TestReservationsRejectBadInput: everything wrong with a reservation comes
// back to the form as a 400 with a reason, not a 500 and not silence.
func TestReservationsRejectBadInput(t *testing.T) {
	env := newResEnv(t)
	for _, tc := range []struct {
		name string
		mut  func(*reservationJSON)
	}{
		{"bad cron", func(r *reservationJSON) { r.Schedule = "0 99 * * *" }},
		{"unknown zone", func(r *reservationJSON) { r.Timezone = "Mars/Olympus" }},
		{"no project", func(r *reservationJSON) { r.Project = "" }},
		{"standing over seats", func(r *reservationJSON) { r.Standing = 99 }},
		{"submit that will not render", func(r *reservationJSON) { r.Submit = "request_cpus = 1\nqueue\n" }},
		{"no seats", func(r *reservationJSON) { r.Seats = 0 }},
		{"unparseable start", func(r *reservationJSON) { r.StartsAt = "next tuesday" }},
		{"unparseable end", func(r *reservationJSON) { r.EndsAt = "2026-09-01" }},
		{"an end and a count at once", func(r *reservationJSON) {
			r.StartsAt, r.EndsAt, r.Occurrences = "2026-09-01T00:00:00Z", "2026-12-18T00:00:00Z", 15
		}},
		{"a count with no start", func(r *reservationJSON) { r.Occurrences = 15 }},
		{"a start after the end", func(r *reservationJSON) {
			r.StartsAt, r.EndsAt = "2026-12-18T00:00:00Z", "2026-09-01T00:00:00Z"
		}},
	} {
		body := goodReservation()
		tc.mut(&body)
		w := env.do(t, http.MethodPost, "/api/v1/admin/reservations", env.admin, body)
		if w.Code != http.StatusBadRequest {
			t.Errorf("%s: status %d, want 400 (body %s)", tc.name, w.Code, w.Body)
		}
		if w.Body.Len() == 0 {
			t.Errorf("%s: rejected with no reason", tc.name)
		}
	}
}

// TestReservationsOffByDefault: the subsystem holds pool capacity by
// evicting other people's jobs, so it does nothing until an operator
// turns it on -- and says so rather than looking like an auth failure.
func TestReservationsOffByDefault(t *testing.T) {
	env := newResEnv(t)
	env.h.reservationsEnabled = false
	for _, tc := range []struct {
		method, target string
	}{
		{http.MethodGet, "/api/v1/admin/reservations"},
		{http.MethodPost, "/api/v1/admin/reservations"},
		{http.MethodGet, "/api/v1/admin/reservations/cs301"},
		{http.MethodDelete, "/api/v1/admin/reservations/cs301"},
		{http.MethodGet, "/api/v1/admin/reservations/cs301/windows"},
	} {
		w := env.do(t, tc.method, tc.target, env.admin, goodReservation())
		if w.Code != http.StatusServiceUnavailable {
			t.Errorf("%s %s: status %d, want 503", tc.method, tc.target, w.Code)
		}
		if !strings.Contains(w.Body.String(), "HTTP_API_RESERVATIONS") {
			t.Errorf("%s %s: the refusal does not name the setting: %s", tc.method, tc.target, w.Body)
		}
	}
}

func TestReservationsRequireAdmin(t *testing.T) {
	env := newResEnv(t)
	for _, tc := range []struct {
		name, sid string
		want      int
	}{
		{"anonymous", "", http.StatusUnauthorized},
		{"non-admin", env.user, http.StatusForbidden},
	} {
		if w := env.do(t, http.MethodGet, "/api/v1/admin/reservations", tc.sid, nil); w.Code != tc.want {
			t.Errorf("%s list: status %d, want %d", tc.name, w.Code, tc.want)
		}
		if w := env.do(t, http.MethodPost, "/api/v1/admin/reservations", tc.sid, goodReservation()); w.Code != tc.want {
			t.Errorf("%s create: status %d, want %d", tc.name, w.Code, tc.want)
		}
		if w := env.do(t, http.MethodDelete, "/api/v1/admin/reservations/cs301", tc.sid, nil); w.Code != tc.want {
			t.Errorf("%s delete: status %d, want %d", tc.name, w.Code, tc.want)
		}
	}
}

// TestReservationWindowsPreview is what makes a cron box usable: the admin
// sees when the reservation will actually hold seats, and when the
// controller starts holding cores back for it.
func TestReservationWindowsPreview(t *testing.T) {
	env := newResEnv(t)
	if w := env.do(t, http.MethodPost, "/api/v1/admin/reservations", env.admin, goodReservation()); w.Code != http.StatusOK {
		t.Fatalf("create: %d %s", w.Code, w.Body)
	}
	w := env.do(t, http.MethodGet, "/api/v1/admin/reservations/cs301/windows?days=21", env.admin, nil)
	if w.Code != http.StatusOK {
		t.Fatalf("windows: status %d, body %s", w.Code, w.Body)
	}
	var got struct {
		Windows []windowJSON `json:"windows"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &got); err != nil {
		t.Fatalf("decode: %v", err)
	}
	// Mondays and Wednesdays over three weeks.
	if len(got.Windows) < 5 {
		t.Fatalf("got %d windows over 21 days, want at least 5", len(got.Windows))
	}
	for _, win := range got.Windows {
		if !win.End.After(win.Start) {
			t.Errorf("window %v..%v does not advance", win.Start, win.End)
		}
		if got := win.Start.Sub(win.PlanFrom); got != 6*time.Hour {
			t.Errorf("planning starts %v before the bell, want 6h", got)
		}
		if win.Occurrences < 1 {
			t.Errorf("window covers %d occurrences", win.Occurrences)
		}
	}
	if w := env.do(t, http.MethodGet, "/api/v1/admin/reservations/cs301/windows?days=0", env.admin, nil); w.Code != http.StatusBadRequest {
		t.Errorf("days=0: status %d, want 400", w.Code)
	}
	if w := env.do(t, http.MethodGet, "/api/v1/admin/reservations/nope/windows", env.admin, nil); w.Code != http.StatusNotFound {
		t.Errorf("windows for a missing reservation: status %d, want 404", w.Code)
	}
}

// TestReservationHealthReportsNotRunning: no prober is not the same as
// healthy. An admin page that said "fine" when nothing had been checked
// would hide exactly the failure this endpoint exists for.
func TestReservationHealthReportsNotRunning(t *testing.T) {
	env := newResEnv(t)
	w := env.do(t, http.MethodGet, "/api/v1/admin/reservations/health", env.admin, nil)
	if w.Code != http.StatusOK {
		t.Fatalf("status %d, body %s", w.Code, w.Body)
	}
	var got map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &got); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if running, _ := got["running"].(bool); running {
		t.Errorf("reported running with no prober wired: %v", got)
	}
}

// TestReservationHealthSurfacesADeniedWrite is the whole point: an
// access point that may not update machine ads must say so here.
func TestReservationHealthSurfacesADeniedWrite(t *testing.T) {
	env := newResEnv(t)
	p := &reservation.Prober{
		Source: startsFor("ep1", `Owner =?= "alice"`),
		Writer: deniedWriter{},
	}
	if _, err := p.Visit(context.Background()); err != nil {
		t.Fatalf("Visit: %v", err)
	}
	env.h.reservationProber = p

	w := env.do(t, http.MethodGet, "/api/v1/admin/reservations/health", env.admin, nil)
	if w.Code != http.StatusOK {
		t.Fatalf("status %d, body %s", w.Code, w.Body)
	}
	var got struct {
		Running bool   `json:"running"`
		Healthy bool   `json:"healthy"`
		Machine string `json:"machine"`
		Detail  string `json:"detail"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &got); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if !got.Running || got.Healthy {
		t.Errorf("health = %+v, want running and unhealthy", got)
	}
	if got.Machine != "ep1" || !strings.Contains(got.Detail, "not authorized") {
		t.Errorf("health does not name the machine and reason: %+v", got)
	}
}

// TestReservationHealthNeedsAdmin.
func TestReservationHealthNeedsAdmin(t *testing.T) {
	env := newResEnv(t)
	if w := env.do(t, http.MethodGet, "/api/v1/admin/reservations/health", env.user, nil); w.Code != http.StatusForbidden {
		t.Errorf("non-admin got %d, want 403", w.Code)
	}
}

type staticStarts map[string]string

func (s staticStarts) Starts(context.Context) (map[string]string, error) {
	return map[string]string(s), nil
}

func startsFor(machine, start string) reservation.StartSource {
	return staticStarts{machine: start}
}

type deniedWriter struct{}

func (deniedWriter) Probe(context.Context, string) error {
	return errors.New("DENIED: not authorized to update machine ad")
}

// TestReservationHealthNamesUnprovisionedExecutePoints: an execute
// point whose START never consults the sieve is held, reports as held,
// and admits everything anyway. Nothing else in the system can tell, so
// this endpoint is where an operator finds out -- with the line to add.
func TestReservationHealthNamesUnprovisionedExecutePoints(t *testing.T) {
	env := newResEnv(t)
	p := &reservation.Prober{
		Source: startsFor("ep1", `Owner =?= "alice"`),
		Writer: acceptingWriter{},
	}
	if _, err := p.Visit(context.Background()); err != nil {
		t.Fatalf("Visit: %v", err)
	}
	env.h.reservationProber = p

	w := env.do(t, http.MethodGet, "/api/v1/admin/reservations/health", env.admin, nil)
	if w.Code != http.StatusOK {
		t.Fatalf("status %d, body %s", w.Code, w.Body)
	}
	var got struct {
		Running       bool     `json:"running"`
		Healthy       bool     `json:"healthy"`
		Unprovisioned []string `json:"unprovisioned"`
		Stanza        string   `json:"stanza"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &got); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if !got.Healthy {
		// This access point is working; what is missing is a line in
		// somebody else's configuration file.
		t.Errorf("an unprovisioned execute point made the access point read as unhealthy: %+v", got)
	}
	if len(got.Unprovisioned) != 1 || got.Unprovisioned[0] != "ep1" {
		t.Errorf("unprovisioned = %v, want [ep1]", got.Unprovisioned)
	}
	if !strings.Contains(got.Stanza, "ReservationStart") {
		t.Errorf("health does not carry the line to add: %q", got.Stanza)
	}
}

type acceptingWriter struct{}

func (acceptingWriter) Probe(context.Context, string) error { return nil }

// TestStartReservationsIsOffUnlessConfigured: a reservation holds
// capacity by evicting other people's jobs, so nothing starts because
// somebody upgraded.
func TestStartReservationsIsOffUnlessConfigured(t *testing.T) {
	env := newResEnv(t)
	env.h.reservationProber = nil
	env.h.reservationsEnabled = false
	env.h.startReservations(t.Context())
	if env.h.reservationProber != nil {
		t.Errorf("the prober started although reservations are disabled")
	}

	// Enabled but with no collector to read: there is nothing to
	// administer, and starting a loop that fails every minute is worse
	// than not starting it.
	env.h.reservationsEnabled = true
	env.h.collector = nil
	env.h.startReservations(t.Context())
	if env.h.reservationProber != nil {
		t.Errorf("the prober started with no collector to read")
	}
}

// TestStampingNeedsTheEstimator: the stamps come from the runtime
// estimator, so there is nothing to write without it. Starting the loop
// anyway would write nothing every five minutes while the admin page
// reported a running stamper.
func TestStampingNeedsTheEstimator(t *testing.T) {
	env := newResEnv(t)
	env.h.reservationStamper = nil
	env.h.reservationsEnabled = true
	env.h.runtimeEst = nil
	env.h.startReservationStamping(t.Context())
	if env.h.reservationStamper != nil {
		t.Errorf("stamping started with no runtime estimator to stamp from")
	}

	env.h.reservationsEnabled = false
	env.h.startReservationStamping(t.Context())
	if env.h.reservationStamper != nil {
		t.Errorf("stamping started although reservations are disabled")
	}
}

// TestReservationRecurrenceBoundsRoundTrip: the form sends a term as
// RFC3339 and an empty string for "no bound", and has to get back what
// it sent -- a term that quietly became "for ever" between the form and
// the table is a class holding capacity after it finished.
func TestReservationRecurrenceBoundsRoundTrip(t *testing.T) {
	env := newResEnv(t)

	// Unbounded first: the fields are present and empty, not missing.
	if w := env.do(t, http.MethodPost, "/api/v1/admin/reservations", env.admin, goodReservation()); w.Code != http.StatusOK {
		t.Fatalf("create: %d %s", w.Code, w.Body)
	}
	var raw map[string]any
	if err := json.Unmarshal(env.do(t, http.MethodGet, "/api/v1/admin/reservations/cs301", env.admin, nil).Body.Bytes(), &raw); err != nil {
		t.Fatalf("decode: %v", err)
	}
	for _, field := range []string{"starts_at", "ends_at"} {
		if got, ok := raw[field]; !ok || got != "" {
			t.Errorf("unbounded %s = %v (present %v), want an empty string", field, got, ok)
		}
	}
	if got, ok := raw["occurrences"]; !ok || got != float64(0) {
		t.Errorf("unbounded occurrences = %v (present %v), want 0", got, ok)
	}

	term := goodReservation()
	term.StartsAt = "2026-09-01T08:00:00Z"
	term.EndsAt = "2026-12-18T17:00:00Z"
	if w := env.do(t, http.MethodPost, "/api/v1/admin/reservations", env.admin, term); w.Code != http.StatusOK {
		t.Fatalf("create with a term: %d %s", w.Code, w.Body)
	}
	var got reservationJSON
	if err := json.Unmarshal(env.do(t, http.MethodGet, "/api/v1/admin/reservations/cs301", env.admin, nil).Body.Bytes(), &got); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if got.StartsAt != term.StartsAt || got.EndsAt != term.EndsAt {
		t.Errorf("term round-tripped as %q..%q, want %q..%q", got.StartsAt, got.EndsAt, term.StartsAt, term.EndsAt)
	}

	counted := goodReservation()
	counted.StartsAt = term.StartsAt
	counted.Occurrences = 15
	if w := env.do(t, http.MethodPost, "/api/v1/admin/reservations", env.admin, counted); w.Code != http.StatusOK {
		t.Fatalf("create with a count: %d %s", w.Code, w.Body)
	}
	if err := json.Unmarshal(env.do(t, http.MethodGet, "/api/v1/admin/reservations/cs301", env.admin, nil).Body.Bytes(), &got); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if got.Occurrences != 15 || got.EndsAt != "" {
		t.Errorf("count round-tripped as %d occurrences, ends_at %q", got.Occurrences, got.EndsAt)
	}
}

// TestReservationWindowsPreviewHonoursTheBounds: the preview is what the
// admin checks the term against, so it has to show the recurrence
// stopping rather than the cron expression running on.
func TestReservationWindowsPreviewHonoursTheBounds(t *testing.T) {
	env := newResEnv(t)
	windows := func(t *testing.T) []windowJSON {
		t.Helper()
		w := env.do(t, http.MethodGet, "/api/v1/admin/reservations/cs301/windows?days=21", env.admin, nil)
		if w.Code != http.StatusOK {
			t.Fatalf("windows: %d %s", w.Code, w.Body)
		}
		var got struct {
			Windows []windowJSON `json:"windows"`
		}
		if err := json.Unmarshal(w.Body.Bytes(), &got); err != nil {
			t.Fatalf("decode: %v", err)
		}
		return got.Windows
	}

	if w := env.do(t, http.MethodPost, "/api/v1/admin/reservations", env.admin, goodReservation()); w.Code != http.StatusOK {
		t.Fatalf("create: %d %s", w.Code, w.Body)
	}
	if n := len(windows(t)); n < 5 {
		t.Fatalf("unbounded preview has %d windows over 21 days, want at least 5", n)
	}

	ended := goodReservation()
	ended.EndsAt = time.Now().Add(-24 * time.Hour).UTC().Format(time.RFC3339)
	if w := env.do(t, http.MethodPost, "/api/v1/admin/reservations", env.admin, ended); w.Code != http.StatusOK {
		t.Fatalf("create ended: %d %s", w.Code, w.Body)
	}
	if n := len(windows(t)); n != 0 {
		t.Errorf("a reservation whose term ended yesterday previews %d windows", n)
	}

	later := goodReservation()
	later.StartsAt = time.Now().Add(14 * 24 * time.Hour).UTC().Format(time.RFC3339)
	if w := env.do(t, http.MethodPost, "/api/v1/admin/reservations", env.admin, later); w.Code != http.StatusOK {
		t.Fatalf("create future: %d %s", w.Code, w.Body)
	}
	start := time.Now().Add(14 * 24 * time.Hour)
	got := windows(t)
	if len(got) == 0 {
		t.Fatal("a term opening in a fortnight previews nothing inside 21 days; the check below would prove nothing")
	}
	for _, win := range got {
		if win.Start.Before(start) {
			t.Errorf("preview shows a window at %v, before the term opens at %v", win.Start, start)
		}
	}
}

// fortnightlyReservation is the request cron cannot express: a window
// every other Tuesday.
func fortnightlyReservation() reservationJSON {
	j := goodReservation()
	j.Schedule = ""
	j.ScheduleKind = string(reservation.KindRecurrence)
	j.Recurrence = &reservation.Recurrence{
		Freq: reservation.FreqWeekly, Interval: 2, ByWeekday: []int{2}, TimeOfDay: "14:00",
	}
	j.StartsAt = "2026-03-03T00:00:00Z"
	return j
}

func decodeWindows(t *testing.T, body []byte) windowsJSON {
	t.Helper()
	var got windowsJSON
	if err := json.Unmarshal(body, &got); err != nil {
		t.Fatalf("decode windows: %v (body %s)", err, body)
	}
	return got
}

// TestReservationRecurrenceRoundTripsThroughTheAPI: the structured form
// goes out the way it came in, because the admin page redisplays what it
// posted and a field quietly dropped would read as a field the operator
// never set.
func TestReservationRecurrenceRoundTripsThroughTheAPI(t *testing.T) {
	env := newResEnv(t)
	if w := env.do(t, http.MethodPost, "/api/v1/admin/reservations", env.admin, fortnightlyReservation()); w.Code != http.StatusOK {
		t.Fatalf("create: %d %s", w.Code, w.Body)
	}
	w := env.do(t, http.MethodGet, "/api/v1/admin/reservations/cs301", env.admin, nil)
	if w.Code != http.StatusOK {
		t.Fatalf("get: %d %s", w.Code, w.Body)
	}
	var got reservationJSON
	if err := json.Unmarshal(w.Body.Bytes(), &got); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if got.ScheduleKind != "recurrence" {
		t.Errorf("schedule_kind came back %q", got.ScheduleKind)
	}
	if got.Recurrence == nil {
		t.Fatal("recurrence came back null")
	}
	if got.Recurrence.Freq != reservation.FreqWeekly || got.Recurrence.Interval != 2 ||
		len(got.Recurrence.ByWeekday) != 1 || got.Recurrence.ByWeekday[0] != 2 ||
		got.Recurrence.TimeOfDay != "14:00" {
		t.Errorf("recurrence came back as %+v", got.Recurrence)
	}
	// The windows are the only thing anybody acts on, so check the
	// stored reservation really lands on alternate Tuesdays.
	w = env.do(t, http.MethodGet, "/api/v1/admin/reservations/cs301/windows?days=365", env.admin, nil)
	wins := decodeWindows(t, w.Body.Bytes())
	if len(wins.Windows) < 2 {
		t.Fatalf("got %d windows over a year: %+v", len(wins.Windows), wins)
	}
	for i, win := range wins.Windows {
		if win.Start.Weekday() != time.Tuesday {
			t.Errorf("window %d starts on a %v", i, win.Start.Weekday())
		}
		if i > 0 {
			if gap := win.Start.Sub(wins.Windows[i-1].Start); gap != 14*24*time.Hour {
				t.Errorf("window %d is %v after the one before, want 336h", i, gap)
			}
		}
	}
}

// TestReservationAlwaysKindHasNoWindows: an empty window list means two
// different things, so the preview says which. A page that could not
// tell them apart would show "nothing upcoming" for a reservation
// holding capacity right now.
func TestReservationAlwaysKindHasNoWindows(t *testing.T) {
	env := newResEnv(t)
	body := goodReservation()
	body.ScheduleKind = string(reservation.KindAlways)
	body.Schedule, body.DurationSeconds, body.LeadSeconds, body.HoldSeconds = "", 0, 0, 0
	if w := env.do(t, http.MethodPost, "/api/v1/admin/reservations", env.admin, body); w.Code != http.StatusOK {
		t.Fatalf("create: %d %s", w.Code, w.Body)
	}
	w := env.do(t, http.MethodGet, "/api/v1/admin/reservations/cs301/windows", env.admin, nil)
	if w.Code != http.StatusOK {
		t.Fatalf("windows: %d %s", w.Code, w.Body)
	}
	got := decodeWindows(t, w.Body.Bytes())
	if len(got.Windows) != 0 {
		t.Errorf("an always-on reservation listed %d windows", len(got.Windows))
	}
	if got.ScheduleKind != "always" {
		t.Errorf("the preview reported schedule_kind %q", got.ScheduleKind)
	}
}

// TestDraftWindowsPreviewMatchesTheSavedOne is the point of the draft
// endpoint: it must be the same enumeration. A preview computed any
// other way is how a form comes to show an operator a schedule that is
// not the one that will run.
func TestDraftWindowsPreviewMatchesTheSavedOne(t *testing.T) {
	env := newResEnv(t)
	body := fortnightlyReservation()
	if w := env.do(t, http.MethodPost, "/api/v1/admin/reservations", env.admin, body); w.Code != http.StatusOK {
		t.Fatalf("create: %d %s", w.Code, w.Body)
	}
	saved := env.do(t, http.MethodGet, "/api/v1/admin/reservations/cs301/windows?days=90", env.admin, nil)
	if saved.Code != http.StatusOK {
		t.Fatalf("saved windows: %d %s", saved.Code, saved.Body)
	}
	draft := env.do(t, http.MethodPost, "/api/v1/admin/reservations/windows?days=90", env.admin, body)
	if draft.Code != http.StatusOK {
		t.Fatalf("draft windows: %d %s", draft.Code, draft.Body)
	}
	want, got := decodeWindows(t, saved.Body.Bytes()), decodeWindows(t, draft.Body.Bytes())
	if len(want.Windows) == 0 {
		t.Fatal("the saved reservation previewed no windows, so there is nothing to compare")
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("the draft previewed %+v, the saved reservation %+v", got, want)
	}
}

// TestDraftWindowsPreviewNeedsOnlyTheTiming: a draft is previewed while
// it is still being written, so withholding the preview over an empty
// submit file would withhold it exactly when the recurrence is being
// worked out.
func TestDraftWindowsPreviewNeedsOnlyTheTiming(t *testing.T) {
	env := newResEnv(t)
	body := fortnightlyReservation()
	body.ID, body.Owner, body.Project, body.Submit = "", "", "", ""
	body.Seats, body.Standing = 0, 0
	w := env.do(t, http.MethodPost, "/api/v1/admin/reservations/windows?days=60", env.admin, body)
	if w.Code != http.StatusOK {
		t.Fatalf("status %d, body %s", w.Code, w.Body)
	}
	if got := decodeWindows(t, w.Body.Bytes()); len(got.Windows) == 0 {
		t.Error("a half-written draft previewed nothing")
	}
	// Saving the same thing is still refused: the preview is lenient,
	// the table is not.
	if w := env.do(t, http.MethodPost, "/api/v1/admin/reservations", env.admin, body); w.Code != http.StatusBadRequest {
		t.Errorf("saving a half-written reservation gave %d, want 400", w.Code)
	}
}

// TestDraftWindowsPreviewRefusesWhatItCannotEnumerate: the 400 text is
// shown to the operator verbatim, so it has to name what is wrong.
func TestDraftWindowsPreviewRefusesWhatItCannotEnumerate(t *testing.T) {
	env := newResEnv(t)
	for _, tc := range []struct {
		name string
		mut  func(*reservationJSON)
		want string
	}{
		{"weekly with no weekdays", func(j *reservationJSON) {
			j.Recurrence = &reservation.Recurrence{Freq: reservation.FreqWeekly, TimeOfDay: "14:00"}
		}, "needs by_weekday"},
		{"an interval with no start date", func(j *reservationJSON) {
			j.StartsAt = ""
		}, "needs a start date"},
		{"no recurrence at all", func(j *reservationJSON) {
			j.Recurrence = nil
		}, "recurrence is required"},
		{"an unknown kind", func(j *reservationJSON) {
			j.ScheduleKind = "fortnightly"
		}, "not one of cron"},
		{"no duration", func(j *reservationJSON) {
			j.DurationSeconds = 0
		}, "duration_seconds must be positive"},
	} {
		body := fortnightlyReservation()
		tc.mut(&body)
		w := env.do(t, http.MethodPost, "/api/v1/admin/reservations/windows", env.admin, body)
		if w.Code != http.StatusBadRequest {
			t.Errorf("%s: status %d, want 400 (body %s)", tc.name, w.Code, w.Body)
			continue
		}
		if !strings.Contains(w.Body.String(), tc.want) {
			t.Errorf("%s: body %s does not mention %q", tc.name, w.Body, tc.want)
		}
	}
	// A GET is not a preview: the draft is a document, and the endpoint
	// that takes one has to say so.
	if w := env.do(t, http.MethodGet, "/api/v1/admin/reservations/windows", env.admin, nil); w.Code != http.StatusMethodNotAllowed {
		t.Errorf("GET gave %d, want 405", w.Code)
	}
	// And it is admin-only like the rest of the collection.
	if w := env.do(t, http.MethodPost, "/api/v1/admin/reservations/windows", env.user, fortnightlyReservation()); w.Code != http.StatusForbidden {
		t.Errorf("a non-admin draft preview gave %d, want 403", w.Code)
	}
}
