package httpserver

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

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
	if target == "/api/v1/admin/reservations" {
		e.h.handleAdminReservations(w, r)
	} else {
		e.h.handleAdminReservation(w, r)
	}
	return w
}

func goodReservation() reservationJSON {
	return reservationJSON{
		ID: "cs301", Project: "cs301-f26", Submit: testSeatSubmit,
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
