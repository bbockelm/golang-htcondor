package reservation

import (
	"context"
	"database/sql"
	"errors"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/bbockelm/golang-htcondor/webapi/httpserver/appdb"
)

func testStore(t *testing.T) *Store {
	t.Helper()
	db, err := appdb.Open(filepath.Join(t.TempDir(), "app.db"))
	if err != nil {
		t.Fatalf("appdb.Open: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	if err := appdb.Migrate(context.Background(), db); err != nil {
		t.Fatalf("appdb.Migrate: %v", err)
	}
	return NewStore(db)
}

func storedSpec(t *testing.T, id string) *Spec {
	t.Helper()
	s := seatSpec(gpuSeat)
	s.ID = id
	s.Schedule = mustSchedule(t, "0 14 * * 1,3", time.UTC)
	return s
}

func TestStoreRoundTrip(t *testing.T) {
	st := testStore(t)
	ctx := context.Background()
	want := storedSpec(t, "cs301")

	if err := st.Put(ctx, want); err != nil {
		t.Fatalf("Put: %v", err)
	}
	got, err := st.Get(ctx, "cs301")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got.Project != want.Project || got.Seats != want.Seats || got.Standing != want.Standing {
		t.Errorf("project/seats/standing round-tripped as %q/%d/%d", got.Project, got.Seats, got.Standing)
	}
	if got.Duration != want.Duration || got.Lead != want.Lead || got.Hold != want.Hold {
		t.Errorf("durations round-tripped as %v/%v/%v", got.Duration, got.Lead, got.Hold)
	}
	if got.Submit != want.Submit {
		t.Error("the submit file did not round-trip")
	}
	if !got.Enabled {
		t.Error("Enabled did not round-trip")
	}
	// The schedule is stored as text and re-parsed, so check it still
	// computes the same occurrence rather than just comparing strings.
	from := time.Date(2026, 3, 2, 0, 0, 0, 0, time.UTC)
	gotNext, ok1 := got.Schedule.Next(from)
	wantNext, ok2 := want.Schedule.Next(from)
	if !ok1 || !ok2 || !gotNext.Equal(wantNext) {
		t.Errorf("schedule round-tripped to %v, want %v", gotNext, wantNext)
	}
}

func TestStoreKeepsTheTimeZone(t *testing.T) {
	chi, err := time.LoadLocation("America/Chicago")
	if err != nil {
		t.Skipf("no tzdata: %v", err)
	}
	st := testStore(t)
	ctx := context.Background()
	spec := storedSpec(t, "cs301")
	spec.Schedule = mustSchedule(t, "0 14 * * *", chi)
	if err := st.Put(ctx, spec); err != nil {
		t.Fatalf("Put: %v", err)
	}
	got, err := st.Get(ctx, "cs301")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got.Schedule.Location().String() != "America/Chicago" {
		t.Fatalf("zone round-tripped as %q", got.Schedule.Location())
	}
	// A 14:00 class is still 14:00 wall clock after the round trip.
	at, ok := got.Schedule.Next(time.Date(2026, 11, 3, 0, 0, 0, 0, chi))
	if !ok || at.Hour() != 14 {
		t.Errorf("next occurrence %v is not 14:00 local", at)
	}
}

func TestStorePutUpdates(t *testing.T) {
	st := testStore(t)
	ctx := context.Background()
	spec := storedSpec(t, "cs301")
	if err := st.Put(ctx, spec); err != nil {
		t.Fatalf("Put: %v", err)
	}
	spec.Seats = 50
	spec.Enabled = false
	if err := st.Put(ctx, spec); err != nil {
		t.Fatalf("Put (update): %v", err)
	}
	got, err := st.Get(ctx, "cs301")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got.Seats != 50 || got.Enabled {
		t.Errorf("update gave seats=%d enabled=%v, want 50/false", got.Seats, got.Enabled)
	}
	all, err := st.List(ctx)
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(all) != 1 {
		t.Errorf("Put on an existing ID made %d rows, want 1", len(all))
	}
}

// TestStoreRejectsInvalid: a row the controller cannot act on should never
// reach the table, so the admin finds out at the form rather than at the
// bell.
func TestStoreRejectsInvalid(t *testing.T) {
	st := testStore(t)
	ctx := context.Background()
	for _, tc := range []struct {
		name string
		mut  func(*Spec)
	}{
		{"no project", func(s *Spec) { s.Project = "" }},
		{"standing over seats", func(s *Spec) { s.Standing = s.Seats + 1 }},
		{"submit that will not render", func(s *Spec) { s.Submit = "request_cpus = 1\nqueue\n" }},
	} {
		spec := storedSpec(t, "bad-"+tc.name)
		tc.mut(spec)
		if err := st.Put(ctx, spec); err == nil {
			t.Errorf("%s: Put accepted it", tc.name)
		}
	}
	all, err := st.List(ctx)
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(all) != 0 {
		t.Errorf("%d invalid rows reached the table", len(all))
	}
}

func TestStoreListAndDelete(t *testing.T) {
	st := testStore(t)
	ctx := context.Background()
	for _, id := range []string{"cs301", "bio500", "astro101"} {
		if err := st.Put(ctx, storedSpec(t, id)); err != nil {
			t.Fatalf("Put %s: %v", id, err)
		}
	}
	all, err := st.List(ctx)
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(all) != 3 {
		t.Fatalf("List gave %d, want 3", len(all))
	}
	// Ordered by ID so the admin page does not shuffle between loads.
	if all[0].ID != "astro101" || all[2].ID != "cs301" {
		t.Errorf("List order = %s, %s, %s", all[0].ID, all[1].ID, all[2].ID)
	}
	if err := st.Delete(ctx, "bio500"); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	if _, err := st.Get(ctx, "bio500"); !errors.Is(err, ErrNotFound) {
		t.Errorf("Get after Delete gave %v, want ErrNotFound", err)
	}
	// Deleting what is already gone is not an error.
	if err := st.Delete(ctx, "bio500"); err != nil {
		t.Errorf("second Delete: %v", err)
	}
}

func TestStoreGetMissing(t *testing.T) {
	st := testStore(t)
	_, err := st.Get(context.Background(), "nope")
	if !errors.Is(err, ErrNotFound) {
		t.Errorf("Get on a missing ID gave %v, want ErrNotFound", err)
	}
	// The ID is in the message, so an operator reading a log knows which
	// reservation was asked for.
	if !strings.Contains(err.Error(), "nope") {
		t.Errorf("error %q does not name the reservation", err)
	}
}

var _ scanner = (*sql.Row)(nil)
