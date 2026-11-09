package reservation

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"
)

// ErrNotFound is returned when no reservation has the given ID.
var ErrNotFound = errors.New("reservation not found")

// Store persists reservations in the API server's application database.
//
// A Spec holds a parsed *Schedule, which is not storable, so the row keeps
// the cron text and the zone name and the schedule is re-parsed on read. A
// row whose schedule no longer parses -- a zone dropped from the system
// tzdata, say -- is reported rather than silently skipped, because a
// reservation that quietly stops happening is worse than one that fails
// loudly.
type Store struct {
	db *sql.DB
}

// NewStore wraps an already-migrated database. The caller keeps ownership
// of db.
func NewStore(db *sql.DB) *Store { return &Store{db: db} }

// Put inserts or replaces a reservation. The spec is validated first, so a
// row that cannot be acted on never reaches the table.
func (s *Store) Put(ctx context.Context, spec *Spec) error {
	if err := spec.Validate(); err != nil {
		return fmt.Errorf("reservation %s is not valid: %w", spec.ID, err)
	}
	if err := spec.CheckSubmit(); err != nil {
		return err
	}
	zone := "Local"
	if loc := spec.Schedule.Location(); loc != nil {
		zone = loc.String()
	}
	enabled := 0
	if spec.Enabled {
		enabled = 1
	}
	_, err := s.db.ExecContext(ctx, `
		INSERT INTO reservations
			(id, owner, project, submit, seats, standing, duration_s, lead_s, hold_s,
			 schedule, timezone, enabled, starts_unix, ends_unix, occurrences, updated_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
		ON CONFLICT(id) DO UPDATE SET
			owner=excluded.owner,
			project=excluded.project, submit=excluded.submit, seats=excluded.seats,
			standing=excluded.standing, duration_s=excluded.duration_s,
			lead_s=excluded.lead_s, hold_s=excluded.hold_s, schedule=excluded.schedule,
			timezone=excluded.timezone, enabled=excluded.enabled,
			starts_unix=excluded.starts_unix, ends_unix=excluded.ends_unix,
			occurrences=excluded.occurrences,
			updated_at=CURRENT_TIMESTAMP`,
		spec.ID, spec.Owner, spec.Project, spec.Submit, spec.Seats, spec.Standing,
		int64(spec.Duration/time.Second), int64(spec.Lead/time.Second),
		int64(spec.Hold/time.Second), spec.Schedule.String(), zone, enabled,
		unixOrZero(spec.Starts), unixOrZero(spec.Ends), spec.Occurrences)
	if err != nil {
		return fmt.Errorf("storing reservation %s: %w", spec.ID, err)
	}
	return nil
}

const selectColumns = `id, owner, project, submit, seats, standing, duration_s, lead_s, hold_s, schedule, timezone, enabled, starts_unix, ends_unix, occurrences`

// Get reads one reservation. It returns ErrNotFound when there is no such
// row.
func (s *Store) Get(ctx context.Context, id string) (*Spec, error) {
	row := s.db.QueryRowContext(ctx, `SELECT `+selectColumns+` FROM reservations WHERE id = ?`, id)
	spec, err := scanSpec(row)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, fmt.Errorf("%q: %w", id, ErrNotFound)
	}
	return spec, err
}

// List reads every reservation, ordered by ID so the admin page is stable
// between loads.
func (s *Store) List(ctx context.Context) ([]*Spec, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT `+selectColumns+` FROM reservations ORDER BY id`)
	if err != nil {
		return nil, fmt.Errorf("listing reservations: %w", err)
	}
	defer func() { _ = rows.Close() }()
	var out []*Spec
	for rows.Next() {
		spec, err := scanSpec(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, spec)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("listing reservations: %w", err)
	}
	return out, nil
}

// Delete removes a reservation. Deleting one that is not there is not an
// error: the caller wanted it gone and it is.
func (s *Store) Delete(ctx context.Context, id string) error {
	if _, err := s.db.ExecContext(ctx, `DELETE FROM reservations WHERE id = ?`, id); err != nil {
		return fmt.Errorf("deleting reservation %s: %w", id, err)
	}
	return nil
}

// scanner is the part of *sql.Row and *sql.Rows that scanSpec needs.
type scanner interface{ Scan(dest ...any) error }

func scanSpec(sc scanner) (*Spec, error) {
	var (
		spec                 Spec
		durS, leadS, holdS   int64
		startsUnix, endsUnix int64
		cron, zone           string
		enabled              int
	)
	if err := sc.Scan(&spec.ID, &spec.Owner, &spec.Project, &spec.Submit, &spec.Seats, &spec.Standing,
		&durS, &leadS, &holdS, &cron, &zone, &enabled,
		&startsUnix, &endsUnix, &spec.Occurrences); err != nil {
		return nil, err
	}
	spec.Duration = time.Duration(durS) * time.Second
	spec.Lead = time.Duration(leadS) * time.Second
	spec.Hold = time.Duration(holdS) * time.Second
	spec.Enabled = enabled != 0

	loc := time.Local
	if zone != "" && zone != "Local" {
		l, err := time.LoadLocation(zone)
		if err != nil {
			return nil, fmt.Errorf("reservation %s: time zone %q: %w", spec.ID, zone, err)
		}
		loc = l
	}
	sched, err := ParseSchedule(cron, loc)
	if err != nil {
		return nil, fmt.Errorf("reservation %s: schedule %q: %w", spec.ID, cron, err)
	}
	spec.Schedule = sched
	// The bounds are instants, but reading them in the schedule's zone
	// is what makes a log line or a form field show the term starting
	// on the day the admin typed.
	spec.Starts = timeOrZero(startsUnix, loc)
	spec.Ends = timeOrZero(endsUnix, loc)
	return &spec, nil
}

// timeOrZero reverses unixOrZero: a bound is stored as zero when it is
// absent, so that a row says "unbounded" the same way the zero
// time.Time does and no reader has to special-case a NULL.
func timeOrZero(unix int64, loc *time.Location) time.Time {
	if unix == 0 {
		return time.Time{}
	}
	return time.Unix(unix, 0).In(loc)
}
