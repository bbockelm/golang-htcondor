package jobwatch

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"time"
)

// DefaultTTL is how long a watch lives if the caller names no deadline.
//
// Every watch has one. An agent that registers a watch and never comes
// back is the common case, not the exception, and without an expiry the
// evaluator's work grows without bound producing answers nobody will
// read. A day is long enough to outlast the gap between an agent's turns
// and short enough that abandoned watches drain on their own.
const DefaultTTL = 24 * time.Hour

// MaxTTL bounds what a caller may ask for.
const MaxTTL = 7 * 24 * time.Hour

// Store persists watches. Every method that reads on a caller's behalf
// takes an owner and filters on it, rather than leaving that to the
// caller: the evaluator reads job ads as the daemon, so this column is
// the only thing confining a watch's results to the person who
// registered it, and a forgotten filter here is a cross-user leak.
type Store struct {
	db  *sql.DB
	now func() time.Time
}

// NewStore wraps an already-migrated application database.
func NewStore(db *sql.DB) *Store { return &Store{db: db, now: time.Now} }

// Register stores a compiled watch and returns it with its id and
// deadline filled in. ttl <= 0 uses DefaultTTL; anything above MaxTTL is
// clamped rather than refused, since a caller asking for "forever" wants
// the longest available, not an error.
func (s *Store) Register(ctx context.Context, w *Watch, ttl time.Duration) (*Watch, error) {
	if w == nil {
		return nil, fmt.Errorf("no watch to register")
	}
	if err := w.Compile(); err != nil {
		return nil, err
	}
	switch {
	case ttl <= 0:
		ttl = DefaultTTL
	case ttl > MaxTTL:
		ttl = MaxTTL
	}
	id, err := newID()
	if err != nil {
		return nil, err
	}
	w.ID, w.CreatedAt = id, s.now().UTC()
	expires := w.CreatedAt.Add(ttl)

	tracked, err := json.Marshal(w.Tracked)
	if err != nil {
		return nil, fmt.Errorf("encoding the tracked set: %w", err)
	}
	_, err = s.db.ExecContext(ctx, `
		INSERT INTO job_watches (id, owner, label, constraint_expr, event, condition_expr, mode,
		                         created_at, tracked_json, expires_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		w.ID, w.Owner, w.Label, w.Constraint, string(w.Event), w.Condition, string(w.Mode),
		w.CreatedAt, string(tracked), expires)
	if err != nil {
		return nil, fmt.Errorf("registering the watch: %w", err)
	}
	return w, nil
}

// Live returns every watch the evaluator should still consider: not yet
// fired and not expired. Not owner-scoped, because the evaluator works
// on behalf of all of them -- the scoping happens on the read side.
func (s *Store) Live(ctx context.Context) ([]*Watch, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT id, owner, label, constraint_expr, event, condition_expr, mode, created_at, tracked_json
		  FROM job_watches
		 WHERE fired_at IS NULL AND expires_at > ?
		 ORDER BY created_at`, s.now().UTC())
	if err != nil {
		return nil, err
	}
	return scanWatches(rows)
}

// ForOwner returns an owner's watches, most recently registered first.
// fired selects which half: true for outcomes to read, false for still
// waiting, nil for both.
func (s *Store) ForOwner(ctx context.Context, owner string, fired *bool) ([]*Watch, error) {
	if owner == "" {
		// Refuse rather than return everything. An empty owner here is a
		// caller whose identity could not be established, and answering
		// it with every user's watches is the failure mode worth making
		// impossible.
		return nil, ErrNoOwner
	}
	q := `SELECT id, owner, label, constraint_expr, event, condition_expr, mode, created_at, tracked_json,
	             fired_at, matched_json, matched_total, delivered_at
	        FROM job_watches WHERE owner = ? AND expires_at > ?`
	args := []any{owner, s.now().UTC()}
	if fired != nil {
		if *fired {
			q += ` AND fired_at IS NOT NULL`
		} else {
			q += ` AND fired_at IS NULL`
		}
	}
	q += ` ORDER BY created_at DESC`
	rows, err := s.db.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	return scanFullWatches(rows)
}

// SaveProgress records what an evaluation learned about a watch that did
// not fire: the tracked set only. It is separate from Fire so that the
// common case -- nothing happened -- cannot accidentally write a fired
// timestamp.
func (s *Store) SaveProgress(ctx context.Context, id string, tracked []JobID) error {
	blob, err := json.Marshal(tracked)
	if err != nil {
		return fmt.Errorf("encoding the tracked set: %w", err)
	}
	_, err = s.db.ExecContext(ctx,
		`UPDATE job_watches SET tracked_json = ? WHERE id = ? AND fired_at IS NULL`, string(blob), id)
	return err
}

// Fire records the first time a watch was satisfied. The
// "fired_at IS NULL" guard makes it idempotent: two evaluators, or a
// retry after a partial failure, must not move the moment it happened or
// replace the jobs that caused it.
func (s *Store) Fire(ctx context.Context, id string, out Outcome, at time.Time) error {
	matched, err := json.Marshal(out.Matched)
	if err != nil {
		return fmt.Errorf("encoding the matched jobs: %w", err)
	}
	tracked, err := json.Marshal(out.Tracked)
	if err != nil {
		return fmt.Errorf("encoding the tracked set: %w", err)
	}
	_, err = s.db.ExecContext(ctx, `
		UPDATE job_watches
		   SET fired_at = ?, matched_json = ?, matched_total = ?, tracked_json = ?
		 WHERE id = ? AND fired_at IS NULL`,
		at.UTC(), string(matched), out.Satisfied, string(tracked), id)
	return err
}

// MarkDelivered notes that an owner has read these outcomes. It does not
// delete them: a fired watch stays readable until it expires, so an
// agent that loses its context, or a second session, can still find out
// what happened. Owner-scoped so one caller cannot mark another's.
func (s *Store) MarkDelivered(ctx context.Context, owner string, ids []string) error {
	if owner == "" {
		return ErrNoOwner
	}
	now := s.now().UTC()
	for _, id := range ids {
		if _, err := s.db.ExecContext(ctx,
			`UPDATE job_watches SET delivered_at = ? WHERE id = ? AND owner = ?`, now, id, owner); err != nil {
			return err
		}
	}
	return nil
}

// Cancel removes one of an owner's watches.
func (s *Store) Cancel(ctx context.Context, owner, id string) (bool, error) {
	if owner == "" {
		return false, ErrNoOwner
	}
	res, err := s.db.ExecContext(ctx, `DELETE FROM job_watches WHERE id = ? AND owner = ?`, id, owner)
	if err != nil {
		return false, err
	}
	n, err := res.RowsAffected()
	return n > 0, err
}

// Prune deletes expired watches and reports how many went. Expiry is
// what keeps an abandoned watch from being evaluated forever.
func (s *Store) Prune(ctx context.Context) (int64, error) {
	res, err := s.db.ExecContext(ctx, `DELETE FROM job_watches WHERE expires_at <= ?`, s.now().UTC())
	if err != nil {
		return 0, err
	}
	return res.RowsAffected()
}

func newID() (string, error) {
	b := make([]byte, 8)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("generating a watch id: %w", err)
	}
	return "w-" + hex.EncodeToString(b), nil
}

func scanWatches(rows *sql.Rows) ([]*Watch, error) {
	defer func() { _ = rows.Close() }()
	var out []*Watch
	for rows.Next() {
		w := &Watch{}
		var event, mode, tracked string
		if err := rows.Scan(&w.ID, &w.Owner, &w.Label, &w.Constraint, &event, &w.Condition, &mode,
			&w.CreatedAt, &tracked); err != nil {
			return nil, err
		}
		if err := finish(w, event, mode, tracked); err != nil {
			return nil, err
		}
		out = append(out, w)
	}
	return out, rows.Err()
}

func scanFullWatches(rows *sql.Rows) ([]*Watch, error) {
	defer func() { _ = rows.Close() }()
	var out []*Watch
	for rows.Next() {
		w := &Watch{}
		var event, mode, tracked, matched string
		var firedAt, deliveredAt sql.NullTime
		if err := rows.Scan(&w.ID, &w.Owner, &w.Label, &w.Constraint, &event, &w.Condition, &mode,
			&w.CreatedAt, &tracked, &firedAt, &matched, &w.MatchedTotal, &deliveredAt); err != nil {
			return nil, err
		}
		if err := finish(w, event, mode, tracked); err != nil {
			return nil, err
		}
		if firedAt.Valid {
			w.FiredAt = firedAt.Time
		}
		if deliveredAt.Valid {
			w.DeliveredAt = deliveredAt.Time
		}
		if err := json.Unmarshal([]byte(matched), &w.Matched); err != nil {
			return nil, fmt.Errorf("watch %s: decoding matched jobs: %w", w.ID, err)
		}
		out = append(out, w)
	}
	return out, rows.Err()
}

// finish restores the typed fields and compiles the expressions. A
// stored row that no longer parses, or names an event this build does
// not know, is an error rather than a watch that quietly matches
// nothing -- which is indistinguishable from one still waiting.
func finish(w *Watch, event, mode, tracked string) error {
	w.Event, w.Mode = Event(event), Mode(mode)
	if !w.Event.Valid() {
		return fmt.Errorf("watch %s: stored event %q is not one this build knows", w.ID, event)
	}
	if w.Mode != ModeAny && w.Mode != ModeAll {
		return fmt.Errorf("watch %s: stored mode %q is not one this build knows", w.ID, mode)
	}
	if err := json.Unmarshal([]byte(tracked), &w.Tracked); err != nil {
		return fmt.Errorf("watch %s: decoding the tracked set: %w", w.ID, err)
	}
	return w.Compile()
}
