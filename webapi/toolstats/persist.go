package toolstats

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"
)

// LoadFrom reads the persisted totals into the store, replacing
// whatever it holds.
//
// A missing table is not an error: a server whose database predates
// this feature, or one whose migrations have not run yet, starts from
// zero rather than refusing to start. Statistics are not worth failing
// a boot over.
func (s *Store) LoadFrom(ctx context.Context, db *sql.DB) error {
	out, err := s.readRows(ctx, db)
	if out == nil {
		return err
	}
	s.Load(out)
	return err
}

// ReloadFrom is the recovery path: it re-reads the table after a failed
// load and MERGES, so the calls counted while the database was
// unreadable are added to the stored history rather than replacing it
// or being thrown away.
func (s *Store) ReloadFrom(ctx context.Context, db *sql.DB) error {
	out, err := s.readRows(ctx, db)
	if out == nil {
		return err
	}
	s.Merge(out)
	return err
}

// readRows reads the table. It returns a nil map when the caller must
// not apply anything -- a read that failed, or no database at all --
// and a non-nil map (with a possibly non-nil error naming skipped
// rows) when what was read is safe to use.
func (s *Store) readRows(ctx context.Context, db *sql.DB) (map[Key]Entry, error) {
	if db == nil {
		return nil, nil
	}
	rows, err := db.QueryContext(ctx,
		`SELECT tool, actor, client, outcome, calls, duration_sum_seconds, buckets, last_call_at
		   FROM mcp_tool_stats`)
	if err != nil {
		if isMissingTable(err) {
			// Nothing to read and nothing to destroy: a database that
			// predates this feature starts from zero and may flush.
			return map[Key]Entry{}, nil
		}
		s.markLoadFailed()
		return nil, fmt.Errorf("toolstats: load: %w", err)
	}
	defer func() { _ = rows.Close() }()

	out := map[Key]Entry{}
	skipped := 0
	for rows.Next() {
		var (
			k           Key
			e           Entry
			bucketsJSON string
			lastCall    int64
		)
		if err := rows.Scan(&k.Tool, &k.User, &k.Client, &k.Outcome,
			&e.Calls, &e.DurationSum, &bucketsJSON, &lastCall); err != nil {
			// Skip the row, keep the rest. SQLite is dynamically
			// typed, so a single cell holding the wrong kind of value
			// -- written by hand, or by some future bug -- used to
			// abort the whole load and leave the store empty, which a
			// later flush then wrote back over every good row. One
			// unreadable row costs that row.
			//
			// The skipped row is NOT dropped from the table: it is
			// absent from the store, so no flush rewrites it, and an
			// operator can still see and repair it.
			skipped++
			continue
		}
		// A row whose bucket array will not parse still has usable
		// counts; losing its distribution is better than losing the
		// deployment's call history because one cell was corrupted.
		if bucketsJSON != "" {
			_ = json.Unmarshal([]byte(bucketsJSON), &e.Buckets)
		}
		if lastCall > 0 {
			e.LastCall = time.Unix(lastCall, 0)
		}
		out[k] = e
	}
	if err := rows.Err(); err != nil {
		// The iteration itself failed, so what was read is a partial
		// prefix of the table rather than the table. Loading it would
		// make the store disagree with the rows a flush overwrites.
		s.markLoadFailed()
		return nil, fmt.Errorf("toolstats: load: %w", err)
	}
	if skipped > 0 {
		return out, fmt.Errorf("toolstats: load: %d unreadable row(s) skipped; %d loaded",
			skipped, len(out))
	}
	return out, nil
}

// Flush writes the current totals.
//
// The whole snapshot is written every time, as an upsert per series.
// That is deliberately simple: the row count is bounded by the number
// of (tool, user, client, outcome) combinations actually seen, the
// write happens on a timer rather than per call, and a crash between
// flushes loses at most one interval of counting -- which is the
// trade this feature exists to make, not a defect in it.
//
// The whole flush is one transaction so a reader never sees half of it,
// and so a failure partway leaves the previous totals intact rather
// than a mixture of two runs.
func (s *Store) Flush(ctx context.Context, db *sql.DB) error {
	if db == nil {
		return nil
	}
	// Never write absolute totals over a record this store failed to
	// read: the store is empty or partial, and the upsert would
	// replace the deployment's history with it.
	if s.LoadFailed() {
		return errFlushWithoutLoad
	}
	snap, dirty := s.SnapshotForFlush()
	if !dirty {
		return nil
	}
	if err := s.flush(ctx, db, snap); err != nil {
		// Hand the series back so the next tick retries them;
		// otherwise a transient failure would silently drop everything
		// counted since the last success.
		s.MarkDirty(snap)
		return err
	}
	return nil
}

func (s *Store) flush(ctx context.Context, db *sql.DB, snap map[Key]Entry) error {
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("toolstats: flush: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	stmt, err := tx.PrepareContext(ctx,
		`INSERT INTO mcp_tool_stats
		   (tool, actor, client, outcome, calls, duration_sum_seconds, buckets, last_call_at)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?)
		 ON CONFLICT(tool, actor, client, outcome) DO UPDATE SET
		   calls                = excluded.calls,
		   duration_sum_seconds = excluded.duration_sum_seconds,
		   buckets              = excluded.buckets,
		   last_call_at         = excluded.last_call_at`)
	if err != nil {
		return fmt.Errorf("toolstats: flush: %w", err)
	}
	defer func() { _ = stmt.Close() }()

	for k, e := range snap {
		buckets, err := json.Marshal(e.Buckets)
		if err != nil {
			return fmt.Errorf("toolstats: flush: %w", err)
		}
		var last int64
		if !e.LastCall.IsZero() {
			last = e.LastCall.Unix()
		}
		if _, err := stmt.ExecContext(ctx, k.Tool, k.User, k.Client, k.Outcome,
			e.Calls, e.DurationSum, string(buckets), last); err != nil {
			return fmt.Errorf("toolstats: flush: %w", err)
		}
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("toolstats: flush: %w", err)
	}
	return nil
}

// isMissingTable reports whether err is SQLite's "no such table".
// Matched on the message because the pure-Go driver does not expose a
// typed error for it.
func isMissingTable(err error) bool {
	return err != nil && strings.Contains(strings.ToLower(err.Error()), "no such table")
}

// errFlushWithoutLoad is returned instead of overwriting a durable
// record that could not be read. Counting continues in memory, and a
// later successful load lets the flush resume -- see LoadFailed.
var errFlushWithoutLoad = errors.New(
	"toolstats: refusing to flush: the persisted totals could not be read, " +
		"so writing would replace them with this process's counts alone")

// ErrFlushWithoutLoad reports whether err is that refusal, so a caller
// can log it as the deliberate safety stop it is rather than as a
// database failure.
func ErrFlushWithoutLoad(err error) bool { return errors.Is(err, errFlushWithoutLoad) }
