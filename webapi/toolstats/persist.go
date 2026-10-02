package toolstats

import (
	"context"
	"database/sql"
	"encoding/json"
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
	if db == nil {
		return nil
	}
	rows, err := db.QueryContext(ctx,
		`SELECT tool, actor, client, outcome, calls, duration_sum_seconds, buckets, last_call_at
		   FROM mcp_tool_stats`)
	if err != nil {
		if isMissingTable(err) {
			return nil
		}
		return fmt.Errorf("toolstats: load: %w", err)
	}
	defer func() { _ = rows.Close() }()

	out := map[Key]Entry{}
	for rows.Next() {
		var (
			k           Key
			e           Entry
			bucketsJSON string
			lastCall    int64
		)
		if err := rows.Scan(&k.Tool, &k.User, &k.Client, &k.Outcome,
			&e.Calls, &e.DurationSum, &bucketsJSON, &lastCall); err != nil {
			return fmt.Errorf("toolstats: load: %w", err)
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
		return fmt.Errorf("toolstats: load: %w", err)
	}
	s.Load(out)
	return nil
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
	snap, dirty := s.SnapshotForFlush()
	if !dirty {
		return nil
	}
	if err := s.flush(ctx, db, snap); err != nil {
		// Re-arm so the next tick retries; otherwise a transient
		// failure would silently drop everything counted since the
		// last success.
		s.MarkDirty()
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
