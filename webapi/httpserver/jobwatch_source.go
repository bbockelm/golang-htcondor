package httpserver

import (
	"context"
	"fmt"
	"time"

	"github.com/PelicanPlatform/classad/classad"

	htcondor "github.com/bbockelm/golang-htcondor"
	"github.com/bbockelm/golang-htcondor/logging"
	"github.com/bbockelm/golang-htcondor/webapi/jobwatch"
)

// watchSource feeds the job-watch evaluator.
//
// It reads through the htcondordb mirror when one is usable and falls
// back to the schedd for the live queue only. History deliberately has
// no schedd fallback: condor_history scans the on-disk history file, and
// putting that on a background loop that runs every thirty seconds would
// spend more of the access point than every agent's polling did. The
// evaluator already degrades when history is unavailable -- it loses the
// success/failure distinction and keeps everything else -- which is the
// right trade for a mirror that is down.
type watchSource struct {
	h *Handler
	// feed, when warm, supplies terminal records observed on the change
	// stream. It is merged with -- never substituted for -- the history
	// table: the feed answers sooner and without an archive, the archive
	// answers for anything the feed missed or evicted.
	feed *jobwatch.Feed
}

// Queue returns one owner's jobs.
//
// The owner is interpolated here and the watch's own constraint is not:
// the constraint never reaches a backend query at all (see
// jobwatch.Source), so the only expression built here is one this daemon
// authored from an authenticated identity.
//
// Truncated is set by fetching one row past the limit. It matters more
// than a normal over-fetch: the evaluator treats a tracked job's absence
// from a COMPLETE queue as evidence that it finished, so a silently
// truncated read would report a running cluster as done.
func (s watchSource) Queue(ctx context.Context, owner string, attrs []string, limit int,
	yield func(*classad.ClassAd)) (bool, error) {
	constraint := fmt.Sprintf("Owner == %s", classadStringLit(owner))

	// One past the limit, so "there were more" is detected rather than
	// assumed away. The probe row is counted and dropped, never yielded.
	seen := 0
	count := func(ad *classad.ClassAd) {
		seen++
		if seen <= limit {
			yield(ad)
		}
	}

	if err := s.streamMirror(ctx, "jobs", constraint, attrs, limit+1, count); err == nil {
		return seen > limit, nil
	} else if s.h.dbMirror.Enabled() {
		s.h.logger.Debug(logging.DestinationHTTP,
			"job watches: mirror unavailable for the queue, using the schedd", "error", err)
	}

	// The schedd fallback restarts the count: the mirror attempt may
	// have yielded rows before failing, but a fold is idempotent per job
	// (each ad's placement is recorded by identity), so re-feeding them
	// is harmless.
	seen = 0
	ads, _, err := s.h.schedd.QueryWithOptions(ctx, constraint, &htcondor.QueryOptions{
		Limit:      limit + 1,
		Projection: attrs,
		FetchOpts:  htcondor.FetchNormal,
	})
	if err != nil {
		return false, fmt.Errorf("reading the queue from the schedd: %w", err)
	}
	for _, ad := range ads {
		count(ad)
	}
	return seen > limit, nil
}

// History returns one owner's finished jobs since a point in time,
// from two sources that cover each other's gaps.
//
// The change stream is preferred where it has an answer. A job's outcome
// exists in the queue only for the moment before the ad is destroyed, so
// the stream sees it and a poll does not -- and the stream has it
// immediately, where the history archive has it only once the schedd has
// written and the syncer has read the history file.
//
// The archive fills in everything the stream could not: jobs that ended
// before this daemon connected, anything lost to a gap or an eviction,
// and the whole picture when no feed is configured. Rows from the
// archive win on conflict; they are the durable record, and the stream
// is an observation of it in flight.
func (s watchSource) History(ctx context.Context, owner string, attrs []string, since time.Time, limit int,
	yield func(*classad.ClassAd)) error {
	seen := make(map[jobKey]struct{}, 64)
	emit := func(ad *classad.ClassAd) {
		k := keyOf(ad)
		if _, dup := seen[k]; dup {
			return
		}
		seen[k] = struct{}{}
		yield(ad)
	}

	// The archive first, so its rows win the deduplication: it is the
	// durable record, and the stream is an observation of it in flight.
	var archiveErr error
	if s.h.dbMirror.Enabled() {
		constraint := fmt.Sprintf("(Owner == %s) && (EnteredCurrentStatus >= %d || CompletionDate >= %d)",
			classadStringLit(owner), since.Unix(), since.Unix())
		archiveErr = s.streamMirror(ctx, "history", constraint, attrs, limit, emit)
	} else {
		archiveErr = fmt.Errorf("no htcondordb mirror is configured")
	}

	// Then whatever the change stream saw end, which covers jobs whose
	// history row has not landed yet and everything during an archive
	// outage. This is what keeps terminal outcomes resolving when the
	// archive is unreachable.
	var streamed int
	if s.feed != nil {
		for _, ad := range s.feed.Terminal(owner, since) {
			streamed++
			emit(ad)
		}
	}
	if archiveErr != nil && streamed == 0 {
		return fmt.Errorf("terminal job outcomes cannot be resolved: %w", archiveErr)
	}
	if archiveErr != nil {
		s.h.logger.Debug(logging.DestinationHTTP,
			"job watches: history unavailable, using change-stream terminal records", "error", archiveErr)
	}
	return nil
}

type jobKey struct{ cluster, proc int64 }

func keyOf(ad *classad.ClassAd) jobKey {
	var k jobKey
	k.cluster, _ = ad.EvaluateAttrInt("ClusterId")
	k.proc, _ = ad.EvaluateAttrInt("ProcId")
	return k
}

// fromMirror runs one bounded, projected read against a mirror table.
// The projection is the difference between a few megabytes and a few
// hundred: a whole job ad parses to about 12 KB of heap, the ten or so
// attributes an evaluation reads to about 1.4 KB.
func (s watchSource) streamMirror(ctx context.Context, table, constraint string, attrs []string, limit int,
	yield func(*classad.ClassAd)) error {
	if !s.h.dbMirror.Enabled() {
		return fmt.Errorf("htcondordb routing is not configured")
	}
	dbc, closer, _, err := s.h.dbMirror.Client(ctx)
	if err != nil {
		return err
	}
	defer closer()

	// Streamed rather than collected: the caller folds each ad and lets
	// it go, so a large queue never exists in memory at once.
	//
	// A row that will not parse stops the read. Skipping it would be
	// worse than failing: to a terminal event a missing job is an ended
	// job, so a dropped row reads as a finished one.
	var parseErr error
	if err := dbc.QueryRawProjectStream(ctx, table, constraint, attrs, limit, func(row string) bool {
		ad, perr := classad.ParseOld(row)
		if perr != nil {
			parseErr = fmt.Errorf("parsing a row from the mirror's %s table: %w", table, perr)
			return false
		}
		yield(ad)
		return true
	}); err != nil {
		return err
	}
	return parseErr
}
