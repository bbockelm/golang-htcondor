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
func (s watchSource) Queue(ctx context.Context, owner string, limit int) (jobwatch.QueueResult, error) {
	constraint := fmt.Sprintf("Owner == %s", classadStringLit(owner))

	if ads, err := s.fromMirror(ctx, "jobs", constraint, limit+1); err == nil {
		return truncate(ads, limit), nil
	} else if s.h.dbMirror.Enabled() {
		s.h.logger.Debug(logging.DestinationHTTP,
			"job watches: mirror unavailable for the queue, using the schedd", "error", err)
	}

	ads, _, err := s.h.schedd.QueryWithOptions(ctx, constraint, &htcondor.QueryOptions{
		Limit:     limit + 1,
		FetchOpts: htcondor.FetchNormal,
	})
	if err != nil {
		return jobwatch.QueueResult{}, fmt.Errorf("reading the queue from the schedd: %w", err)
	}
	return truncate(ads, limit), nil
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
func (s watchSource) History(ctx context.Context, owner string, since time.Time, limit int) ([]*classad.ClassAd, error) {
	var streamed []*classad.ClassAd
	if s.feed != nil {
		streamed = s.feed.Terminal(owner, since)
	}
	if !s.h.dbMirror.Enabled() {
		if len(streamed) > 0 {
			return streamed, nil
		}
		return nil, fmt.Errorf("no htcondordb mirror is configured and the change feed has nothing yet; " +
			"terminal job outcomes cannot be resolved")
	}
	constraint := fmt.Sprintf("(Owner == %s) && (EnteredCurrentStatus >= %d || CompletionDate >= %d)",
		classadStringLit(owner), since.Unix(), since.Unix())
	archived, err := s.fromMirror(ctx, "history", constraint, limit)
	if err != nil {
		if len(streamed) > 0 {
			// The feed is exactly what makes a history outage survivable
			// rather than a freeze: outcomes keep resolving for jobs it
			// watched end.
			s.h.logger.Debug(logging.DestinationHTTP,
				"job watches: history unavailable, using change-feed terminal records", "error", err)
			return streamed, nil
		}
		return nil, err
	}
	return mergeTerminal(archived, streamed), nil
}

// mergeTerminal combines archive rows with stream observations, letting
// the archive win per job.
func mergeTerminal(archived, streamed []*classad.ClassAd) []*classad.ClassAd {
	if len(streamed) == 0 {
		return archived
	}
	type key struct{ cluster, proc int64 }
	seen := make(map[key]struct{}, len(archived))
	idOf := func(ad *classad.ClassAd) key {
		var k key
		k.cluster, _ = ad.EvaluateAttrInt("ClusterId")
		k.proc, _ = ad.EvaluateAttrInt("ProcId")
		return k
	}
	for _, ad := range archived {
		seen[idOf(ad)] = struct{}{}
	}
	out := archived
	for _, ad := range streamed {
		if _, dup := seen[idOf(ad)]; !dup {
			out = append(out, ad)
		}
	}
	return out
}

// fromMirror runs one bounded read against a mirror table.
func (s watchSource) fromMirror(ctx context.Context, table, constraint string, limit int) ([]*classad.ClassAd, error) {
	if !s.h.dbMirror.Enabled() {
		return nil, fmt.Errorf("htcondordb routing is not configured")
	}
	dbc, closer, _, err := s.h.dbMirror.Client(ctx)
	if err != nil {
		return nil, err
	}
	defer closer()

	rows, err := dbc.QueryRawProject(ctx, table, constraint, nil, limit)
	if err != nil {
		return nil, fmt.Errorf("querying the mirror's %s table: %w", table, err)
	}
	ads := make([]*classad.ClassAd, 0, len(rows))
	for _, row := range rows {
		ad, perr := classad.ParseOld(row)
		if perr != nil {
			// One unreadable row must not be silently dropped: a missing
			// job reads as a finished job to the terminal events.
			return nil, fmt.Errorf("parsing a row from the mirror's %s table: %w", table, perr)
		}
		ads = append(ads, ad)
	}
	return ads, nil
}

func truncate(ads []*classad.ClassAd, limit int) jobwatch.QueueResult {
	if len(ads) > limit {
		return jobwatch.QueueResult{Ads: ads[:limit], Truncated: true}
	}
	return jobwatch.QueueResult{Ads: ads}
}
