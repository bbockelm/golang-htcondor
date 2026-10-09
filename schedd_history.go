package htcondor

import (
	"context"

	"github.com/PelicanPlatform/classad/classad"
	"github.com/bbockelm/cedar/commands"
)

// historyEndpoint is the schedd as a history peer: QUERY_SCHEDD_HISTORY, rate-limited by the
// process's schedd limiter like every other schedd query.
func (s *Schedd) historyEndpoint() historyEndpoint {
	e := historyEndpoint{address: s.address, cfg: s.cfg, command: commands.QUERY_SCHEDD_HISTORY, daemon: "schedd"}
	if m := rateLimitManagerFor(s.cfg); m != nil {
		e.rateLimit = m.WaitSchedd
	}
	return e
}

// QueryHistory queries the schedd for job history records
// constraint is a ClassAd constraint expression (use "true" to get all records)
// projection is a list of attributes to return (use nil to get all attributes)
//
// This method queries standard job history (completed jobs) by default.
// For epoch or transfer history, use QueryHistoryWithOptions.
func (s *Schedd) QueryHistory(ctx context.Context, constraint string, projection []string) ([]*classad.ClassAd, error) {
	opts := &HistoryQueryOptions{
		Source:     HistorySourceJobHistory,
		Projection: projection,
	}
	return s.QueryHistoryWithOptions(ctx, constraint, opts)
}

// QueryHistoryWithOptions queries the schedd for history records with options
// opts specifies query options including source type, limit, and projection
// Returns the matching history ads
func (s *Schedd) QueryHistoryWithOptions(ctx context.Context, constraint string, opts *HistoryQueryOptions) ([]*classad.ClassAd, error) {
	return s.historyEndpoint().queryWithOptions(ctx, constraint, opts)
}

// HistoryAdResult represents a single history ad or error from a streaming query
type HistoryAdResult struct {
	Ad  *classad.ClassAd
	Err error
}

// QueryHistoryStream queries the schedd for history and streams ads through a channel
// Returns a channel and an error. If the error is non-nil, it indicates a problem
// before the request was sent (e.g., invalid parameters, connection failure).
// The channel will be closed when all ads have been sent or an error occurs during streaming.
func (s *Schedd) QueryHistoryStream(ctx context.Context, constraint string, opts *HistoryQueryOptions, streamOpts *StreamOptions) (<-chan HistoryAdResult, error) {
	return s.historyEndpoint().queryStream(ctx, constraint, opts, streamOpts)
}
