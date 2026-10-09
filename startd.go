package htcondor

import (
	"context"

	"github.com/PelicanPlatform/classad/classad"
	"github.com/bbockelm/cedar/commands"
	"github.com/bbockelm/golang-htcondor/config"
)

// Startd is a client for one execution point's condor_startd. Today it speaks only the startd's
// remote-history protocol (GET_HISTORY, HTCondor 8.9.7+), which serves the per-job records the
// startd appends to its STARTD_HISTORY file as each job finishes on that machine. That file is the
// execution point's own view of what ran there -- it exists even for jobs whose submitting schedd
// is not ours, and it survives the schedd forgetting the job.
type Startd struct {
	name    string
	address string
	// cfg is the HTCondor configuration this client authenticates and
	// rate-limits with; nil means the process-wide default. See WithConfig.
	cfg *config.Config
}

// NewStartd creates a new Startd instance.
// address can be a hostname:port or a sinful string like "<IP:PORT?addrs=...>".
func NewStartd(name string, address string) *Startd {
	return &Startd{name: name, address: address}
}

// Name returns the startd's name.
func (s *Startd) Name() string { return s.name }

// Address returns the startd's address.
func (s *Startd) Address() string { return s.address }

// historyEndpoint is the startd as a history peer. Unlike the schedd's, it is not rate limited:
// there is no startd limiter, and the schedd's would throttle a fan-out across a pool's execution
// points on a knob that means something else.
func (s *Startd) historyEndpoint() historyEndpoint {
	return historyEndpoint{address: s.address, cfg: s.cfg, command: commands.GET_HISTORY, daemon: "startd"}
}

// startdOptions forces the startd record source, which is the only thing this daemon serves: the
// caller's other options (constraint, projection, since, limit, direction) are kept.
func startdOptions(opts *HistoryQueryOptions) *HistoryQueryOptions {
	var out HistoryQueryOptions
	if opts != nil {
		out = *opts
	}
	out.Source = HistorySourceStartd
	return &out
}

// QueryHistory queries the startd for the job history records it wrote as jobs finished on that
// machine. constraint is a ClassAd constraint expression (use "true" or "" for all records);
// projection is the attributes to return (nil for condor_history's default set, []string{"*"} for
// every attribute).
func (s *Startd) QueryHistory(ctx context.Context, constraint string, projection []string) ([]*classad.ClassAd, error) {
	return s.QueryHistoryWithOptions(ctx, constraint, &HistoryQueryOptions{Projection: projection})
}

// QueryHistoryWithOptions queries the startd's history with options. opts.Source is ignored -- the
// startd serves startd history and nothing else.
func (s *Startd) QueryHistoryWithOptions(ctx context.Context, constraint string, opts *HistoryQueryOptions) ([]*classad.ClassAd, error) {
	return s.historyEndpoint().queryWithOptions(ctx, constraint, startdOptions(opts))
}

// QueryHistoryStream queries the startd's history and streams the records through a channel, which
// is closed when the query finishes or fails. A non-nil error means the query never started.
func (s *Startd) QueryHistoryStream(ctx context.Context, constraint string, opts *HistoryQueryOptions, streamOpts *StreamOptions) (<-chan HistoryAdResult, error) {
	return s.historyEndpoint().queryStream(ctx, constraint, startdOptions(opts), streamOpts)
}
