package appolicy

import (
	"context"
	"time"

	htcondor "github.com/bbockelm/golang-htcondor"
	"github.com/bbockelm/golang-htcondor/config"
)

// SubmitLookupWait bounds how long a submission waits for the access
// point's request defaults when they are not cached. A submission is
// never refused for want of them: past this it goes ahead with the
// fallbacks.
const SubmitLookupWait = 10 * time.Second

// submitParams answers the submit engine's JOB_DEFAULT_REQUEST* questions:
// with the access point's own value wherever its schedd answered, so that
// a job submitted here gets what condor_submit on the access point would
// give it -- and what get_access_point_policy reports -- and otherwise
// with this server's configuration, then HTCondor's built-in default.
//
// An unset knob the schedd reported is an answer: it is not overridden by
// a local value, which would describe some other machine.
type submitParams struct {
	snap  *Snapshot
	local *config.Config
}

func (p submitParams) Get(name string) (string, bool) {
	if v := p.snap.Get(name); v.Asked && v.Err == nil {
		return v.Raw, true
	}
	if p.local != nil {
		return p.local.Get(name)
	}
	return "", false
}

// SubmitParams returns the submit engine's request defaults from a
// reading of the access point (which may be nil) over local.
func SubmitParams(snap *Snapshot, local *config.Config) htcondor.SubmitParams {
	return submitParams{snap: snap, local: local}
}

// SubmitContext returns ctx carrying the request defaults for a job
// submitted to the access point ap through src.
//
// It never fails the submission. When the access point cannot be asked
// in time, the context carries local's values and the error says why, for
// the caller to log.
func (c *Cache) SubmitContext(ctx context.Context, ap string, src ConfigSource, local *config.Config) (context.Context, error) {
	var snap *Snapshot
	var err error
	if c != nil && src != nil {
		lctx, cancel := context.WithTimeout(ctx, SubmitLookupWait)
		snap, err = c.Get(lctx, ap, src)
		cancel()
	}
	return htcondor.WithSubmitParams(ctx, SubmitParams(snap, local)), err
}
