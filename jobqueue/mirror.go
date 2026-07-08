// Package jobqueue mirrors a schedd's job_queue.log into a watch-enabled
// collections.Collection, so job ads can be watched -- resumable, constraint
// filtered, coalesced -- with the same subscription model as the collector's ad
// watch.
package jobqueue

import (
	"context"
	"strconv"
	"strings"
	"time"

	"github.com/PelicanPlatform/classad/collections"

	"github.com/bbockelm/golang-htcondor/classadlog"
)

// jobFactoryPrivateAttrs are cluster-ad attributes a proc does not inherit and
// that must not fan out to procs when they change: HTCondor's job-factory (late
// materialization) bookkeeping, which mutates as procs are materialized but is
// meaningless to a proc. Keeping these parent-private means a 10k-proc factory's
// per-proc cluster-ad churn causes zero watch fan-out.
var jobFactoryPrivateAttrs = []string{
	"JobMaterializeNextProcId",
	"JobMaterializeNextRow",
	"TotalSubmitProcs",
	"EditedClusterAttrs",
	"JobMaterializePaused",
	"JobMaterializePauseReason",
}

// parseJobKey splits a job_queue.log key "cluster.proc" into its integers.
func parseJobKey(key []byte) (cluster, proc int, ok bool) {
	s := string(key)
	dot := strings.LastIndexByte(s, '.')
	if dot < 0 {
		return 0, 0, false
	}
	cl, err1 := strconv.Atoi(s[:dot])
	pr, err2 := strconv.Atoi(s[dot+1:])
	if err1 != nil || err2 != nil {
		return 0, 0, false
	}
	return cl, pr, true
}

// jobParentKey maps a proc key "N.M" (M >= 0) to its cluster ad "N.-1"; a cluster
// ad (M == -1) or a malformed key has no parent.
func jobParentKey(key []byte) []byte {
	cl, pr, ok := parseJobKey(key)
	if !ok || pr < 0 {
		return nil
	}
	return []byte(strconv.Itoa(cl) + ".-1")
}

// jobStructural marks cluster ads (proc == -1), which are chained-to but hidden.
func jobStructural(key []byte) bool {
	_, pr, ok := parseJobKey(key)
	return ok && pr == -1
}

// mirrorable reports whether a key is a real job or its cluster ad (cluster >= 1),
// excluding the schedd's header/schema ads (cluster 0) and malformed keys.
func mirrorable(key []byte) bool {
	cl, _, ok := parseJobKey(key)
	return ok && cl >= 1
}

// DefaultPollInterval is how often the log is polled when Options.PollInterval
// is unset.
const DefaultPollInterval = 200 * time.Millisecond

// Options configures a Mirror.
type Options struct {
	// PollInterval is how often job_queue.log is polled (default 200ms).
	PollInterval time.Duration
	// WatchHistory is the backing collection's delete-journal capacity, enabling
	// Watch (default 8192). See collections.Options.
	WatchHistory int
	// WatchCoalesce batches the collection's live watch events (default 50ms), so
	// the many rapid SetAttribute updates a freshly submitted job takes are
	// delivered as one settled Upsert. See collections.Options.
	WatchCoalesce time.Duration
}

// Mirror tails a schedd job_queue.log and reflects the reconstructed job ads into
// a watch-enabled collections.Collection (keyed by the log's "cluster.proc"). It
// applies only committed transactions and coalesces early-job churn, so watchers
// see settled job state.
//
// Proc ads chain to their cluster ad (the collection is configured with
// ParentKeyFor/IsStructural), so a query or watch resolves attributes stored only
// on the cluster (e.g. DAGManJobId, Owner) and results/events carry them
// flattened. Cluster ads are hidden from results; factory bookkeeping is
// parent-private, so late-materialization churn does not fan out to procs.
type Mirror struct {
	reader   *classadlog.Reader
	col      *collections.Collection
	mirrored map[string]struct{} // keys currently reflected in col
	interval time.Duration
}

// New creates a Mirror over the job_queue.log at filename. The log need not exist
// yet; the mirror picks it up when it appears.
func New(filename string, opts Options) (*Mirror, error) {
	r, err := classadlog.NewReader(filename)
	if err != nil {
		return nil, err
	}
	if opts.PollInterval <= 0 {
		opts.PollInterval = DefaultPollInterval
	}
	if opts.WatchHistory <= 0 {
		opts.WatchHistory = 8192
	}
	if opts.WatchCoalesce <= 0 {
		opts.WatchCoalesce = 50 * time.Millisecond
	}
	col := collections.New(collections.Options{
		WatchHistory:  opts.WatchHistory,
		WatchCoalesce: opts.WatchCoalesce,
		// Chain proc ads to their cluster ad so a query/watch like DAGManJobId == 42
		// resolves the cluster's attribute; the cluster ad is stored (co-located,
		// used as the parent) but hidden from results. Factory bookkeeping stays
		// parent-private so its per-proc churn does not fan out.
		ParentKeyFor:       jobParentKey,
		IsStructural:       jobStructural,
		ParentPrivateAttrs: jobFactoryPrivateAttrs,
	})
	return &Mirror{
		reader:   r,
		col:      col,
		mirrored: make(map[string]struct{}),
		interval: opts.PollInterval,
	}, nil
}

// Collection returns the watch-enabled collection reflecting the job queue. Use
// its Watch method (optionally via collections.WatchFilter) to subscribe.
func (m *Mirror) Collection() *collections.Collection { return m.col }

// Run polls the log and syncs changes into the collection until ctx is cancelled,
// starting with an immediate sync. Transient poll errors (e.g. the log not
// existing yet) are retried on the next tick.
func (m *Mirror) Run(ctx context.Context) error {
	_ = m.Poll(ctx)
	ticker := time.NewTicker(m.interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
			_ = m.Poll(ctx)
		}
	}
}

// Poll reads any new log entries and syncs the resulting committed changes into
// the collection. Run calls it on a timer; call it directly for synchronous
// control (e.g. in tests).
func (m *Mirror) Poll(ctx context.Context) error {
	if err := m.reader.Poll(ctx); err != nil {
		return err
	}
	m.sync()
	return nil
}

// sync applies the reader's pending committed changes to the collection.
func (m *Mirror) sync() {
	keys, reset, inTxn := m.reader.Changes()
	if inTxn {
		return // a transaction is open; wait for it to commit
	}
	if reset {
		m.resync()
		return
	}
	for _, key := range keys {
		m.applyKey(key)
	}
}

// applyKey mirrors one key's current state into the collection. Cluster ads are
// mirrored too (as structural parents); the schedd's header/schema ads (cluster
// 0) and malformed keys are skipped.
func (m *Mirror) applyKey(key string) {
	if !mirrorable([]byte(key)) {
		return
	}
	ad := m.reader.GetClassAd(key)
	if ad == nil {
		delete(m.mirrored, key)
		_ = m.col.Delete([]byte(key))
		return
	}
	m.mirrored[key] = struct{}{}
	_ = m.col.Put([]byte(key), ad)
}

// resync rebuilds the collection after a log rotation: put every current ad and
// delete any previously-mirrored key that is no longer present.
func (m *Mirror) resync() {
	live := make(map[string]struct{})
	for _, key := range m.reader.GetAllKeys() {
		if !mirrorable([]byte(key)) {
			continue
		}
		ad := m.reader.GetClassAd(key)
		if ad == nil {
			continue
		}
		live[key] = struct{}{}
		_ = m.col.Put([]byte(key), ad)
	}
	for key := range m.mirrored {
		if _, ok := live[key]; !ok {
			_ = m.col.Delete([]byte(key))
		}
	}
	m.mirrored = live
}
