package httpserver

import (
	"archive/tar"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"path"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"
	"unicode/utf8"

	"github.com/PelicanPlatform/classad/classad"
	htcondor "github.com/bbockelm/golang-htcondor"
	"github.com/bbockelm/golang-htcondor/logging"
	"github.com/bbockelm/golang-htcondor/webapi/dagman"
)

// GET /api/v1/jobs/{cluster}.{proc}/dag returns a DAGMan workflow's
// structure plus a per-node state overlay, which is everything a drawing
// needs and nothing it does not.
//
// Both halves come out of the manager job's spool, and NEITHER comes from
// the .dag file. A spooled job's sandbox is read with TRANSFER_DATA,
// which for a spooled job is a CHANGED-FILE transfer: the schedd built a
// catalog of the sandbox at stage-in and sends back only what is newer
// (FileTransfer::FindChangedFiles, file_transfer.cpp ~1300). The .dag was
// staged as input and DAGMan only reads it, so it is never newer and
// never comes back. What DAGMan WRITES during the run does come back for
// free, so that is what is read:
//
//   - The STRUCTURE comes from the DOT file DAGMan writes for a DAG that
//     says `DOT <file>` -- every node, every edge, written once at
//     startup. It never changes, so it is cached: a whole-sandbox
//     transfer is the same cost the /stdout and /stderr endpoints already
//     pay, and an ordinary page load must not pay it twice.
//   - The STATE comes from the NODE_STATUS_FILE, which DAGMan rewrites
//     every 30 seconds, supplemented by the live queue and the archive
//     for the job ids, hold reasons and exit codes that the status file
//     does not carry.
//
// Workflows submitted through this server declare both commands
// automatically (dagman.Instrument). One submitted any other way is
// readable here only if its author asked for them.
const (
	// dagCacheMaxEntries and dagCacheTTL bound the structure cache.
	//
	// The bound on entries is memory: a cached structure holds every
	// node name, and a 100,000-node workflow is ordinary here.
	//
	// The TTL is NOT about staleness of the graph -- the DOT file is
	// written once and never rewritten, so a cached structure can never
	// disagree with the workflow it came from. It exists so a cluster id
	// recycled after a schedd queue reset cannot be served another
	// workflow's graph.
	dagCacheMaxEntries = 16
	dagCacheTTL        = time.Hour

	// An ordinary load NEVER re-fetches the sandbox.
	//
	// There used to be a dagStatusMaxAge here: a cached entry whose node
	// status half was older than 45 seconds was thrown away and an
	// ordinary page load re-paid a whole-sandbox transfer. Almost every
	// real page view is more than 45 seconds after the last one, so the
	// "cheap cached load" was a fiction -- nearly every load paid the
	// transfer -- and it quietly contradicted the panel's own design,
	// which is explicit-load with a Refresh button and no polling.
	//
	// So the cached structure AND the cached state are served as they
	// are, and the response says how old they are (FetchedAt) so the
	// panel can too. ?refresh=1 is the only thing that fetches.

	// dagBigFileMaxBytes is the ceiling on the files this endpoint exists
	// to read: the DOT file and the node status file. It is generous
	// because it has to be -- a 100,000-node workflow's DOT file is tens
	// of megabytes and its status file more -- and refusing to draw
	// exactly the workflows that most need drawing would defeat the
	// endpoint.
	dagBigFileMaxBytes = 64 << 20
	// dagAuxFileMaxBytes is the ceiling on every other text file taken
	// from the spool. Anything larger is skipped rather than fetched into
	// memory.
	dagAuxFileMaxBytes = 8 << 20
	// dagAuxTotalMaxBytes is the budget for those OTHER files together.
	//
	// It deliberately does not cover the two files this endpoint exists
	// to read. A shared ceiling made the generous per-file one a lie:
	// the exact 100,000-node workflow dagBigFileMaxBytes exists for -- a
	// 50 MiB dot file beside a 50 MiB status file -- clears both
	// per-file ceilings and blew a 96 MiB shared total, so the endpoint
	// hard-refused precisely the graphs it was sized for. The aux files
	// are not essential (a log, a submit file), so their budget behaves
	// like the per-file aux ceiling: past it they are skipped, and the
	// graph is still read.
	dagAuxTotalMaxBytes = 96 << 20

	// dagMaxSpoolEntries caps how many regular files are looked at.
	//
	// The byte ceilings do not bound this. A fan-out workflow that
	// writes a per-node output file into the DAG's own Iwd -- the normal
	// shape -- leaves one tiny file per node in the spool, and a million
	// Go map entries exhaust memory long before a million small files
	// add up to a byte limit.
	dagMaxSpoolEntries = 50000

	// dagNodeTextMaxBytes bounds the two per-node strings that come from
	// outside this server and have no length of their own: DAGMan's
	// StatusDetails and the schedd's HoldReason.
	//
	// Every other field in a node entry is a name, a state word or a job
	// id, and 23 real nodes measured 2.8 KB of response in total. These
	// two are the only ones that can make that arbitrarily large: a hold
	// reason from a failed file transfer carries the plugin's own output
	// and runs to kilobytes, and twenty of those is a response two
	// orders of magnitude bigger than the workflow it describes.
	//
	// Truncating does not lose the information: the node carries its job
	// id, and the job page shows the reason in full. The panel renders
	// these as one paragraph in a group's detail box, which is far less
	// than this much text.
	dagNodeTextMaxBytes = 1024

	// dagNodeListLimit is how many per-node entries the response will
	// carry. Past this the caller gets groups only: a JSON array of
	// 100,000 node objects is not a payload a browser should be handed,
	// and the groups are what a drawing actually uses.
	dagNodeListLimit = 500

	// dagSandboxTimeout bounds the whole-sandbox fetch. It is longer
	// than the 30s the single-file endpoints use because this one reads
	// the stream to the end rather than stopping at the first match.
	dagSandboxTimeout = 2 * time.Minute

	// dagSandboxConcurrency caps whole-sandbox transfers in flight
	// across the whole process.
	//
	// Each one buffers up to the ceilings above for up to
	// dagSandboxTimeout, so a handful is already a gigabyte of live
	// heap. Without a cap, one caller looping on ?refresh=1 against
	// their OWN workflow is an out-of-memory for everybody sharing this
	// process.
	dagSandboxConcurrency = 4

	// dagNegativeCacheTTL is how long "this workflow publishes no
	// structure" and "its dot file will not parse" are remembered.
	//
	// Short, because both can stop being true -- DAGMan may be about to
	// write the file -- but not zero: a UI polls precisely because it
	// got no answer, and without this each poll re-pays a whole-sandbox
	// transfer.
	dagNegativeCacheTTL = 30 * time.Second

	// dagStartupGrace is how long after a manager job starts running its
	// DOT file may be missing without that meaning the workflow does not
	// publish one. DAGMan writes it immediately after parsing
	// (dagman_main.cpp:1135), but "immediately" is after it has read a
	// possibly enormous DAG, and the file still has to reach the spool.
	dagStartupGrace = 2 * time.Minute

	// schedulerUniverse is JobUniverse 7, which is what a DAGMan manager
	// job runs as.
	schedulerUniverse = 7
)

// Node states, as the response spells them. These are the union of what
// the status file, the queue and the archive can say, which is why there
// are more of them than JobStatus has values.
const (
	dagStateDone         = "done"
	dagStateRunning      = "running"
	dagStateIdle         = "idle"
	dagStateHeld         = "held"
	dagStateFailed       = "failed"
	dagStateRemoved      = "removed"
	dagStateTransferring = "transferring"
	dagStateSuspended    = "suspended"
	dagStateSubmitted    = "submitted"
	dagStateReady        = "ready"
	dagStatePreRun       = "prerun"
	dagStatePostRun      = "postrun"
	dagStateFutile       = "futile"
	dagStateUnready      = "unready"
)

// State sources, as the response names them.
const (
	dagSourceStatusFile = "status-file"
	dagSourceDot        = "dot-file"
	dagSourceQueue      = "queue"
	dagSourceArchive    = "archive"
	dagSourceInferred   = "inferred"
)

// DagGraphResponse is the body of GET /api/v1/jobs/{id}/dag.
type DagGraphResponse struct {
	Cluster int    `json:"cluster"`
	DagFile string `json:"dag_file"`
	// DotFile and StatusFile name the files this answer was read out of,
	// so a caller looking at the spool can find them.
	DotFile    string `json:"dot_file"`
	StatusFile string `json:"status_file,omitempty"`
	NodeCount  int    `json:"node_count"`
	EdgeCount  int    `json:"edge_count"`
	GroupCount int    `json:"group_count"`

	Groups []DagGraphGroup `json:"groups"`
	// Nodes is the per-node overlay, or null when the workflow is too
	// large to list node by node. NodesOmitted then says so and
	// NodesOmittedReason says why.
	Nodes              []DagGraphNode `json:"nodes"`
	NodesOmitted       bool           `json:"nodes_omitted,omitempty"`
	NodesOmittedReason string         `json:"nodes_omitted_reason,omitempty"`

	// ApproximateLayering is set when the grouping is not the exact
	// structural one -- a cycle, or a refinement that hit its bound -- so
	// the group layering is a best effort rather than a topology.
	ApproximateLayering bool `json:"approximate_layering,omitempty"`

	// StateSources names which of status-file/dot-file/queue/archive
	// actually contributed a node state.
	StateSources []string `json:"state_sources"`
	// StatusFileTime is the node status file's own timestamp, present
	// only when that file contributed. It matters: the queue half of this
	// response is live, while the status file is only as fresh as DAGMan's
	// last write plus the last whole-sandbox fetch.
	StatusFileTime int64 `json:"status_file_time,omitempty"`
	// Warnings carry what could not be consulted, so a missing archive
	// reads as "not available" rather than as "nothing ran".
	Warnings []string `json:"warnings,omitempty"`
	// FetchedAt is when the structure and the node states in this answer
	// were actually read out of the spool -- NOT when this response was
	// assembled. On a cached load those are minutes apart, and the panel
	// reports this as the age of what it is drawing.
	FetchedAt time.Time `json:"fetched_at"`
	// TookMS is how long this request spent producing the answer, which
	// is the number the panel shows and the one an operator compares a
	// cached load against a refresh with.
	TookMS int64 `json:"took_ms"`
}

// DagGraphGroup is one collapsed group plus the state histogram of its
// members, which is what a drawing colours a shape by.
type DagGraphGroup struct {
	ID    string `json:"id"`
	Label string `json:"label"`
	// Description is what the group's nodes run, when it is known. It is
	// empty for a workflow read from a DOT file, which carries no submit
	// descriptions.
	Description string         `json:"description"`
	Count       int            `json:"count"`
	ParentIDs   []string       `json:"parent_ids"`
	Status      map[string]int `json:"status"`
}

// DagGraphNode is one node's state.
type DagGraphNode struct {
	Name    string `json:"name"`
	GroupID string `json:"group_id"`
	State   string `json:"state"`
	// JobID, HoldReason and ExitCode are the "why" behind a state, and
	// they come from the queue or the archive even when the state itself
	// came from the status file -- a node the status file calls an error
	// is a number until something says which job failed and how.
	JobID      string `json:"job_id,omitempty"`
	HoldReason string `json:"hold_reason,omitempty"`
	ExitCode   *int   `json:"exit_code,omitempty"`
	// Detail is DAGMan's own note about the node, when the status file
	// carried one ("idle: 2 held", an error message, "Had an ancestor
	// node fail").
	Detail string `json:"detail,omitempty"`
	Source string `json:"source"`
}

// dagTimings is how long each phase of one /dag answer took.
//
// It exists because "the panel is slow" is not actionable: the answer is
// assembled out of a whole-sandbox transfer, two file parses and two
// queries, and which of those dominates decides what there is to fix.
// A phase that did not run this time stays zero, which is itself the
// interesting reading -- a cached load's sandbox time IS zero.
type dagTimings struct {
	manager   time.Duration // the manager job's own ad
	structure time.Duration // cache lookup plus, on a miss, everything below
	sandbox   time.Duration // the whole-sandbox transfer
	dotParse  time.Duration
	statParse time.Duration
	queue     time.Duration
	archive   time.Duration
}

// log emits one debug line with every phase, so a slow load in the field
// can be attributed without a profiler.
func (t *dagTimings) log(s *Handler, cluster, proc int, total time.Duration, cached bool) {
	s.logger.Debug(logging.DestinationHTTP, "Served DAG graph",
		"job", fmt.Sprintf("%d.%d", cluster, proc),
		"cached", cached,
		"total_ms", total.Milliseconds(),
		"manager_ms", t.manager.Milliseconds(),
		"structure_ms", t.structure.Milliseconds(),
		"sandbox_ms", t.sandbox.Milliseconds(),
		"dot_parse_ms", t.dotParse.Milliseconds(),
		"status_parse_ms", t.statParse.Milliseconds(),
		"queue_ms", t.queue.Milliseconds(),
		"archive_ms", t.archive.Milliseconds())
}

// dagManagerProjection is what the manager job's ad has to answer:
// whether it is a DAGMan job at all, whether it was spooled, which file
// it was told to run, and how long it has been at it.
var dagManagerProjection = []string{
	"ClusterId", "ProcId", "JobStatus", "JobUniverse",
	"SUBMIT_Iwd", "Iwd", "Arguments", "Args", "Owner",
	"JobCurrentStartDate", "EnteredCurrentStatus", "QDate",
}

// handleJobDag handles GET /api/v1/jobs/{cluster}.{proc}/dag.
func (s *Handler) handleJobDag(w http.ResponseWriter, r *http.Request, cluster, proc int) {
	if r.Method != http.MethodGet {
		s.writeError(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}

	// Authenticate first, then owner-scope: both are exactly what the
	// neighbouring per-job file handlers do, and the scoped constraint
	// is reused verbatim for the sandbox transfer below, so a caller
	// cannot reach a workflow whose ad they could not read.
	ctx, needsRedirect, err := s.requireAuthentication(r)
	if err != nil {
		if needsRedirect {
			s.redirectToLogin(w, r)
			return
		}
		s.writeError(w, http.StatusUnauthorized, fmt.Sprintf("Authentication failed: %v", err))
		return
	}
	constraint, err := s.jobOwnerScope(ctx, r, cluster, proc)
	if err != nil {
		s.writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	started := time.Now()
	timings := &dagTimings{}
	phase := time.Now()
	ads, _, err := s.getSchedd().QueryWithOptions(ctx, constraint,
		&htcondor.QueryOptions{Projection: dagManagerProjection})
	timings.manager = time.Since(phase)
	if err != nil {
		s.logger.Error(logging.DestinationHTTP, "Failed to query DAGMan manager job", "error", err,
			"job", fmt.Sprintf("%d.%d", cluster, proc))
		s.writeError(w, http.StatusInternalServerError, "Failed to query job")
		return
	}
	if len(ads) == 0 {
		s.writeError(w, http.StatusNotFound, fmt.Sprintf("Job not found: %d.%d", cluster, proc))
		return
	}

	dagFile, status, msg := dagPrecondition(ads[0], cluster, proc)
	if status != 0 {
		s.writeError(w, status, msg)
		return
	}

	phase = time.Now()
	structure, status, msg := s.dagStructureFor(ctx, r, constraint, cluster, proc, dagFile, ads[0],
		r.URL.Query().Get("refresh") == "1", timings)
	timings.structure = time.Since(phase)
	if status != 0 {
		s.writeError(w, status, msg)
		return
	}

	resp := s.buildDagResponse(ctx, r, cluster, structure, timings)
	resp.TookMS = time.Since(started).Milliseconds()
	timings.log(s, cluster, proc, time.Since(started), timings.sandbox == 0)
	s.writeJSON(w, http.StatusOK, resp)
}

// dagPrecondition decides whether this job has a workflow graph at all,
// and says why not in words the caller can act on. A generic 400 here is
// useless: "not a DAG", "submitted from a shell" and "we cannot read the
// spool" call for three different reactions.
//
// status 0 means proceed, and dagFile is the .dag the manager was told to
// run -- which is not a file this endpoint reads, but is what the names
// of the files it DOES read are derived from.
func dagPrecondition(ad *classad.ClassAd, cluster, proc int) (dagFile string, status int, msg string) {
	universe, _ := ad.EvaluateAttrInt("JobUniverse")
	if universe != schedulerUniverse {
		return "", http.StatusNotFound, fmt.Sprintf(
			"Job %d.%d is not a DAGMan workflow: only a scheduler-universe job (JobUniverse 7) "+
				"running condor_dagman manages a workflow, and this one is universe %d.",
			cluster, proc, universe)
	}

	// A spooled job's Iwd IS its spool directory, and the schedd backs
	// the submit-time Iwd up in SUBMIT_Iwd exactly when it repoints Iwd
	// there. A non-empty SUBMIT_Iwd is therefore the test for "the files
	// are in the spool", which is the only place this server can reach.
	// The Iwd is NOT echoed. The ad read that produced it is owner
	// scoped only for a browser session, so for a token caller this path
	// is reachable against another user's job, and Iwd is that user's
	// home directory. The policy is the useful half of the message and
	// it survives without the path.
	if spooled, _ := ad.EvaluateAttrString("SUBMIT_Iwd"); strings.TrimSpace(spooled) == "" {
		return "", http.StatusConflict, fmt.Sprintf(
			"Workflow %d.%d was submitted from a shell on the access point, so its graph is not "+
				"available here.", cluster, proc)
	}

	dagFile = dagFileFromAd(ad)
	if dagFile == "" {
		return "", http.StatusNotFound, fmt.Sprintf(
			"Job %d.%d is a scheduler-universe job but its arguments name no -Dag file, "+
				"so it is not a DAGMan workflow manager.", cluster, proc)
	}
	return dagFile, 0, ""
}

// dagFileFromAd pulls the .dag file name out of the manager job's command
// line. Arguments is the V2 (new) syntax and Args the V1 fallback; a job
// ad carries whichever the submit file used, so both have to work.
func dagFileFromAd(ad *classad.ClassAd) string {
	if raw, ok := ad.EvaluateAttrString("Arguments"); ok && strings.TrimSpace(raw) != "" {
		if f := dagArgFromArgv(splitArgsV2(raw)); f != "" {
			return f
		}
	}
	if raw, ok := ad.EvaluateAttrString("Args"); ok && strings.TrimSpace(raw) != "" {
		if f := dagArgFromArgv(strings.Fields(raw)); f != "" {
			return f
		}
	}
	return ""
}

// dagArgFromArgv finds the argument after -Dag. DAGMan's own option
// parsing is case-insensitive and condor_submit_dag has written it
// "-Dag", "-dag" and "-DAG" over the years.
func dagArgFromArgv(argv []string) string {
	for i, a := range argv {
		if strings.EqualFold(a, "-dag") && i+1 < len(argv) {
			// Only the basename can be looked for: a spooled sandbox is
			// one flat directory.
			return path.Base(filepath.ToSlash(argv[i+1]))
		}
	}
	return ""
}

// splitArgsV2 splits an Arguments value written in submit "new syntax":
// space separated, with a run that contains whitespace wrapped in single
// quotes and a literal single quote doubled inside it. The surrounding
// double quotes belong to the submit file, not to the job ad, so the
// value here starts straight into the arguments.
func splitArgsV2(raw string) []string {
	var (
		out    []string
		cur    strings.Builder
		inQ    bool
		inWord bool
	)
	flush := func() {
		if inWord {
			out = append(out, cur.String())
			cur.Reset()
			inWord = false
		}
	}
	for i := 0; i < len(raw); i++ {
		c := raw[i]
		switch {
		case c == '\'' && inQ && i+1 < len(raw) && raw[i+1] == '\'':
			cur.WriteByte('\'')
			i++
		case c == '\'':
			inQ = !inQ
			inWord = true
		case !inQ && (c == ' ' || c == '\t' || c == '\n'):
			flush()
		default:
			cur.WriteByte(c)
			inWord = true
		}
	}
	flush()
	return out
}

// ---------------------------------------------------------------------
// Structure: fetched from the spool, cached.
// ---------------------------------------------------------------------

// dagStructure is everything one whole-sandbox fetch produced. It is
// immutable once built, so a cached copy is shared without copying.
type dagStructure struct {
	dagFile string
	dotFile string
	// owner is the manager job's Owner attribute: WHOSE workflow this
	// is. It is recorded because a cache hit skips the sandbox transfer,
	// and the schedd's per-job owner check goes with it -- see
	// dagCacheAccess.
	owner    string
	grouping *dagman.Grouping
	// dotStates are the per-node states the DOT file's labels carried, by
	// lower-cased node name. They are only meaningful when the DAG's
	// author asked for `DOT ... UPDATE`; without it the file is written
	// once at startup and every node reads as idle, which is why the
	// status file outranks this.
	dotStates map[string]string
	// statusStates are what DAGMan's node status file said at the moment
	// the sandbox was fetched.
	statusStates   map[string]dagStatusEntry
	statusFileName string
	statusFileTime int64
	// statusNextUpdate is the status file's own NextUpdate, and
	// sawStatusEnd says whether the ad that carries it was there at all.
	//
	// Both are needed. NextUpdate is inserted ONLY on the StatusEnd ad
	// (condor_dagman/dag.cpp:2703), so a file truncated at its last ad
	// -- the case parseNodeStatusFile deliberately tolerates -- leaves
	// it zero, and reading that zero as "DAGMan has written this file
	// for the last time" freezes a RUNNING workflow's state for the
	// whole cache TTL while still reporting status-file as its source.
	statusNextUpdate int64
	sawStatusEnd     bool
	fetchedAt        time.Time
}

// dagStatusEntry is one node's line in the status file.
type dagStatusEntry struct {
	state  string
	detail string
}

// stateIsFinal reports whether the state half of this structure can still
// change. It is used to decide whether an ordinary load has to re-fetch.
//
// A zero NextUpdate is only DAGMan's "never again" when a StatusEnd ad
// was actually read; an absent one means the file was truncated mid
// rewrite, which is the opposite conclusion.
func (st *dagStructure) stateIsFinal() bool {
	return st.statusFileName != "" && st.sawStatusEnd && st.statusNextUpdate == 0
}

// dagStructureCache is a small bounded, time-bounded cache. There is no
// shared LRU helper in this package to reuse (jobwatch has one, for
// something else), and a purpose-built one is forty lines.
//
// It is a package-level singleton rather than a Handler field because
// adding a field means editing handler.go, which is not this change's to
// edit. Entries are keyed by cluster.proc AND the resolved dot file
// name.
//
// The key is not enough to make a hit SAFE, and an earlier version of
// this comment claimed that it was -- that "nothing reaches the cache
// before the caller has passed the same owner-scoped ad lookup the rest
// of the per-job endpoints use". The ad lookup is not that check. For a
// bearer-token, API-key or UserHeader caller, bulkOwnerScope returns the
// constraint UNSCOPED (it only scopes a browser session), deliberately,
// because the schedd is supposed to be the backstop -- and the schedd
// backstops a SANDBOX TRANSFER (UserCheck2, per job, on a
// WRITE-registered command), not an ad read. A cache hit skips the
// transfer, so a hit does not merely save work: it removes the only
// authorization check on the path, and hands one user's node names,
// edges and DAGMan status details to another.
//
// So every entry records the manager job's owner, and dagCacheAccess
// decides whether this caller may be served it. A caller who may not
// falls through to a real transfer, which the schedd refuses.
type dagStructureCache struct {
	mu      sync.Mutex
	max     int
	ttl     time.Duration
	entries []dagCacheEntry // oldest first
	now     func() time.Time
}

// dagCacheEntry is one cached answer: a structure, or the refusal that
// producing it yielded. Both are cached, for different lifetimes -- see
// dagNegativeCacheTTL.
type dagCacheEntry struct {
	key string
	// owner is the Owner of the manager job this entry describes. An
	// empty one is never usable by anybody.
	owner string
	value *dagStructure
	// err is set on a negative entry, and then value is nil.
	err error
	at  time.Time
}

// lifetime is how long this entry may be served for.
func (e dagCacheEntry) lifetime(def time.Duration) time.Duration {
	if e.err != nil && dagNegativeCacheTTL < def {
		return dagNegativeCacheTTL
	}
	return def
}

// dagCacheAccess is who is asking, and about whose workflow. It is what
// makes a hit usable or not.
type dagCacheAccess struct {
	// owner is the Owner on the manager ad this request just read.
	owner string
	// caller is the authenticated actor reduced to the bare username
	// that Owner is stored as (ownerFromActor).
	caller string
	// admin is the Web UI admin path the neighbouring handlers define
	// (isWebUIAdmin). An admin may read any user's job, so an admin may
	// be served any user's entry -- the cache must not be the one place
	// that breaks the admin view.
	admin bool
}

// mayUse reports whether this caller may be served this entry.
//
// The owner match is demanded of an admin too, for a different reason:
// an entry whose owner is not the owner of the ad just read describes a
// DIFFERENT workflow under a recycled cluster id.
func (a dagCacheAccess) mayUse(e dagCacheEntry) bool {
	if a.owner == "" || e.owner == "" || e.owner != a.owner {
		return false
	}
	return a.admin || (a.caller != "" && a.caller == a.owner)
}

// mayShare reports whether this caller may be attached to a build
// another caller has in flight. It is the question mayUse asks -- a
// shared result is a cache hit under another name -- minus the entry,
// which does not exist yet.
func (a dagCacheAccess) mayShare() bool {
	return a.owner != "" && (a.admin || (a.caller != "" && a.caller == a.owner))
}

func newDagStructureCache(maxEntries int, ttl time.Duration) *dagStructureCache {
	return &dagStructureCache{max: maxEntries, ttl: ttl, now: time.Now}
}

var dagStructures = newDagStructureCache(dagCacheMaxEntries, dagCacheTTL)

func (c *dagStructureCache) get(key string) (dagCacheEntry, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	for i, e := range c.entries {
		if e.key != key {
			continue
		}
		if c.now().Sub(e.at) > e.lifetime(c.ttl) {
			c.entries = append(c.entries[:i], c.entries[i+1:]...)
			return dagCacheEntry{}, false
		}
		return e, true
	}
	return dagCacheEntry{}, false
}

func (c *dagStructureCache) put(e dagCacheEntry) {
	c.mu.Lock()
	defer c.mu.Unlock()
	e.at = c.now()
	for i, old := range c.entries {
		if old.key == e.key {
			c.entries = append(c.entries[:i], c.entries[i+1:]...)
			break
		}
	}
	c.entries = append(c.entries, e)
	if len(c.entries) > c.max {
		c.entries = c.entries[len(c.entries)-c.max:]
	}
}

func dagCacheKey(cluster, proc int, dotFile string) string {
	return fmt.Sprintf("%d.%d|%s", cluster, proc, dotFile)
}

// dagSandboxSem caps concurrent whole-sandbox transfers process-wide.
var dagSandboxSem = make(chan struct{}, dagSandboxConcurrency)

// dagSandboxFetches counts the whole-sandbox transfers this endpoint has
// started. It exists so a test can assert that a load was served from
// the cache: "the structure came back and matches" is satisfied by an
// implementation with no cache at all.
var dagSandboxFetches atomic.Int64

// dagFlight collapses concurrent builds of the same key into one.
//
// Without it, N simultaneous loads of one workflow are N whole-sandbox
// transfers, each buffering up to the ceilings above: fifty tabs on a
// dashboard, or fifty ?refresh=1 in a loop, is gigabytes of live heap in
// a process shared with everyone else. x/sync/singleflight is only an
// INDIRECT dependency of this module and promoting it is a go.mod change
// this branch may not make, so this is the thirty lines of it needed.
//
// The key carries the caller when mayShare is false, so a caller who
// would not be allowed a cache hit is not handed another caller's result
// through the side door either: they get their own transfer, which the
// schedd refuses.
type dagFlight struct {
	mu    sync.Mutex
	calls map[string]*dagFlightCall
}

type dagFlightCall struct {
	done  chan struct{}
	value *dagStructure
	err   error
}

var dagFlights = &dagFlight{}

func (g *dagFlight) do(key string, fn func() (*dagStructure, error)) (*dagStructure, error) {
	g.mu.Lock()
	if g.calls == nil {
		g.calls = map[string]*dagFlightCall{}
	}
	if call, ok := g.calls[key]; ok {
		g.mu.Unlock()
		<-call.done
		return call.value, call.err
	}
	call := &dagFlightCall{done: make(chan struct{})}
	g.calls[key] = call
	g.mu.Unlock()

	// The delete happens before the close, so a caller arriving in
	// between starts a fresh build rather than joining a finished one.
	// Waiters read value/err only after the close, which orders the
	// write before their read.
	defer func() {
		g.mu.Lock()
		delete(g.calls, key)
		g.mu.Unlock()
		close(call.done)
	}()
	call.value, call.err = fn()
	return call.value, call.err
}

// errDagNoStructure means the transfer worked and the workflow had not
// published its structure in it.
//
// It is not "the .dag is missing": the .dag is ALWAYS missing (see the
// file comment), and this endpoint never wanted it. It means there is no
// DOT file, which has two very different causes -- DAGMan has not written
// it yet, or the DAG never asked for one -- and dagNoStructureMessage
// decides which to say.
var errDagNoStructure = errors.New("workflow has not published a dot file")

// dagNoStructureError is errDagNoStructure carrying the one fact
// dagNoStructureMessage needs in order to tell those two causes apart.
// It travels WITH the error so a negative cache entry can be re-served
// without a sandbox to re-derive it from.
type dagNoStructureError struct{ started bool }

func (e *dagNoStructureError) Error() string { return errDagNoStructure.Error() }

func (e *dagNoStructureError) Is(target error) bool { return target == errDagNoStructure }

// errDagUnparsableDot means the DOT file was there and would not parse.
// It is cached briefly for the same reason errDagNoStructure is.
var errDagUnparsableDot = errors.New("workflow's dot file could not be parsed")

// dagStructureFor returns the cached structure or fetches it.
//
// refresh bypasses the cache lookup, and it is the ONLY thing that does:
// an ordinary load is served whatever the cache holds, however old.
func (s *Handler) dagStructureFor(ctx context.Context, r *http.Request, constraint string,
	cluster, proc int, dagFile string, managerAd *classad.ClassAd, refresh bool,
	timings *dagTimings) (*dagStructure, int, string) {

	dotFile := dagman.DotFileName(dagFile)
	owner, _ := managerAd.EvaluateAttrString("Owner")
	access := dagCacheAccess{
		owner:  strings.TrimSpace(owner),
		caller: ownerFromActor(htcondor.GetAuthenticatedUserFromContext(ctx)),
		admin:  s.isWebUIAdmin(r),
	}
	structure, err := cachedDagStructure(dagStructures, dagCacheKey(cluster, proc, dotFile),
		access, refresh,
		func() (*dagStructure, error) {
			fetchCtx, cancel := context.WithTimeout(ctx, dagSandboxTimeout)
			defer cancel()
			st, started, err := s.buildDagStructure(fetchCtx, constraint, dagFile, dotFile, timings)
			if err != nil {
				return nil, err
			}
			if st == nil {
				return nil, &dagNoStructureError{started: started}
			}
			st.owner = access.owner
			return st, nil
		})
	var noStructure *dagNoStructureError
	switch {
	case errors.As(err, &noStructure):
		return nil, http.StatusConflict, dagNoStructureMessage(managerAd, dotFile, noStructure.started)
	case err != nil:
		// The detail is logged, not returned. It carries the schedd's
		// own sinful address and whatever the transfer said, which is
		// operator information rather than the caller's;
		// handleJobOutputFile draws the same line.
		s.logger.Error(logging.DestinationHTTP, "Failed to read DAG structure from spool",
			"error", err, "job", fmt.Sprintf("%d.%d", cluster, proc), "dot_file", dotFile)
		return nil, http.StatusInternalServerError,
			"Failed to read the workflow's structure from its spool."
	}

	return structure, 0, ""
}

// dagManagerDone reports whether the manager job has left the queue, in
// which case anything it has not already written into its spool will
// never appear there.
func dagManagerDone(ad *classad.ClassAd) bool {
	status, _ := ad.EvaluateAttrInt("JobStatus")
	return status == 3 || status == 4
}

// dagNoStructureMessage tells the two causes of a missing DOT file apart.
//
// They call for opposite reactions -- wait, or stop waiting -- so
// answering both with one message would make the endpoint useless on
// whichever case the caller guessed wrong. started is true when the
// sandbox showed DAGMan already past the point where it writes the file.
func dagNoStructureMessage(ad *classad.ClassAd, dotFile string, started bool) string {
	if !started && !dagManagerDone(ad) && !dagManagerRunningSince(ad, dagStartupGrace) {
		return "This workflow has not published its structure yet. Retry in a few seconds."
	}
	// The remaining sentence is an instruction to the workflow's AUTHOR,
	// not a description of this server: `DOT` is a line they put in their
	// own DAG file, and without it there is nothing to draw, ever.
	return fmt.Sprintf(
		"This workflow does not publish its structure: its DAG declares no DOT command, so there "+
			"is nothing to draw. Add `DOT %s` to the DAG file, or submit it through this server, "+
			"which adds it for you.", dotFile)
}

// dagManagerRunningSince reports whether the manager job has been running
// (or, if it never started, sitting in the queue) for longer than d.
func dagManagerRunningSince(ad *classad.ClassAd, d time.Duration) bool {
	for _, attr := range []string{"JobCurrentStartDate", "EnteredCurrentStatus", "QDate"} {
		if at, ok := ad.EvaluateAttrInt(attr); ok && at > 0 {
			return time.Since(time.Unix(at, 0)) > d
		}
	}
	return false
}

// cachedDagStructure is the cache policy on its own, so it can be tested
// (and mutated) without a schedd behind it.
//
// refresh skips the LOOKUP and nothing else: the freshly built structure
// still replaces the cached one, because ?refresh=1 is a UI refresh
// button and the next ordinary page load must not pay for another
// whole-sandbox transfer.
func cachedDagStructure(cache *dagStructureCache, key string, access dagCacheAccess,
	refresh bool, build func() (*dagStructure, error)) (*dagStructure, error) {

	if !refresh {
		if hit, ok := cache.get(key); ok && access.mayUse(hit) {
			if hit.err != nil {
				return nil, hit.err
			}
			// However old. An ordinary load does not transfer a sandbox;
			// it says how old what it is serving is instead.
			return hit.value, nil
		}
	}

	flightKey := key
	if !access.mayShare() {
		// This caller may not be served another caller's entry, so they
		// may not be served another caller's in-flight build either.
		flightKey = key + "\x00" + access.caller
	}
	return dagFlights.do(flightKey, func() (*dagStructure, error) {
		st, err := build()
		switch {
		case err == nil:
			cache.put(dagCacheEntry{key: key, owner: access.owner, value: st})
		case errors.Is(err, errDagNoStructure), errors.Is(err, errDagUnparsableDot):
			// A refusal a retry cannot change in the next few seconds.
			// Caching it is what stops a UI that polls because it got no
			// answer from re-paying a whole-sandbox transfer per poll.
			cache.put(dagCacheEntry{key: key, owner: access.owner, err: err})
		}
		return st, err
	})
}

// buildDagStructure does the expensive half: one whole-sandbox transfer,
// then the DOT file DAGMan wrote out of it.
//
// A nil structure with a nil error means the transfer worked and the
// workflow had published no DOT file; started then says whether DAGMan
// had already got far enough to have written one.
func (s *Handler) buildDagStructure(ctx context.Context, constraint, dagFile, dotFile string,
	timings *dagTimings) (st *dagStructure, started bool, err error) {

	// One slot per concurrent whole-sandbox transfer, process-wide. Each
	// one buffers tens of megabytes for up to dagSandboxTimeout, so this
	// is what keeps one caller's refresh loop from being everyone's
	// out-of-memory. The wait respects the caller's context, so a client
	// that gives up does not hold a place in the queue.
	select {
	case dagSandboxSem <- struct{}{}:
		defer func() { <-dagSandboxSem }()
	case <-ctx.Done():
		return nil, false, fmt.Errorf("waiting for a sandbox transfer slot: %w", ctx.Err())
	}
	dagSandboxFetches.Add(1)

	phase := time.Now()
	files, err := s.fetchSandboxTextFiles(ctx, constraint, dagBigFilePredicate(dagFile))
	timings.sandbox = time.Since(phase)
	if err != nil {
		return nil, false, err
	}

	phase = time.Now()
	name, body, ok := findDotFile(files, dotFile)
	if !ok {
		timings.dotParse = time.Since(phase)
		return nil, dagmanPastStartup(files), nil
	}

	graph, err := dagman.ParseDot(strings.NewReader(body))
	timings.dotParse = time.Since(phase)
	if err != nil {
		return nil, true, fmt.Errorf("read %s: %w: %w", name, errDagUnparsableDot, err)
	}
	st = &dagStructure{
		dagFile:   dagFile,
		dotFile:   name,
		grouping:  dagman.CollapseGraph(graph),
		dotStates: map[string]string{},
		fetchedAt: time.Now(),
	}
	for _, n := range graph.Nodes {
		if n.State != "" {
			st.dotStates[strings.ToLower(n.Name)] = dotNodeState(n.State)
		}
	}

	// The node status file is the state half, and it is read out of the
	// same tar because there is no cheaper way to reach one file of a
	// spooled sandbox.
	phase = time.Now()
	defer func() { timings.statParse = time.Since(phase) }()
	if statusName, statusBody, ok := findStatusFile(files, dagman.StatusFileName(dagFile)); ok {
		states, at, next, sawEnd := parseNodeStatusFile(statusBody)
		if len(states) > 0 {
			st.statusStates, st.statusFileName = states, statusName
			st.statusFileTime, st.statusNextUpdate = at, next
			st.sawStatusEnd = sawEnd
		}
	}
	return st, true, nil
}

// findDotFile finds the DOT file DAGMan wrote.
//
// The expected name is tried first, and then every text file in the
// sandbox is sniffed for a `digraph` header. The fallback is not
// paranoia: a DAG whose author declared their own `DOT mygraph.dot` is
// readable here for free, and one that said DONT-OVERWRITE has DAGMan
// writing mygraph.dot.0, mygraph.dot.1 ... (Dag::ChooseDotFileName), so
// the name in the DAG is not even the name on disk.
func findDotFile(files map[string]string, want string) (name, body string, ok bool) {
	if body, ok := files[want]; ok && looksLikeDot(body) {
		return want, body, true
	}
	return bestNamedFile(files, want, looksLikeDot, dotNameRank)
}

// bestNamedFile picks the highest-ranking candidate among the files that
// sniff right, breaking a tie on the sorted name.
//
// The tie-break is the point. Both fallbacks scan a map, and Go
// randomises map iteration order deliberately, so two equal-ranking
// candidates -- a node's own stdout that happens to contain the word
// "digraph", beside the real file -- resolved differently on successive
// requests for the same workflow, and the graph changed shape between
// two page loads with nothing having changed. A strict ">" does not fix
// that; it is what caused it.
func bestNamedFile(files map[string]string, want string, looks func(string) bool,
	rank func(name, want string) int) (string, string, bool) {

	best, bestRank := "", 0
	for name, body := range files {
		if !looks(body) {
			continue
		}
		r := rank(name, want)
		if best == "" || r > bestRank || (r == bestRank && name < best) {
			best, bestRank = name, r
		}
	}
	if best == "" {
		return "", "", false
	}
	return best, files[best], true
}

func looksLikeDot(body string) bool {
	head := body
	if len(head) > 4096 {
		head = head[:4096]
	}
	return strings.Contains(head, "digraph")
}

func dotNameRank(name, want string) int {
	switch {
	case name == want:
		return 3
	case strings.HasPrefix(name, want):
		return 2
	case strings.HasSuffix(name, ".dot"):
		return 1
	default:
		return 0
	}
}

// findStatusFile finds the node status file the same way: by the expected
// name, then by what a node status file looks like. Its first ad is the
// DagStatus ad in either format this endpoint reads.
//
// It ranks its candidates exactly as findDotFile does. It used to take
// the first sniff match instead, and a spooled DAG's node outputs land
// in the DAG's OWN spool: a node whose stdout mentions NodeStatus is a
// plausible false candidate, and with no ranking it won or lost by map
// order.
func findStatusFile(files map[string]string, want string) (name, body string, ok bool) {
	if body, ok := files[want]; ok && looksLikeNodeStatus(body) {
		return want, body, true
	}
	return bestNamedFile(files, want, looksLikeNodeStatus, statusNameRank)
}

// statusNameRank ranks a candidate status file the way dotNameRank ranks
// a candidate dot file.
func statusNameRank(name, want string) int {
	switch {
	case name == want:
		return 3
	case strings.HasPrefix(name, want):
		return 2
	case strings.HasSuffix(name, ".status"):
		return 1
	default:
		return 0
	}
}

func looksLikeNodeStatus(body string) bool {
	head := body
	if len(head) > 4096 {
		head = head[:4096]
	}
	return strings.Contains(head, "DagStatus") || strings.Contains(head, "NodeStatus")
}

// dagmanPastStartup reports whether DAGMan got as far as the point where
// it writes the DOT file. Its own log says so: "Dag contains N total
// nodes" is printed immediately before Dag::DumpDotFile is called
// (dagman_main.cpp:1123-1135), so a log holding that line and a sandbox
// holding no DOT file together mean the DAG declared none.
func dagmanPastStartup(files map[string]string) bool {
	for name, body := range files {
		if strings.HasSuffix(name, ".dagman.out") && strings.Contains(body, "Dag contains") {
			return true
		}
	}
	return false
}

// dagBigFilePredicate says which files get the large ceiling: the two
// this endpoint exists to read, under either the name it expects or the
// name an author chose.
func dagBigFilePredicate(dagFile string) func(string) bool {
	dot := dagman.DotFileName(dagFile)
	status := dagman.StatusFileName(dagFile)
	return func(name string) bool {
		return name == dot || name == status ||
			strings.HasPrefix(name, dot+".") || // DONT-OVERWRITE numbering
			strings.HasSuffix(name, ".dot") || strings.HasSuffix(name, ".status")
	}
}

// fetchSandboxTextFiles pulls the manager job's whole spool and keeps
// every regular text entry, by basename.
//
// The whole stream is read: there is no single name to stop at, because
// the DOT file may be under a name the author chose and the status file
// under another, and either may come anywhere in the tar.
//
// Size discipline: the DOT and status files get a large ceiling because a
// 100,000-node workflow's legitimately are large; every other file gets a
// small one and is SKIPPED past that rather than refused, since a
// workflow's own <dag>.dagman.out log routinely runs to hundreds of
// megabytes and refusing to draw the graph because the log is big would
// be absurd. The hard refusals are a single oversize target file and a
// spool with more files in it than dagMaxSpoolEntries.
func (s *Handler) fetchSandboxTextFiles(ctx context.Context, constraint string,
	big func(string) bool) (map[string]string, error) {

	return sandboxTextFiles(big, defaultDagFileLimits(), func(w io.Writer) <-chan error {
		return s.getSchedd().ReceiveJobSandbox(ctx, constraint, w)
	})
}

// dagFileLimits is the size discipline as a value.
//
// It is a parameter rather than four constants read straight out of the
// loop so a test can prove the arithmetic -- which file is counted
// against which budget, and which budget refuses rather than skips --
// without allocating a hundred megabytes per case. The production
// numbers are in defaultDagFileLimits and nowhere else.
type dagFileLimits struct {
	// big is the ceiling on a target file (the dot or status file).
	// Exceeding it is a hard refusal: it is the file that was asked for.
	big int64
	// aux is the ceiling on any other file, which is skipped past it.
	aux int64
	// auxTotal is the budget for the aux files TOGETHER. The target
	// files are exempt from it.
	auxTotal int64
	// entries is how many regular files are looked at at all.
	entries int
}

func defaultDagFileLimits() dagFileLimits {
	return dagFileLimits{
		big:      dagBigFileMaxBytes,
		aux:      dagAuxFileMaxBytes,
		auxTotal: dagAuxTotalMaxBytes,
		entries:  dagMaxSpoolEntries,
	}
}

// sandboxTextFiles is the pipe plumbing and the error precedence, split
// from the schedd so both can be tested.
//
// The precedence is the whole reason it is split. collectTarTextFiles
// stops early on a refusal, closing the reader stops the transfer, and
// the transfer then fails with io.ErrClosedPipe -- OUR doing. Reporting
// that first, as this did, replaced every carefully worded refusal with
// "download sandbox: io: read/write on closed pipe", which tells the
// caller nothing about the workflow that provoked it.
func sandboxTextFiles(big func(string) bool, lim dagFileLimits,
	start func(io.Writer) <-chan error) (map[string]string, error) {

	pipeReader, pipeWriter := io.Pipe()
	sandboxErrChan := start(pipeWriter)
	finalErrChan := make(chan error, 1)
	go func() {
		err := <-sandboxErrChan
		if err != nil {
			_ = pipeWriter.CloseWithError(err)
		} else {
			_ = pipeWriter.Close()
		}
		finalErrChan <- err
	}()

	files, readErr := collectTarTextFiles(tar.NewReader(pipeReader), big, lim)
	_ = pipeReader.Close()
	transferErr := <-finalErrChan

	switch {
	case readErr != nil && transferErr != nil && errors.Is(readErr, transferErr):
		// The read failed BECAUSE the transfer did -- CloseWithError
		// hands the writer's error straight to the reader -- so the
		// cause is the better message.
		return nil, fmt.Errorf("download sandbox: %w", transferErr)
	case readErr != nil:
		// A refusal of our own. It outranks whatever closing the pipe
		// under the transfer made the transfer say.
		return nil, readErr
	case transferErr != nil && !errors.Is(transferErr, io.ErrClosedPipe):
		return nil, fmt.Errorf("download sandbox: %w", transferErr)
	}
	return files, nil
}

// collectTarTextFiles is the loop, split out so it can be tested against
// a tar built in memory rather than against a schedd.
func collectTarTextFiles(tr *tar.Reader, big func(string) bool, lim dagFileLimits) (
	map[string]string, error) {

	files := map[string]string{}
	var total int64
	entries := 0
	for {
		header, err := tr.Next()
		if errors.Is(err, io.EOF) {
			return files, nil
		}
		if err != nil {
			return nil, fmt.Errorf("read tar: %w", err)
		}
		if header.Typeflag != tar.TypeReg {
			continue
		}
		entries++
		if entries > lim.entries {
			// Counting is not redundant with the byte ceilings: a
			// million one-line files clear every one of them and still
			// exhaust memory on Go map overhead alone.
			return nil, fmt.Errorf("this job's spool holds more than %d files, which is more than "+
				"this endpoint will read; a workflow whose nodes write their output into the "+
				"workflow's own submit directory cannot have its graph read here", lim.entries)
		}
		name := path.Base(filepath.ToSlash(header.Name))
		isBig := big != nil && big(name)
		limit := lim.aux
		if isBig {
			limit = lim.big
		}
		if header.Size > limit {
			if isBig {
				return nil, fmt.Errorf("the workflow's %s is %d bytes, larger than the %d "+
					"this endpoint will read", name, header.Size, limit)
			}
			continue
		}
		// The aux budget governs only the aux files -- the two target
		// files are exempt, or the generous per-file ceiling they exist
		// for could never be spent -- and it is measured against the
		// same number the accumulator keeps: bytes actually KEPT. The
		// two used to disagree, the check counting a file the text
		// sniff below was about to throw away.
		if !isBig && total+header.Size > lim.auxTotal {
			continue
		}
		buf := &bytes.Buffer{}
		if _, err := io.CopyN(buf, tr, header.Size); err != nil && !errors.Is(err, io.EOF) {
			return nil, fmt.Errorf("read %s: %w", name, err)
		}
		if !looksLikeText(buf.Bytes()) {
			continue
		}
		if !isBig {
			total += header.Size
		}
		files[name] = buf.String()
	}
}

// looksLikeText keeps binaries -- a staged executable, a tarball -- out of
// the map without pretending to sniff a MIME type. A DOT file, a submit
// file and a node status file are all UTF-8 with no NUL.
func looksLikeText(b []byte) bool {
	if bytes.IndexByte(b, 0) >= 0 {
		return false
	}
	return utf8.Valid(b)
}

// ---------------------------------------------------------------------
// The node status file.
// ---------------------------------------------------------------------

// parseNodeStatusFile reads a NODE_STATUS_FILE: a collection of ads, one
// DagStatus, one NodeStatus per node, and a closing StatusEnd. It returns
// the per-node entries by lower-cased node name, the file's own
// timestamp, and its NextUpdate (zero when DAGMan wrote it for the last
// time).
//
// Both formats DAGMan can write are read, because both turn up. The
// ClassAd stream is DAGMan's default and so is what an instrumented
// workflow produces -- naming a format in the command is what an older
// access point refuses (see dagman.Instrument). The JSON forms arrive
// from a workflow whose author asked for them, and from any access point
// this server is told to ask for them on later.
//
// Attributes are looked up BY NAME in both formats. DAGMan's own
// documentation says the order is not guaranteed, and reading the third
// field of a line would break silently the day it changes.
//
// A file that is being rewritten while we read it will have a truncated
// last ad; whatever parsed before that point is still good, so a parse
// error ends the scan rather than discarding the result. The fourth
// return says whether the closing StatusEnd ad was among what parsed,
// which is exactly how a truncated file is told from a finished one:
// NextUpdate rides on StatusEnd and on nothing else.
func parseNodeStatusFile(body string) (map[string]dagStatusEntry, int64, int64, bool) {
	if isJSONStatusFile(body) {
		return parseNodeStatusJSON(body)
	}
	return parseNodeStatusClassAds(body)
}

func isJSONStatusFile(body string) bool {
	for _, line := range strings.SplitN(body, "\n", 16) {
		if line = strings.TrimSpace(line); line != "" {
			return strings.HasPrefix(line, "{")
		}
	}
	return false
}

// parseNodeStatusJSON reads a stream of JSON objects, which handles both
// COMPACT (one per line) and pretty-printed output: json.Decoder reads
// concatenated values either way.
func parseNodeStatusJSON(body string) (map[string]dagStatusEntry, int64, int64, bool) {
	states := map[string]dagStatusEntry{}
	var at, next int64
	var sawEnd bool
	dec := json.NewDecoder(strings.NewReader(body))
	for {
		var raw map[string]interface{}
		if err := dec.Decode(&raw); err != nil {
			break
		}
		ad := jsonAd(raw)
		kind := strings.ToLower(statusAdKind(ad.str("MyType"), ad.str("Type")))
		switch kind {
		case "dagstatus", "statusend":
			sawEnd = sawEnd || kind == "statusend"
			if ts := ad.num("Timestamp"); ts > at {
				at = ts
			}
			// Only StatusEnd carries NextUpdate, and only a file
			// DAGMan has written for the last time says 0 -- so it is
			// set when present rather than defaulted.
			if ad.has("NextUpdate") {
				next = ad.num("NextUpdate")
			}
		case "nodestatus":
			name := ad.str("Node")
			if name == "" {
				continue
			}
			states[strings.ToLower(name)] = dagStatusEntry{
				state:  nodeStatusState(ad.num("NodeStatus")),
				detail: ad.str("StatusDetails"),
			}
		}
	}
	return states, at, next, sawEnd
}

// jsonAd looks an attribute up by name, case-insensitively, because
// ClassAd attribute names are case-insensitive and nothing promises the
// spelling DAGMan happens to use today.
type jsonAd map[string]interface{}

func jsonAdKey(m map[string]interface{}, name string) string {
	if _, ok := m[name]; ok {
		return name
	}
	for k := range m {
		if strings.EqualFold(k, name) {
			return k
		}
	}
	return name
}

func (a jsonAd) has(name string) bool {
	_, ok := a[jsonAdKey(a, name)]
	return ok
}

func (a jsonAd) str(name string) string {
	s, _ := a[jsonAdKey(a, name)].(string)
	return s
}

func (a jsonAd) num(name string) int64 {
	switch v := a[jsonAdKey(a, name)].(type) {
	case float64:
		return int64(v)
	case json.Number:
		n, _ := v.Int64()
		return n
	default:
		return 0
	}
}

func parseNodeStatusClassAds(body string) (map[string]dagStatusEntry, int64, int64, bool) {
	states := map[string]dagStatusEntry{}
	var at, next int64
	var sawEnd bool
	reader := classad.NewReader(strings.NewReader(body))
	for reader.Next() {
		ad := reader.ClassAd()
		myType, _ := ad.EvaluateAttrString("MyType")
		altType, _ := ad.EvaluateAttrString("Type")
		myType = statusAdKind(myType, altType)
		switch {
		case strings.EqualFold(myType, "DagStatus"), strings.EqualFold(myType, "StatusEnd"):
			sawEnd = sawEnd || strings.EqualFold(myType, "StatusEnd")
			if ts, ok := ad.EvaluateAttrInt("Timestamp"); ok && ts > at {
				at = ts
			}
			if n, ok := ad.EvaluateAttrInt("NextUpdate"); ok {
				next = n
			}
		case strings.EqualFold(myType, "NodeStatus"):
			name, ok := ad.EvaluateAttrString("Node")
			if !ok || name == "" {
				continue
			}
			status, ok := ad.EvaluateAttrInt("NodeStatus")
			if !ok {
				continue
			}
			detail, _ := ad.EvaluateAttrString("StatusDetails")
			states[strings.ToLower(name)] = dagStatusEntry{state: nodeStatusState(status), detail: detail}
		}
	}
	return states, at, next, sawEnd
}

// statusAdKind is which ad this is, under either name DAGMan has used
// for it.
//
// The attribute is ATTR_MY_TYPE in DAGMan's source, which is "MyType" --
// but a 25.8 access point writes these ads with "Type" instead, which
// was found by reading a status file a real DAGMan had written rather
// than by reading the source. Taking either costs one line; taking only
// the documented one silently loses every node state against half the
// access points in the field.
func statusAdKind(myType, altType string) string {
	if myType != "" {
		return myType
	}
	return altType
}

// nodeStatusState maps DAGMan's Node::status_t (condor_dagman/node.h) to
// the response's vocabulary.
func nodeStatusState(status int64) string {
	switch status {
	case 0:
		return dagStateUnready
	case 1:
		return dagStateReady
	case 2:
		return dagStatePreRun
	case 3:
		return dagStateSubmitted
	case 4:
		return dagStatePostRun
	case 5:
		return dagStateDone
	case 6:
		return dagStateFailed
	case 7:
		return dagStateFutile
	default:
		return dagStateUnready
	}
}

// dotNodeState maps a DOT label's state letter to the response's
// vocabulary. It is coarser than the status file's: the generator writes
// (I) for both READY and NOT_READY and for FUTILE, so "idle" is as much
// as the letter can mean.
func dotNodeState(letter string) string {
	switch letter {
	case dagman.DotStateDone:
		return dagStateDone
	case dagman.DotStateRunning:
		return dagStateSubmitted
	case dagman.DotStatePre:
		return dagStatePreRun
	case dagman.DotStatePost:
		return dagStatePostRun
	case dagman.DotStateError:
		return dagStateFailed
	default:
		return dagStateReady
	}
}

// ---------------------------------------------------------------------
// State: overlaid on the structure.
// ---------------------------------------------------------------------

// dagNodeState is one node's state before it is rolled up.
type dagNodeState struct {
	state      string
	jobID      string
	holdReason string
	exitCode   *int
	detail     string
	source     string
}

// buildDagResponse overlays state on the structure.
//
// Precedence per node is: the node status file, the DOT file's own
// labels, the queue, the archive, then "unready". It is in that order
// because it is the order of AUTHORITY over the question being asked.
// The question is what the WORKFLOW thinks of this node, and only DAGMan
// knows that: a node can be waiting on a PRE script, waiting on a POST
// script, ready but unsubmitted, or futile because an ancestor failed,
// and none of those four is a job, so no queue and no archive can
// describe them. The queue knows about jobs, which is a different thing:
// a node whose job finished a second ago is still POSTRUN to DAGMan.
//
// The queue and the archive are not thereby discarded: they supply the
// job id, the hold reason and the exit code for every node they know,
// whichever source named the state. That is the "why" behind a status
// file's number -- "error" is not actionable, "error, job 42.0 exited 1"
// is.
func (s *Handler) buildDagResponse(ctx context.Context, r *http.Request, cluster int,
	st *dagStructure, timings *dagTimings) DagGraphResponse {

	live := map[string]dagNodeState{}
	var sources []string
	var warnings []string

	phase := time.Now()
	queued, err := s.dagQueueStates(ctx, r, cluster, live)
	timings.queue = time.Since(phase)
	if err != nil {
		// Logged, not echoed: the error text carries the schedd's own
		// address and internals, which handleJobOutputFile deliberately
		// keeps out of a response body.
		s.logger.Error(logging.DestinationHTTP, "DAG node queue query failed",
			"error", err, "cluster", cluster)
		warnings = append(warnings, "The job queue could not be consulted, so some nodes may read "+
			"as unready.")
	}

	// Only ask the archive about what the queue did not explain. On a
	// finished workflow that is every node; on a running one it is the
	// nodes that already left the queue.
	archived := 0
	if len(live) < st.grouping.NodeCount {
		var scanned int
		phase = time.Now()
		archived, scanned, err = s.dagArchiveStates(ctx, r, cluster, st.grouping.NodeCount, live)
		timings.archive = time.Since(phase)
		if err != nil {
			s.logger.Error(logging.DestinationHTTP, "DAG node archive query failed",
				"error", err, "cluster", cluster)
			warnings = append(warnings, "The job history could not be consulted, so nodes that have "+
				"finished may read as unready.")
		}
		if w := dagArchiveTruncationWarning(scanned, st.grouping.NodeCount); w != "" {
			warnings = append(warnings, w)
		}
	}

	states, used := mergeDagStates(st, live)

	for _, src := range []string{dagSourceStatusFile, dagSourceDot, dagSourceQueue, dagSourceArchive} {
		if used[src] {
			sources = append(sources, src)
		}
	}
	// The queue and the archive still contributed when they only supplied
	// a job id, so report them whenever they answered at all.
	if queued > 0 && !used[dagSourceQueue] {
		sources = append(sources, dagSourceQueue)
	}
	if archived > 0 && !used[dagSourceArchive] {
		sources = append(sources, dagSourceArchive)
	}
	if sources == nil {
		sources = []string{}
	}

	resp := DagGraphResponse{
		Cluster:             cluster,
		DagFile:             st.dagFile,
		DotFile:             st.dotFile,
		StatusFile:          st.statusFileName,
		NodeCount:           st.grouping.NodeCount,
		EdgeCount:           st.grouping.EdgeCount,
		GroupCount:          len(st.grouping.Groups),
		ApproximateLayering: st.grouping.Approximate,
		StateSources:        sources,
		Warnings:            warnings,
		// When the spool was READ, not when this response was built. On
		// a cached load those are minutes apart, and the age of the
		// state is the thing the panel has to be able to say.
		FetchedAt: st.fetchedAt.UTC(),
	}
	if used[dagSourceStatusFile] {
		resp.StatusFileTime = st.statusFileTime
	}
	resp.Groups, resp.Nodes = rollUpDagGroups(st.grouping, states)
	if st.grouping.NodeCount > dagNodeListLimit {
		resp.Nodes = nil
		resp.NodesOmitted = true
		resp.NodesOmittedReason = fmt.Sprintf(
			"This workflow has %d nodes, too many to list one by one. The per-group counts "+
				"describe every node.", st.grouping.NodeCount)
	}
	return resp
}

// mergeDagStates applies the precedence to every node of the structure,
// and reports which sources ended up being used.
//
// It is a pure function of the structure and what the queue and archive
// said, so the precedence can be tested -- and mutated -- without a
// schedd behind it.
func mergeDagStates(st *dagStructure, live map[string]dagNodeState) (map[string]dagNodeState, map[string]bool) {
	states := make(map[string]dagNodeState, st.grouping.NodeCount)
	used := map[string]bool{}
	for _, grp := range st.grouping.Groups {
		for _, member := range grp.Members {
			key := strings.ToLower(member)
			state := dagNodeState{state: dagStateUnready, source: dagSourceInferred}
			if entry, ok := st.statusStates[key]; ok {
				// DAGMan's own answer about its own node. Nothing else
				// knows about a PRE script, a POST script, a node that is
				// ready but unsubmitted, or one that is futile.
				state = dagNodeState{state: entry.state, detail: entry.detail, source: dagSourceStatusFile}
			} else if dot, ok := st.dotStates[key]; ok {
				state = dagNodeState{state: dot, source: dagSourceDot}
			}
			if l, ok := live[key]; ok {
				if state.source == dagSourceInferred || state.source == dagSourceDot {
					// Nothing authoritative has spoken -- the DOT label is
					// only meaningful for a DAG that asked for UPDATE, and
					// even then it is as old as the file. The job the
					// queue or the archive knows about is the better
					// answer.
					state.state, state.source = l.state, l.source
				}
				// Either way, the details belong to the job: they are the
				// "why" behind whatever the state is. The source that
				// supplied them contributed to this answer even when it
				// did not name the state.
				state.jobID, state.holdReason, state.exitCode = l.jobID, l.holdReason, l.exitCode
				used[l.source] = true
			}
			used[state.source] = true
			states[key] = state
		}
	}
	return states, used
}

// rollUpDagGroups turns per-node states into the per-group histogram a
// drawing colours by, and the flat node list.
func rollUpDagGroups(g *dagman.Grouping, states map[string]dagNodeState) ([]DagGraphGroup, []DagGraphNode) {
	groups := make([]DagGraphGroup, 0, len(g.Groups))
	nodes := make([]DagGraphNode, 0, g.NodeCount)
	for _, grp := range g.Groups {
		hist := map[string]int{}
		for _, name := range grp.Members {
			st, ok := states[strings.ToLower(name)]
			if !ok {
				st = dagNodeState{state: dagStateUnready, source: dagSourceInferred}
			}
			hist[st.state]++
			nodes = append(nodes, DagGraphNode{
				Name:       name,
				GroupID:    grp.ID,
				State:      st.state,
				JobID:      st.jobID,
				HoldReason: clampDagNodeText(st.holdReason),
				ExitCode:   st.exitCode,
				Detail:     clampDagNodeText(st.detail),
				Source:     st.source,
			})
		}
		parents := grp.ParentIDs
		if parents == nil {
			parents = []string{}
		}
		groups = append(groups, DagGraphGroup{
			ID:          grp.ID,
			Label:       grp.Label,
			Description: grp.Description,
			Count:       grp.Count,
			ParentIDs:   parents,
			Status:      hist,
		})
	}
	return groups, nodes
}

// clampDagNodeText bounds one of the two free-text per-node fields. It
// cuts on a rune boundary, because the result is JSON and half a rune is
// not text.
func clampDagNodeText(s string) string {
	if len(s) <= dagNodeTextMaxBytes {
		return s
	}
	cut := dagNodeTextMaxBytes
	for cut > 0 && !utf8.RuneStart(s[cut]) {
		cut--
	}
	return s[:cut] + "\u2026"
}

// dagNodeProjection is what a node job has to answer about itself.
var dagNodeProjection = []string{"ClusterId", "ProcId", "JobStatus", "DAGNodeName", "HoldReason"}

// dagQueueStates fills in the nodes that still have a job in the queue.
func (s *Handler) dagQueueStates(ctx context.Context, r *http.Request, cluster int,
	out map[string]dagNodeState) (int, error) {

	constraint, err := s.bulkOwnerScope(ctx, r, fmt.Sprintf("DAGManJobId == %d", cluster))
	if err != nil {
		return 0, err
	}
	ads, _, err := s.getSchedd().QueryWithOptions(ctx, constraint,
		&htcondor.QueryOptions{Projection: dagNodeProjection})
	if err != nil {
		return 0, err
	}
	n := 0
	for _, ad := range ads {
		name, ok := ad.EvaluateAttrString("DAGNodeName")
		if !ok || name == "" {
			continue
		}
		status, _ := ad.EvaluateAttrInt("JobStatus")
		st := dagNodeState{state: queueJobState(status), jobID: adJobID(ad), source: dagSourceQueue}
		if status == 5 {
			st.holdReason, _ = ad.EvaluateAttrString("HoldReason")
		}
		// A node with many procs reports the most interesting one:
		// held beats running beats idle beats done, because that is the
		// one an operator has to look at.
		key := strings.ToLower(name)
		if prev, seen := out[key]; seen && dagStateRank(prev.state) >= dagStateRank(st.state) {
			continue
		}
		out[key] = st
		n++
	}
	return n, nil
}

// dagArchiveStates fills in nodes whose jobs have already left the queue,
// from the same history the /api/v1/jobs/archive endpoint reads.
func (s *Handler) dagArchiveStates(ctx context.Context, r *http.Request, cluster, nodeCount int,
	out map[string]dagNodeState) (n, scanned int, err error) {

	constraint, err := s.bulkOwnerScope(ctx, r, fmt.Sprintf("DAGManJobId == %d", cluster))
	if err != nil {
		return 0, 0, err
	}
	limit, scanLimit := dagArchiveBounds(nodeCount)
	ads, err := s.getSchedd().QueryHistoryWithOptions(ctx, constraint, &htcondor.HistoryQueryOptions{
		Source:     htcondor.HistorySourceJobHistory,
		Projection: append(append([]string{}, dagNodeProjection...), "ExitCode", "ExitBySignal"),
		// A workflow's nodes are contiguous and recent in the history
		// file, so a bounded backwards scan finds them all without
		// reading years of it.
		Limit:     limit,
		ScanLimit: scanLimit,
		Backwards: true,
	})
	if err != nil {
		return 0, 0, err
	}
	scanned = len(ads)
	for _, ad := range ads {
		name, ok := ad.EvaluateAttrString("DAGNodeName")
		if !ok || name == "" {
			continue
		}
		key := strings.ToLower(name)
		if _, known := out[key]; known {
			// The queue is the more authoritative source about a job and
			// has already spoken for this node.
			continue
		}
		st := dagNodeState{state: archiveJobState(ad), jobID: adJobID(ad), source: dagSourceArchive}
		if code, ok := ad.EvaluateAttrInt("ExitCode"); ok {
			c := int(code)
			st.exitCode = &c
		}
		out[key] = st
		n++
	}
	return n, scanned, nil
}

// dagArchiveBounds sizes the history query to the workflow in front of
// it, which is the whole difference between a page load that costs
// nothing and one that costs seconds.
//
// The old bounds were flat: 20,000 matches and a 200,000-record scan,
// for every workflow. The schedd walks the history file backwards and
// stops at the FIRST of the two, so a 20-node workflow -- which can
// never produce 20,000 matches -- never hit the match limit and the scan
// ran the full 200,000 records EVERY TIME the panel was opened. Measured
// against a 200,000-record history file that is ~0.9s of pure waste per
// load on a warm local disk, and it is paid on a cached load too,
// because the archive is not cached.
//
// So the match limit is sized to the workflow: once the workflow's own
// node jobs have been found the scan stops, which for the ordinary case
// -- a workflow whose nodes ran recently -- is a few dozen records
// instead of two hundred thousand. The slack covers DAGMan retries,
// which submit a node again under the same DAGNodeName.
//
// The scan limit still has to exist, because a workflow with fewer
// finished nodes than the match limit (a RUNNING one: the common case)
// can never satisfy the match limit and would otherwise run to the end
// of the file again. It is bounded by the workflow too, with a floor
// that is large enough to reach past unrelated jobs submitted since.
// The cost of that bound is real and is stated in the response: a node
// whose job left the queue but sits further back in the history than
// the scan reaches keeps the state DAGMan gave it and loses its job id
// and exit code.
func dagArchiveBounds(nodeCount int) (limit, scanLimit int) {
	limit = nodeCount*dagArchiveProcsPerNode + dagArchiveLimitSlack
	if limit > dagArchiveLimit || limit <= 0 {
		limit = dagArchiveLimit
	}
	scanLimit = nodeCount * dagArchiveScanPerNode
	if scanLimit < dagArchiveScanFloor {
		scanLimit = dagArchiveScanFloor
	}
	if scanLimit > dagArchiveScanLimit || scanLimit <= 0 {
		scanLimit = dagArchiveScanLimit
	}
	return limit, scanLimit
}

// dagArchiveTruncationWarning says that the archive answer was cut off,
// or "" when it was not.
//
// Silence here is the defect it exists for. The archive query stops at
// its match limit, and the nodes past the cut read as "unready" from
// "inferred" -- which is exactly what a node that never started reads
// as. A finished 100,000-node workflow would report 80% of itself as
// never having run, with nothing in the response to say otherwise.
//
// A full answer and a truncated one are indistinguishable in the ads
// themselves, so the count is the only signal there is. It is compared
// against the bound this workflow actually asked for, not against the
// flat ceiling: sizing the query to the workflow moved the cut.
func dagArchiveTruncationWarning(scanned, nodeCount int) string {
	limit, _ := dagArchiveBounds(nodeCount)
	if scanned < limit {
		return ""
	}
	return "The job history answer was cut short, so some nodes that have finished may read " +
		"as unready."
}

const (
	// dagArchiveLimit and dagArchiveScanLimit are the ceilings the
	// per-workflow bounds are clamped to; dagArchiveBounds explains why
	// they are ceilings rather than the values used.
	dagArchiveLimit     = 20000
	dagArchiveScanLimit = 200000
	// dagArchiveProcsPerNode and dagArchiveLimitSlack size the match
	// limit: one record per node plus room for retries and multi-proc
	// nodes, plus a fixed floor so a one-node workflow still asks for
	// more than one record.
	dagArchiveProcsPerNode = 4
	dagArchiveLimitSlack   = 16
	// dagArchiveScanPerNode and dagArchiveScanFloor size the scan: how
	// far back into the history file this is willing to look for a
	// workflow of this size.
	dagArchiveScanPerNode = 200
	dagArchiveScanFloor   = 5000
)

func adJobID(ad *classad.ClassAd) string {
	cluster, ok := ad.EvaluateAttrInt("ClusterId")
	if !ok {
		return ""
	}
	proc, _ := ad.EvaluateAttrInt("ProcId")
	return fmt.Sprintf("%d.%d", cluster, proc)
}

// queueJobState maps JobStatus to the response's vocabulary.
func queueJobState(status int64) string {
	switch status {
	case 1:
		return dagStateIdle
	case 2:
		return dagStateRunning
	case 3:
		return dagStateRemoved
	case 4:
		return dagStateDone
	case 5:
		return dagStateHeld
	case 6:
		return dagStateTransferring
	case 7:
		return dagStateSuspended
	default:
		return dagStateSubmitted
	}
}

// archiveJobState distinguishes a node that finished from one that
// failed, which JobStatus alone does not: a job that exits 1 is
// "Completed" in the queue's vocabulary and a failure in the workflow's.
func archiveJobState(ad *classad.ClassAd) string {
	status, _ := ad.EvaluateAttrInt("JobStatus")
	if status == 3 {
		return dagStateRemoved
	}
	if status != 4 {
		return queueJobState(status)
	}
	if bySignal, ok := ad.EvaluateAttrBool("ExitBySignal"); ok && bySignal {
		return dagStateFailed
	}
	if code, ok := ad.EvaluateAttrInt("ExitCode"); ok && code != 0 {
		return dagStateFailed
	}
	return dagStateDone
}

// dagStateRank orders the states of a node's several procs by how much
// they demand attention, so a node with one held proc reads as held.
func dagStateRank(state string) int {
	switch state {
	case dagStateHeld:
		return 5
	case dagStateFailed:
		return 4
	case dagStateRunning, dagStateTransferring, dagStateSuspended:
		return 3
	case dagStateIdle:
		return 2
	case dagStateRemoved:
		return 1
	default:
		return 0
	}
}
