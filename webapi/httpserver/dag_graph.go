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

	// dagStatusMaxAge is how stale the node status half of a cached entry
	// may be before an ordinary load re-fetches the sandbox.
	//
	// The structure and the state arrive in the same tar, so they share a
	// cache entry -- but they do not share a lifetime. The status file is
	// the AUTHORITATIVE source for node state, and serving an hour-old
	// copy of it as if it were current would be worse than not having it.
	// It is rewritten at most every 30 seconds (the interval this server
	// asks for), so re-reading it about that often is the most the file
	// itself can offer. A workflow that has finished is exempt: DAGMan
	// says so in the status file's own NextUpdate, and a final file never
	// changes again.
	dagStatusMaxAge = 45 * time.Second

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
	// dagTotalFileMaxBytes is the ceiling on everything kept together.
	dagTotalFileMaxBytes = 96 << 20

	// dagNodeListLimit is how many per-node entries the response will
	// carry. Past this the caller gets groups only: a JSON array of
	// 100,000 node objects is not a payload a browser should be handed,
	// and the groups are what a drawing actually uses.
	dagNodeListLimit = 500

	// dagSandboxTimeout bounds the whole-sandbox fetch. It is longer
	// than the 30s the single-file endpoints use because this one reads
	// the stream to the end rather than stopping at the first match.
	dagSandboxTimeout = 2 * time.Minute

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
	Warnings  []string  `json:"warnings,omitempty"`
	FetchedAt time.Time `json:"fetched_at"`
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

	ads, _, err := s.getSchedd().QueryWithOptions(ctx, constraint,
		&htcondor.QueryOptions{Projection: dagManagerProjection})
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

	structure, status, msg := s.dagStructureFor(ctx, constraint, cluster, proc, dagFile, ads[0],
		r.URL.Query().Get("refresh") == "1")
	if status != 0 {
		s.writeError(w, status, msg)
		return
	}

	s.writeJSON(w, http.StatusOK, s.buildDagResponse(ctx, r, cluster, structure))
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
	if spooled, _ := ad.EvaluateAttrString("SUBMIT_Iwd"); strings.TrimSpace(spooled) == "" {
		iwd, _ := ad.EvaluateAttrString("Iwd")
		if iwd == "" {
			iwd = "its submit directory"
		}
		return "", http.StatusConflict, fmt.Sprintf(
			"This workflow was submitted from a shell on the access point, so its files are in %s "+
				"and are not readable through this server.", iwd)
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
	dagFile  string
	dotFile  string
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
	// statusNextUpdate is the status file's own NextUpdate: zero when
	// DAGMan wrote the file for the last time, which is how a finished
	// workflow says its state will never change again.
	statusNextUpdate int64
	fetchedAt        time.Time
}

// dagStatusEntry is one node's line in the status file.
type dagStatusEntry struct {
	state  string
	detail string
}

// stateIsFinal reports whether the state half of this structure can still
// change. It is used to decide whether an ordinary load has to re-fetch.
func (st *dagStructure) stateIsFinal() bool {
	return st.statusFileName != "" && st.statusNextUpdate == 0
}

// dagStructureCache is a small bounded, time-bounded cache. There is no
// shared LRU helper in this package to reuse (jobwatch has one, for
// something else), and a purpose-built one is forty lines.
//
// It is a package-level singleton rather than a Handler field because
// adding a field means editing handler.go, which is not this change's to
// edit. Entries are keyed by cluster.proc AND the resolved dot file name,
// and nothing reaches the cache before the caller has passed the same
// owner-scoped ad lookup the rest of the per-job endpoints use, so a hit
// cannot serve a workflow the caller could not already read.
type dagStructureCache struct {
	mu      sync.Mutex
	max     int
	ttl     time.Duration
	entries []dagCacheEntry // oldest first
	now     func() time.Time
}

type dagCacheEntry struct {
	key   string
	value *dagStructure
	at    time.Time
}

func newDagStructureCache(maxEntries int, ttl time.Duration) *dagStructureCache {
	return &dagStructureCache{max: maxEntries, ttl: ttl, now: time.Now}
}

var dagStructures = newDagStructureCache(dagCacheMaxEntries, dagCacheTTL)

func (c *dagStructureCache) get(key string) (*dagStructure, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	for i, e := range c.entries {
		if e.key != key {
			continue
		}
		if c.now().Sub(e.at) > c.ttl {
			c.entries = append(c.entries[:i], c.entries[i+1:]...)
			return nil, false
		}
		return e.value, true
	}
	return nil, false
}

func (c *dagStructureCache) put(key string, v *dagStructure) {
	c.mu.Lock()
	defer c.mu.Unlock()
	for i, e := range c.entries {
		if e.key == key {
			c.entries = append(c.entries[:i], c.entries[i+1:]...)
			break
		}
	}
	c.entries = append(c.entries, dagCacheEntry{key: key, value: v, at: c.now()})
	if len(c.entries) > c.max {
		c.entries = c.entries[len(c.entries)-c.max:]
	}
}

func dagCacheKey(cluster, proc int, dotFile string) string {
	return fmt.Sprintf("%d.%d|%s", cluster, proc, dotFile)
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

// dagStructureFor returns the cached structure or fetches it.
//
// refresh bypasses the cache lookup. So does a cached entry whose node
// status half has gone stale, because that half is live data sharing a
// cache entry with data that is not: see dagStatusMaxAge.
func (s *Handler) dagStructureFor(ctx context.Context, constraint string, cluster, proc int,
	dagFile string, managerAd *classad.ClassAd, refresh bool) (*dagStructure, int, string) {

	dotFile := dagman.DotFileName(dagFile)
	var started bool
	structure, err := cachedDagStructure(dagStructures, dagCacheKey(cluster, proc, dotFile), refresh,
		func() (*dagStructure, error) {
			fetchCtx, cancel := context.WithTimeout(ctx, dagSandboxTimeout)
			defer cancel()
			st, ok, err := s.buildDagStructure(fetchCtx, constraint, dagFile, dotFile)
			if err != nil {
				return nil, err
			}
			if st == nil {
				started = ok
				return nil, errDagNoStructure
			}
			return st, nil
		})
	switch {
	case errors.Is(err, errDagNoStructure):
		return nil, http.StatusConflict, dagNoStructureMessage(managerAd, dotFile, started)
	case err != nil:
		s.logger.Error(logging.DestinationHTTP, "Failed to read DAG structure from spool",
			"error", err, "job", fmt.Sprintf("%d.%d", cluster, proc), "dot_file", dotFile)
		return nil, http.StatusInternalServerError,
			fmt.Sprintf("Failed to read the workflow's structure from its spool: %v", err)
	}

	return structure, 0, ""
}

// dagNoStructureMessage tells the two causes of a missing DOT file apart.
//
// They call for opposite reactions -- wait, or stop waiting -- so
// answering both with one message would make the endpoint useless on
// whichever case the caller guessed wrong. started is true when the
// sandbox showed DAGMan already past the point where it writes the file.
func dagNoStructureMessage(ad *classad.ClassAd, dotFile string, started bool) string {
	status, _ := ad.EvaluateAttrInt("JobStatus")
	finished := status == 3 || status == 4
	if !started && !finished && !dagManagerRunningSince(ad, dagStartupGrace) {
		return fmt.Sprintf(
			"This workflow has not published its structure yet: DAGMan writes %s just after it "+
				"finishes parsing the DAG, and it has not got there. Retry in a few seconds.",
			dotFile)
	}
	return fmt.Sprintf(
		"This workflow does not publish its structure: its DAG declares no DOT command, so DAGMan "+
			"wrote no %s into the spool and there is nothing to read the graph from. Workflows "+
			"submitted through this server are instrumented for this automatically; one submitted "+
			"another way needs `DOT %s` in its DAG file.", dotFile, dotFile)
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
func cachedDagStructure(cache *dagStructureCache, key string, refresh bool,
	build func() (*dagStructure, error)) (*dagStructure, error) {

	if !refresh {
		if hit, ok := cache.get(key); ok && !dagStateStale(hit, time.Now()) {
			return hit, nil
		}
	}
	structure, err := build()
	if err != nil {
		return nil, err
	}
	cache.put(key, structure)
	return structure, nil
}

// dagStateStale says whether a cached entry's node states are too old to
// serve. A workflow whose status file is final never goes stale, and one
// that publishes no status file has no live half to go stale.
func dagStateStale(st *dagStructure, now time.Time) bool {
	if st.statusFileName == "" || st.stateIsFinal() {
		return false
	}
	return now.Sub(st.fetchedAt) > dagStatusMaxAge
}

// buildDagStructure does the expensive half: one whole-sandbox transfer,
// then the DOT file DAGMan wrote out of it.
//
// A nil structure with a nil error means the transfer worked and the
// workflow had published no DOT file; started then says whether DAGMan
// had already got far enough to have written one.
func (s *Handler) buildDagStructure(ctx context.Context, constraint, dagFile, dotFile string) (
	st *dagStructure, started bool, err error) {

	files, err := s.fetchSandboxTextFiles(ctx, constraint, dagBigFilePredicate(dagFile))
	if err != nil {
		return nil, false, err
	}

	name, body, ok := findDotFile(files, dotFile)
	if !ok {
		return nil, dagmanPastStartup(files), nil
	}

	graph, err := dagman.ParseDot(strings.NewReader(body))
	if err != nil {
		return nil, true, fmt.Errorf("read %s: %w", name, err)
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
	if statusName, statusBody, ok := findStatusFile(files, dagman.StatusFileName(dagFile)); ok {
		states, at, next := parseNodeStatusFile(statusBody)
		if len(states) > 0 {
			st.statusStates, st.statusFileName = states, statusName
			st.statusFileTime, st.statusNextUpdate = at, next
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
	best := ""
	for name, body := range files {
		if !looksLikeDot(body) {
			continue
		}
		// Prefer the longest match on the expected stem, so
		// "workflow.dot.3" beats an unrelated "extra.dot" and the choice
		// does not depend on map iteration order.
		if best == "" || dotNameRank(name, want) > dotNameRank(best, want) {
			best = name
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
func findStatusFile(files map[string]string, want string) (name, body string, ok bool) {
	if body, ok := files[want]; ok && looksLikeNodeStatus(body) {
		return want, body, true
	}
	for name, body := range files {
		if looksLikeNodeStatus(body) {
			return name, body, true
		}
	}
	return "", "", false
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
// be absurd. Only the total is a hard refusal.
func (s *Handler) fetchSandboxTextFiles(ctx context.Context, constraint string,
	big func(string) bool) (map[string]string, error) {

	pipeReader, pipeWriter := io.Pipe()
	sandboxErrChan := s.getSchedd().ReceiveJobSandbox(ctx, constraint, pipeWriter)
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

	files, readErr := collectTarTextFiles(tar.NewReader(pipeReader), big)

	_ = pipeReader.Close()
	if err := <-finalErrChan; err != nil {
		return nil, fmt.Errorf("download sandbox: %w", err)
	}
	if readErr != nil {
		return nil, readErr
	}
	return files, nil
}

// collectTarTextFiles is the loop, split out so it can be tested against
// a tar built in memory rather than against a schedd.
func collectTarTextFiles(tr *tar.Reader, big func(string) bool) (map[string]string, error) {
	files := map[string]string{}
	var total int64
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
		name := path.Base(filepath.ToSlash(header.Name))
		limit := int64(dagAuxFileMaxBytes)
		if big != nil && big(name) {
			limit = dagBigFileMaxBytes
		}
		if header.Size > limit {
			if limit == dagBigFileMaxBytes {
				return nil, fmt.Errorf("the workflow's %s is %d bytes, larger than the %d "+
					"this endpoint will read", name, header.Size, limit)
			}
			continue
		}
		if total+header.Size > dagTotalFileMaxBytes {
			return nil, fmt.Errorf("this job's spool holds more than %d bytes of files; its workflow "+
				"graph cannot be read through this endpoint", int64(dagTotalFileMaxBytes))
		}
		buf := &bytes.Buffer{}
		if _, err := io.CopyN(buf, tr, header.Size); err != nil && !errors.Is(err, io.EOF) {
			return nil, fmt.Errorf("read %s: %w", name, err)
		}
		if !looksLikeText(buf.Bytes()) {
			continue
		}
		total += header.Size
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
// error ends the scan rather than discarding the result.
func parseNodeStatusFile(body string) (map[string]dagStatusEntry, int64, int64) {
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
func parseNodeStatusJSON(body string) (map[string]dagStatusEntry, int64, int64) {
	states := map[string]dagStatusEntry{}
	var at, next int64
	dec := json.NewDecoder(strings.NewReader(body))
	for {
		var raw map[string]interface{}
		if err := dec.Decode(&raw); err != nil {
			break
		}
		ad := jsonAd(raw)
		switch strings.ToLower(statusAdKind(ad.str("MyType"), ad.str("Type"))) {
		case "dagstatus", "statusend":
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
	return states, at, next
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

func parseNodeStatusClassAds(body string) (map[string]dagStatusEntry, int64, int64) {
	states := map[string]dagStatusEntry{}
	var at, next int64
	reader := classad.NewReader(strings.NewReader(body))
	for reader.Next() {
		ad := reader.ClassAd()
		myType, _ := ad.EvaluateAttrString("MyType")
		altType, _ := ad.EvaluateAttrString("Type")
		myType = statusAdKind(myType, altType)
		switch {
		case strings.EqualFold(myType, "DagStatus"), strings.EqualFold(myType, "StatusEnd"):
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
	return states, at, next
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
func (s *Handler) buildDagResponse(ctx context.Context, r *http.Request, cluster int, st *dagStructure) DagGraphResponse {
	live := map[string]dagNodeState{}
	var sources []string
	var warnings []string

	queued, err := s.dagQueueStates(ctx, r, cluster, live)
	if err != nil {
		warnings = append(warnings, fmt.Sprintf("the job queue could not be consulted: %v", err))
	}

	// Only ask the archive about what the queue did not explain. On a
	// finished workflow that is every node; on a running one it is the
	// nodes that already left the queue.
	archived := 0
	if len(live) < st.grouping.NodeCount {
		archived, err = s.dagArchiveStates(ctx, r, cluster, live)
		if err != nil {
			warnings = append(warnings, fmt.Sprintf(
				"the job archive could not be consulted, so nodes that have left the queue may read "+
					"as unready: %v", err))
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
		FetchedAt:           time.Now().UTC(),
	}
	if used[dagSourceStatusFile] {
		resp.StatusFileTime = st.statusFileTime
	}
	resp.Groups, resp.Nodes = rollUpDagGroups(st.grouping, states)
	if st.grouping.NodeCount > dagNodeListLimit {
		resp.Nodes = nil
		resp.NodesOmitted = true
		resp.NodesOmittedReason = fmt.Sprintf(
			"this workflow has %d nodes, more than the %d this endpoint lists individually; "+
				"the per-group status counts describe every node.",
			st.grouping.NodeCount, dagNodeListLimit)
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
				HoldReason: st.holdReason,
				ExitCode:   st.exitCode,
				Detail:     st.detail,
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
func (s *Handler) dagArchiveStates(ctx context.Context, r *http.Request, cluster int,
	out map[string]dagNodeState) (int, error) {

	constraint, err := s.bulkOwnerScope(ctx, r, fmt.Sprintf("DAGManJobId == %d", cluster))
	if err != nil {
		return 0, err
	}
	ads, err := s.getSchedd().QueryHistoryWithOptions(ctx, constraint, &htcondor.HistoryQueryOptions{
		Source:     htcondor.HistorySourceJobHistory,
		Projection: append(append([]string{}, dagNodeProjection...), "ExitCode", "ExitBySignal"),
		// A workflow's nodes are contiguous and recent in the history
		// file, so a bounded backwards scan finds them all without
		// reading years of it.
		Limit:     dagArchiveLimit,
		ScanLimit: dagArchiveScanLimit,
		Backwards: true,
	})
	if err != nil {
		return 0, err
	}
	n := 0
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
	return n, nil
}

const (
	dagArchiveLimit     = 20000
	dagArchiveScanLimit = 200000
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
