// Package htcondor provides HTCondor job submission functionality.
//
//nolint:unparam // Many functions return error for interface consistency even when currently not failing
package htcondor

import (
	"errors"
	"fmt"
	"io"
	"math"
	"os"
	"os/user"
	"regexp"
	"runtime"
	"slices"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/PelicanPlatform/classad/ast"
	"github.com/PelicanPlatform/classad/classad"
	"github.com/bbockelm/golang-htcondor/config"
	"github.com/bbockelm/golang-htcondor/version"
)

// submitVersionString and condorPlatformString are the SubmitVersion
// / CondorPlatform values the Go library stamps onto every job ad,
// matching the role of CondorVersion()/CondorPlatform() in
// HTCondor's submit_utils.cpp (see HTCONDOR-3413: the schedd sets
// CondorVersion on the cluster ad, and the *client* is expected to
// supply SubmitVersion so downstream tooling — condor_q, history,
// log forensics — can identify which client minted the job).
//
// The version number is version.HTCondorCompat rather than this
// module's own version, because CondorVersionInfo
// (condor_ver_info.cpp) requires a three-part HTCondor version and
// rejects anything below 6.x -- a "v0.18.7" here parses as "older
// than everything". We include "golang-htcondor" plus our real
// version in the BuildID segment so an operator reading a job log
// can still tell the submission came from this library, not from
// condor_submit.
//
// Computed once at package init from the linker-injected version
// values; recomputing per submission would waste CPU and the values
// can't change at runtime anyway.
var (
	submitVersionString  = version.CondorVersionString(version.GetBuild().BuildID())
	condorPlatformString = fmt.Sprintf(
		"$CondorPlatform: %s_%s $",
		runtime.GOARCH, runtime.GOOS,
	)
)

// SubmitFile represents a parsed HTCondor submit file
type SubmitFile struct {
	cfg *config.Config
	// assigned maps the upper-cased name of every command the submit
	// file itself assigned to the spelling it was first written with.
	// cfg cannot answer whether the file assigned a name: it is seeded
	// with HTCondor's param_info defaults, so a submit command that
	// shares a name with a config knob reads as "set" even when the
	// file never mentioned it. See submitCommand. The original spelling
	// is kept because request_<resource> carries the resource tag's
	// capitalization into the job attribute; see
	// setCustomResourceRequests.
	assigned map[string]string
	universe int
	// params answers the configuration knobs condor_submit reads with
	// param(); nil means HTCondor's built-in defaults. See SubmitParams.
	params SubmitParams
	// defaultDisk is the RequestDisk expression the job ad being built
	// took from JOB_DEFAULT_REQUESTDISK, or "" when it took none. Reset
	// by every setResourceRequests; see defaultDiskEvaluates.
	defaultDisk string
	// submitUser is the account the submission is charged to, which the
	// accounting group is built from. Empty means the parse was given
	// none and falls back to the account running it; see submitUserName.
	submitUser string
	// localAccess is SubmitParseOptions.AllowLocalAccess, kept because a
	// few of condor_submit's keywords read the submitting process's
	// ENVIRONMENT rather than the submit file -- `use_scitokens` falls
	// back to BEARER_TOKEN_FILE. That is the same host access the option
	// gates for $ENV() and `include command`, so it answers for it too.
	localAccess bool
	// submitTime is the QDate every proc of one submission shares, in Unix
	// seconds, or 0 before the submission has been stamped.
	//
	// condor_submit reads the clock once and hands that one value to
	// init_base_ad, so every proc of a cluster carries the same QDate.
	// Reading the clock per proc instead gives a multi-proc submission two
	// QDates whenever it straddles a second boundary, which makes one
	// cluster look submitted at two different times to anything that groups
	// or sorts by it, and leaves QDate on the proc ads because it no longer
	// matches the cluster ad and so does not fold away.
	submitTime int64

	// Queue statement information
	queueCount    int
	queueVars     []string
	queueIterator SubmitIterator
	// queueStmt is the queue statement as parsed, kept because a late
	// materialization digest has to write the statement back out for the
	// schedd to iterate. Nil when the file has no queue statement.
	queueStmt *config.QueueStatement
}

// SubmitIterator provides iteration over queue items
type SubmitIterator interface {
	// Next advances to the next item and returns true if successful
	Next() bool
	// Values returns the current row's variable values
	Values() map[string]string
	// Count returns the total number of items
	Count() int
}

// JobID represents a cluster/proc pair
type JobID struct {
	Cluster int
	Proc    int
}

// SubmitResult contains the results of submitting jobs
type SubmitResult struct {
	ClusterID int
	NumProcs  int

	// ClusterAd is the same ad as ProcAds[0], not a separate one. The first
	// proc's ad is what becomes the cluster ad: it is sent in full at proc id
	// -1, and every later proc ad is reduced to what differs from it. It is
	// not a template assembled from the attributes all procs share.
	ClusterAd *classad.ClassAd

	ProcAds []*classad.ClassAd

	// Factory is set when the submission is a job factory: the submit file
	// asked for late materialization with max_materialize, max_idle or
	// materialize_max_idle. ProcAds is then empty, because a factory
	// submission sends no proc ads -- it sends this instead and the schedd
	// materializes the procs itself. Nil for an ordinary submission.
	Factory *JobFactory
}

// Universe constants matching HTCondor
const (
	UniverseMin       = 0
	UniverseStandard  = 1
	UniverseVanilla   = 5
	UniverseScheduler = 7
	UniverseGrid      = 9
	UniverseJava      = 10
	UniverseParallel  = 11
	UniverseLocal     = 12
	UniverseVM        = 13
	// NB: there is deliberately no docker/container universe constant.
	// HTCondor has no numeric docker or container universe (14 is
	// CONDOR_UNIVERSE_MAX, a non-universe placeholder). Docker and
	// container jobs run in VANILLA with the WantDocker/WantContainer
	// toppings; see parseUniverse and setContainerSettings.
)

// SubmitParseOptions controls what a submit-file parse is allowed to do
// besides reading the text it was handed.
type SubmitParseOptions struct {
	// AllowLocalAccess lets the parse reach the host it runs on:
	// `include` and `include command` directives (the latter runs a
	// shell command), the $ENV() macro function, `queue ... from
	// <itemdata file>` and `queue ... matching <glob>`.
	//
	// Off by default, which is the setting a daemon parsing a submit
	// file it received over the network wants: none of these should
	// run with the daemon's identity on a remote caller's behalf —
	// `include command` alone would be command execution as the daemon
	// user. Set it for a submit file the local user wrote and that the
	// parse runs on that user's behalf, which is how condor_submit
	// reads one.
	AllowLocalAccess bool

	// Params answers the configuration knobs condor_submit reads from
	// its own configuration rather than from the submit file: the
	// JOB_DEFAULT_REQUEST* defaults for a job that omits request_cpus,
	// request_memory, request_disk or request_gpus. Nil uses HTCondor's
	// built-in defaults.
	Params SubmitParams

	// SubmitUser is the account the submission is charged to: the user
	// condor_submit would have taken from the host it ran on and passed
	// to SubmitHash::init_base_ad. It is what an accounting group is
	// completed with -- `accounting_group = Proj` becomes
	// `AccountingGroup = "Proj.<SubmitUser>"`, because the accountant
	// reads that attribute as <group>.<user> and a bare group name is a
	// submitter alias rather than a group.
	//
	// Empty falls back to the account running the parse, which is right
	// for a tool submitting on its own user's behalf. A daemon parsing a
	// submit file it received for someone else must set this to the
	// authenticated submitter, or the group is charged to the daemon's
	// own account.
	SubmitUser string
}

// ParseSubmitFile parses a submit file from a reader. The parse cannot
// reach the local host: see SubmitParseOptions.AllowLocalAccess and
// ParseSubmitFileWithOptions for a parse on behalf of the local user.
func ParseSubmitFile(r io.Reader) (*SubmitFile, error) {
	return ParseSubmitFileWithOptions(r, SubmitParseOptions{})
}

// ParseSubmitFileWithOptions parses a submit file from a reader with
// explicit parse options.
func ParseSubmitFileWithOptions(r io.Reader, opts SubmitParseOptions) (*SubmitFile, error) {
	raw, err := io.ReadAll(r)
	if err != nil {
		return nil, fmt.Errorf("failed to read submit file: %w", err)
	}

	// Pre-pass: rewrite any `queue VARS from ((<inline rows>))` blocks
	// into `queue VARS from <tempfile>`. The Go grammar (parser.y)
	// only knows the from-file and in-list forms, but the table-style
	// submit page generates the inline-paren form because that's what
	// HTCondor's own condor_submit accepts. We materialize the rows
	// to a temp file, let the existing parser handle the rewritten
	// form, then delete the temp file on the way out — fileIterator
	// slurps the file fully during ParseSubmitFile so it's safe to
	// remove immediately afterward.
	expanded, tempFiles, err := expandInlineQueueBlocks(string(raw))
	if err != nil {
		return nil, fmt.Errorf("failed to parse submit file: %w", err)
	}
	defer func() {
		for _, p := range tempFiles {
			_ = os.Remove(p)
		}
	}()

	// We need to parse the submit file in two passes:
	// 1. Parse to get the queue statement
	// 2. Execute assignments to build the config

	// First pass: parse to get statements including queue
	//
	// ParseStrict, not Parse: a line HTCondor rejects fails the whole submit
	// file there, and the lenient mode here does not. The grammar has no error
	// production, so a syntax error stops the parse, but a default reduction
	// has usually already stored the statements read up to that point — which
	// Parse then returns with a nil error. A submit file with one bad line
	// silently lost that line and every command after it.
	lexer := config.NewLexer(strings.NewReader(expanded))
	stmts, err := config.ParseStrict(lexer)
	if err != nil {
		return nil, fmt.Errorf("failed to parse submit file: %w", err)
	}

	// Find the queue statement (should be last, but we'll take the first we find)
	var queueStmt *config.QueueStatement
	var configStmts []config.Statement

	for _, stmt := range stmts {
		if qs, ok := stmt.(*config.QueueStatement); ok {
			if queueStmt == nil {
				queueStmt = qs
			}
			// Don't include queue statements in config execution
			continue
		}
		configStmts = append(configStmts, stmt)
	}

	// Create config and execute non-queue statements
	cfg := config.NewEmptyWithOptions(config.ConfigOptions{NoLocalAccess: !opts.AllowLocalAccess})
	if err := cfg.ExecuteStatements(configStmts); err != nil {
		return nil, fmt.Errorf("failed to execute submit file: %w", err)
	}

	sf := &SubmitFile{
		cfg:         cfg,
		assigned:    assignedNames(configStmts),
		universe:    UniverseVanilla, // Default
		queueCount:  1,               // Default if no queue statement
		params:      opts.Params,
		submitUser:  opts.SubmitUser,
		localAccess: opts.AllowLocalAccess,
	}

	// Set universe if specified. Read through submitCommand like every
	// other submit command: there is no UNIVERSE knob in param_info
	// today, but relying on that would make a future upstream addition
	// silently change every job's universe.
	if univ, ok := sf.submitCommand("universe"); ok {
		sf.universe = parseUniverse(univ)
	}

	// Create iterator from queue statement
	if queueStmt != nil {
		// The itemdata rewrite above wrote the inline `from ((rows))`
		// form to temp files this call created, so those stay readable
		// even when the submit file itself may not name a local file.
		iterator, err := createIteratorFromQueue(queueStmt, queueFileAccess{
			allowAny:   opts.AllowLocalAccess,
			allowPaths: tempFiles,
		})
		if err != nil {
			return nil, fmt.Errorf("failed to create queue iterator: %w", err)
		}
		sf.queueIterator = iterator
		sf.queueCount = iterator.Count()
		sf.queueVars = queueStmt.VarNames
		sf.queueStmt = queueStmt
	} else {
		// No queue statement means queue 1
		sf.queueIterator = newSimpleIterator(1)
		sf.queueCount = 1
	}

	return sf, nil
}

// inlineQueueBlockOpen matches the opening line of an inline queue
// block: `queue VAR(, VAR2)* from ((`. The pattern is intentionally
// loose about whitespace (operators sometimes write `queue x from((`)
// and case-insensitive about `queue` / `from` (HTCondor itself is).
var inlineQueueBlockOpen = regexp.MustCompile(`(?i)^\s*(queue\b[^\n]*?\bfrom)\s*\(\(\s*(.*)$`)

// expandInlineQueueBlocks finds `queue ... from ((<rows>))` blocks in
// the input and rewrites them to `queue ... from <tempfile>`, with
// the row text written to a fresh temp file. Returns the rewritten
// input and the paths of any temp files the caller must remove on
// the way out.
//
// Notes:
//
//   - The opening `((` and closing `))` may share their line with row
//     content. We honor both:
//
//     queue x from ((    val1
//     val2
//     val3))             # all three rows are queued
//
//   - Comment lines (#-prefixed) and blank lines inside the block are
//     dropped to match what fileIterator does when it reads the file.
//
//   - Multiple inline blocks in the same submit file are fine; each
//     gets its own temp file.
//
//   - Unterminated blocks return a clear error pointing at the open
//     line.
func expandInlineQueueBlocks(in string) (string, []string, error) {
	lines := strings.Split(in, "\n")
	var out []string
	var temps []string

	for i := 0; i < len(lines); i++ {
		line := lines[i]
		m := inlineQueueBlockOpen.FindStringSubmatch(line)
		if m == nil {
			out = append(out, line)
			continue
		}

		queuePrefix := strings.TrimSpace(m[1]) // "queue VARS from"
		afterOpen := m[2]                      // anything after `((` on the same line

		var rows []string
		// Same-line close: `... from ((row1)) ...trailing`. trailing
		// is currently discarded, but we accept the close.
		if idx := strings.Index(afterOpen, "))"); idx >= 0 {
			head := strings.TrimSpace(afterOpen[:idx])
			if head != "" {
				rows = append(rows, head)
			}
		} else {
			// Same-line content (before first newline) is one row.
			if h := strings.TrimSpace(afterOpen); h != "" {
				rows = append(rows, h)
			}
			// Consume subsequent lines until `))`.
			openLine := i + 1 // 1-indexed for the error message
			closed := false
			for i++; i < len(lines); i++ {
				ln := lines[i]
				if idx := strings.Index(ln, "))"); idx >= 0 {
					if h := strings.TrimSpace(ln[:idx]); h != "" {
						rows = append(rows, h)
					}
					closed = true
					break
				}
				rows = append(rows, ln)
			}
			if !closed {
				return "", nil, fmt.Errorf(
					"failed to parse submit file: unterminated 'queue ... from ((' opened at line %d (no closing '))' found)",
					openLine)
			}
		}

		// Strip blanks and comments — fileIterator does the same when
		// it reads a real on-disk queue file, so the inline form
		// behaves identically.
		var keep []string
		for _, r := range rows {
			r = strings.TrimSpace(r)
			if r == "" || strings.HasPrefix(r, "#") {
				continue
			}
			keep = append(keep, r)
		}

		if len(keep) == 0 {
			return "", nil, fmt.Errorf(
				"failed to parse submit file: 'queue ... from ((...))' at line %d has no rows",
				i+1)
		}

		tmp, err := os.CreateTemp("", "htcondor-api-queue-*.txt")
		if err != nil {
			return "", nil, fmt.Errorf("failed to create temp file for inline queue block: %w", err)
		}
		body := strings.Join(keep, "\n") + "\n"
		if _, werr := tmp.WriteString(body); werr != nil {
			_ = tmp.Close()
			_ = os.Remove(tmp.Name())
			return "", nil, fmt.Errorf("write temp queue file: %w", werr)
		}
		if cerr := tmp.Close(); cerr != nil {
			_ = os.Remove(tmp.Name())
			return "", nil, fmt.Errorf("close temp queue file: %w", cerr)
		}
		temps = append(temps, tmp.Name())
		// The path goes in bare. Everything after `from` is the item
		// file's name verbatim, trimmed and otherwise untouched, so a
		// path holding `/`, `-`, a space or a quote needs no quoting --
		// and must not be given any, since quotes would become part of
		// the name. This used to wrap the path in double quotes because
		// the grammar accepted only an IDENT or a STRING there, which is
		// no longer how the tail is read.
		out = append(out, queuePrefix+" "+tmp.Name())
	}
	return strings.Join(out, "\n"), temps, nil
}

// parseUniverse converts universe string to integer constant
func parseUniverse(univ string) int {
	univ = strings.ToLower(strings.TrimSpace(univ))
	switch univ {
	case "standard":
		return UniverseStandard
	case "vanilla":
		return UniverseVanilla
	case "scheduler":
		return UniverseScheduler
	case "grid":
		return UniverseGrid
	case "java":
		return UniverseJava
	case "parallel", "mpi":
		return UniverseParallel
	case "local":
		return UniverseLocal
	case "vm":
		return UniverseVM
	case "docker", "container":
		// "docker" and "container" are not universes of their own -- in
		// HTCondor they are vanilla-universe "toppings". condor_submit
		// keeps JobUniverse == VANILLA and selects the runtime with the
		// WantDocker/WantContainer flags plus DockerImage/ContainerImage
		// (set in setContainerSettings). There is no numeric docker or
		// container universe: 14 is CONDOR_UNIVERSE_MAX, a placeholder no
		// shadow can run ("cannot support universe 14"), which is exactly
		// what a JobUniverse of 14 produced.
		return UniverseVanilla
	default:
		return UniverseVanilla
	}
}

// QueueCount reports how many job processes this submit file queues.
//
// It is the submit parser's own answer, iterator included, which is the
// only place the question can be answered correctly: the queue statement
// has half a dozen forms, and `queue 2 x in (a, b)` is four processes
// while `queue name from ((rows))` is as many as there are rows. A caller
// that counts by re-reading the text gets some of those forms wrong, and
// the ones it gets wrong are the multi-process ones that matter.
func (sf *SubmitFile) QueueCount() int {
	return sf.queueCount
}

// QueueVars reports the variable names the queue statement binds per row,
// in the order the statement lists them. Empty when the statement binds
// none, which is the common `queue` and `queue N`.
//
// The caller gets a copy: the names belong to the parsed submit file and
// outlive the call, and a caller that sorted or appended to them in place
// would be editing that file's own state.
func (sf *SubmitFile) QueueVars() []string {
	if len(sf.queueVars) == 0 {
		return nil
	}
	out := make([]string, len(sf.queueVars))
	copy(out, sf.queueVars)
	return out
}

// stampSubmitTime returns the submission's QDate, reading the clock on the
// first call and returning that same value afterwards. Submit and SubmitLate
// clear it so a SubmitFile submitted twice stamps each submission separately;
// a caller driving MakeClusterAd and MakeProcAd itself gets one value across
// the pair without having to ask for it.
func (sf *SubmitFile) stampSubmitTime() int64 {
	if sf.submitTime == 0 {
		sf.submitTime = time.Now().Unix()
	}
	return sf.submitTime
}

// MakeJobAd creates a ClassAd for a single job
// This is the main transformation from submit file to job ClassAd
// queueVars contains variable substitutions from the queue statement
func (sf *SubmitFile) MakeJobAd(jobID JobID, queueVars map[string]string) (*classad.ClassAd, error) {
	ad := classad.New()

	// Set basic job identifiers
	_ = ad.Set("ClusterId", jobID.Cluster)
	_ = ad.Set("ProcId", jobID.Proc)
	_ = ad.Set("JobUniverse", sf.universe)

	// WantParallelScheduling goes with the universe: SetUniverse writes it,
	// and only when it is true. It is written here, before the `+Attr` pass,
	// for the same reason C++ writes it in SetUniverse -- a
	// `+WantParallelScheduling` has to be able to overwrite it.
	sf.setParallelSchedulingFlag(ad)

	// Set job status (1 = idle)
	_ = ad.Set("JobStatus", 1)

	// QDate: Unix epoch seconds at the moment of submission. HTCondor's
	// own condor_submit sets this on the client side before sending the ad,
	// and downstream tooling (the web UI's "Submitted" column, condor_q
	// formatting, history records) expects it to be present. Without
	// QDate the schedd doesn't backfill, so the field stays undefined
	// and clients render nothing.
	_ = ad.Set("QDate", sf.stampSubmitTime())

	// SubmitVersion + CondorPlatform: condor_submit stamps these
	// onto every base job (submit_utils.cpp around ATTR_SUBMIT_VERSION).
	// Forensics tooling reads them to identify the submitter; without
	// them, a job ad looks like it came from an unknown source. See
	// the package-level submitVersionString / condorPlatformString
	// comment for format rationale.
	_ = ad.Set("SubmitVersion", submitVersionString)
	_ = ad.Set("CondorPlatform", condorPlatformString)

	// Apply live macro substitutions using a macro context
	// This implements HTCondor's "live" macros that change per-job
	sf.pushMacroContext(jobID, queueVars)
	defer sf.popMacroContext()

	// Set executable
	if err := sf.setExecutable(ad); err != nil {
		return nil, err
	}

	// Set arguments
	if err := sf.setArguments(ad); err != nil {
		return nil, err
	}

	// Set environment
	if err := sf.setEnvironment(ad); err != nil {
		return nil, err
	}

	// Set input/output/error files
	if err := sf.setStandardFiles(ad); err != nil {
		return nil, err
	}

	// Set container/docker settings. Before setFileTransfer, which is
	// where condor_submit decides whether the container image has to be
	// carried to the execute node and rewrites ContainerImage to the
	// name the transfer will leave in the sandbox.
	if err := sf.setContainerSettings(ad); err != nil {
		return nil, err
	}

	// Set file transfer settings
	if err := sf.setFileTransfer(ad); err != nil {
		return nil, err
	}

	// Set requirements
	if err := sf.setRequirements(ad); err != nil {
		return nil, err
	}

	// The transforms the schedd applies when the job is evicted.
	//
	// Before the resource requests, because the retry_request_memory
	// family appends ITS tag to the same list (addTransformOnEvict) and
	// SetOnEvictExpressions overwrites the list outright. Run the other
	// way round, the built-in transform's tag is written and then thrown
	// away, leaving a TransformBody_RequestMemory nothing names -- and a
	// body nothing names is never run.
	sf.setOnEvictChecks(ad)

	// Set request_* resources
	if err := sf.setResourceRequests(ad); err != nil {
		return nil, err
	}

	// Set the request_<resource> commands that have no dedicated
	// handling. Before setCustomAttributes, which outranks them.
	if err := sf.setCustomResourceRequests(ad); err != nil {
		return nil, err
	}

	// Set rank
	if err := sf.setRank(ad); err != nil {
		return nil, err
	}

	// Set owner and accounting
	if err := sf.setOwnership(ad); err != nil {
		return nil, err
	}

	// The credential settings, which condor_submit reads for every job
	// whatever the universe (SetGSICredentials).
	if err := sf.setGSICredentials(ad); err != nil {
		return nil, err
	}

	// Set job status and control attributes
	if err := sf.setJobStatusControl(ad); err != nil {
		return nil, err
	}

	// Set any custom attributes (+ or MY.)
	if err := sf.setCustomAttributes(ad); err != nil {
		return nil, err
	}

	// After the custom attributes, which can supply what a configured
	// RequestDisk default reads (or replace it outright).
	if err := sf.defaultDiskEvaluates(ad); err != nil {
		return nil, err
	}

	// Set universe-specific parameters
	switch sf.universe {
	case UniverseGrid:
		if err := sf.setGridParams(ad); err != nil {
			return nil, err
		}
	case UniverseVM:
		if err := sf.setVMParams(ad); err != nil {
			return nil, err
		}
	}

	if err := sf.setUngatedFamilies(ad); err != nil {
		return nil, err
	}

	// MinHosts/MaxHosts: the machine count for a parallel job, the
	// default pair of 1 for everything else.
	if err := sf.setHostCounts(ad); err != nil {
		return nil, err
	}

	// The parallel universe's two implied settings. Before the keyword
	// pass, which is what `want_io_proxy` goes through.
	if err := sf.setParallelSandbox(ad); err != nil {
		return nil, err
	}

	// The keywords whose job attribute and value shape come straight from
	// HTCondor's own keyword table. SubmitHash runs this pass after the
	// universe-specific setters and before the job-deferral pass, which
	// reads the Cron* attributes it writes.
	if err := sf.setSimpleSubmitKeywords(ad); err != nil {
		return nil, err
	}

	// Set periodic expressions (all universes)
	if err := sf.setPeriodicExpressions(ad); err != nil {
		return nil, err
	}

	// Set signal handling
	if err := sf.setSignalHandling(ad); err != nil {
		return nil, err
	}

	// Set simple job expressions
	if err := sf.setSimpleJobExprs(ad); err != nil {
		return nil, err
	}

	// Set extended job expressions
	if err := sf.setExtendedJobExprs(ad); err != nil {
		return nil, err
	}

	// Derive the GPU constraint expression, which reads the job ad rather
	// than the submit file and so has to run after everything that can
	// write a GPU attribute onto it.
	if err := sf.setGPUResourceRequirements(ad); err != nil {
		return nil, err
	}

	// Set auto-generated attributes (should be last)
	if err := sf.setAutoAttributes(ad); err != nil {
		return nil, err
	}

	return ad, nil
}

// setExecutable sets the executable attribute
func (sf *SubmitFile) setExecutable(ad *classad.ClassAd) error {
	exec, ok := sf.submitCommand("executable")
	if !ok {
		return fmt.Errorf("executable is required")
	}

	cmd, err := sf.resolveExecutable(exec)
	if err != nil {
		return err
	}
	_ = ad.Set("Cmd", cmd)
	return nil
}

// Path resolution.
//
// HTCondor records the executable and the user log as absolute paths, so a
// job's ad does not depend on the directory the submitter happened to be in
// when they ran condor_submit. The rule lives in SubmitHash::full_path and
// SubmitHash::ComputeIWD in src/condor_utils/submit_utils.cpp; the three
// functions below are a port of it.
//
// Which paths get resolved is not uniform, and the differences are
// deliberate -- see resolveExecutable and setStandardFiles.

// compressPath performs the only normalization SubmitHash::compress_path
// does: runs of directory separators collapse to one. "." and ".."
// components are left exactly where they are, so "a/./b" stays "a/./b" and
// HTCondor's own ad for that job carries the dot. Matching that matters
// more than producing a prettier path, since the ad is what the shadow and
// the starter later compare and open.
//
// Backslash counts as a separator here because compress_path treats both,
// on every platform.
func compressPath(path string) string {
	var b strings.Builder
	b.Grow(len(path))
	prevSep := false
	for i := 0; i < len(path); i++ {
		c := path[i]
		sep := c == '/' || c == '\\'
		if sep && prevSep {
			continue
		}
		b.WriteByte(c)
		prevSep = sep
	}
	return b.String()
}

// fullPath resolves name against base the way SubmitHash::full_path does on
// a POSIX host: a name that already starts at the root keeps its own path,
// anything else is joined to base, and the result is only slash-collapsed.
//
// Note what this does NOT do. It does not check the filesystem, resolve
// symlinks or fold away "..", and it has no notion of a URL: full_path
// treats "http://host/x" as a relative name like any other and HTCondor
// stores the join. A Go parser that special-cased URLs here would hand the
// schedd a different ad than condor_submit does for the same file.
func fullPath(name, base string) string {
	if strings.HasPrefix(name, "/") {
		return compressPath("/" + name)
	}
	return compressPath("/" + base + "/" + name)
}

// jobIwd returns the job's initial working directory: ComputeIWD resolves a
// relative initialdir against the submitting directory and falls back to
// that directory outright when the submit file names none.
//
// ComputeIWD also refuses a directory it cannot stat, which this does not:
// rejecting a submit file over the state of the parsing host's filesystem
// is condor_submit's business, not a library parser's.
func (sf *SubmitFile) jobIwd() (string, error) {
	cwd, err := os.Getwd()
	if err != nil {
		return "", fmt.Errorf("failed to get current working directory: %w", err)
	}
	dir, ok := sf.submitCommandAlt("initialdir", "iwd")
	if !ok {
		dir, _ = sf.submitCommandAlt("initial_dir", "job_iwd")
	}
	if dir == "" {
		return compressPath(cwd), nil
	}
	if strings.HasPrefix(dir, "/") {
		return compressPath(dir), nil
	}
	// dircat: the directory loses its trailing separators, the name its
	// leading ones, and one separator joins them.
	return compressPath(strings.TrimRight(cwd, "/\\") + "/" + strings.TrimLeft(dir, "/\\")), nil
}

// resolveExecutable returns the path Cmd records for the executable named
// in the submit file.
//
// Two things about SetExecutable are easy to get wrong. It resolves against
// the SUBMITTING directory rather than against Iwd -- full_path(ename,
// /*use_iwd=*/false) -- so initialdir moves the job's working directory and
// its log without moving where the executable was found. And it resolves
// only when the executable is being transferred: a job that is not sending
// its executable is naming a path on the execute machine, and rewriting
// that against a submit-side directory would name a file that does not
// exist there. The universes whose "executable" is not a file at all --
// vm, and the ec2/gce/azure grid types, where it is just a job name --
// reach the same branch by having their transfer forced off.
func (sf *SubmitFile) resolveExecutable(name string) (string, error) {
	if !sf.transfersExecutable() {
		return name, nil
	}
	cwd, err := os.Getwd()
	if err != nil {
		return "", fmt.Errorf("failed to get current working directory: %w", err)
	}
	return fullPath(name, cwd), nil
}

// transfersExecutable reports whether SetExecutable would transfer the
// executable, which is what decides whether Cmd is resolved.
//
// The test on transfer_executable is deliberately not parseBool: SetExecutable
// turns transfer off only for a value whose first character is 'f' or 'F',
// so "transfer_executable = 0" leaves it ON there. Reading it as a boolean
// here would resolve one set of submit files differently from condor_submit.
func (sf *SubmitFile) transfersExecutable() bool {
	if !sf.executableIsAFile() {
		return false
	}
	te, ok := sf.submitCommand("transfer_executable")
	if !ok || te == "" {
		return true
	}
	return te[0] != 'f' && te[0] != 'F'
}

// executableIsAFile reports whether the submit file's "executable" names a
// file on the submitting host at all. For vm universe and the ec2, gce and
// azure grid types it is only the job's name, and SetExecutable marks those
// ignore_it -- which forces transfer off and leaves Cmd exactly as written.
func (sf *SubmitFile) executableIsAFile() bool {
	if sf.universe == UniverseVM {
		return false
	}
	if sf.universe != UniverseGrid {
		return true
	}
	res, _ := sf.submitCommand("grid_resource")
	gridType, _, _ := strings.Cut(strings.TrimSpace(res), " ")
	switch strings.ToLower(gridType) {
	case "ec2", "gce", "azure":
		return false
	}
	return true
}

// setArguments sets the arguments attribute
// HTCondor supports two styles of argument quoting:
// 1. Old style: no surrounding quotes, uses Args attribute, backslash escapes quotes
// 2. New style: surrounded by double quotes, uses Arguments attribute
func (sf *SubmitFile) setArguments(ad *classad.ClassAd) error {
	// Check both "arguments" and "args"
	args, ok := sf.submitCommand("arguments")
	if !ok {
		args, ok = sf.submitCommand("args")
	}

	if !ok || args == "" {
		_ = ad.Set("Args", "")
		return nil
	}

	// Detect style by checking if the argument string is surrounded by double quotes
	trimmed := strings.TrimSpace(args)
	isNewStyle := strings.HasPrefix(trimmed, `"`) && strings.HasSuffix(trimmed, `"`) && len(trimmed) >= 2

	if isNewStyle {
		// New style: remove outer quotes and process
		inner := trimmed[1 : len(trimmed)-1]
		processed := processNewStyleArguments(inner)
		_ = ad.Set("Arguments", processed)
	} else {
		// Old style: process backslash escapes then set Args
		processed := processOldStyleArguments(args)
		_ = ad.Set("Args", processed)
	}

	return nil
}

// processOldStyleArguments processes old style argument quoting
// In old style: backslash escapes double quotes: \" becomes "
// This matches HTCondor's V1 argument parsing
func processOldStyleArguments(s string) string {
	// Replace backslash-escaped double quotes
	return strings.ReplaceAll(s, `\"`, `"`)
}

// processNewStyleArguments processes new style argument quoting
// In new style (string already has outer quotes removed):
//   - Double quotes are escaped by doubling: "" becomes "
//   - Single quotes delimit arguments with embedded spaces
//   - Special characters (space, tab, newline, single quote) are wrapped in single quotes
//   - When starting a quoted section, if the previous character is already a quote,
//     erase it first to combine sections (this prevents repeated quotes)
//   - Doubled single quotes (”) become a single literal quote
//   - This creates the V2 storage format that HTCondor's executor can parse
//   - Backslash has no special meaning
func processNewStyleArguments(s string) string {
	var result strings.Builder
	inSingleQuote := false
	i := 0

	for i < len(s) {
		ch := s[i]

		switch {
		case ch == '"' && i+1 < len(s) && s[i+1] == '"':
			// Doubled double quote -> single double quote
			result.WriteByte('"')
			i += 2

		case ch == '\'' && i+1 < len(s) && s[i+1] == '\'':
			// Doubled single quote - represents a literal single quote
			// Apply the combining logic: if previous char is ', erase it first
			resultStr := result.String()
			if len(resultStr) > 0 && resultStr[len(resultStr)-1] == '\'' {
				// Erase the trailing quote to combine sections
				result.Reset()
				result.WriteString(resultStr[:len(resultStr)-1])
			} else {
				// Start a new quoted section
				result.WriteByte('\'')
			}
			// Write the escaped quote (two quotes)
			result.WriteString("''")
			// End the quoted section
			result.WriteByte('\'')
			i += 2

		case ch == '\'':
			// Single quote - toggle quote mode
			inSingleQuote = !inSingleQuote
			// Don't write the single quote delimiter itself
			i++

		case (ch == ' ' || ch == '\t' || ch == '\n' || ch == '\r') && inSingleQuote:
			// Whitespace inside single quotes - wrap in quotes
			// Apply the combining logic: if previous char is ', erase it first
			resultStr := result.String()
			if len(resultStr) > 0 && resultStr[len(resultStr)-1] == '\'' {
				// Erase the trailing quote to combine sections
				result.Reset()
				result.WriteString(resultStr[:len(resultStr)-1])
			} else {
				// Start a new quoted section
				result.WriteByte('\'')
			}
			// Write the whitespace character
			result.WriteByte(ch)
			// End the quoted section
			result.WriteByte('\'')
			i++

		default:
			result.WriteByte(ch)
			i++
		}
	}

	return result.String()
}

// --- ArgList, as condor_utils/condor_arglist.cpp implements it ---
//
// The tool-daemon and java-VM argument keywords go through HTCondor's ArgList
// rather than being stored as typed. A value is V2 when it opens with a double
// quote and V1 otherwise, and the round trip through the list is lossy in both
// directions on purpose: V1 collapses runs of whitespace between arguments,
// and V2 re-quotes an argument that contains a space so the starter can find
// its boundaries again.

// isV2QuotedArgs reports whether a submit value is in V2 syntax.
//
// Only the LEADING quote decides, exactly as ArgList::IsV2QuotedString does.
// A value that opens with a quote and never closes one is a V2 string that
// fails to parse, not a V1 string.
func isV2QuotedArgs(s string) bool {
	s = strings.TrimLeft(s, " \t\n\v\f\r")
	return strings.HasPrefix(s, `"`)
}

// parseArgsV2Quoted is ArgList::AppendArgsV2Quoted: a double-quoted string
// whose interior doubled quotes stand for one quote, split into arguments.
func parseArgsV2Quoted(value string) ([]string, error) {
	if !isV2QuotedArgs(value) {
		return nil, fmt.Errorf("expecting a double-quoted string (V2 format)")
	}
	raw, err := v2QuotedToV2Raw(value)
	if err != nil {
		return nil, err
	}
	return splitArgsV2(raw)
}

// parseArgsV1WackedOrV2Quoted is ArgList::AppendArgsV1WackedOrV2Quoted, which
// is what reads the keyword a submit file is most likely to use. It reports
// which syntax the value turned out to be in, because that is what decides
// which attribute the result is stored under.
func parseArgsV1WackedOrV2Quoted(value string) (args []string, wasV1 bool, err error) {
	if isV2QuotedArgs(value) {
		args, err = parseArgsV2Quoted(value)
		return args, false, err
	}
	raw, err := v1WackedToV1Raw(value)
	if err != nil {
		return nil, true, err
	}
	return splitArgsV1(raw), true, nil
}

// v2QuotedToV2Raw strips the surrounding quotes and unescapes the doubled
// ones. Anything after the closing quote but whitespace is an error, which is
// how a half-quoted value is caught rather than silently truncated.
func v2QuotedToV2Raw(value string) (string, error) {
	rest := strings.TrimLeft(value, " \t\n\v\f\r")
	rest = rest[1:] // the opening quote; isV2QuotedArgs checked it
	var raw strings.Builder
	terminated := false
	for len(rest) > 0 {
		c := rest[0]
		if c != '"' {
			raw.WriteByte(c)
			rest = rest[1:]
			continue
		}
		rest = rest[1:]
		if len(rest) > 0 && rest[0] == '"' {
			raw.WriteByte('"')
			rest = rest[1:]
			continue
		}
		terminated = true
		break
	}
	if !terminated {
		return "", fmt.Errorf("unterminated double-quote")
	}
	if strings.TrimLeft(rest, " \t\n\v\f\r") != "" {
		return "", fmt.Errorf("unexpected characters following the closing double-quote: %q", rest)
	}
	return raw.String(), nil
}

// v1WackedToV1Raw unescapes \" and rejects a bare double quote, which in V1
// syntax has no meaning and so is a submit error rather than a literal.
func v1WackedToV1Raw(value string) (string, error) {
	var raw strings.Builder
	for i := 0; i < len(value); i++ {
		switch {
		case value[i] == '\\' && i+1 < len(value) && value[i+1] == '"':
			raw.WriteByte('"')
			i++
		case value[i] == '"':
			return "", fmt.Errorf("found an illegal unescaped double-quote: %s", value[i:])
		default:
			raw.WriteByte(value[i])
		}
	}
	return raw.String(), nil
}

// splitArgsV1 is ArgList::AppendArgsV1Raw_unix: whitespace separates
// arguments and nothing quotes, so a V1 value cannot carry an argument with a
// space in it.
func splitArgsV1(raw string) []string {
	return strings.FieldsFunc(raw, func(r rune) bool {
		return r == ' ' || r == '\t' || r == '\n' || r == '\r'
	})
}

// splitArgsV2 is split_args(): whitespace separates arguments, single quotes
// group one, and a doubled single quote inside a group is a literal quote.
func splitArgsV2(raw string) ([]string, error) {
	var (
		args   []string
		buf    strings.Builder
		parsed bool
	)
	for i := 0; i < len(raw); i++ {
		switch raw[i] {
		case '\'':
			parsed = true
			i++
			closed := false
			for i < len(raw) {
				if raw[i] != '\'' {
					buf.WriteByte(raw[i])
					i++
					continue
				}
				if i+1 < len(raw) && raw[i+1] == '\'' {
					buf.WriteByte('\'')
					i += 2
					continue
				}
				closed = true
				break
			}
			if !closed {
				return nil, fmt.Errorf("unbalanced quote in %q", raw)
			}
		case ' ', '\t', '\n', '\r':
			if parsed {
				parsed = false
				args = append(args, buf.String())
				buf.Reset()
			}
		default:
			parsed = true
			buf.WriteByte(raw[i])
		}
	}
	if parsed {
		args = append(args, buf.String())
	}
	return args, nil
}

// joinArgsV1 is ArgList::GetArgsStringV1Raw: the arguments separated by one
// space each. The arguments came from a whitespace split, so none of them can
// contain the whitespace that would make this unrepresentable.
func joinArgsV1(args []string) string {
	return strings.Join(args, " ")
}

// joinArgsV2 is join_args(): each argument appended, with the characters that
// would otherwise split it wrapped in single quotes. A quoted run is extended
// rather than reopened, so adjacent special characters produce one quoted
// section instead of a repeated quote.
func joinArgsV2(args []string) string {
	var result strings.Builder
	for _, arg := range args {
		if result.Len() > 0 {
			result.WriteByte(' ')
		}
		if arg == "" {
			result.WriteString("''")
			continue
		}
		for i := 0; i < len(arg); i++ {
			c := arg[i]
			if c != ' ' && c != '\t' && c != '\n' && c != '\r' && c != '\'' {
				result.WriteByte(c)
				continue
			}
			if s := result.String(); len(s) > 0 && s[len(s)-1] == '\'' {
				// Combine with the quoted section that just ended rather
				// than opening a second one.
				trimmed := s[:len(s)-1]
				result.Reset()
				result.WriteString(trimmed)
			} else {
				result.WriteByte('\'')
			}
			if c == '\'' {
				result.WriteByte('\'') // repeated to escape it
			}
			result.WriteByte(c)
			result.WriteByte('\'')
		}
	}
	return result.String()
}

// setEnvironment sets the environment attribute.
//
// The submit-file value and the job-ad value are not the same string, and
// storing one as the other loses the environment silently -- the job runs,
// with variables named things like `"PATH`.
//
// HTCondor reads the ad with Env::MergeFrom (condor_utils/env.cpp): the
// `Environment` attribute is parsed as V2 RAW, and `Env` as V1. Neither
// accepts the surrounding double quotes that mark the V2 form in a SUBMIT
// FILE. So `environment = "A=1 B=2"` has to reach the ad as `A=1 B=2`,
// with the doubled `""` escapes collapsed; and the unquoted legacy form
// belongs under `Env`, where the delimiter is auto-detected, rather than
// under `Environment`, where a `;`-separated list would become one
// variable whose value contains the rest.
func (sf *SubmitFile) setEnvironment(ad *classad.ClassAd) error {
	env, ok := sf.submitCommand("environment")
	if !ok {
		env, ok = sf.submitCommand("env")
	}
	if !ok || env == "" {
		return nil
	}

	if raw, isV2 := envV2Raw(env); isV2 {
		_ = ad.Set("Environment", raw)
		return nil
	}
	_ = ad.Set("Env", env)
	return nil
}

// envV2Raw converts the submit file's V2 environment form -- the whole
// list wrapped in double quotes, with `""` standing for a literal quote --
// into the V2 raw form the job ad carries. Reports false for anything that
// is not in the V2 form.
func envV2Raw(env string) (string, bool) {
	trimmed := strings.TrimSpace(env)
	if len(trimmed) < 2 || !strings.HasPrefix(trimmed, `"`) || !strings.HasSuffix(trimmed, `"`) {
		return "", false
	}
	return strings.ReplaceAll(trimmed[1:len(trimmed)-1], `""`, `"`), true
}

// unixNullFile is UNIX_NULL_FILE from the C++ submit code
// (src/condor_includes/condor_constants.h): the name condor_submit
// canonicalizes an unnamed stdin/stdout/stderr to.
const unixNullFile = "/dev/null"

// checkStdFile mirrors SubmitHash::CheckStdFile
// (src/condor_utils/submit_utils.cpp): it canonicalizes the filename a
// submit file gave for one of the standard streams and reports whether
// that stream is still a candidate for transfer.
//
// An absent or empty name, and an explicit /dev/null, are the same
// thing to condor_submit: the file becomes /dev/null and transfer (and
// streaming) is turned off for it. Anything else is transferred.
//
// Leaving the attribute unset instead is not a harmless shorthand for
// "no file". The shadow's file-transfer code only treats a stdout/stderr
// name as "nothing to send back" when it literally reads /dev/null --
// nullFile() in src/condor_utils/nullfile.cpp matches that string, not
// the empty one. With the attribute missing, JobStdoutFile stays "",
// nullFile("") is false, and the FailureFiles seeding in
// file_transfer.cpp (which, unlike the OutputFiles path, has no
// hasJobOutput() guard) queues the empty name. The starter then uploads
// failure files whose list starts with "", which the shadow resolves
// against the sandbox root and walks.
func checkStdFile(value string) (file string, transferIt bool) {
	if value == "" || value == unixNullFile {
		return unixNullFile, false
	}
	return value, true
}

// setStandardFiles sets input, output, and error file attributes.
//
// Each of the three standard streams has two accepted submit-command
// spellings. SetStdin, SetStdout and SetStderr in
// src/condor_utils/submit_utils.cpp read them as
// submit_param(SUBMIT_KEY_Input, SUBMIT_KEY_Stdin) and so on, so
// "stdin", "stdout" and "stderr" name the same files as "input",
// "output" and "error"; see submitCommandAlt for which one wins.
func (sf *SubmitFile) setStandardFiles(ad *classad.ClassAd) error {
	// In/Out/Err are always assigned, even when the submit file names
	// none of them: SetStdin/SetStdout/SetStderr in submit_utils.cpp
	// assign unconditionally, and CheckStdFile has already turned the
	// missing name into /dev/null. The matching Transfer* attribute is
	// written only in the not-transferred case, which is also what the
	// C++ does (it assigns Transfer<X> = false when transfer_it came
	// back false, and otherwise leaves it to the default).
	//
	// Two things can make transfer_it false, and the C++ applies them
	// in this order: the transfer_input / transfer_output /
	// transfer_error submit command, read first, and then CheckStdFile,
	// which forces it off for a stream whose file is the null file
	// whatever the submit command said.
	for _, std := range stdioStreams {
		value, _ := sf.submitCommandAlt(std.fileCmd, std.altFileCmd)
		file, transferIt := checkStdFile(value)
		if !sf.stdioTransferIt(std.transferCmd) {
			transferIt = false
		}
		_ = ad.Set(std.fileAttr, file)
		if !transferIt {
			_ = ad.Set(std.transferAttr, false)
		}
	}

	// The three standard streams keep the name as written:
	// SetStdin/SetStdout/SetStderr do no path resolution and the starter
	// resolves the name in the sandbox. The user log is the opposite --
	// a file-role keyword (f_logfile) in the simple-keyword table, which
	// resolves it against Iwd -- and is written there, not here.

	return nil
}

// stdioStreams names, for each of the three standard streams, the submit
// commands that describe it and the job attributes it is written to.
var stdioStreams = []struct {
	fileCmd      string // submit command: input / output / error
	altFileCmd   string // its second accepted spelling: stdin / stdout / stderr
	transferCmd  string // submit command: transfer_input / transfer_output / transfer_error
	streamCmd    string // submit command: stream_input / stream_output / stream_error
	fileAttr     string // job attribute holding the filename
	transferAttr string // job attribute written when the stream is not transferred
	streamAttr   string // job attribute written for the streaming choice
}{
	{"input", "stdin", "transfer_input", "stream_input", "In", "TransferIn", "StreamIn"},
	{"output", "stdout", "transfer_output", "stream_output", "Out", "TransferOut", "StreamOut"},
	{"error", "stderr", "transfer_error", "stream_error", "Err", "TransferErr", "StreamErr"},
}

// stdioTransferIt reports whether the submit file leaves the standard
// stream governed by transferCmd eligible for transfer.
//
// condor_submit carries this as the transfer_it flag in
// SetStdin/SetStdout/SetStderr (src/condor_utils/submit_utils.cpp). It
// starts true and the transfer_input / transfer_output / transfer_error
// submit command can turn it off. When it is off the job ad gets
// Transfer<X> = false and the matching Stream<X> assignment is skipped
// entirely -- that assignment sits behind "if (transfer_it)" -- so a
// stream the submit file both asks to stream and asks not to transfer
// carries no streaming attribute at all.
//
// The other route to transfer_it == false is checkStdFile, which turns
// it off for a stream whose file is the null file; the caller applies
// that one after this.
func (sf *SubmitFile) stdioTransferIt(transferCmd string) bool {
	value, ok := sf.submitCommand(transferCmd)
	if !ok {
		return true
	}
	return parseBool(value, true)
}

// shouldTransferFiles is ShouldTransferFiles_t from
// src/condor_utils/enum_utils.h.
type shouldTransferFiles int

const (
	stfNo shouldTransferFiles = iota + 1
	stfYes
	stfIfNeeded
)

// fileTransferOutput is FileTransferOutput_t from the same header.
type fileTransferOutput int

const (
	ftoNone fileTransferOutput = iota
	ftoOnExit
	ftoOnExitOrEvict
	ftoOnSuccess
)

// The two translation tables, in HTCondor's order
// (src/condor_utils/enum_utils.cpp). Order is load-bearing twice over:
// a name is matched case-insensitively against the first row that has it,
// and the canonical spelling written to the job ad is the FIRST row
// carrying the value, which is how `should_transfer_files = always`
// reaches the ad as "YES" and `when_to_transfer_output = ONEXIT` as
// "ON_EXIT".
var shouldTransferFilesTable = []struct {
	name string
	val  shouldTransferFiles
}{
	{"YES", stfYes}, {"TRUE", stfYes}, {"ALWAYS", stfYes},
	{"NO", stfNo}, {"FALSE", stfNo}, {"NEVER", stfNo},
	{"IF_NEEDED", stfIfNeeded}, {"AUTO", stfIfNeeded},
}

var fileTransferOutputTable = []struct {
	name string
	val  fileTransferOutput
}{
	{"ON_EXIT_OR_EVICT", ftoOnExitOrEvict}, {"ALWAYS", ftoOnExitOrEvict},
	{"ON_EXIT", ftoOnExit}, {"ONEXIT", ftoOnExit},
	{"NONE", ftoNone}, {"NULL", ftoNone},
	{"ON_SUCCESS", ftoOnSuccess}, {"ONSUCCESS", ftoOnSuccess},
	// These eight are the whole set. condor_submit also answers for a
	// few names that are not in its table -- NEVER and FALSE among them
	// -- but not consistently: its translation tables are arrays of
	// fixed-size structs terminated by an entry whose name is empty,
	// FileTransferOutputTranslation has no such entry, and the lookup
	// walks off the end into whatever the build laid out after it. The
	// answer differs between HTCondor versions in both directions:
	// 25.14.1 reads NEVER as a value that CONTRADICTS
	// should_transfer_files = NO, and 26.2.0 reads it as the value that
	// AGREES with it, so each version rejects the file the other
	// accepts. There is no behavior here to mirror, so these names are
	// rejected like any other unknown value.
}

func shouldTransferFilesNum(s string) (shouldTransferFiles, bool) {
	for _, row := range shouldTransferFilesTable {
		if strings.EqualFold(row.name, s) {
			return row.val, true
		}
	}
	return 0, false
}

func shouldTransferFilesName(v shouldTransferFiles) string {
	for _, row := range shouldTransferFilesTable {
		if row.val == v {
			return row.name
		}
	}
	return ""
}

func fileTransferOutputNum(s string) (fileTransferOutput, bool) {
	for _, row := range fileTransferOutputTable {
		if strings.EqualFold(row.name, s) {
			return row.val, true
		}
	}
	return 0, false
}

func fileTransferOutputName(v fileTransferOutput) string {
	for _, row := range fileTransferOutputTable {
		if row.val == v {
			return row.name
		}
	}
	return ""
}

// vmCheckpoint and vmNetworking report the two VM flags that decide a VM
// job's file transfer settings.
//
// Both are read with the submit keyword first and the attribute name
// second, the way SetUniverse reads them
// (submit_param_bool(SUBMIT_KEY_VM_Checkpoint, ATTR_JOB_VM_CHECKPOINT,
// false)). They are shared by the transfer override below and by
// setVMParams so that the flag the override acts on and the flag the job
// ad records can never disagree.
func (sf *SubmitFile) vmCheckpoint() bool {
	v, ok := sf.submitCommandAlt("vm_checkpoint", "JobVMCheckpoint")
	return ok && parseBool(v, false)
}

func (sf *SubmitFile) vmNetworking() bool {
	v, ok := sf.submitCommandAlt("vm_networking", "JobVMNetworking")
	return ok && parseBool(v, false)
}

// resolveVMTransferMode applies the file transfer settings SetUniverse
// forces on a vm universe job, discarding whatever the submit file asked
// for.
//
// A VM job always transfers files, whatever should_transfer_files says:
// the snapshot disks a vmware job writes, and vm_cdrom_files, have to
// come back to the submit machine, and there is nowhere else for them to
// go. SetUniverse does this by writing YES and the matching
// when_to_transfer_output back into the submit macros before
// SetTransferFiles ever reads them, so the override is total -- a VM job
// with `should_transfer_files = NO` gets YES, and a VM job with a
// should_transfer_files or when_to_transfer_output value that would be a
// hard error in any other universe is accepted, because the bad value is
// overwritten before anything validates it.
//
// This is not the recorded ShouldTransferFiles DEFAULT divergence. That
// one is about what a silent submit file gets; this is a universe
// overriding what the submit file actually said.
//
// The one thing the submitter still controls is the checkpoint case.
// vm_checkpoint asks for ON_EXIT_OR_EVICT so the checkpointed image is
// written out on eviction; vm_networking alongside it is accepted only
// when the file asked for ON_EXIT_OR_EVICT itself, which is condor's way
// of making the submitter acknowledge that the two interact.
func (sf *SubmitFile) resolveVMTransferMode() (shouldTransferFiles, fileTransferOutput, error) {
	if !sf.vmCheckpoint() {
		return stfYes, ftoOnExit, nil
	}
	if sf.vmNetworking() {
		// Read before the override, so this sees what the submitter
		// wrote rather than what SetUniverse is about to write. An
		// absent or unparsable value fails the check just as a wrong
		// one does.
		raw, ok := sf.submitCommandAlt("WhenToTransferOutput", "when_to_transfer_output")
		v, valid := fileTransferOutputNum(raw)
		if !ok || !valid || v != ftoOnExitOrEvict {
			return 0, 0, fmt.Errorf("vm_checkpoint and vm_networking together require an explicit when_to_transfer_output = ON_EXIT_OR_EVICT")
		}
	}
	return stfYes, ftoOnExitOrEvict, nil
}

// resolveTransferMode decides should_transfer_files and
// when_to_transfer_output together, the way SubmitHash::SetTransferFiles
// does (src/condor_utils/submit_utils.cpp).
//
// They are one decision, not two. Each defaults to a value that makes
// sense only in the light of the other, each can be written with several
// spellings that collapse onto a handful of values, and four combinations
// are contradictory enough that condor_submit refuses the file rather
// than guess. Treating them as independent strings -- which is what the
// Go parser did -- let a job reach the schedd saying both that it does
// not transfer files and that it transfers them on exit.
//
// Both are read attribute-name-first: SetTransferFiles asks for
// submit_param(ATTR_SHOULD_TRANSFER_FILES, SUBMIT_KEY_ShouldTransferFiles),
// so `ShouldTransferFiles` in the submit file outranks
// `should_transfer_files`.
//
// inFilesSpecified and outFilesSpecified are SetTransferFiles'
// in_files_specified / out_files_specified: they only matter for the
// should_transfer_files = NO check at the end.
//
// The DEFAULT for should_transfer_files is deliberately left as this
// package has always had it (YES, where condor_submit uses IF_NEEDED);
// changing it changes which machines a job matches on a shared-filesystem
// pool, and that decision is not this function's to make. Everything
// else here follows condor_submit, and the default feeds the same
// "did the submitter choose this?" flag the C++ keeps, so the
// interactions below behave identically either way.
func (sf *SubmitFile) resolveTransferMode(inFilesSpecified, outFilesSpecified bool) (shouldTransferFiles, fileTransferOutput, error) {
	// A vm universe job never gets this far in condor_submit: SetUniverse
	// has already overwritten both settings, so none of the reading,
	// canonicalizing or checking below ever sees what the file wrote.
	if sf.universe == UniverseVM {
		return sf.resolveVMTransferMode()
	}

	should := stfYes
	defaultShould := true
	if raw, ok := sf.submitCommandAlt("ShouldTransferFiles", "should_transfer_files"); ok {
		v, valid := shouldTransferFilesNum(raw)
		if !valid {
			return 0, 0, fmt.Errorf("invalid value (%s) for ShouldTransferFiles: specify YES, NO, or IF_NEEDED", raw)
		}
		should = v
		defaultShould = false
	}

	if should == stfNo && (inFilesSpecified || outFilesSpecified) {
		return 0, 0, fmt.Errorf("transfer_input_files/transfer_output_files name files to transfer, but should_transfer_files is NO")
	}

	when := ftoOnExit
	defaultWhen := true
	if raw, ok := sf.submitCommandAlt("WhenToTransferOutput", "when_to_transfer_output"); ok {
		v, valid := fileTransferOutputNum(raw)
		if !valid {
			return 0, 0, fmt.Errorf("invalid value (%s) for WhenToTransferOutput: specify ON_EXIT or ON_EXIT_OR_EVICT", raw)
		}
		when = v
		defaultWhen = false
	}

	// A file that turned transfer off and said nothing about when gets
	// the consistent answer rather than the contradiction below.
	if !defaultShould && defaultWhen && should == stfNo {
		when = ftoNone
	}

	if (should == stfNo) != (when == ftoNone) {
		return 0, 0, fmt.Errorf("WhenToTransferOutput specified as %s yet ShouldTransferFiles defined as %s",
			fileTransferOutputName(when), shouldTransferFilesName(should))
	}

	// ON_EXIT_OR_EVICT cannot work with IF_NEEDED, so a submitter who
	// asked for the first and left the second alone gets YES.
	if defaultShould && when == ftoOnExitOrEvict && should == stfIfNeeded {
		should = stfYes
	}
	if when == ftoOnExitOrEvict && should == stfIfNeeded {
		return 0, 0, fmt.Errorf(`"when_to_transfer_output = ON_EXIT_OR_EVICT" and "should_transfer_files = IF_NEEDED" are incompatible`)
	}

	return should, when, nil
}

// setFileTransfer sets file transfer related attributes
func (sf *SubmitFile) setFileTransfer(ad *classad.ClassAd) error {
	// transfer_input_files - parse comma-separated list.
	//
	// Empty stays unset, unlike transfer_output_files below. That
	// asymmetry is condor's, not ours: `transfer_input_files = ""`
	// emits no TransferInput attribute at all, while
	// `transfer_output_files = ""` emits TransferOutput = "".
	//
	// Both lists answer to a second spelling, the attribute's own name.
	// SetTransferFiles reads them as submit_param(SUBMIT_KEY_Transfer-
	// InputFiles, SUBMIT_KEY_TransferInputFilesAlt), and the alternate is
	// literally "TransferInputFiles" (submit_utils.h). A submit file
	// using that spelling named files condor_submit transfers and the Go
	// parser did not, so the job ran without them.
	inFiles, inSpecified := sf.submitCommandAlt("transfer_input_files", "TransferInputFiles")
	inFileList := parseFileList(inFiles)
	// in_files_specified in SetTransferFiles is "the list had entries",
	// not "the command was present": an empty list leaves it false.
	inSpecified = inSpecified && len(inFileList) > 0

	outFiles, outSpecified := sf.submitCommandAlt("transfer_output_files", "TransferOutputFiles")

	should, when, err := sf.resolveTransferMode(inSpecified, outSpecified)
	if err != nil {
		return err
	}
	_ = ad.Set("ShouldTransferFiles", shouldTransferFilesName(should))
	// WhenToTransferOutput is written only when the job might transfer.
	// With should_transfer_files = NO condor_submit leaves the attribute
	// off entirely; writing "ON_EXIT" there describes a job that
	// transfers output, which is the opposite of what the file asked for.
	if should != stfNo {
		_ = ad.Set("WhenToTransferOutput", fileTransferOutputName(when))
	}

	// A container job's image is an input file like any other: once
	// condor_submit decides to transfer it, it goes on the end of this
	// list, after whatever the submit file named. Without it the job
	// reaches the execute node with no image to run.
	imageAdded, err := sf.processContainerInputFiles(ad, &inFileList)
	if err != nil {
		return err
	}

	// A tool daemon's binary is an input file too, and so is the file it
	// reads. SetTransferFiles adds ToolDaemonCmd and ToolDaemonInput to the
	// list it is about to write, so a job that asked to run under strace
	// reaches the execute node with strace in its sandbox; without them the
	// starter has a ToolDaemonCmd naming a path that is not there.
	//
	// condor_submit reads them off the job ad, because SetTDP runs first
	// (the order-dependency list at the top of submit_utils.cpp says
	// "SetTDP >> SetTransferFiles"). Here the TDP family is written after
	// this point, so the keywords are read instead -- setToolDaemon stores
	// them verbatim, so it is the same value either way.
	sf.addToolDaemonInputFiles(&inFileList, should)

	if inSpecified || imageAdded {
		// Join with commas for ClassAd string list format
		_ = ad.Set("TransferInput", strings.Join(inFileList, ","))
	}

	// transfer_output_files - parse comma-separated list.
	//
	// An explicitly empty list is set, not skipped: condor_submit emits
	// TransferOutput = "" for `transfer_output_files = ""` and the shadow
	// reads that as "transfer nothing". Leaving the attribute off instead
	// means the default -- transfer every new file in the scratch
	// directory -- which is the opposite of what the user asked for, and
	// for a job that builds a large artifact it is the difference between
	// transferring nothing and transferring gigabytes.
	//
	// transfer_input_files is deliberately not symmetric here; see above.
	if outSpecified {
		_ = ad.Set("TransferOutput", strings.Join(parseFileList(outFiles), ","))
	}

	// transfer_output_remaps is stored VERBATIM, trimmed and with one layer
	// of surrounding quotes taken off (trim_and_strip_quotes_in_place), and
	// nothing else. SetTransferFiles does not parse it -- it appends the
	// submitter's text to any remaps condor_submit generated itself -- and
	// the shadow is what splits it, on `;` and `=`, when the job finishes.
	//
	// Parsing and rebuilding it here did two things wrong. It dropped the
	// spaces around the separators, so a remap the submitter wrote as
	// `out.txt = final.txt` came out `out.txt=final.txt`; and it went
	// through a MAP, so two or more remaps came out in Go's map iteration
	// order -- a different attribute value run to run from one submit file.
	if tor, ok := sf.simpleKeywordParam("transfer_output_remaps", "TransferOutputRemaps"); ok {
		if remaps := trimAndStripSubmitQuotes(tor); remaps != "" {
			_ = ad.Set("TransferOutputRemaps", remaps)
		}
	}

	// output_destination - a URL the sandbox's output is written to
	// instead of being sent back to the submit machine.
	//
	// Stored exactly as written, quotes included: it is an f_as_string
	// keyword in SubmitHash's table, and `output_destination =
	// "https://x/y"` reaches the job ad with the quotes still on it --
	// which is also why that spelling leaves the value looking like no
	// URL at all and contributes no transfer-plugin method.
	if dest, ok := sf.submitCommand("output_destination"); ok {
		_ = ad.Set("OutputDestination", dest)
	}

	// transfer_executable
	transferExec := true
	if te, ok := sf.submitCommand("transfer_executable"); ok {
		transferExec = parseBool(te, true)
	}
	_ = ad.Set("TransferExecutable", transferExec)

	// skip_filechecks - don't check if input files exist
	if sfc, ok := sf.submitCommand("skip_filechecks"); ok {
		_ = ad.Set("SkipFileChecks", parseBool(sfc, false))
	}

	return nil
}

// setContainerSettings sets container/docker related attributes
func (sf *SubmitFile) setContainerSettings(ad *classad.ClassAd) error {
	// Whether this is a docker job, a container job or neither decides
	// every attribute below, and nothing below is written for a job
	// that is neither. The two runtimes must not be conflated: the
	// starter selects the proc from the WantDocker / WantContainer flag
	// (starter.cpp LookupBool), so a job that set an image but no
	// want-flag would silently run as a plain vanilla job.
	//
	// WantDocker marks the DOCKER UNIVERSE and nothing else: it is the
	// flag the docker starter reads, and `universe = docker` is the only
	// way to get it. docker_image on its own does NOT mean a docker
	// job -- condor_submit treats any image keyword outside that
	// universe as an implicit CONTAINER job, so it writes WantContainer
	// together with WantDockerImage, the image-kind flag. A job marked
	// WantDocker instead is asking for a docker execute node rather than
	// a container one, and on an Apptainer-only pool (the OSPool norm)
	// it matches nothing.
	isDocker, isContainer, err := sf.containerJobRoles()
	if err != nil {
		return err
	}
	if err := sf.setContainerImages(ad, isDocker, isContainer); err != nil {
		return err
	}

	// container_network. docker_network_type writes the same attribute
	// through the simple-keyword table; this spelling is not one of
	// HTCondor's keywords.
	if network, ok := sf.submitCommand("container_network"); ok {
		_ = ad.Set("DockerNetworkType", network)
	}

	// docker_volumes or container_volumes - comma-separated list
	if volumes, ok := sf.submitCommand("docker_volumes"); ok {
		volList := parseFileList(volumes)
		if len(volList) > 0 {
			_ = ad.Set("DockerVolumes", strings.Join(volList, ","))
		}
	} else if volumes, ok := sf.submitCommand("container_volumes"); ok {
		volList := parseFileList(volumes)
		if len(volList) > 0 {
			_ = ad.Set("DockerVolumes", strings.Join(volList, ","))
		}
	}

	// container_service_names, and the port each service listens on.
	if err := sf.setContainerServices(ad, isDocker, isContainer); err != nil {
		return err
	}

	// require_container - force use of container
	if rc, ok := sf.submitCommand("require_container"); ok {
		_ = ad.Set("RequireContainer", parseBool(rc, false))
	}

	// docker_mount_volumes. mount_under_scratch is a keyword of its own
	// and goes through the simple-keyword table, which keeps it a string.
	if mv, ok := sf.submitCommand("docker_mount_volumes"); ok {
		_ = ad.Set("DockerMountVolumes", parseBool(mv, true))
	}

	// container_image_sha256
	if sha, ok := sf.submitCommand("container_image_sha256"); ok {
		_ = ad.Set("ContainerImageSHA256", sha)
	}

	return nil
}

// isDockerUniverse reports whether the submit file asked for
// `universe = docker`, the one case that gets WantDocker. parseUniverse
// has already folded it into VANILLA by the time the ad is built, so the
// spelling is the only thing left to read it from.
func (sf *SubmitFile) isDockerUniverse() bool {
	univ, ok := sf.submitCommand("universe")
	return ok && strings.EqualFold(strings.TrimSpace(univ), "docker")
}

// containerImageCapability returns the TARGET capability a container
// image's execute node must advertise, classifying the image the way
// HTCondor's image_type_from_string does: a "docker:" repo needs
// HasDockerURL, a ".sif" file needs HasSIF, and anything else (a sandbox
// directory) needs HasSandboxImage.
func containerImageCapability(image string) string {
	_, capability := containerImageKind(image)
	return capability
}

// containerImageKind classifies a container_image the way HTCondor's
// image_type_from_string does, returning both the job attribute that
// enables the runtime for that image kind (WantDockerImage / WantSIF /
// WantSandboxImage) and the execute-node capability the job must require
// (HasDockerURL / HasSIF / HasSandboxImage).
//
// The wantAttr is load-bearing, not cosmetic: the starter's
// Singularity::job_enabled turns the Apptainer/Singularity runtime on
// ONLY when one of WantDockerImage/WantSIF/WantSandboxImage is set (or
// SINGULARITY_JOB is configured). Setting ContainerImage + WantContainer
// alone leaves an Apptainer-only execute node (the OSPool/CHTC norm)
// running the job on bare metal.
func containerImageKind(image string) (wantAttr, capability string) {
	img := strings.TrimSpace(image)
	switch {
	case strings.HasPrefix(img, "docker:"):
		return "WantDockerImage", "TARGET.HasDockerURL =?= true"
	case strings.HasSuffix(img, ".sif"):
		return "WantSIF", "TARGET.HasSIF =?= true"
	default:
		return "WantSandboxImage", "TARGET.HasSandboxImage =?= true"
	}
}

// setRequirements sets the Requirements expression
func (sf *SubmitFile) setRequirements(ad *classad.ClassAd) error {
	var reqParts []string

	// Start with user-specified requirements
	if req, ok := sf.submitCommand("requirements"); ok {
		reqParts = append(reqParts, "("+req+")")
	}

	// A scheduler- or local-universe job is never matched to a machine.
	// The schedd evaluates its Requirements against the SCHEDD's own ad
	// (Scheduler::jobCanRun, condor_schedd.V6/schedd.cpp: EvalBool with the
	// job as MY and scheduler.publish()'s ad as TARGET), and undefined is
	// treated as false.
	//
	// That ad is not empty: Scheduler::publish assigns Arch, OpSys,
	// OpSysVer, Memory, Disk and Cpus, so TARGET.Arch and friends would
	// actually resolve. What it does NOT assign is HasFileTransfer -- and
	// that is the clause that silently killed the job: the transfer clause
	// evaluated to undefined, Requirements went false, and the job sat Idle
	// forever with nothing in the log but "SchedUniverseJobsIdle = 1".
	// FileSystemDomain and the GPU attributes are absent from the schedd ad
	// too.
	//
	// condor_submit does not add the transfer clauses for these universes
	// either. SetRequirements (condor_utils/submit_utils.cpp) has no early
	// return; the HasFileTransfer / FileSystemDomain / per-file-encryption
	// clauses are gated on mightTransfer(JobUniverse), which is true only
	// for vanilla, mpi, parallel, java and vm.
	//
	// Dropping the rest of the machine clauses as well (Arch, OpSys,
	// Memory, Disk) goes further than condor_submit does, and is safe: a
	// job that is never matched has no use for them, and jobCanRun skips
	// the Requirements check entirely when the attribute is absent. What
	// the user wrote in `requirements` is kept, since that IS evaluated.
	if sf.universe == UniverseScheduler || sf.universe == UniverseLocal {
		return sf.finishRequirements(ad, reqParts)
	}

	// Add TARGET.OpSys check for non-grid jobs
	if sf.universe != UniverseGrid {
		// Target type requirement - must be a machine (not another job, etc.)
		reqParts = append(reqParts, "(TARGET.Arch =!= UNDEFINED)")
		reqParts = append(reqParts, "(TARGET.OpSys =!= UNDEFINED)")
	}

	// The resource clauses each name a request attribute, so each is
	// added only when the job will carry that attribute: a clause over
	// an attribute left unset ("undefined") is itself undefined, and a
	// job whose Requirements is undefined matches nothing.

	// Add TARGET.Disk check if we're transferring files
	if stf, ok := sf.submitCommand("should_transfer_files"); ok {
		if _, disk := sf.requestValue("request_disk"); disk && strings.ToUpper(stf) == "YES" {
			reqParts = append(reqParts, "(TARGET.Disk >= RequestDisk)")
		}
	}

	// Add memory requirement check if specified
	if v, ok := sf.submitCommand("request_memory"); ok && !isUndefinedRequest(v) {
		reqParts = append(reqParts, "(TARGET.Memory >= RequestMemory)")
	}

	// Add CPU requirement check if specified
	if v, ok := sf.submitCommand("request_cpus"); ok && !isUndefinedRequest(v) {
		reqParts = append(reqParts, "(TARGET.Cpus >= RequestCpus)")
	}

	// Add the GPU requirement for a GPU request, the configured default
	// included: a job that asks for GPUs because the site said every job
	// does must not land on a slot without one.
	if reqGpus, ok := sf.requestValue("request_gpus"); ok {
		if intGpus, err := parseInt(reqGpus); err == nil && intGpus > 0 {
			reqParts = append(reqParts, "(TARGET.Gpus >= RequestGpus)")
		}
	}

	// Add specific OpSys requirement if specified
	if reqOpsys, ok := sf.submitCommand("request_opsys"); ok {
		reqParts = append(reqParts, fmt.Sprintf("(TARGET.OpSys == %q)", reqOpsys))
	}

	// Add specific Arch requirement if specified
	if reqArch, ok := sf.submitCommand("request_arch"); ok {
		reqParts = append(reqParts, fmt.Sprintf("(TARGET.Arch == %q)", reqArch))
	}

	// Add the container/docker requirement, mirroring HTCondor's
	// submit_utils.cpp SetRequirements. A docker job needs HasDocker; a
	// container job needs HasContainer AND the capability for the image
	// kind (HasDockerURL / HasSIF / HasSandboxImage). The container form
	// is runtime-agnostic on purpose -- a node with Apptainer that can
	// pull a docker repo advertises HasDockerURL -- so it is not pinned
	// to Docker (or to Singularity/Apptainer specifically).
	if _, ok := sf.submitCommand("docker_image"); ok {
		reqParts = append(reqParts, "(TARGET.HasDocker =?= true)")
	} else if img, ok := sf.submitCommand("container_image"); ok {
		reqParts = append(reqParts, "(TARGET.HasContainer =?= true && "+containerImageCapability(img)+")")
	}

	// Require container support if explicitly requested.
	if rc, ok := sf.submitCommand("require_container"); ok {
		if parseBool(rc, false) {
			reqParts = append(reqParts, "(TARGET.HasContainer =?= true)")
		}
	}

	// Add file system domain requirements
	if fsDomain, ok := sf.submitCommand("file_system_domain"); ok {
		reqParts = append(reqParts, fmt.Sprintf("(TARGET.FileSystemDomain == %q)", fsDomain))
	}

	// Add HasFileTransfer requirement if needed
	if stf, ok := sf.submitCommand("should_transfer_files"); ok {
		if strings.ToUpper(stf) == "YES" {
			reqParts = append(reqParts, "(TARGET.HasFileTransfer)")
		}
	}

	return sf.finishRequirements(ad, reqParts)
}

// finishRequirements joins the collected clauses and sets Requirements.
// Split out so the universes that take none of the machine-oriented
// clauses share the one place that writes the attribute.
func (sf *SubmitFile) finishRequirements(ad *classad.ClassAd, reqParts []string) error {
	if len(reqParts) == 0 {
		// Nothing to require -- a scheduler- or local-universe job that
		// named no requirements of its own. Set TRUE rather than leaving
		// the attribute off.
		//
		// The distinction matters outside matchmaking. A schedd can carry
		// SUBMIT_REQUIREMENT_<name> expressions that reference the job's
		// Requirements, and an absent attribute makes those evaluate to
		// undefined rather than false. The OSPool access point has one:
		//
		//     SUBMIT_REQUIREMENT_ModulesWarning = ! unresolved(Requirements, "HAS_MODULES")
		//
		// With no Requirements attribute that is `! undefined`, which is
		// not a boolean, and the schedd refuses the whole transaction --
		// "CommitTransaction failed: Submit requirement ModulesWarning
		// evaluated to non-boolean". Every DAGMan submission to such an
		// access point failed, because the manager job is exactly the
		// case that reaches here with nothing to require.
		//
		// condor_submit never produces a job without Requirements; its
		// SetRequirements always assigns the attribute. Writing TRUE is
		// the honest equivalent for a universe that is never matched to a
		// machine, and it cannot change what the job matches: the schedd
		// skips the check when it is absent and passes it when it is TRUE.
		trueExpr, err := classad.ParseExpr("true")
		if err != nil {
			return fmt.Errorf("failed to parse the default requirements expression: %w", err)
		}
		_ = ad.Set("Requirements", trueExpr)
		return nil
	}

	requirements := strings.Join(reqParts, " && ")
	// Requirements is an expression, not a string - parse it
	reqExpr, err := classad.ParseExpr(requirements)
	if err != nil {
		return fmt.Errorf("failed to parse requirements expression: %w", err)
	}
	_ = ad.Set("Requirements", reqExpr)

	return nil
}

// setExprAttr stores a submit command whose value is a ClassAd expression,
// not a string.
//
// The job policy evaluator does not coerce. user_job_policy.cpp
// (AnalyzePolicy, ~lines 415-427) evaluates each policy expression and
// requires the result to be a number; anything else -- including a string
// that happens to read "ExitCode == 0" -- is not a boolean, so the
// expression is treated as unsatisfied and evaluation falls through to the
// default action. For on_exit_remove that default is REMOVE, which is
// exactly backwards: a DAGMan job that should have been requeued after an
// abnormal exit was removed from the queue instead. Storing these as
// strings is therefore not a cosmetic difference; it inverts the policy.
//
// A blank value means the command was not really given (condor_submit sets
// no attribute in that case), so nothing is stored. A value that does not
// parse is an error rather than a silently stored string.
func setExprAttr(ad *classad.ClassAd, attr, command, value string) error {
	value = strings.TrimSpace(value)
	if value == "" {
		return nil
	}
	expr, err := classad.ParseExpr(value)
	if err != nil {
		return fmt.Errorf("%s: %q is not a valid ClassAd expression: %w", command, value, err)
	}
	_ = ad.Set(attr, expr)
	return nil
}

// canonicalConcurrencyLimits renders a concurrency_limits value the way
// SubmitHash::SetConcurrencyLimits stores it: lower-cased, split on
// HTCondor's list separators (comma, space, tab, CR, LF) with the items
// trimmed, sorted, and rejoined with commas.
//
// Canonicalizing matters because the negotiator looks the names up
// literally -- "A, b" and "a,b" are two different sets of keys, and a
// job whose limits are spelled differently from the configuration's
// consumes nothing and is throttled by nothing.
func canonicalConcurrencyLimits(value string) string {
	items := strings.FieldsFunc(strings.ToLower(value), func(r rune) bool {
		return r == ',' || r == ' ' || r == '\t' || r == '\r' || r == '\n'
	})
	if len(items) == 0 {
		return ""
	}
	sort.Strings(items)
	return strings.Join(items, ",")
}

// setResourceRequests sets the request_* attributes, the way
// condor_submit's SetRequestResources does (condor_utils/submit_utils.cpp).
//
// A request the submit file omits takes the configured default,
// JOB_DEFAULT_REQUEST{CPUS,MEMORY,DISK,GPUS}, processed exactly as if the
// user had written it: a size with an optional unit suffix is scaled to
// the attribute's base unit, anything else is stored as an expression,
// and "undefined" -- written by the user or by the default -- leaves the
// attribute unset. condor_submit applies the defaults only when it is not
// materializing jobs from a cluster ad, because the materialized jobs
// inherit them from that ad; this engine builds every job ad in full,
// SubmitLate included, so each one gets them.
func (sf *SubmitFile) setResourceRequests(ad *classad.ClassAd) error {
	sf.defaultDisk = ""

	// CPUs: a count, so no units -- but it may be an expression, which
	// condor_submit stores unevaluated. A parallel-universe job that
	// names no request_cpus asks for one CPU per node whatever
	// JOB_DEFAULT_REQUESTCPUS says: SetParallelParams assigns 1 before
	// the default is looked at, to keep pre-8.9 behaviour.
	if v, ok := sf.submitCommand("request_cpus"); ok {
		if err := setRequestCount(ad, "RequestCpus", v); err != nil {
			return err
		}
	} else if sf.universe == UniverseParallel {
		_ = ad.Set("RequestCpus", int64(1))
	} else if v, ok := sf.requestDefault("request_cpus"); ok {
		if err := setRequestCount(ad, "RequestCpus", v); err != nil {
			return fmt.Errorf("JOB_DEFAULT_REQUESTCPUS: %w", err)
		}
	}

	// Memory in MiB. A bare number is already in MiB; a K/M/G/T suffix
	// scales from bytes, so request_memory = 4GB is RequestMemory = 4096.
	// A VM job with no request_memory asks for the memory its VM is
	// given, ahead of any configured default, as condor_submit does.
	// setRequestMemory, not setRequestSize: a memory request is the one
	// request that can also carry automatic retry (retry_request_memory
	// and its siblings), which condor_submit reads only once it has a
	// size to grow from. The VM branch deliberately does not: its
	// request is an expression, so there is nothing to grow.
	if v, ok := sf.submitCommand("request_memory"); ok {
		if err := sf.setRequestMemory(ad, v); err != nil {
			return err
		}
	} else if _, vm := sf.submitCommand("vm_memory"); vm && sf.universe == UniverseVM {
		_ = setExprAttr(ad, "RequestMemory", "request_memory", "MY.JobVMMemory")
	} else if v, ok := sf.requestDefault("request_memory"); ok {
		if err := sf.setRequestMemory(ad, v); err != nil {
			return fmt.Errorf("JOB_DEFAULT_REQUESTMEMORY: %w", err)
		}
	}

	// Disk in KiB. Same rule with a KiB base: request_disk = 10GB is
	// RequestDisk = 10485760.
	if v, ok := sf.submitCommand("request_disk"); ok {
		if err := setRequestSize(ad, "RequestDisk", v, unitKiB); err != nil {
			return err
		}
	} else if v, ok := sf.requestDefault("request_disk"); ok {
		if err := setRequestSize(ad, "RequestDisk", v, unitKiB); err != nil {
			return fmt.Errorf("JOB_DEFAULT_REQUESTDISK: %w", err)
		}
		if e, ok := ad.Lookup("RequestDisk"); ok {
			sf.defaultDisk = e.String()
		}
	}

	// GPUs. HTCondor ships no default, so a job that names none asks for
	// none unless the site configured JOB_DEFAULT_REQUESTGPUS.
	if v, ok := sf.submitCommand("request_gpus"); ok {
		if err := setRequestCount(ad, "RequestGpus", v); err != nil {
			return err
		}
	} else if v, ok := sf.requestDefault("request_gpus"); ok {
		if err := setRequestCount(ad, "RequestGpus", v); err != nil {
			return fmt.Errorf("JOB_DEFAULT_REQUESTGPUS: %w", err)
		}
	}

	// GPU memory per device (MiB)
	if gpuMem, ok := sf.submitCommand("request_gpu_memory"); ok {
		if err := setSizeAttr(ad, "RequestGpuMemory", gpuMem, unitMiB); err != nil {
			return err
		}
	}

	// The GPU property constraints, which are read only once the job has
	// asked for a GPU.
	if err := sf.setGPUPropertyConstraints(ad); err != nil {
		return err
	}

	return nil
}

// setRequestSize is setSizeAttr for a request_* command, which also
// accepts "undefined": the request is deliberately left unset.
func setRequestSize(ad *classad.ClassAd, attr, raw string, base int64) error {
	if isUndefinedRequest(raw) {
		return nil
	}
	return setSizeAttr(ad, attr, raw, base)
}

// setRequestCount is setCountAttr with the same "undefined" rule.
func setRequestCount(ad *classad.ClassAd, attr, raw string) error {
	if isUndefinedRequest(raw) {
		return nil
	}
	return setCountAttr(ad, attr, raw)
}

// requestKeywordPrefix is SUBMIT_KEY_RequestPrefix: every submit
// command that asks for a machine resource starts with it.
const requestKeywordPrefix = "request_"

// specialRequestKeywords are the request_<tag> commands that do not
// reach the generic path, lower-cased.
//
// The first six are SubmitHash::is_special_request_resource(): each has
// its own setter, which is why request_cpus is an amount of CPUs in
// RequestCpus and not an expression in RequestCpus the way a custom tag
// would be. request_cpu and request_gpu are there to be caught: they
// are the singular misspellings, and condor_submit warns and sets
// nothing rather than inventing a "Cpu" resource.
//
// The last two are the request_ entries flagged f_error in
// prunable_keywords. They are likely attempts to constrain GPU memory,
// which is gpus_minimum_memory; condor_submit warns and, again, sets
// nothing.
var specialRequestKeywords = map[string]bool{
	"request_cpus":        true,
	"request_cpu":         true,
	"request_gpus":        true,
	"request_gpu":         true,
	"request_disk":        true,
	"request_memory":      true,
	"request_gpu_memory":  true,
	"request_gpus_memory": true,
}

// setCustomResourceRequests sets Request<Tag> for every
// request_<tag> command with no dedicated handling, the way
// SubmitHash::SetRequestResources does in
// src/condor_utils/submit_utils.cpp.
//
// request_<tag> is generic: the attribute name is the literal
// "Request" followed by the command name with "request_" cut off,
// keeping the tag's capitalization exactly as the file wrote it. So
// request_A0 is RequestA0, request_licenses is Requestlicenses (not
// RequestLicenses) and Request_Foo is RequestFoo. That is how a job
// asks for a resource the pool defines itself -- licenses, site slot
// types -- and the startd advertises the matching Target<Tag>.
//
// The value is stored as a ClassAd expression, unevaluated and with no
// unit scaling: request_slots = 2*2 is the expression 2 * 2, and
// "undefined" is the undefined literal rather than an instruction to
// leave the attribute out, which is what it means for request_cpus and
// the other three. A value that is not an expression at all --
// request_foo = 10GB -- is an error, as it is for condor_submit.
//
// A tag shorter than two characters, or one starting with an
// underscore, is not a resource request and is passed over.
func (sf *SubmitFile) setCustomResourceRequests(ad *classad.ClassAd) error {
	upperPrefix := strings.ToUpper(requestKeywordPrefix)
	commands := make([]string, 0, len(sf.assigned))
	for upper, name := range sf.assigned {
		if !strings.HasPrefix(upper, upperPrefix) {
			continue
		}
		if specialRequestKeywords[strings.ToLower(name)] {
			continue
		}
		tag := name[len(requestKeywordPrefix):]
		if len(tag) < 2 || tag[0] == '_' {
			continue
		}
		commands = append(commands, name)
	}
	// Assign in a fixed order so a submit file always builds the same
	// ad; the C++ side walks a hash table, where the order is its own
	// business because no two tags can collide.
	sort.Strings(commands)

	for _, name := range commands {
		value, ok := sf.submitCommand(name)
		if !ok {
			continue
		}
		attr := "Request" + name[len(requestKeywordPrefix):]
		expr, err := classad.ParseExpr(strings.TrimSpace(value))
		if err != nil {
			return fmt.Errorf("%s: %q is not a valid ClassAd expression: %w", name, value, err)
		}
		_ = ad.Set(attr, expr)
	}
	return nil
}

// setRank stores the job's Rank, mirroring SubmitHash::SetRank.
//
// Rank is an EXPRESSION -- the negotiator evaluates it against each
// candidate machine ad -- so `rank = Memory` has to reach the ad as the
// attribute reference Memory, not as the string "Memory". A string is
// truthy nonsense to the matchmaker: it ranks every machine identically
// and silently throws away the submitter's preference. The expression is
// parsed here so an unparsable one is a submit error, which is what
// condor_submit does with it (AssignJobExpr aborts the submission).
//
// `preferences` is the keyword's historical spelling and C++ still reads
// it as the alternate name. An empty value, from either spelling, takes
// the default rather than erroring: submit_param hands SetRank an empty
// string, which it treats as "nothing was said" and falls through to
// AssignJobVal(ATTR_RANK, 0.0).
func (sf *SubmitFile) setRank(ad *classad.ClassAd) error {
	rank, ok := sf.submitCommandAlt("rank", "preferences")
	if ok {
		rank = strings.TrimSpace(rank)
	}
	if !ok || rank == "" {
		_ = ad.Set("Rank", 0.0)
		return nil
	}
	expr, err := classad.ParseExpr(rank)
	if err != nil {
		return fmt.Errorf("rank: %q is not a valid ClassAd expression: %w", rank, err)
	}
	_ = ad.Set("Rank", expr)
	return nil
}

// setOwnership sets owner and accounting attributes, mirroring
// SubmitHash::SetAccountingGroup in src/condor_utils/submit_utils.cpp.
//
// The attribute the accountant reads is AccountingGroup, and it reads it
// as "<group>.<user>": a value with no dot in it is a submitter ALIAS,
// not a group, so storing `accounting_group = Proj` verbatim charges a
// submitter named Proj rather than the group's quota. The group is
// therefore always completed with a user -- accounting_group_user when
// the file gives one, otherwise the submitting account. Nothing here
// looks for a dot already in the group: HTCondor appends regardless, so
// `accounting_group = Proj.bob` charges "Proj.bob.<user>", a nested
// group, and that is the behavior a job gets today.
//
// AcctGroup and AcctGroupUser are written alongside it (HTCondor calls
// them "currently unused", but they are what a job transform or a
// schedd-side policy matches on). accounting_group_user alone, with no
// group, means the submission is charged to that user by name.
func (sf *SubmitFile) setOwnership(ad *classad.ClassAd) error {
	// Owner - do not set a placeholder as this causes a failure
	// instead of being ignored.

	// Every keyword here is read with submit_param(name, attr), so the job
	// ATTRIBUTE's name is an accepted spelling of the submit command:
	// `AccountingGroup = grp` in a submit file is this keyword, not a
	// custom attribute, and `NiceUser = true` is nice_user. Reading only
	// the submit spelling left a file written the other way with no
	// accounting group at all -- and a nice_user job that was not nice.
	if project, ok := sf.simpleKeywordParam("project_name", "ProjectName"); ok {
		_ = ad.Set("ProjectName", project)
	}

	group, hasGroup := sf.simpleKeywordParam("accounting_group", "AccountingGroup")

	// nice_user is shorthand for accounting_group =
	// $(NICE_USER_ACCOUNTING_GROUP_NAME). A nice_user job with no group
	// of its own is charged to that group, which is what makes it
	// preemptable; one that names a group keeps its group and the
	// nice_user flag is ignored.
	if nu, ok := sf.simpleKeywordParam("nice_user", "NiceUser"); ok && parseBool(nu, false) {
		if !hasGroup {
			group, hasGroup = sf.niceUserGroup(), true
		}
		// Backward-compatibility hack from HTCondor: nice_user jobs are
		// preemptable. setJobStatusControl runs after this and lets an
		// explicit max_job_retirement_time overwrite it, which is the
		// order condor_submit uses.
		_ = ad.Set("MaxJobRetirementTime", 0)
	}

	groupUser, hasGroupUser := sf.simpleKeywordParam("accounting_group_user", "AcctGroupUser")
	if !hasGroup && !hasGroupUser {
		return nil
	}
	if !hasGroupUser {
		groupUser = sf.submitUserName()
	}

	_ = ad.Set("AcctGroupUser", groupUser)
	if hasGroup {
		_ = ad.Set("AcctGroup", group)
		_ = ad.Set("AccountingGroup", group+"."+groupUser)
	} else {
		_ = ad.Set("AccountingGroup", groupUser)
	}

	return nil
}

// niceUserGroup is the accounting group a nice_user job is charged to:
// HTCondor's NICE_USER_ACCOUNTING_GROUP_NAME knob, whose built-in
// default is "nice-user".
func (sf *SubmitFile) niceUserGroup() string {
	if sf != nil && sf.params != nil {
		if v, ok := sf.params.Get("NICE_USER_ACCOUNTING_GROUP_NAME"); ok {
			return v
		}
	}
	return "nice-user"
}

// submitUserName is the account the submission is charged to: the
// SubmitUser the parse was given, or the account running the parse,
// which is what condor_submit passes to init_base_ad.
func (sf *SubmitFile) submitUserName() string {
	if sf != nil && sf.submitUser != "" {
		return sf.submitUser
	}
	return localSubmitUser()
}

// localSubmitUser reports the account this process runs as, the way
// condor_submit's my_username() does. Looked up once: it cannot change
// under us, and user.Current may reach NSS.
var localSubmitUser = sync.OnceValue(func() string {
	if u, err := user.Current(); err == nil && u.Username != "" {
		return u.Username
	}
	return os.Getenv("USER")
})

// setJobStatusControl sets job status and control attributes
func (sf *SubmitFile) setJobStatusControl(ad *classad.ClassAd) error {
	// hold - initial hold state
	if hold, ok := sf.submitCommand("hold"); ok {
		if parseBool(hold, false) {
			_ = ad.Set("JobStatus", 5) // 5 = HELD
		}
	}

	// hold_reason - reason for initial hold
	if reason, ok := sf.submitCommand("hold_reason"); ok {
		_ = ad.Set("HoldReason", reason)
		// Set release reason code if not already set
		if _, ok := sf.submitCommand("hold_reason_code"); !ok {
			_ = ad.Set("HoldReasonCode", 1)
		}
	}

	// hold_reason_code
	if code, ok := sf.submitCommand("hold_reason_code"); ok {
		if intCode, err := parseInt(code); err == nil {
			_ = ad.Set("HoldReasonCode", intCode)
		}
	}

	// hold_reason_subcode
	if subcode, ok := sf.submitCommand("hold_reason_subcode"); ok {
		if intSubcode, err := parseInt(subcode); err == nil {
			_ = ad.Set("HoldReasonSubCode", intSubcode)
		}
	}

	// max_retries, retry_until and success_exit_code are not independent
	// settings: each one on its own turns retries on, and the three
	// together decide JobMaxRetries, JobSuccessExitCode and the
	// OnExitRemove expression. setJobRetries builds all of that in one
	// place, after the +Attr pass, because it has to see an OnExitRemove
	// the submitter set directly.

	// leave_in_queue - keep job in queue after completion. Documented as a
	// ClassAd boolean expression, and the schedd evaluates it against the
	// job ad (e.g. `JobStatus == 4 && (time() - CompletionDate) < 864000`),
	// so it cannot go through parseBool: every non-literal expression
	// collapsed to false and the job left the queue immediately.
	if leaveInQueue, ok := sf.submitCommand("leave_in_queue"); ok {
		if err := setExprAttr(ad, "LeaveJobInQueue", "leave_in_queue", leaveInQueue); err != nil {
			return err
		}
	}

	return sf.setConcurrencyLimits(ad)
}

// setConcurrencyLimits records the concurrency limits the job consumes,
// mirroring SubmitHash::SetConcurrencyLimits.
//
// concurrency_limits and concurrency_limits_expr are two spellings of
// ONE attribute, ConcurrencyLimits, which is what the negotiator reads;
// a job that carried them anywhere else consumed no limit and was
// throttled by nothing. The list form is canonicalized -- lower-cased,
// split, sorted, rejoined with commas -- because the negotiator looks
// the names up literally and "A, b" is not the key "a,b". The
// expression form is stored unevaluated, for the negotiator to evaluate
// against the job ad.
//
// The list form wins when both are present, matching condor_submit's
// precedence (which also rejects the file outright).
func (sf *SubmitFile) setConcurrencyLimits(ad *classad.ClassAd) error {
	if concLimits, ok := sf.submitCommand("concurrency_limits"); ok {
		if limits := canonicalConcurrencyLimits(concLimits); limits != "" {
			_ = ad.Set("ConcurrencyLimits", limits)
		}
		return nil
	}
	if concExpr, ok := sf.submitCommand("concurrency_limits_expr"); ok {
		return setExprAttr(ad, "ConcurrencyLimits", "concurrency_limits_expr", concExpr)
	}
	return nil
}

// setCustomAttributes copies the submit file's custom job attributes
// onto the job ad.
//
// Both spellings HTCondor accepts — `+Foo = expr` and `MY.Foo = expr` —
// arrive here under one key, config.CustomAttrPrefix + name, because
// the config executor canonicalizes the `+` form. The prefix is what
// distinguishes "set this attribute on the job" from "this is a submit
// command"; it is stripped on the way into the ad, so the job carries
// `Foo`, which is the name the user wrote and the name they will query
// by.
//
// The value is a ClassAd EXPRESSION, not a string. That is the whole
// point of the syntax: `+Rank = Memory / 1024` has to reach the job as
// arithmetic, `+Tag = "nightly"` as a string, `+Retry = 3` as an
// integer. An earlier version guessed the type by inspecting the text
// — bool, then int, then float, then "contains an operator, call it an
// expression", then string — and got the common case wrong: the quotes
// in `"nightly"` were kept as part of the value, so the job ad ended up
// with Tag = "\"nightly\"". Handing the text to the ClassAd parser
// makes every case the parser's job instead of a heuristic's.
func (sf *SubmitFile) setCustomAttributes(ad *classad.ClassAd) error {
	// Sorted so a submit file with several custom attributes produces
	// the same ad every time; map order would make the result depend on
	// nothing in particular.
	keys := sf.cfg.Keys()
	sort.Strings(keys)

	for _, key := range keys {
		attrName, ok := customAttrName(key)
		if !ok {
			continue
		}

		// Get expands $(...) macros, so $(Cluster), $(Process) and
		// submit-file macros mean what they mean everywhere else.
		value, ok := sf.cfg.Get(key)
		if !ok {
			continue
		}
		value = strings.TrimSpace(value)
		if value == "" {
			// `+Foo =` with nothing after it, or a value that expanded
			// to nothing, sets the attribute to the ClassAd literal
			// `undefined` rather than leaving it off the ad. That is
			// also what submit's `-Foo = <anything>` form does, which
			// is why it is not the inverse of `+Foo`: a job that asked
			// for Foo to be undefined carries Foo, and an expression
			// reading it sees undefined instead of an inherited value
			// from the cluster ad.
			value = "undefined"
		}

		expr, err := classad.ParseExpr(value)
		if err != nil {
			return fmt.Errorf("custom attribute %s: %q is not a valid ClassAd expression: %w", attrName, value, err)
		}
		_ = ad.Set(attrName, expr)
	}

	return nil
}

// customAttrName reports whether a submit-file key names a custom job
// attribute, and if so what the attribute is called.
//
// The comparison is case-insensitive because the config layer is: a
// user who writes `my.foo` or `My.Foo` has written the same key as
// `MY.Foo`, and HTCondor treats all three alike.
func customAttrName(key string) (string, bool) {
	if len(key) <= len(config.CustomAttrPrefix) {
		return "", false
	}
	if !strings.EqualFold(key[:len(config.CustomAttrPrefix)], config.CustomAttrPrefix) {
		return "", false
	}
	name := key[len(config.CustomAttrPrefix):]
	if name == "" {
		return "", false
	}
	return name, true
}

// Helper functions

func parseBool(s string, def bool) bool {
	s = strings.ToLower(strings.TrimSpace(s))
	switch s {
	case "true", "yes", "1":
		return true
	case "false", "no", "0":
		return false
	default:
		return def
	}
}

// Base units, in bytes, for the size-valued submit commands. HTCondor
// states each of these attributes in its own unit -- RequestMemory is
// MiB, RequestDisk is KiB -- so the base is a property of the command,
// not of the value.
const (
	unitKiB = int64(1024)
	unitMiB = int64(1024) * 1024
)

// parseSizeWithUnits parses a size-valued submit command (request_memory,
// request_disk, image_size, ...) into the attribute's own base unit,
// mirroring HTCondor's parse_int64_bytes() (condor_utils/metric_units.cpp).
//
// The rules, which are the ones condor_submit implements:
//   - an optional fractional part is allowed ("2.5G")
//   - a K/M/G/T suffix (case-insensitive, optional trailing "b"/"B")
//     scales the number to bytes
//   - NO suffix means the number is already in the attribute's base unit,
//     so request_memory = 4096 stays 4096 MiB
//   - the result is the number of base units, rounded UP
//   - anything else (an expression, a bare "B", trailing junk) is not a
//     size; the caller decides what to do with it
//
// Using strconv/fmt.Sscanf here instead is the bug this replaces: "%d"
// stops at the first non-digit and reports no error, so "4GB" parsed as
// a silent 4.
func parseSizeWithUnits(s string, base int64) (int64, bool) {
	p := strings.TrimLeft(s, " \t")

	// Integer part.
	i := 0
	if i < len(p) && (p[i] == '+' || p[i] == '-') {
		i++
	}
	digits := i
	for i < len(p) && p[i] >= '0' && p[i] <= '9' {
		i++
	}
	if i == digits {
		return 0, false
	}
	val, err := strconv.ParseInt(p[:i], 10, 64)
	if err != nil {
		return 0, false
	}

	// Optional fractional part; HTCondor keeps three digits and ignores
	// the rest, since the result is rounded up to the base anyway.
	frac := 0.0
	if i < len(p) && p[i] == '.' {
		i++
		for scale := 10.0; i < len(p) && p[i] >= '0' && p[i] <= '9'; i++ {
			if scale <= 1000.0 {
				frac += float64(p[i]-'0') / scale
				scale *= 10
			}
		}
	}

	for i < len(p) && (p[i] == ' ' || p[i] == '\t') {
		i++
	}

	// Multiplier suffix. No suffix means the value is already in base units.
	mult := base
	if i < len(p) {
		switch p[i] {
		case 'k', 'K':
			mult = unitKiB
		case 'm', 'M':
			mult = unitMiB
		case 'g', 'G':
			mult = unitMiB * 1024
		case 't', 'T':
			mult = unitMiB * 1024 * 1024
		default:
			return 0, false
		}
		i++
		// Tolerate the "b" in "KB".
		if i < len(p) && (p[i] == 'b' || p[i] == 'B') {
			i++
		}
	}

	for i < len(p) && (p[i] == ' ' || p[i] == '\t') {
		i++
	}
	if i != len(p) {
		return 0, false
	}

	// Round up to whole base units, as condor_submit does.
	bytes := int64((float64(val) + frac) * float64(mult))
	return (bytes + base - 1) / base, true
}

// setSizeAttr assigns a size-valued job attribute. A parseable size becomes
// the integer count of base units; anything else is stored as a ClassAd
// expression, which is what condor_submit does (AssignJobExpr) for values
// like "request_memory = ifThenElse(...)" or "MY.JobVMMemory".
//
// The case that matters is the third one. Dropping an unparseable value --
// what the old code did, by guarding on "err == nil" and falling through --
// left the attribute at its hardcoded default with nothing to say the
// request had been ignored. A job that asked for an expression silently
// became a 128 MiB job.
func setSizeAttr(ad *classad.ClassAd, attr, raw string, base int64) error {
	if n, ok := parseSizeWithUnits(raw, base); ok {
		_ = ad.Set(attr, n)
		return nil
	}
	expr, err := classad.ParseExpr(raw)
	if err != nil {
		return fmt.Errorf("%s: %q is neither a size nor a valid expression: %w", attr, raw, err)
	}
	_ = ad.Set(attr, expr)
	return nil
}

// setCountAttr assigns a count-valued job attribute (request_cpus,
// request_gpus). These take no unit suffixes, but like the size-valued
// commands they may be expressions: condor_submit stores
// "request_cpus = 2 * 2" verbatim rather than evaluating it to 4, and
// keeps "request_cpus = 2.5" as a real. So anything that is not a plain
// integer is stored as an expression instead of being dropped.
//
// The integer parse is deliberately strict. fmt.Sscanf("%d") -- what this
// used to use -- accepts "2.5" as 2 and "2 * 2" as 2, silently turning
// both into the wrong count with no error to notice.
func setCountAttr(ad *classad.ClassAd, attr, raw string) error {
	if n, err := strconv.ParseInt(strings.TrimSpace(raw), 10, 64); err == nil {
		_ = ad.Set(attr, n)
		return nil
	}
	expr, err := classad.ParseExpr(raw)
	if err != nil {
		return fmt.Errorf("%s: %q is neither an integer nor a valid expression: %w", attr, raw, err)
	}
	_ = ad.Set(attr, expr)
	return nil
}

func parseInt(s string) (int, error) {
	s = strings.TrimSpace(s)
	var n int
	_, err := fmt.Sscanf(s, "%d", &n)
	return n, err
}

// parseFileList parses a comma-separated list of files
// Handles whitespace and empty entries
func parseFileList(list string) []string {
	parts := strings.Split(trimSubmitQuotes(list), ",")
	var files []string
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p != "" {
			files = append(files, p)
		}
	}
	return files
}

// addToolDaemonInputFiles appends the tool daemon's binary, and the file it
// reads, to a job's transfer list.
//
// Neither is added when the job transfers nothing (should_transfer_files =
// NO), and ToolDaemonInput rides on ToolDaemonCmd: condor_submit looks for
// it only once it has found a daemon to run. A path already on the list is
// not added twice.
//
// One thing is deliberately NOT done here: making the list exist. The
// attribute is still written only when the submit file named files of its
// own (or a container image was added), which means a tool daemon alone does
// not produce a TransferInput -- condor_submit's behaviour, verified against
// the oracle, and not obviously what was intended.
func (sf *SubmitFile) addToolDaemonInputFiles(inFileList *[]string, should shouldTransferFiles) {
	if should == stfNo {
		return
	}
	cmd := sf.submitParam("tool_daemon_cmd", "ToolDaemonCmd")
	if cmd == "" {
		return
	}
	for _, file := range []string{cmd, sf.submitParam("tool_daemon_input", "ToolDaemonInput")} {
		if file == "" || slices.Contains(*inFileList, file) {
			continue
		}
		*inFileList = append(*inFileList, file)
	}
}

// trimSubmitQuotes removes one matching pair of surrounding double quotes
// from a submit command's value, the way condor_submit does:
// `transfer_output_files = "a.txt, b.txt"` names two files, not one file
// whose name starts with a quote.
//
// Without this, the quotes survive into the job ad and the failure lands
// far from the cause -- `transfer_output_files = ""` produced a shadow
// trying to read a file literally named `""` and held the job with a
// transfer error naming neither the setting nor the quotes.
//
// One pair only, and only when both ends match. strings.Trim would strip
// a run of quotes from either end independently, turning `""a""` into `a`
// and quietly accepting input condor would not.
func trimSubmitQuotes(s string) string {
	t := strings.TrimSpace(s)
	if len(t) >= 2 && t[0] == '"' && t[len(t)-1] == '"' {
		return t[1 : len(t)-1]
	}
	return t
}

// setGridParams sets the grid universe attributes, mirroring SetGridParams()
// in condor_utils/submit_utils.cpp.
//
// Two rules govern the family. The whole function is skipped outside the grid
// universe, so ec2_elastic_ip in a vanilla job reaches no attribute at all.
// And within it, the grid TYPE -- the first word of grid_resource -- decides
// only which settings are REQUIRED and whether a job gets the implicit Name
// tag; every other keyword is read whatever the type, so a `batch slurm` job
// that names an AMI still carries EC2AmiID.
//
// The attribute names are HTCondor's own and several do not follow from the
// keyword: ec2_ebs_volumes is EC2ElasticBlockStorageVolumes,
// ec2_parameter_names is EC2ParamNames, and ec2_elastic_ip and ec2_vpc_ip end
// in a lower-case "Ip". The grid manager reads those names and nothing else,
// so a job carrying the keyword's own spelling would launch an instance with
// no elastic IP and no volumes attached.
//
// What this does NOT do is reject a file. condor_submit aborts a submission
// whose grid type is missing a required setting -- an ec2 job with no AMI or
// no credentials, a gce job with no image, an azure job missing any of five
// -- and it validates the ec2_ebs_volumes syntax. Acceptance is the caller's
// policy here, so those files parse and the attributes they did name land in
// the ad.
//
//nolint:gocyclo // one keyword per branch, mirroring SetGridParams
func (sf *SubmitFile) setGridParams(ad *classad.ClassAd) error {
	// Several of the family name files, which condor_submit resolves against
	// Iwd the way it resolves Cmd and UserLog.
	//
	// Which keywords get that treatment is not a property of the value and
	// cannot be inferred from it. HTCondor decides it in two separate places
	// and only one of them is a table: SimpleSubmitKeyword carries an
	// f_filemask field that do_simple_commands reads (today only `log`,
	// `dagman_log`, `output_directory` and `starter_log`), while SetGridParams
	// resolves the cloud credential and data files one call at a time, with no
	// flag to read. `executable` is in the table with f_filemask as well, but
	// it is f_special too and so never reaches that loop -- SetExecutable
	// resolves it against the SUBMITTING directory rather than Iwd.
	iwd, err := sf.jobIwd()
	if err != nil {
		return err
	}

	// grid_resource - Required for grid universe
	if gridResource, ok := sf.submitCommandAlt("grid_resource", "GridResource"); ok {
		_ = ad.Set("GridResource", gridResource)
	}
	// The grid type is the first word of the resource, which may have come
	// from the base ad rather than this file.
	gridType := ""
	if gr, ok := ad.EvaluateAttrString("GridResource"); ok {
		gridType, _, _ = strings.Cut(gr, " ")
		gridType = strings.ToLower(gridType)
	}

	// ARC parameters
	if arcRte, ok := sf.submitCommandAlt("arc_rte", "ArcRte"); ok {
		_ = ad.Set("ArcRte", arcRte)
	}
	if arcResources, ok := sf.submitCommandAlt("arc_resources", "ArcResources"); ok {
		_ = ad.Set("ArcResources", arcResources)
	}

	// Batch system parameters (PBS, LSF, SGE, Slurm, etc.)
	if batchExtraArgs, ok := sf.submitCommandAlt("batch_extra_submit_args", "BatchExtraSubmitArgs"); ok {
		_ = ad.Set("BatchExtraSubmitArgs", batchExtraArgs)
	}
	if batchProject, ok := sf.submitCommandAlt("batch_project", "BatchProject"); ok {
		_ = ad.Set("BatchProject", batchProject)
	}
	if batchQueue, ok := sf.submitCommandAlt("batch_queue", "BatchQueue"); ok {
		_ = ad.Set("BatchQueue", batchQueue)
	}
	if batchRuntime, ok := sf.submitCommandAlt("batch_runtime", "BatchRuntime"); ok {
		if intRuntime, err := parseInt(batchRuntime); err == nil {
			_ = ad.Set("BatchRuntime", intRuntime)
		}
	}

	sf.setEC2Credentials(ad, iwd)
	sf.setEC2Params(ad, iwd)

	// EC2 tags and GCE labels. Both are name/value pairs collected from a
	// prefixed keyword, and both get the implicit Name tag on an ec2 job.
	sf.setGridAVPairs(ad, "ec2_tag_", "EC2Tag", "ec2_tag_names", "EC2TagNames", gridType)
	sf.setGridAVPairs(ad, "cloud_label_", "CloudLabel", "cloud_label_names", "CloudLabelNames", gridType)

	sf.setGCEParams(ad, iwd)
	sf.setAzureParams(ad, iwd)

	// Delegate credentials
	if delegateJobGSI, ok := sf.submitCommand("delegate_job_gsi_credentials_lifetime"); ok {
		if intLifetime, err := parseInt(delegateJobGSI); err == nil {
			_ = ad.Set("DelegateJobGSICredentialsLifetime", intLifetime)
		}
	}

	return nil
}

// ec2InstanceRole is the value that tells the grid manager to take its
// credentials from the instance role it is already running under instead of
// reading a key file. Naming it under either key sets BOTH halves of the
// credential pair, since a role supplies both at once.
const ec2InstanceRole = "FROM INSTANCE"

// setEC2Credentials reads the EC2 access key pair.
//
// Each half has two spellings: ec2_access_key_id names a file that is
// resolved against Iwd, while aws_access_key_id_file (and its s3_ and gs_
// aliases) is a plain keyword that SetSimpleJobExprs assigns verbatim AFTER
// this runs -- so the simple table's value, not this one, is what the job
// ends up carrying when the file uses one of those spellings.
func (sf *SubmitFile) setEC2Credentials(ad *classad.ClassAd, iwd string) {
	for _, cred := range []struct{ key, altKey, attr string }{
		{"ec2_access_key_id", "aws_access_key_id_file", "EC2AccessKeyId"},
		{"ec2_secret_access_key", "aws_secret_access_key_file", "EC2SecretAccessKey"},
	} {
		value, ok := sf.submitCommandAlt(cred.key, cred.attr)
		if !ok {
			value, ok = sf.submitCommandAlt(cred.altKey, cred.attr)
		}
		if !ok {
			continue
		}
		if strings.EqualFold(value, ec2InstanceRole) {
			_ = ad.Set("EC2AccessKeyId", ec2InstanceRole)
			_ = ad.Set("EC2SecretAccessKey", ec2InstanceRole)
			continue
		}
		_ = ad.Set(cred.attr, fullPath(value, iwd))
	}
}

// setEC2Params reads the rest of the EC2 family.
//
//nolint:gocyclo // one keyword per branch, mirroring SetGridParams
func (sf *SubmitFile) setEC2Params(ad *classad.ClassAd, iwd string) {
	// ec2_keypair names a key pair already registered with EC2;
	// ec2_keypair_file names where to WRITE a generated one, so naming both
	// is a contradiction and the file loses.
	if keyPair, ok := sf.submitCommandAlt2("ec2_keypair", "EC2KeyPair", "ec2_keyp_air"); ok {
		_ = ad.Set("EC2KeyPair", keyPair)
	}
	if keyPairFile, ok := sf.submitCommandAlt2("ec2_keypair_file", "EC2KeyPairFile", "ec2_key_pair_file"); ok {
		if _, taken := ad.Lookup("EC2KeyPair"); !taken {
			_ = ad.Set("EC2KeyPairFile", fullPath(keyPairFile, iwd))
		}
	}

	for _, kw := range []struct{ key, attr string }{
		{"ec2_security_groups", "EC2SecurityGroups"},
		{"ec2_security_ids", "EC2SecurityIDs"},
		{"ec2_ami_id", "EC2AmiID"},
		{"ec2_instance_type", "EC2InstanceType"},
		{"ec2_vpc_subnet", "EC2VpcSubnet"},
		{"ec2_vpc_ip", "EC2VpcIp"},
		{"ec2_elastic_ip", "EC2ElasticIp"},
		{"ec2_availability_zone", "EC2AvailabilityZone"},
		{"ec2_ebs_volumes", "EC2ElasticBlockStorageVolumes"},
		{"ec2_spot_price", "EC2SpotPrice"},
		{"ec2_block_device_mapping", "EC2BlockDeviceMapping"},
		{"ec2_user_data", "EC2UserData"},
	} {
		if value, ok := sf.submitCommandAlt(kw.key, kw.attr); ok {
			_ = ad.Set(kw.attr, value)
		}
	}

	if userDataFile, ok := sf.submitCommandAlt("ec2_user_data_file", "EC2UserDataFile"); ok {
		_ = ad.Set("EC2UserDataFile", fullPath(userDataFile, iwd))
	}

	// An instance profile is named by ARN or by name, never both -- and
	// condor_submit keeps the name only when the ARN is there too.
	if arn, ok := sf.submitCommandAlt("ec2_iam_profile_arn", "EC2IamProfileArn"); ok {
		_ = ad.Set("EC2IamProfileArn", arn)
	}
	if name, ok := sf.submitCommandAlt("ec2_iam_profile_name", "EC2IamProfileName"); ok {
		if _, haveArn := ad.Lookup("EC2IamProfileArn"); haveArn {
			_ = ad.Set("EC2IamProfileName", name)
		}
	}

	sf.setEC2RunInstancesParams(ad)
}

// setEC2RunInstancesParams passes arbitrary RunInstances parameters through.
// Each ec2_parameter_<Name> becomes EC2Param_<Name>, and the names are
// collected into EC2ParamNames because ClassAd attribute names are
// case-insensitive while EC2's parameter names are not.
//
// ec2_parameter_names may list names of its own, and the ones found by the
// prefix scan are appended to that list. The de-duplication compares a listed
// name with its dots turned into underscores against the raw scanned name, so
// a name containing a dot never matches itself and is listed twice.
func (sf *SubmitFile) setEC2RunInstancesParams(ad *classad.ClassAd) {
	const prefix = "ec2_parameter_"
	const namesKey = "ec2_parameter_names"

	var paramNames []string
	if listed, ok := sf.submitCommandAlt(namesKey, "EC2ParamNames"); ok {
		paramNames = splitAVList(listed)
	} else if existing, ok := ad.EvaluateAttrString("EC2ParamNames"); ok {
		paramNames = splitAVList(existing)
	}

	for _, key := range sf.assignedWithPrefix(prefix) {
		if strings.EqualFold(key, namesKey) {
			continue
		}
		name := key[len(prefix):]
		value, ok := sf.submitCommand(key)
		if !ok {
			continue
		}
		_ = ad.Set("EC2Param_"+name, value)

		found := false
		for _, existing := range paramNames {
			if strings.EqualFold(strings.ReplaceAll(existing, ".", "_"), name) {
				found = true
				break
			}
		}
		if !found {
			paramNames = append(paramNames, name)
		}
	}

	if len(paramNames) > 0 {
		_ = ad.Set("EC2ParamNames", strings.Join(paramNames, ", "))
	}
}

// setGridAVPairs collects one family of name/value pairs -- EC2 tags, GCE
// labels -- from the <prefix><Name> keywords and the list keyword that names
// them, and records the names under listAttr.
//
// A pair may be written with either the submit prefix (ec2_tag_Foo) or the
// attribute prefix (EC2TagFoo), and the list keyword itself is passed over by
// skipping any name starting with "Names".
//
// On an ec2 job the executable is only a label, so condor_submit also tags the
// instance with it under <prefix>Name, which is what the AWS console shows as
// the instance's name. WantNameTag = false turns that off.
func (sf *SubmitFile) setGridAVPairs(ad *classad.ClassAd, submitPrefix, attrPrefix, listKey, listAttr, gridType string) {
	var names []string
	if listed, ok := sf.submitCommandAlt(listKey, listAttr); ok {
		names = splitAVList(listed)
	} else if existing, ok := ad.EvaluateAttrString(listAttr); ok {
		names = splitAVList(existing)
	}

	for _, key := range sf.assignedWithPrefix(submitPrefix, attrPrefix) {
		var name string
		switch {
		case len(key) > len(submitPrefix) && strings.EqualFold(key[:len(submitPrefix)], submitPrefix):
			name = key[len(submitPrefix):]
		case len(key) > len(attrPrefix) && strings.EqualFold(key[:len(attrPrefix)], attrPrefix):
			name = key[len(attrPrefix):]
		default:
			continue
		}
		if len(name) >= 5 && strings.EqualFold(name[:5], "Names") {
			continue
		}
		if !containsNameFold(names, name) {
			names = append(names, name)
		}
	}

	for _, name := range names {
		value, ok := sf.submitCommandAlt(submitPrefix+name, attrPrefix+name)
		if !ok {
			// Only reachable when the names came from the base ad.
			continue
		}
		_ = ad.Set(attrPrefix+name, value)
	}

	if gridType == "ec2" && !containsNameFold(names, "Name") {
		if parseBool(sf.submitParam("WantNameTag", ""), true) {
			if cmd, ok := ad.EvaluateAttrString("Cmd"); ok {
				_ = ad.Set(attrPrefix+"Name", cmd)
			}
		}
	}

	if len(names) > 0 {
		_ = ad.Set(listAttr, strings.Join(names, ","))
	}
}

// setGCEParams reads the GCE family.
func (sf *SubmitFile) setGCEParams(ad *classad.ClassAd, iwd string) {
	for _, kw := range []struct{ key, attr string }{
		{"gce_auth_file", "GceAuthFile"},
		{"gce_metadata_file", "GceMetadataFile"},
		{"gce_json_file", "GceJsonFile"},
	} {
		if value, ok := sf.submitCommandAlt(kw.key, kw.attr); ok {
			_ = ad.Set(kw.attr, fullPath(value, iwd))
		}
	}
	for _, kw := range []struct{ key, attr string }{
		{"gce_account", "GceAccount"},
		{"gce_image", "GceImage"},
		{"gce_machine_type", "GceMachineType"},
	} {
		if value, ok := sf.submitCommandAlt(kw.key, kw.attr); ok {
			_ = ad.Set(kw.attr, value)
		}
	}
	// The metadata list is re-joined from its comma-separated fields, which
	// drops the spacing the submitter wrote: "a=1, b=2" is stored "a=1,b=2",
	// and the metadata server is handed the name " b" otherwise.
	if metadata, ok := sf.submitCommandAlt("gce_metadata", "GceMetadata"); ok {
		_ = ad.Set("GceMetadata", strings.Join(splitOnCommas(metadata), ","))
	}
	if preemptible, ok := sf.submitCommandAlt("gce_preemptible", "GcePreemptible"); ok {
		_ = ad.Set("GcePreemptible", parseBool(preemptible, false))
	}
}

// setAzureParams reads the Azure family.
func (sf *SubmitFile) setAzureParams(ad *classad.ClassAd, iwd string) {
	if authFile, ok := sf.submitCommandAlt("azure_auth_file", "AzureAuthFile"); ok {
		_ = ad.Set("AzureAuthFile", fullPath(authFile, iwd))
	}
	for _, kw := range []struct{ key, attr string }{
		{"azure_image", "AzureImage"},
		{"azure_location", "AzureLocation"},
		{"azure_size", "AzureSize"},
		{"azure_admin_username", "AzureAdminUsername"},
		{"azure_admin_key", "AzureAdminKey"},
	} {
		if value, ok := sf.submitCommandAlt(kw.key, kw.attr); ok {
			_ = ad.Set(kw.attr, value)
		}
	}
}

// assignedWithPrefix returns the names the submit file assigned that start
// with any of the given prefixes, case-insensitively, in a fixed order.
//
// The order is the sorted one HTCondor's own macro table walks in, and it is
// observable: it decides the order of the names in EC2TagNames and
// EC2ParamNames.
func (sf *SubmitFile) assignedWithPrefix(prefixes ...string) []string {
	var keys []string
	for _, name := range sf.assigned {
		for _, prefix := range prefixes {
			if len(name) > len(prefix) && strings.EqualFold(name[:len(prefix)], prefix) {
				keys = append(keys, name)
				break
			}
		}
	}
	sort.Slice(keys, func(i, j int) bool {
		li, lj := strings.ToLower(keys[i]), strings.ToLower(keys[j])
		if li != lj {
			return li < lj
		}
		return keys[i] < keys[j]
	})
	return keys
}

// splitAVList splits a list of names the way HTCondor's split() does by
// default: on commas and whitespace, discarding empty fields.
func splitAVList(s string) []string {
	fields := strings.FieldsFunc(s, func(r rune) bool {
		return r == ',' || r == ' ' || r == '\t' || r == '\r' || r == '\n'
	})
	if len(fields) == 0 {
		return nil
	}
	return fields
}

// splitOnCommas splits on commas only, discarding empty fields, the way
// HTCondor's split(s, ",") does.
func splitOnCommas(s string) []string {
	var out []string
	for _, field := range strings.Split(s, ",") {
		field = strings.TrimSpace(field)
		if field != "" {
			out = append(out, field)
		}
	}
	return out
}

// containsNameFold reports whether list holds name, ignoring case.
func containsNameFold(list []string, name string) bool {
	for _, item := range list {
		if strings.EqualFold(item, name) {
			return true
		}
	}
	return false
}

// setVMParams sets the VM universe attributes, mirroring SetVMParams() in
// condor_utils/submit_utils.cpp.
//
// The attribute names are HTCondor's own, not the submit keywords': vm_memory
// is JobVMMemory, vm_vcpus is JobVM_VCPUS, vm_disk is VMPARAM_vm_Disk and the
// xen_* keywords become VMPARAM_Xen_*. Nothing reads an attribute named after
// the keyword, so a VM job carrying those would run with the default memory
// and CPU count.
//
// vm_type decides how much of the rest condor_submit even reads: the xen_*
// keywords only for "xen", vm_disk only for "xen" or "kvm", and the
// networking type only when networking is on. Checkpoint, networking and VNC
// land in the ad whether or not the submit file mentions them.
func (sf *SubmitFile) setVMParams(ad *classad.ClassAd) error {
	// vm_type - Required: type of VM (kvm, xen). Stored lower-cased.
	vmType := ""
	if v, ok := sf.submitCommand("vm_type"); ok {
		vmType = strings.ToLower(v)
		_ = ad.Set("JobVMType", vmType)
	}

	// vm_checkpoint - Enable checkpointing.
	//
	// Read through the shared helper, which also honours the attribute
	// spelling (JobVMCheckpoint) that SetUniverse accepts. The same
	// helper decides the job's forced file transfer settings, so a file
	// using that spelling cannot end up with a job ad saying it does not
	// checkpoint next to transfer settings that say it does.
	checkpoint := sf.vmCheckpoint()
	_ = ad.Set("JobVMCheckpoint", checkpoint)

	// vm_networking - Enable networking for VM
	networking := sf.vmNetworking()
	_ = ad.Set("JobVMNetworking", networking)

	// vm_networking_type - Type of networking (nat, bridge, ...), read only
	// when networking is on.
	if networking {
		if v, ok := sf.submitCommand("vm_networking_type"); ok {
			_ = ad.Set("JobVMNetworkingType", v)
		}
	}

	// vm_vnc - Attach a VNC console
	vnc := false
	if v, ok := sf.submitCommand("vm_vnc"); ok {
		vnc = parseBool(v, false)
	}
	_ = ad.Set("JobVMVNCConsole", vnc)

	// vm_memory - Memory for the VM in MiB. condor_submit gives the keyword
	// a built-in default of $(Request_Memory), so a VM job that only asks
	// for request_memory gives its VM that much memory.
	if vmMemory, ok := sf.submitCommandAlt2("vm_memory", "request_memory", "requestmemory"); ok {
		if err := setSizeAttr(ad, "JobVMMemory", vmMemory, unitMiB); err != nil {
			return err
		}
	}

	// vm_vcpus - Number of virtual CPUs, with a floor of 1. Its built-in
	// default is $(Request_CPUs), and the default is the macro's TEXT rather
	// than the evaluated request, so "request_cpus = 2*2" leaves the VM with
	// 2 CPUs, not 4.
	vcpus := 1
	if v, ok := sf.submitCommandAlt2("vm_vcpus", "request_cpus", "requestcpus"); ok {
		vcpus = vmVCPUs(v)
	}
	_ = ad.Set("JobVM_VCPUS", vcpus)

	// vm_macaddr - MAC address for VM
	if vmMac, ok := sf.submitCommand("vm_macaddr"); ok {
		_ = ad.Set("JobVM_MACADDR", vmMac)
	}

	// vm_no_output_vm - Do not transfer the VM files back
	if v, ok := sf.submitCommand("vm_no_output_vm"); ok {
		_ = ad.Set("VMPARAM_No_Output_VM", parseBool(v, false))
	}

	if vmType == vmTypeXen {
		sf.setXenParams(ad)
	}

	// vm_disk - the VM's disk images, "<file>:<device>:<permission>" per
	// disk. Only xen and kvm have one.
	if vmType == vmTypeXen || vmType == vmTypeKVM {
		if vmDisk, ok := sf.submitCommand("vm_disk"); ok {
			_ = ad.Set("VMPARAM_vm_Disk", vmDisk)
		}
	}

	// vmware_dir - VMware working directory
	if vmwareDir, ok := sf.submitCommand("vmware_dir"); ok {
		_ = ad.Set("VMWARE_Dir", vmwareDir)
	}

	// vmware_snapshot_disk - Use snapshot disk
	if vmwareSnapshot, ok := sf.submitCommand("vmware_snapshot_disk"); ok {
		_ = ad.Set("VMWARE_SnapshotDisk", parseBool(vmwareSnapshot, false))
	}

	// vmware_should_transfer_files - Transfer files
	if vmwareTransfer, ok := sf.submitCommand("vmware_should_transfer_files"); ok {
		_ = ad.Set("VMWARE_ShouldTransferFiles", parseBool(vmwareTransfer, true))
	}

	return nil
}

// The vm_type values that have parameters of their own.
const (
	vmTypeXen = "xen"
	vmTypeKVM = "kvm"
)

// The two xen_kernel values that name something other than a kernel file:
// "included" means the disk image boots itself, "vmx" asks for hardware
// virtualization instead. Either one means there is no kernel file, so
// xen_initrd and xen_root do not apply.
const (
	xenKernelIncluded = "included"
	xenKernelHWVT     = "vmx"
)

// setXenParams sets the VMPARAM_Xen_* attributes from the xen_* keywords.
// condor_submit reads them only for a Xen VM; under any other vm_type the
// keywords are silently dropped.
func (sf *SubmitFile) setXenParams(ad *classad.ClassAd) {
	xenKernel, ok := sf.submitCommand("xen_kernel")
	if !ok {
		return
	}
	_ = ad.Set("VMPARAM_Xen_Kernel", xenKernel)

	// "vmx" is a request for hardware virtualization rather than a kernel,
	// and the requirements expression keys off the attribute.
	kernel := strings.ToLower(xenKernel)
	if kernel == xenKernelHWVT {
		_ = ad.Set("JobVMHardwareVT", true)
	}
	realKernelFile := kernel != xenKernelIncluded && kernel != xenKernelHWVT

	// xen_initrd and xen_root describe a real kernel file; with "included"
	// or "vmx" there is none, and condor_submit does not read them.
	if realKernelFile {
		if xenInitrd, ok := sf.submitCommand("xen_initrd"); ok {
			_ = ad.Set("VMPARAM_Xen_Initrd", xenInitrd)
		}
		if xenRoot, ok := sf.submitCommand("xen_root"); ok {
			_ = ad.Set("VMPARAM_Xen_Root", xenRoot)
		}
	}

	// xen_kernel_params keeps one layer of quoting off the value.
	if xenParams, ok := sf.submitCommand("xen_kernel_params"); ok {
		_ = ad.Set("VMPARAM_Xen_Kernel_Params", trimOneQuotePair(xenParams))
	}
}

// trimOneQuotePair mirrors trim_quotes() (condor_utils/stl_string_utils.cpp):
// a leading and a trailing quote are each dropped on their own, so `"a b` and
// `a b'` lose theirs as surely as `"a b"` does. A string shorter than two
// characters is left alone.
func trimOneQuotePair(s string) string {
	if len(s) < 2 {
		return s
	}
	if s[0] == '"' || s[0] == '\'' {
		s = s[1:]
	}
	if n := len(s); n > 0 && (s[n-1] == '"' || s[n-1] == '\'') {
		s = s[:n-1]
	}
	return s
}

// vmVCPUs mirrors condor_submit's vm_vcpus handling: (int)strtol() of the
// value, floored at 1. strtol takes the leading decimal digits and yields 0
// for anything else, and the cast to int truncates to 32 bits, so "abc", "0",
// "-3" and "4294967296" all come out as 1.
func vmVCPUs(raw string) int {
	s := strings.TrimLeft(raw, " \t\n\v\f\r")
	i := 0
	if i < len(s) && (s[i] == '+' || s[i] == '-') {
		i++
	}
	digits := i
	for i < len(s) && s[i] >= '0' && s[i] <= '9' {
		i++
	}
	if i == digits {
		return 1
	}
	v, err := strconv.ParseInt(s[:i], 10, 64)
	if err != nil {
		// strtol saturates at LONG_MAX/LONG_MIN, and truncating either to
		// int lands below the floor.
		return 1
	}
	// The truncation is the point: it is what C++'s (int) cast does.
	n := int32(v) //nolint:gosec // G115: deliberate, see above
	if n > 1 {
		return int(n)
	}
	return 1
}

// setHostCounts gives a job the MinHosts/MaxHosts pair HTCondor writes
// for it, in SubmitHash::SetParallelParams and SetAutoAttributes.
//
// machine_count names a count of MACHINES, and this pair is what records
// it -- there is no MachineCount attribute on a job ad, so a job that
// carried the count under that name asked for the default of one machine
// however many it requested. The count is read only for a parallel or
// MPI job; every other universe ignores the keyword entirely and takes
// the default pair of 1. `node_count` is the alternate spelling, which
// condor_submit reads only when machine_count is absent.
//
// A job that asks for a count of machines must say how many: a parallel or
// MPI job with neither a count nor a MaxHosts of its own is a submit error,
// which is what condor_submit does with it ("No machine_count specified!").
//
// `WantParallelScheduling = true` puts a job of ANY universe on this path --
// it is how a vanilla job asks the dedicated scheduler to schedule it -- so
// the count is read, and required, there too.
func (sf *SubmitFile) setHostCounts(ad *classad.ClassAd) error {
	if sf.universe != UniverseParallel && !sf.wantParallelScheduling() {
		_ = ad.Set("MinHosts", 1)
		_ = ad.Set("MaxHosts", 1)
		return nil
	}
	if count, ok := sf.submitCommandAlt("machine_count", "node_count"); ok {
		// atoi, not a strict parse: HTCondor reads the count with
		// atoi(), which takes the leading digits and ignores the rest.
		if intCount, err := parseInt(count); err == nil {
			_ = ad.Set("MinHosts", intCount)
			_ = ad.Set("MaxHosts", intCount)
			return nil
		}
	}
	// condor_submit has one escape here -- a MaxHosts the ad already
	// carries -- and it is not reachable from a submit file. SetParallelParams
	// runs before the `+Attr` pass, so `+MaxHosts = 3` is not yet in the ad
	// and C++ aborts over it too (verified against the oracle); the only ad
	// that does carry one is the cluster ad a materialized proc is chained
	// to, and this parser builds no proc ads from a cluster ad.
	return fmt.Errorf("no machine_count specified for a %s job", sf.hostCountKind())
}

// hostCountKind names, for the error above, which of the three ways a job
// got onto the machine-count path it took.
func (sf *SubmitFile) hostCountKind() string {
	switch {
	case sf.isMPIUniverse():
		return "MPI universe"
	case sf.universe == UniverseParallel:
		return "parallel universe"
	default:
		return "WantParallelScheduling"
	}
}

// setParallelSchedulingFlag writes WantParallelScheduling when the submit
// file asked for it. A false is not written at all, matching SetUniverse.
func (sf *SubmitFile) setParallelSchedulingFlag(ad *classad.ClassAd) {
	if sf.wantParallelScheduling() {
		_ = ad.Set("WantParallelScheduling", true)
	}
}

// wantParallelScheduling reports whether the submit file set
// WantParallelScheduling, the keyword that asks the dedicated scheduler to
// schedule a job that is not in the parallel universe.
//
// Its only spelling is the job attribute's: condor_submit reads it with
// submit_param_bool(ATTR_WANT_PARALLEL_SCHEDULING, NULL, false), passing no
// alternate name, so `want_parallel_scheduling` is not a submit command.
func (sf *SubmitFile) wantParallelScheduling() bool {
	value, ok := sf.submitCommand("WantParallelScheduling")
	if !ok {
		return false
	}
	b, _ := evalBoolParam(value)
	return b
}

// setParallelSandbox turns on the two things a parallel job needs from the
// schedd and the starter: a spool directory of its own, and the I/O proxy.
//
// SubmitHash::SetParallelParams assigns both unconditionally for
// CONDOR_UNIVERSE_PARALLEL, and the MPI universe does NOT get them -- it is a
// separate universe number there, even though this parser maps both spellings
// onto UniverseParallel.
//
// WantIOProxy is what makes chirp reachable, which is how a parallel job's
// sshd is set up; JobRequiresSandbox tells the schedd to give the job a spool
// directory to do it in (SpooledJobFiles::jobRequiresSpoolDirectory). The
// schedd assumes a spool directory for parallel jobs when the attribute is
// absent, so the consequence of leaving it off is not that spooling stops --
// it is that the attribute a transform or a policy expression reads comes back
// undefined.
//
// Neither is written over a value the job already has. C++ reaches the same
// place from the other direction: it assigns early and lets the `want_io_proxy`
// keyword and the `+Attr` pass overwrite it, and here the keyword pass still
// runs after this one while `+Attr` has already run.
func (sf *SubmitFile) setParallelSandbox(ad *classad.ClassAd) error {
	if sf.universe != UniverseParallel || sf.isMPIUniverse() {
		return nil
	}
	if _, ok := ad.Lookup("WantIOProxy"); !ok {
		_ = ad.Set("WantIOProxy", true)
	}
	if _, ok := ad.Lookup("JobRequiresSandbox"); !ok {
		_ = ad.Set("JobRequiresSandbox", true)
	}
	return nil
}

// isMPIUniverse reports whether the submit file asked for the MPI
// universe. Go maps `universe = mpi` onto UniverseParallel, so the
// spelling is the only thing left to read it from.
func (sf *SubmitFile) isMPIUniverse() bool {
	univ, ok := sf.submitCommand("universe")
	return ok && strings.EqualFold(strings.TrimSpace(univ), "mpi")
}

// setUngatedFamilies stores the families condor_submit reads for every job,
// whatever the universe. Their keywords look universe-specific -- a tool
// daemon, a JVM's arguments, a list of jars -- but condor_submit reads all of
// them from every submit file, and writing one only inside its apparent
// universe is a divergence in its own right.
func (sf *SubmitFile) setUngatedFamilies(ad *classad.ClassAd) error {
	if err := sf.setToolDaemon(ad); err != nil {
		return err
	}
	if err := sf.setBufferNoopAndJarFiles(ad); err != nil {
		return err
	}
	return sf.setJavaVMArgs(ad)
}

// setBufferNoopAndJarFiles stores three groups condor_submit reads straight
// out of its keyword table, with no universe gate and no type conversion.
//
// The buffer settings and the noop-job settings are expressions, not numbers:
// `buffer_size = 1024 * 1024` is legal, and a reader that scans an integer
// off the front drops it. jar_files is a plain string wherever it appears;
// SetTransferFiles is what notices the jars, and only for a java job.
func (sf *SubmitFile) setBufferNoopAndJarFiles(ad *classad.ClassAd) error {
	exprs := []struct{ command, attr string }{
		{"buffer_files", "BufferFiles"},
		{"buffer_size", "BufferSize"},
		{"buffer_block_size", "BufferBlockSize"},
		// A noop job never runs: the schedd completes it at submission with
		// the exit code and signal named here, so dropping either one
		// reports the wrong outcome for a job that stood in for a real one.
		{"noop_job", "IsNoopJob"},
		{"noop_job_exit_code", "NoopJobExitCode"},
		{"noop_job_exit_signal", "NoopJobExitSignal"},
	}
	for _, e := range exprs {
		v := sf.submitParam(e.command, e.attr)
		if v == "" {
			continue
		}
		if err := setExprAttr(ad, e.attr, e.command, v); err != nil {
			return err
		}
	}

	if jarFiles := sf.submitParam("jar_files", "JarFiles"); jarFiles != "" {
		_ = ad.Set("JarFiles", jarFiles)
	}
	return nil
}

// setJavaVMArgs stores the arguments handed to the JVM itself, as
// condor_submit's SetJavaVMArgs does.
//
// It is not gated on the java universe: condor_submit reads these keywords
// for every job, and the starter is what decides whether a JVM is involved.
//
// `java_vm_args` and `java_vm_arguments` are two spellings of one setting and
// using both is an error; `java_vm_arguments2` is the V2 form, which may only
// accompany one of the others when allow_arguments_v1 says so.
func (sf *SubmitFile) setJavaVMArgs(ad *classad.ClassAd) error {
	return sf.setArgListAttrs(ad, argListKeywords{
		v1:      "java_vm_args",
		v1Ext:   "java_vm_arguments",
		v2:      "java_vm_arguments2",
		v1Attr:  "JavaVMArgs",
		v2Attr:  "JavaVMArguments",
		altAttr: "JavaVMArgs",
	})
}

// setToolDaemon stores the tool-daemon (TDP) settings, as condor_submit's
// SetTDP does.
//
// tool_daemon_cmd is the gate: without it condor_submit does not look at the
// rest of the family at all, so a file that names only arguments or a
// redirection sets nothing -- and does not even report using both argument
// spellings, which is an error when the daemon itself is named.
//
// The paths are stored exactly as written. SetTDP passes each through
// check_and_universalize_path, which rewrites mapped drive letters on Windows
// and does nothing anywhere else, so there is no Iwd resolution here.
func (sf *SubmitFile) setToolDaemon(ad *classad.ClassAd) error {
	cmd := sf.submitParam("tool_daemon_cmd", "ToolDaemonCmd")
	if cmd == "" {
		return nil
	}
	_ = ad.Set("ToolDaemonCmd", cmd)

	for _, f := range []struct{ command, attr string }{
		{"tool_daemon_input", "ToolDaemonInput"},
		{"tool_daemon_output", "ToolDaemonOutput"},
		{"tool_daemon_error", "ToolDaemonError"},
	} {
		if v := sf.submitParam(f.command, f.attr); v != "" {
			_ = ad.Set(f.attr, v)
		}
	}

	// suspend_job_at_exec has no other reader: condor_submit records it only
	// here, alongside the daemon that is meant to attach to the stopped job.
	if v := sf.submitParam("suspend_job_at_exec", "SuspendJobAtExec"); v != "" {
		_ = ad.Set("SuspendJobAtExec", parseBool(v, false))
	}

	return sf.setArgListAttrs(ad, argListKeywords{
		v1:      "tool_daemon_args",
		v1Ext:   "tool_daemon_arguments",
		v2:      "tool_daemon_arguments2",
		v1Attr:  "ToolDaemonArgs",
		v2Attr:  "ToolDaemonArguments",
		altAttr: "ToolDaemonArgs",
	})
}

// argListKeywords names one family of argument keywords and the two
// attributes it can land in.
//
// Which of the two it lands in is semantic rather than cosmetic: the V1
// attribute is a flat string the starter splits on whitespace, while the V2
// attribute carries single-quoted grouping, so an argument containing a space
// survives only under the V2 name. That is the same split as Args/Arguments.
type argListKeywords struct {
	v1     string // the backward-compatible spelling
	v1Ext  string // the current spelling; the two are mutually exclusive
	v2     string // the V2 spelling, which must be a double-quoted string
	v1Attr string
	v2Attr string
	// altAttr is the attribute name that also works as a submit keyword for
	// v1Ext, the way condor_submit's submit_param() takes an alternate name.
	altAttr string
}

// setArgListAttrs is the half of condor_submit's SetArguments that the
// tool-daemon and java-VM families repeat: read the three spellings, reject
// the combinations condor_submit rejects, and store the result under the V1
// or the V2 attribute depending on which syntax the value was written in.
func (sf *SubmitFile) setArgListAttrs(ad *classad.ClassAd, kw argListKeywords) error {
	v1 := sf.submitParam(kw.v1, "")
	v1Ext := sf.submitParam(kw.v1Ext, kw.altAttr)
	v2 := sf.submitParam(kw.v2, "")

	if v1 != "" && v1Ext != "" {
		return fmt.Errorf("you specified a value for both %s and %s", kw.v1, kw.v1Ext)
	}
	if v1Ext != "" {
		v1 = v1Ext
	}
	if v2 != "" && v1 != "" && !parseBool(sf.submitParam("allow_arguments_v1", ""), false) {
		return fmt.Errorf("if you wish to specify both %s and %s, you must also specify allow_arguments_v1 = true",
			kw.v1Ext, kw.v2)
	}

	var (
		args  []string
		wasV1 bool
		err   error
	)
	switch {
	case v2 != "":
		args, err = parseArgsV2Quoted(v2)
	case v1 != "":
		args, wasV1, err = parseArgsV1WackedOrV2Quoted(v1)
	default:
		return nil
	}
	if err != nil {
		return fmt.Errorf("failed to parse %s: %w", kw.v1Ext, err)
	}

	if wasV1 {
		if value := joinArgsV1(args); value != "" {
			_ = ad.Set(kw.v1Attr, value)
		}
		return nil
	}
	if value := joinArgsV2(args); value != "" {
		_ = ad.Set(kw.v2Attr, value)
	}
	return nil
}

// setPeriodicExpressions writes the periodic and on-exit policy family the
// way SubmitHash::SetPeriodicExpressions does
// (condor_utils/submit_utils.cpp).
//
// Every attribute here is assigned as an EXPRESSION, the reasons and the
// subcodes included. That is what makes `periodic_hold_reason = "too slow"`
// come out as the ClassAd string "too slow" rather than a string whose own
// first and last characters are quotes: nothing strips the quotes, the value
// is parsed and the quotes are the literal's delimiters. The difference
// shows up wherever the reason is read back -- condor_q -hold and the
// HoldReason the schedd copies onto the job both carried the extra quotes --
// and the subcodes are worse, since a subcode stored as a string is not the
// number a policy expression comparing against it expects.
//
// The alternate spelling of each command is its own attribute name, so
// `PeriodicHoldReason = "x"` is as good as `periodic_hold_reason = "x"`.
func (sf *SubmitFile) setPeriodicExpressions(ad *classad.ClassAd) error {
	// on_exit_hold and on_exit_remove are deliberately absent: condor_submit
	// reads both in SetJobRetries, where the retry settings can override
	// them. See setJobRetries.
	for _, p := range []struct{ command, alt, attr string }{
		{"periodic_hold", "PeriodicHold", "PeriodicHold"},
		{"periodic_hold_reason", "PeriodicHoldReason", "PeriodicHoldReason"},
		{"periodic_hold_subcode", "PeriodicHoldSubCode", "PeriodicHoldSubCode"},
		{"periodic_release", "PeriodicRelease", "PeriodicRelease"},
		{"periodic_remove", "PeriodicRemove", "PeriodicRemove"},
		{"periodic_vacate", "PeriodicVacate", "PeriodicVacate"},
		{"on_exit_hold_reason", "OnExitHoldReason", "OnExitHoldReason"},
		{"on_exit_hold_subcode", "OnExitHoldSubCode", "OnExitHoldSubCode"},
	} {
		value := sf.submitParam(p.command, p.alt)
		if err := setExprAttr(ad, p.attr, p.command, value); err != nil {
			return err
		}
	}

	if err := sf.setJobRetries(ad); err != nil {
		return err
	}

	return sf.setCronAndDeferral(ad)
}

// Deferral timing defaults, from JOB_DEFERRAL_WINDOW_DEFAULT and
// JOB_DEFERRAL_PREP_TIME_DEFAULT in HTCondor's submit_utils.h. condor_submit
// writes both attributes onto every deferred job, so a job that asks for a
// schedule but no window still carries the pair the starter reads.
const (
	deferralWindowDefault   = 0
	deferralPrepTimeDefault = 300
)

// deferralTriggerAttrs are the attributes whose presence makes a job a
// deferred job, in the order SubmitHash::NeedsJobDeferral checks them. Once
// one of them is on the ad, the window and prep time are written too --
// defaulted when the submit file is silent about them.
var deferralTriggerAttrs = []string{
	"CronMinute", "CronHour", "CronDayOfMonth", "CronMonth", "CronDayOfWeek",
	"DeferralTime",
}

// setCronAndDeferral sets the cron_* and deferral_* attributes, following
// SubmitHash::SetJobDeferral.
//
// Three things here are not obvious from the submit commands' names:
//
//   - cron_window and deferral_window are two spellings of ONE attribute,
//     DeferralWindow, and cron_prep_time and deferral_prep_time are two
//     spellings of DeferralPrepTime. There is no CronWindow or CronPrepTime
//     job attribute; writing those names left the schedule in the ad and the
//     timing nowhere the starter looks, so a cron job never deferred. The
//     cron_ spelling wins when both are given.
//   - the window and the prep time are written only for a job that is
//     actually deferred -- one with a cron schedule or a deferral_time. A
//     cron_window on its own sets nothing.
//   - the timing values are expressions, not integers: `(time() + 3600)` is a
//     legal deferral_time. A LITERAL one has to be a non-negative integer,
//     and condor_submit rejects the submit file when it is not.
func (sf *SubmitFile) setCronAndDeferral(ad *classad.ClassAd) error {
	if v := sf.submitParam("deferral_time", "DeferralTime"); v != "" {
		if err := setDeferralExpr(ad, "DeferralTime", "deferral_time", v); err != nil {
			return err
		}
	}

	deferred := false
	for _, attr := range deferralTriggerAttrs {
		if _, ok := ad.Lookup(attr); ok {
			deferred = true
			break
		}
	}
	if !deferred {
		return nil
	}

	window := sf.submitParam("cron_window", "CronWindow")
	command := "cron_window"
	if window == "" {
		window, command = sf.submitParam("deferral_window", "DeferralWindow"), "deferral_window"
	}
	if window != "" {
		if err := setDeferralExpr(ad, "DeferralWindow", command, window); err != nil {
			return err
		}
	} else {
		_ = ad.Set("DeferralWindow", int64(deferralWindowDefault))
	}

	prep := sf.submitParam("cron_prep_time", "CronPrepTime")
	command = "cron_prep_time"
	if prep == "" {
		prep, command = sf.submitParam("deferral_prep_time", "DeferralPrepTime"), "deferral_prep_time"
	}
	if prep != "" {
		if err := setDeferralExpr(ad, "DeferralPrepTime", command, prep); err != nil {
			return err
		}
	} else {
		_ = ad.Set("DeferralPrepTime", int64(deferralPrepTimeDefault))
	}

	return nil
}

// setDeferralExpr stores one deferral timing value as an expression and
// applies the check SetJobDeferral applies: a value that is a literal has to
// be a non-negative integer. A non-literal expression is stored unchecked,
// since only the starter can evaluate it.
func setDeferralExpr(ad *classad.ClassAd, attr, command, value string) error {
	expr, err := classad.ParseExpr(value)
	if err != nil {
		return fmt.Errorf("%s = %s is invalid, must eval to a non-negative integer", command, value)
	}
	if n, isInt, isLiteral := literalInteger(value); isLiteral && (!isInt || n < 0) {
		return fmt.Errorf("%s = %s is invalid, must eval to a non-negative integer", command, value)
	}
	_ = ad.Set(attr, expr)
	return nil
}

// defaultJobMaxRetries is the built-in default of the DEFAULT_JOB_MAX_RETRIES
// config knob: how many times a job retries when the submit file turned
// retries on without saying how many.
const defaultJobMaxRetries = 2

// retryExprPrefix is the fixed head of the OnExitRemove expression
// condor_submit builds for a retrying job: stop once the job has completed
// more times than it is allowed to retry, or once it exits with a code that
// counts as done. The exit-code half is filled in by setJobRetries.
const retryExprPrefix = "NumJobCompletions > JobMaxRetries || ExitCode =?= "

// setJobRetries writes JobMaxRetries, JobSuccessExitCode, OnExitHold and
// OnExitRemove, following SubmitHash::SetJobRetries.
//
// The four settings are entangled, which is why they are not handled where
// their submit commands are read:
//
//   - max_retries, success_exit_code and retry_until each turn retries ON by
//     themselves. With retries on, a job that did not say max_retries still
//     gets JobMaxRetries (DEFAULT_JOB_MAX_RETRIES), and one that did not say
//     on_exit_hold still gets OnExitHold = false.
//   - retry_until is NOT a job attribute. A plain integer becomes a futility
//     exit code (`ExitCode =?= 42`); anything else is used as the expression
//     it is. Either way it is folded into OnExitRemove, and a job ad carrying
//     a RetryUntil attribute is carrying something nothing reads.
//   - with retries on, OnExitRemove is REPLACED by the generated expression,
//     and the submitter's own on_exit_remove is OR'd onto the end of it.
//     Keeping only the submitter's expression -- which is what the Go parser
//     did -- removes the job on its first failure, so it never retries.
//
// An OnExitRemove the submitter set directly, with +OnExitRemove or
// MY.OnExitRemove, is left alone unless success_exit_code or retry_until
// asked for a change. That is why this runs after the +Attr pass.
func (sf *SubmitFile) setJobRetries(ad *classad.ClassAd) error {
	erc := sf.submitParam("on_exit_remove", "OnExitRemove")
	ehc := sf.submitParam("on_exit_hold", "OnExitHold")

	enableRetries := false

	var numRetries int64
	numRetriesSpecified := false
	if v := sf.submitParam("max_retries", "JobMaxRetries"); v != "" {
		n, ok := evalLongParam(v)
		if !ok {
			return fmt.Errorf("max_retries = %s is invalid, must eval to an integer", v)
		}
		numRetries, numRetriesSpecified, enableRetries = n, true, true
	}

	var successCode int64
	successExitCodeSet := false
	if v := sf.submitParam("success_exit_code", "JobSuccessExitCode"); v != "" {
		n, ok := evalLongParam(v)
		if !ok || n < math.MinInt32 || n >= math.MaxInt32 {
			return fmt.Errorf("success_exit_code = %s is invalid, must eval to an integer", v)
		}
		successCode, successExitCodeSet, enableRetries = n, true, true
	}

	retryUntil := sf.submitParam("retry_until", "")
	if retryUntil != "" {
		enableRetries = true
	}

	if !enableRetries {
		if err := setExprAttr(ad, "OnExitRemove", "on_exit_remove", erc); err != nil {
			return err
		}
		return setExprAttr(ad, "OnExitHold", "on_exit_hold", ehc)
	}

	if retryUntil != "" {
		folded, err := foldRetryUntil(retryUntil)
		if err != nil {
			return err
		}
		retryUntil = folded
	}

	if !numRetriesSpecified {
		if _, ok := ad.Lookup("JobMaxRetries"); !ok {
			numRetries, numRetriesSpecified = defaultJobMaxRetries, true
		}
	}
	if numRetriesSpecified {
		_ = ad.Set("JobMaxRetries", numRetries)
	}

	if ehc == "" {
		if _, ok := ad.Lookup("OnExitHold"); !ok {
			_ = ad.Set("OnExitHold", false)
		}
	} else if err := setExprAttr(ad, "OnExitHold", "on_exit_hold", ehc); err != nil {
		return err
	}

	// An OnExitRemove already on the ad stands, unless success_exit_code or
	// retry_until named a change to it.
	if _, ok := ad.Lookup("OnExitRemove"); ok && !successExitCodeSet && retryUntil == "" {
		return nil
	}

	codeCheck := strconv.FormatInt(successCode, 10)
	if successExitCodeSet {
		_ = ad.Set("JobSuccessExitCode", successCode)
		codeCheck = "JobSuccessExitCode"
	}
	if retryUntil != "" {
		codeCheck += " || " + retryUntil
	}

	onExitRemove := retryExprPrefix + codeCheck
	if erc != "" {
		wrapped, err := wrapExprForOr(erc)
		if err != nil {
			return fmt.Errorf("on_exit_remove = %s is invalid, it must be a boolean expression", erc)
		}
		onExitRemove += " || " + wrapped
	}
	return setExprAttr(ad, "OnExitRemove", "on_exit_remove", onExitRemove)
}

// foldRetryUntil turns a retry_until value into the clause that goes into
// OnExitRemove.
//
// A value that names no attribute and evaluates to an integer is a futility
// exit code -- the code that means "do not bother retrying" -- so it becomes
// a comparison against ExitCode. Everything else is used as the boolean
// expression it is.
func foldRetryUntil(value string) (string, error) {
	invalid := fmt.Errorf("retry_until = %s is invalid, it must be an integer or boolean expression", value)

	expr, err := classad.ParseExpr(value)
	if err != nil {
		return "", invalid
	}
	scratch := classad.New()
	if len(scratch.ExternalRefs(expr)) == 0 && len(scratch.InternalRefs(expr)) == 0 {
		if code, ok := evalLongParam(value); ok {
			if code < math.MinInt32 || code > math.MaxInt32 {
				return "", invalid
			}
			return "ExitCode =?= " + strconv.FormatInt(code, 10), nil
		}
	}
	wrapped, werr := wrapExprForOr(value)
	if werr != nil {
		return "", invalid
	}
	return wrapped, nil
}

// wrapExprForOr parenthesizes an expression only when it would otherwise
// lose its grouping under an `||` joined onto it -- WrapExprTreeInParensForOp
// in compat_classad_util.cpp.
//
// Every ClassAd operator binds at least as tightly as `||` except the ternary
// `? :`, so the ternary is the only shape that needs the parentheses. Adding
// them anywhere else would change the expression TREE (`a || (b || c)` rather
// than `(a || b) || c`) even though the value is the same.
func wrapExprForOr(value string) (string, error) {
	expr, err := classad.ParseExpr(value)
	if err != nil {
		return "", err
	}
	scratch := classad.New()
	scratch.InsertExpr("X", expr)
	tree := scratch.AST()
	if tree == nil || len(tree.Attributes) != 1 {
		return "(" + value + ")", nil
	}
	if _, ternary := tree.Attributes[0].Value.(*ast.ConditionalExpr); ternary {
		return "(" + value + ")", nil
	}
	return value, nil
}

// submitParam reads a submit command the way SubmitHash::submit_param does: a
// command whose value expands to nothing counts as UNSET, and an empty
// primary suppresses the alternate spelling rather than deferring to it.
// Pass "" for altKey when the command has no alternate.
func (sf *SubmitFile) submitParam(key, altKey string) string {
	var (
		v  string
		ok bool
	)
	if altKey == "" {
		v, ok = sf.submitCommand(key)
	} else {
		v, ok = sf.submitCommandAlt(key, altKey)
	}
	if !ok {
		return ""
	}
	return strings.TrimSpace(v)
}

// evalLongParam is string_is_long_param (condor_config.cpp): a plain decimal
// integer, or failing that an expression evaluated in an empty scope, with
// booleans and reals coerced to an integer the way EvalInteger coerces them.
// It is what lets `max_retries = 2+3` mean five.
func evalLongParam(value string) (int64, bool) {
	s := strings.TrimSpace(value)
	n, err := strconv.ParseInt(s, 10, 64)
	if err == nil {
		return n, true
	}
	if errors.Is(err, strconv.ErrRange) {
		// strtoll saturates rather than failing, and so does ParseInt:
		// n already holds the saturated value.
		return n, true
	}
	expr, perr := classad.ParseExpr(s)
	if perr != nil {
		return 0, false
	}
	v := expr.Eval(classad.New())
	switch {
	case v.IsInteger():
		i, _ := v.IntValue()
		return i, true
	case v.IsBool():
		b, _ := v.BoolValue()
		if b {
			return 1, true
		}
		return 0, true
	case v.IsReal():
		f, _ := v.RealValue()
		return int64(f), true
	}
	return 0, false
}

// literalInteger reports whether a value is a ClassAd LITERAL -- a constant
// with no operators, parentheses aside -- and if so whether it is an integer
// and what its value is. It is the Go side of ExprTreeIsLiteral followed by
// Value::IsIntegerValue, which is how condor_submit decides whether a timing
// value is something it can range-check at submit time.
//
// `1 + 1` is deliberately NOT a literal: condor_submit stores it unchecked
// and lets the starter evaluate it.
func literalInteger(value string) (n int64, isInt bool, isLiteral bool) {
	s := stripOuterParens(value)
	if i, err := strconv.ParseInt(s, 10, 64); err == nil {
		return i, true, true
	}
	switch {
	case strings.EqualFold(s, "true"), strings.EqualFold(s, "false"),
		strings.EqualFold(s, "undefined"), strings.EqualFold(s, "error"):
		return 0, false, true
	case len(s) >= 2 && s[0] == '"' && s[len(s)-1] == '"':
		return 0, false, true
	}
	if _, err := strconv.ParseFloat(s, 64); err == nil {
		return 0, false, true
	}
	return 0, false, false
}

// stripOuterParens removes parentheses that wrap the whole expression, the
// way ExprTreeIsLiteral dives through PARENTHESES_OP nodes. A leading '(' that
// closes before the end -- `(a) + (b)` -- wraps only part of the expression
// and is left alone.
func stripOuterParens(s string) string {
	for {
		s = strings.TrimSpace(s)
		if len(s) < 2 || s[0] != '(' || s[len(s)-1] != ')' {
			return s
		}
		depth := 0
		wrapsAll := true
		for i := 0; i < len(s); i++ {
			switch s[i] {
			case '(':
				depth++
			case ')':
				depth--
				if depth == 0 && i != len(s)-1 {
					wrapsAll = false
				}
			}
			if !wrapsAll {
				break
			}
		}
		if !wrapsAll {
			return s
		}
		s = s[1 : len(s)-1]
	}
}

// setAutoAttributes sets auto-generated attributes
func (sf *SubmitFile) setAutoAttributes(ad *classad.ClassAd) error {
	// IWD (Initial Working Directory). Absolute even when the submit
	// file gives a relative initialdir or none at all, which is what
	// every path recorded against it -- UserLog above all -- depends on.
	iwd, err := sf.jobIwd()
	if err != nil {
		return err
	}
	_ = ad.Set("Iwd", iwd)

	// Owner - the user submitting the job
	// This would typically come from the authenticated user
	if owner, ok := sf.submitCommand("owner"); ok {
		_ = ad.Set("Owner", owner)
	}

	// QDate - Time job was submitted (in Unix epoch seconds)
	// We'll set this when actually submitting
	// For now, just note that it should be set

	// CompletionDate - Time job completed
	// This is set by the schedd, not by us

	// JobStartDate - Time job started executing
	// This is set by the startd/schedd, not by us

	// EnteredCurrentStatus - Time job entered current status
	// This is managed by the schedd

	// JobCurrentStartDate - Time of most recent start
	// This is managed by the schedd

	// CurrentHosts - Machines currently running the job
	// This is managed by the schedd

	// NumJobStarts - Number of times job has started
	// Initialize to 0
	_ = ad.Set("NumJobStarts", 0)

	// NumRestarts - Number of times job has been restarted
	// Initialize to 0
	_ = ad.Set("NumRestarts", 0)

	// NumSystemHolds - Number of times placed on hold by system
	// Initialize to 0
	_ = ad.Set("NumSystemHolds", 0)

	// JobRunCount - Number of times job has run
	// Initialize to 0
	_ = ad.Set("JobRunCount", 0)

	// The starter ignores the checkpoint exit code unless the job also
	// asks for file transfer on checkpoint, so condor_submit turns the
	// flag on for any job that named one (SubmitHash::SetAutoAttributes).
	// Without it a self-checkpointing job exited with its checkpoint
	// code, nothing was transferred, and the exit looked like an
	// ordinary one.
	if _, ok := sf.submitCommand("checkpoint_exit_code"); ok {
		_ = ad.Set("WantFTOnCheckpoint", true)
	} else if _, ok := ad.Lookup("SuccessCheckpointExitCode"); ok {
		_ = ad.Set("WantFTOnCheckpoint", true)
	}

	sf.setTransferPluginMethods(ad)
	sf.deriveStarterDebug(ad)
	sf.applyJobLeaseFloor(ad)

	return nil
}

// transferPluginGate reports whether this job is one condor_submit would
// derive WantTransferPluginMethods for.
//
// SetRequirements only reaches that derivation when mightTransfer() is
// true for the universe (vanilla, mpi, parallel, java and vm -- not
// grid, local or scheduler), when ShouldTransferFiles is not NO, and
// when the submitter's own `requirements` does not already name
// HasFileTransfer or HasJobTransferPlugins.
func (sf *SubmitFile) transferPluginGate(ad *classad.ClassAd) bool {
	switch sf.universe {
	case UniverseVanilla, UniverseParallel, UniverseJava, UniverseVM:
	default:
		// MPI has no constant here and parseUniverse never yields it.
		return false
	}

	if should, ok := ad.EvaluateAttrString("ShouldTransferFiles"); ok {
		if v, valid := shouldTransferFilesNum(should); valid && v == stfNo {
			return false
		}
	}

	// condor_submit decides this from the attribute references it pulls
	// out of the parsed Requirements; naming either attribute suppresses
	// the generated transfer clause and the attribute with it, whether
	// the reference is bare, TARGET.-qualified or MY.-qualified. Matching
	// the identifier in the text the submitter wrote reaches the same
	// answer without a second expression walk.
	req, ok := sf.submitCommand("requirements")
	if !ok {
		return true
	}
	return !namesIdentifier(req, "HasFileTransfer") && !namesIdentifier(req, "HasJobTransferPlugins")
}

// namesIdentifier reports whether expr contains name as a whole
// identifier, ignoring case. A longer attribute that merely starts with
// the same letters -- HasFileTransferPluginMethods, which condor_submit
// counts separately -- must not match.
func namesIdentifier(expr, name string) bool {
	isWord := func(c byte) bool {
		return c == '_' || (c >= '0' && c <= '9') ||
			(c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z')
	}
	lower, target := strings.ToLower(expr), strings.ToLower(name)
	for i := 0; ; {
		j := strings.Index(lower[i:], target)
		if j < 0 {
			return false
		}
		start := i + j
		end := start + len(target)
		beforeOK := start == 0 || !isWord(lower[start-1])
		afterOK := end == len(lower) || !isWord(lower[end])
		if beforeOK && afterOK {
			return true
		}
		i = start + 1
	}
}

// setTransferPluginMethods writes WantTransferPluginMethods: the file
// transfer plugin methods the job NEEDS but does not bring with it.
//
// condor_submit builds it in SetRequirements from the URL schemes it
// finds in TransferInput, OutputDestination and the right-hand sides of
// TransferOutputRemaps, minus the methods the job supplies itself in
// TransferPlugins -- which is the direction that is easy to get
// backwards: transfer_plugins SUBTRACTS from this list rather than
// filling it. The startd advertises HasFileTransferPluginMethods, so a
// job that never says it needs `osdf` can match a machine with no osdf
// plugin and fail its input transfer there.
//
// It runs after the custom-attribute pass for the same reason the C++
// does: `+TransferInput = "http://..."` names a URL the job will fetch
// just as much as transfer_input_files does.
func (sf *SubmitFile) setTransferPluginMethods(ad *classad.ClassAd) {
	if !sf.transferPluginGate(ad) {
		return
	}

	// Methods the job brings. TransferPlugins is "TAR=mytarplugin;
	// HTTP,HTTPS=myhttpplugin": each group before its "=" is a list of
	// method names, separated by commas or whitespace.
	supplied := map[string]bool{}
	if plugins, ok := ad.EvaluateAttrString("TransferPlugins"); ok {
		for _, group := range strings.Split(plugins, ";") {
			eq := strings.Index(group, "=")
			if eq < 0 {
				continue
			}
			for _, m := range strings.FieldsFunc(group[:eq], func(r rune) bool {
				return r == ',' || r == ' ' || r == '\t'
			}) {
				supplied[strings.ToLower(m)] = true
			}
		}
	}

	// Methods the job needs, in the order condor_submit visits them. The
	// set is case-insensitive and keeps the first spelling it saw.
	var wanted []string
	seen := map[string]bool{}
	add := func(s string) {
		scheme, ok := submitURLScheme(s)
		if !ok || supplied[strings.ToLower(scheme)] || seen[strings.ToLower(scheme)] {
			return
		}
		seen[strings.ToLower(scheme)] = true
		wanted = append(wanted, scheme)
	}

	if files, ok := ad.EvaluateAttrString("TransferInput"); ok {
		for _, f := range strings.Split(files, ",") {
			add(f)
		}
	}
	if dest, ok := ad.EvaluateAttrString("OutputDestination"); ok {
		add(dest)
	}
	if remaps, ok := ad.EvaluateAttrString("TransferOutputRemaps"); ok {
		for _, remap := range strings.Split(remaps, ";") {
			if eq := strings.Index(remap, "="); eq >= 0 {
				add(strings.TrimSpace(remap[eq+1:]))
			}
		}
	}

	if len(wanted) == 0 {
		return
	}
	sort.Slice(wanted, func(i, j int) bool {
		return strings.ToLower(wanted[i]) < strings.ToLower(wanted[j])
	})
	_ = ad.Set("WantTransferPluginMethods", strings.Join(wanted, ","))
}

// submitURLScheme mirrors IsUrl() and getURLType(url, true) from
// src/condor_utils/condor_url.cpp: it reports the scheme of a string
// HTCondor would treat as a URL, and whether it is one at all.
//
// HTCondor is stricter than RFC 3986 here -- it insists on the "//"
// authority marker and on something after it -- and the scheme it
// reports is the part AFTER the last '+', '-' or '.', so a
// `chtc+https://` URL needs the `https` plugin. Case is preserved,
// because the attribute is built from the spelling the submitter used.
func submitURLScheme(s string) (string, bool) {
	isAlpha := func(c byte) bool {
		return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z')
	}
	if s == "" || !isAlpha(s[0]) {
		return "", false
	}
	isSchemeChar := func(c byte) bool {
		return isAlpha(c) || (c >= '0' && c <= '9') || c == '+' || c == '-' || c == '.'
	}
	i := 1
	for i < len(s) && isSchemeChar(s[i]) {
		i++
	}
	if i+3 >= len(s) || s[i] != ':' || s[i+1] != '/' || s[i+2] != '/' {
		return "", false
	}
	start := 0
	for j := i; j > 0; j-- {
		if c := s[j]; c == '+' || c == '-' || c == '.' {
			start = j + 1
			break
		}
	}
	return s[start:i], true
}

// deriveStarterDebug turns the starter's own debug log on for a job that
// asked for the log file but not for the flags to write it with:
// SubmitHash::SetAutoAttributes defaults JobStarterDebug to true whenever
// JobStarterLog is set and JobStarterDebug is not, which means "use the
// pool's STARTER_DEBUG flags". Without it the file named by `starter_log` is
// never written, so a submitter debugging a job gets an empty hand.
//
// The trigger is read from the submit keywords rather than from the ad
// because of WHERE SetAutoAttributes sits: it runs before the `+Attr` pass,
// so `+JobStarterLog = "x"` does not derive anything on the C++ side, and
// reading the ad here -- after this parser's `+Attr` pass -- would.
// simpleKeywordParam is the same gate the keyword pass itself uses, including
// its second accepted spelling (the attribute name) and its rule that a value
// expanding to nothing means the file did not set it.
func (sf *SubmitFile) deriveStarterDebug(ad *classad.ClassAd) {
	if _, ok := sf.simpleKeywordParam("starter_log", "JobStarterLog"); !ok {
		return
	}
	if _, ok := sf.simpleKeywordParam("starter_debug", "JobStarterDebug"); ok {
		return
	}
	_ = ad.Set("JobStarterDebug", true)
}

// jobLeaseFloor is the shortest job lease condor_submit will record. A lease
// below it is rejected with a warning and replaced
// (SubmitHash::ReportCommonMistakes), because a claim lease of a few seconds
// expires before the schedd can reconnect to a disconnected job and the job
// is thrown back into the queue instead of resuming.
const jobLeaseFloor = 20

// applyJobLeaseFloor raises a short job_lease_duration to jobLeaseFloor.
//
// Only a literal number is raised, and only after truncation toward zero:
// ReportCommonMistakes tests the expression with ExprTreeIsLiteralNumber into
// a long long, so `19.9` is 19 and is raised while `0.5` is 0 and is left
// alone, `4 + 5` is not a literal at all and is stored unchecked, and a
// quoted "5" is a string rather than a number. Zero and negative values are
// left alone too: they are the documented ways to ask for no lease.
//
// Gated on the submit keyword for the same reason deriveStarterDebug is: the
// C++ check runs before the `+Attr` pass, so `+JobLeaseDuration = 5` keeps
// its 5.
func (sf *SubmitFile) applyJobLeaseFloor(ad *classad.ClassAd) {
	if _, ok := sf.simpleKeywordParam("job_lease_duration", "JobLeaseDuration"); !ok {
		return
	}
	expr, ok := ad.Lookup("JobLeaseDuration")
	if !ok || expr == nil {
		return
	}
	n, isNum := literalNumberTruncated(expr.String())
	if isNum && n > 0 && n < jobLeaseFloor {
		_ = ad.Set("JobLeaseDuration", jobLeaseFloor)
	}
}

// literalNumberTruncated is ExprTreeIsLiteralNumber(expr, long long &): a
// ClassAd literal that is a number, with a real truncated toward zero and a
// boolean counted as 0 or 1. A string literal is not a number, and anything
// built with an operator is not a literal.
func literalNumberTruncated(value string) (int64, bool) {
	s := stripOuterParens(value)
	if i, err := strconv.ParseInt(s, 10, 64); err == nil {
		return i, true
	}
	switch {
	case strings.EqualFold(s, "true"):
		return 1, true
	case strings.EqualFold(s, "false"):
		return 0, true
	}
	// A real. ParseFloat also accepts spellings ClassAd's lexer does not
	// ("inf", "0x1p3"), so those are turned away rather than truncated into
	// a number the C++ side never saw.
	if strings.ContainsAny(s, "xXpPnNiI") {
		return 0, false
	}
	f, err := strconv.ParseFloat(s, 64)
	if err != nil || math.IsInf(f, 0) || math.IsNaN(f) {
		return 0, false
	}
	return int64(f), true
}

// Submit submits the jobs from this submit file
// Returns the cluster ID and number of procs created
func (sf *SubmitFile) Submit(clusterID int) (*SubmitResult, error) {
	// One submission, one QDate: see stampSubmitTime.
	sf.submitTime = 0

	result := &SubmitResult{
		ClusterID: clusterID,
		NumProcs:  sf.queueCount,
		ProcAds:   make([]*classad.ClassAd, 0, sf.queueCount),
	}

	// Iterate through queue items to create job ads
	proc := 0
	for sf.queueIterator.Next() {
		queueVars := sf.queueIterator.Values()

		jobID := JobID{Cluster: clusterID, Proc: proc}
		procAd, err := sf.MakeJobAd(jobID, queueVars)
		if err != nil {
			return nil, fmt.Errorf("failed to create proc %d ad: %w", proc, err)
		}

		if proc == 0 {
			result.ClusterAd = procAd
		}
		result.ProcAds = append(result.ProcAds, procAd)
		proc++
	}

	return result, nil
}

// pushMacroContext sets up live macros for job ad creation
// These are HTCondor-specific macros that change with each job/proc
func (sf *SubmitFile) pushMacroContext(jobID JobID, queueVars map[string]string) {
	// Set standard HTCondor submit-time macros
	// These are "live" values that change for each proc
	sf.cfg.Set("Cluster", strconv.Itoa(jobID.Cluster))
	sf.cfg.Set("Process", strconv.Itoa(jobID.Proc))
	sf.cfg.Set("ProcId", strconv.Itoa(jobID.Proc))       // Alias for Process
	sf.cfg.Set("ClusterId", strconv.Itoa(jobID.Cluster)) // Alias for Cluster
	sf.cfg.Set("Node", strconv.Itoa(jobID.Proc))         // Alias for Process (parallel universe)

	// Set queue-specific macros
	for varName, varValue := range queueVars {
		sf.cfg.Set(varName, varValue)
	}

	// Set Item, Step, Row if they're in queueVars
	// These are used with queue from/in statements
	//
	// Item is NOT an alias for ItemIndex. It is the default name of the
	// queue statement's loop variable, so it holds the item's VALUE, and the
	// loop above already set it when the statement named no variable of its
	// own. A statement that did name one leaves Item unset, which is what
	// HTCondor does: $(Item) is empty under `queue 2 x in (a, b)`.
	if itemIndex, ok := queueVars["ItemIndex"]; ok {
		sf.cfg.Set("ItemIndex", itemIndex)
	} else {
		// If not in queue vars, default to process ID
		sf.cfg.Set("ItemIndex", strconv.Itoa(jobID.Proc))
	}

	if step, ok := queueVars["Step"]; ok {
		sf.cfg.Set("Step", step)
	} else {
		sf.cfg.Set("Step", strconv.Itoa(jobID.Proc))
	}

	if row, ok := queueVars["Row"]; ok {
		sf.cfg.Set("Row", row)
	} else {
		sf.cfg.Set("Row", strconv.Itoa(jobID.Proc))
	}
}

// popMacroContext cleans up after job ad creation
// Note: In current implementation, we don't need to restore values
// because each Submit() call gets fresh macro values
func (sf *SubmitFile) popMacroContext() {
	// Currently a no-op since we don't cache and restore
	// In a full implementation, this would restore saved values
}

// MakeClusterAd creates a cluster ad with common attributes for all jobs
// This is part of late materialization - the cluster ad serves as a template
func (sf *SubmitFile) MakeClusterAd(clusterID int) (*classad.ClassAd, error) {
	// Create a cluster ad using ProcId = -1 (HTCondor convention)
	clusterJobID := JobID{Cluster: clusterID, Proc: -1}

	// For late materialization, we create the first proc ad and use it as template
	// In true late materialization, only common attributes go in cluster ad
	// but for simplicity, we'll create a full ad with Proc 0
	return sf.MakeJobAd(clusterJobID, map[string]string{})
}

// MakeProcAd creates a proc-specific ad given a cluster ad template
// This is used in late materialization to create individual proc ads efficiently
func (sf *SubmitFile) MakeProcAd(clusterID int, procID int, queueVars map[string]string) (*classad.ClassAd, error) {
	jobID := JobID{Cluster: clusterID, Proc: procID}
	return sf.MakeJobAd(jobID, queueVars)
}

// SubmitLate submits the jobs from this submit file as a job factory when
// the file asks to be submitted as one, and exactly as Submit does when it
// does not.
//
// A file that sets max_materialize, max_idle or materialize_max_idle is
// asking the schedd to materialize its procs itself. For one, the result
// carries a Factory and no proc ads: the submission is the cluster ad, the
// itemdata rows and the submit digest, which is a handful of round trips
// whatever the job count. For any other file there is nothing to late
// materialize, so this builds the same per-proc ads Submit does.
func (sf *SubmitFile) SubmitLate(clusterID int) (*SubmitResult, error) {
	// One submission, one QDate: see stampSubmitTime.
	sf.submitTime = 0

	// Built before the cluster ad, as condor_submit builds it. condor_submit
	// has to: it reads the first row without making the loop variables live,
	// because its digest is a dump of a macro table that a live row would
	// have written into. This does not have to -- the digest protects the
	// per-proc knobs by name during expansion, so it comes out the same
	// wherever the iterator is -- but the order is kept so the two can be
	// read against each other.
	factory, err := sf.Factory(clusterID)
	if err != nil {
		return nil, err
	}
	if factory == nil {
		return sf.Submit(clusterID)
	}

	result := &SubmitResult{
		ClusterID: clusterID,
		NumProcs:  sf.queueCount,
		Factory:   factory,
	}

	// condor_submit still sends a cluster ad, built with the first row's
	// loop variables live, and the schedd chains every proc it materializes
	// to it.
	queueVars := map[string]string{}
	if sf.queueIterator.Next() {
		queueVars = sf.queueIterator.Values()
	}
	clusterAd, err := sf.MakeJobAd(JobID{Cluster: clusterID, Proc: 0}, queueVars)
	if err != nil {
		return nil, fmt.Errorf("failed to create cluster ad: %w", err)
	}
	result.ClusterAd = clusterAd

	return result, nil
}

// expandSubmitMacros expands HTCondor submit-specific macros in a string
// This is a helper for explicit macro expansion when needed
func (sf *SubmitFile) expandSubmitMacros(value string, jobID JobID, queueVars map[string]string) string {
	// Common submit-time macros that might not be in config
	macros := map[string]string{
		"Cluster":   strconv.Itoa(jobID.Cluster),
		"ClusterId": strconv.Itoa(jobID.Cluster),
		"Process":   strconv.Itoa(jobID.Proc),
		"ProcId":    strconv.Itoa(jobID.Proc),
		"Node":      strconv.Itoa(jobID.Proc),
	}

	// Add queue variables
	for k, v := range queueVars {
		macros[k] = v
	}

	// Simple macro expansion (real implementation would use config.expandMacros)
	result := value
	for macro, replacement := range macros {
		result = strings.ReplaceAll(result, "$("+macro+")", replacement)
	}

	return result
}

// setSignalHandling writes the kill-signal family the way
// SubmitHash::SetKillSig does (condor_utils/submit_utils.cpp).
//
// Every one of these attributes holds a signal NAME, not a number -- see
// fixupKillSigName, which does the conversion and the validation.
//
// `kill_sig` alone has a default, and it depends on the universe: a vanilla
// job gets no KillSig at all, and every other universe gets "SIGTERM". The
// difference is not cosmetic. The vanilla starter decides the soft-kill
// signal for itself (SIGTERM for a bare job, but the container runtime's own
// stop signal for a docker or container job), so writing "SIGTERM" onto a
// vanilla job overrides a choice the starter was meant to make, while leaving
// it off a scheduler- or local-universe job leaves the shadow with no signal
// to send on condor_rm.
func (sf *SubmitFile) setSignalHandling(ad *classad.ClassAd) error {
	killSig, err := fixupKillSigName("kill_sig", sf.submitParam("kill_sig", "KillSig"))
	if err != nil {
		return err
	}
	if killSig == "" && sf.universe != UniverseVanilla {
		killSig = "SIGTERM"
	}
	if killSig != "" {
		_ = ad.Set("KillSig", killSig)
	}

	for _, sig := range []struct{ command, alt, attr string }{
		{"remove_kill_sig", "RemoveKillSig", "RemoveKillSig"},
		{"hold_kill_sig", "HoldKillSig", "HoldKillSig"},
	} {
		name, err := fixupKillSigName(sig.command, sf.submitParam(sig.command, sig.alt))
		if err != nil {
			return err
		}
		if name != "" {
			_ = ad.Set(sig.attr, name)
		}
	}

	// kill_sig_timeout is read with atoi(), so a value that is not a
	// number is 0 rather than an error, and the attribute is written
	// whenever the command is present at all.
	if timeout := sf.submitParam("kill_sig_timeout", "KillSigTimeout"); timeout != "" {
		_ = ad.Set("KillSigTimeout", cAtoi(timeout))
	}

	return nil
}

// setSimpleJobExprs sets simple job expression attributes
// These are standard HTCondor job attributes that are commonly used
func (sf *SubmitFile) setSimpleJobExprs(ad *classad.ClassAd) error {
	// image_size - disk image size in KiB (often auto-calculated)
	if imageSize, ok := sf.submitCommand("image_size"); ok {
		if err := setSizeAttr(ad, "ImageSize", imageSize, unitKiB); err != nil {
			return err
		}
	}

	// executable_size - size of executable in KiB
	if execSize, ok := sf.submitCommand("executable_size"); ok {
		if err := setSizeAttr(ad, "ExecutableSize", execSize, unitKiB); err != nil {
			return err
		}
	}

	// disk_usage - disk usage in KiB
	if diskUsage, ok := sf.submitCommand("disk_usage"); ok {
		if err := setSizeAttr(ad, "DiskUsage", diskUsage, unitKiB); err != nil {
			return err
		}
	}

	// JobNotification - when to send email
	if notification, ok := sf.submitCommand("notification"); ok {
		// Convert notification string to integer code
		notifCode := 0
		switch strings.ToLower(notification) {
		case "always":
			notifCode = 1
		case "complete":
			notifCode = 2
		case "error":
			notifCode = 3
		case "never":
			notifCode = 0
		default:
			// Try parsing as integer
			if intNotif, err := parseInt(notification); err == nil {
				notifCode = intNotif
			}
		}
		_ = ad.Set("JobNotification", notifCode)
	}

	// WantRemoteIO - request remote I/O
	if wantIO, ok := sf.submitCommand("want_remote_io"); ok {
		_ = ad.Set("WantRemoteIO", parseBool(wantIO, false))
	}

	// WantRemoteSyscalls - request remote system calls
	if wantSyscalls, ok := sf.submitCommand("want_remote_syscalls"); ok {
		_ = ad.Set("WantRemoteSyscalls", parseBool(wantSyscalls, false))
	}

	// Streaming stdin/stdout/stderr.
	//
	// The attribute names are HTCondor's, not the submit commands'.
	// ATTR_STREAM_INPUT, ATTR_STREAM_OUTPUT and ATTR_STREAM_ERROR in
	// src/condor_includes/condor_attributes.h are StreamIn, StreamOut and
	// StreamErr; the starter and the shadow look those up (jic_shadow.cpp,
	// remoteresource.cpp). Nothing reads StreamInput/StreamOutput/StreamError.
	//
	// Presence matters as much as the value. The starter's decision to
	// write the job's stdout to _condor_stdout and let the shadow rename
	// it back is guarded by LookupBool(ATTR_STREAM_OUTPUT, stream) &&
	// !stream, and LookupBool is false for an absent attribute -- so
	// omitting StreamOut is not the same as setting it false. condor_submit
	// writes the attribute with a false default for every transferred
	// stream, so the submit command being absent is not a reason to skip.
	//
	// Not being transferred is. The assignment in SetStdin/SetStdout/
	// SetStderr sits behind "if (transfer_it)", and both routes to
	// transfer_it == false clear it: checkStdFile for a null file, and an
	// explicit transfer_<x> = false.
	//
	// The file is read through its alias as well: whether the stream is
	// transferred is a property of the stream, not of which of the two
	// accepted spellings the submit file used to name it.
	for _, std := range stdioStreams {
		fileValue, _ := sf.submitCommandAlt(std.fileCmd, std.altFileCmd)
		if _, transferIt := checkStdFile(fileValue); !transferIt {
			continue
		}
		if !sf.stdioTransferIt(std.transferCmd) {
			continue
		}
		stream, _ := sf.submitCommand(std.streamCmd)
		_ = ad.Set(std.streamAttr, parseBool(stream, false))
	}

	// copy_to_spool - copy files to spool directory
	if copyToSpool, ok := sf.submitCommand("copy_to_spool"); ok {
		_ = ad.Set("CopyToSpool", parseBool(copyToSpool, false))
	}

	return nil
}

// setExtendedJobExprs sets extended job expression attributes
// These are less common attributes that provide additional job control
//
//nolint:gocyclo // Complex function required for extended job expression handling
func (sf *SubmitFile) setExtendedJobExprs(ad *classad.ClassAd) error {
	// want_checkpoint - request checkpoint capability
	if wantCheckpoint, ok := sf.submitCommand("want_checkpoint"); ok {
		_ = ad.Set("WantCheckpoint", parseBool(wantCheckpoint, false))
	}

	// preserve_relative_executable - keep relative path for executable
	if preserveExec, ok := sf.submitCommand("preserve_relative_executable"); ok {
		_ = ad.Set("PreserveRelativeExecutable", parseBool(preserveExec, false))
	}

	// remote_nodenumber - for MPI jobs, the node number
	if nodeNum, ok := sf.submitCommand("remote_nodenumber"); ok {
		if intNum, err := parseInt(nodeNum); err == nil {
			_ = ad.Set("RemoteNodeNumber", intNum)
		}
	}

	// KeystoreFile, KeystoreAlias, KeystorePassphraseFile - Java universe security
	if keystore, ok := sf.submitCommand("keystore_file"); ok {
		_ = ad.Set("KeystoreFile", keystore)
	}
	if keystoreAlias, ok := sf.submitCommand("keystore_alias"); ok {
		_ = ad.Set("KeystoreAlias", keystoreAlias)
	}
	if keystorePass, ok := sf.submitCommand("keystore_passphrase_file"); ok {
		_ = ad.Set("KeystorePassphraseFile", keystorePass)
	}

	return nil
}

// assignedNames collects every name the submit file assigns, including
// inside conditionals, keyed upper-cased for case-insensitive lookup
// and holding the spelling the file used.
//
// A name that appears only in a branch that did not execute is still
// counted. That is deliberate: the alternative is to inspect cfg, which
// cannot distinguish "the file set this" from "param_info has a default
// for a knob of the same name" -- exactly the confusion this exists to
// remove. Over-counting yields a value the user did write somewhere;
// under-counting would silently resurrect the config default.
func assignedNames(stmts []config.Statement) map[string]string {
	names := make(map[string]string)
	var walk func([]config.Statement)
	walk = func(list []config.Statement) {
		for _, stmt := range list {
			switch st := stmt.(type) {
			case *config.Assignment:
				// AssignedName, not st.Name: `+Foo = 1` defines the
				// macro MY.Foo and does NOT make Foo a submit command
				// the file set.
				name := config.AssignedName(st)
				// First spelling wins, as insert_macro does: it keeps
				// the name already in the macro set and replaces only
				// the value, so
				//
				//	request_Foo = 1
				//	request_FOO = 2
				//
				// is RequestFoo = 2, not RequestFOO = 2.
				if _, seen := names[strings.ToUpper(name)]; !seen {
					names[strings.ToUpper(name)] = name
				}
			case *config.Conditional:
				walk(st.ThenBlock)
				for _, ei := range st.ElseIfBlock {
					walk(ei.Block)
				}
				walk(st.ElseBlock)
			}
		}
	}
	walk(stmts)
	return names
}

// submitCommand reads a submit-file command.
//
// This is NOT cfg.Get. The submit file's config namespace is seeded with
// HTCondor's param_info defaults (config.NewEmptyWithOptions calls
// initBuiltins), and config lookups are case-insensitive, so a submit
// command whose name collides with a config knob resolves to that knob's
// default even when the submit file never mentions it. Five attributes
// leaked into every job ad that way -- among them
//
//	max_transfer_input_mb  -> MAX_TRANSFER_INPUT_MB  -> MaxTransferInputMB = -1
//
// which a schedd that protects the attribute rejects outright:
//
//	CommitTransaction failed: You are not allowed to change
//	MAX_TRANSFER_INPUT_MB. (error code 22)
//
// Requiring the name to have been assigned by the file matches
// condor_submit, where a submit command and a config macro of the same
// name are separate things. Macro expansion still sees the whole config,
// so $(SOME_KNOB) inside a submit file keeps working.
func (sf *SubmitFile) submitCommand(key string) (string, bool) {
	if sf == nil {
		return "", false
	}
	if _, ok := sf.assigned[strings.ToUpper(key)]; !ok {
		return "", false
	}
	return sf.cfg.Get(key)
}

// Command returns the value the submit file assigned to a submit command,
// macro-expanded but otherwise exactly as written, and whether the file
// assigned it at all.
//
// This is what the submitter typed, which is not always what the job ad
// records. `executable = run.sh` reads back here as "run.sh" while the ad's
// Cmd has been resolved to an absolute path, so a caller asking whether the
// submitter named a path on a machine or a file they intend to upload has to
// ask here rather than read Cmd.
func (sf *SubmitFile) Command(key string) (string, bool) {
	return sf.submitCommand(key)
}

// submitCommandAlt reads a submit-file command that has a second
// accepted spelling, mirroring
// SubmitHash::submit_param(name, alt_name) in
// src/condor_utils/submit_utils.cpp.
//
// The primary name wins, and it wins by being present rather than by
// having a value: submit_param looks the alternate up only when
// lookup_macro finds nothing at all under the primary, and it does that
// before expanding either. So
//
//	output =
//	stdout = so.txt
//
// leaves condor_submit with no output file -- the empty primary
// suppresses the alternate instead of deferring to it, and checkStdFile
// then canonicalizes the unnamed stream to /dev/null -- and the order
// the two appear in the file makes no difference.
func (sf *SubmitFile) submitCommandAlt(key, altKey string) (string, bool) {
	if value, ok := sf.submitCommand(key); ok {
		return value, true
	}
	return sf.submitCommand(altKey)
}

// submitCommandAlt2 is submitCommandAlt with a second fallback, for the two
// VM keywords whose built-in default is itself a macro reference with its own
// default: vm_memory defaults to $(Request_Memory), which defaults to
// $(RequestMemory), so all three spellings have to be tried in turn.
func (sf *SubmitFile) submitCommandAlt2(key, altKey, altKey2 string) (string, bool) {
	if value, ok := sf.submitCommandAlt(key, altKey); ok {
		return value, true
	}
	return sf.submitCommand(altKey2)
}
