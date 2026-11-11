package httpserver

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"io/fs"
	"mime"
	"mime/multipart"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"unicode/utf8"

	htcondor "github.com/bbockelm/golang-htcondor"
	"github.com/bbockelm/golang-htcondor/logging"
	"github.com/bbockelm/golang-htcondor/webapi/apassign"
	"github.com/bbockelm/golang-htcondor/webapi/dagman"
	"github.com/bbockelm/golang-htcondor/webapi/multiap"
)

// POST /api/v1/jobs/dag submits a DAGMan workflow.
//
// It is the REST half of what the MCP server's submit_dag tool does, and
// deliberately not a second implementation of it: everything between
// "a caller handed us a DAG" and "the schedd has a submit file and a
// sandbox" is dagman.Prepare, which both surfaces call. What is here is
// how the bytes arrive, how the answer is shaped, and the multi-AP
// routing every other /api/v1/jobs write does.
//
// ONE REQUEST, NOT TWO. Every other submission here is submit-then-
// upload: POST /jobs returns a job held for input spooling, and
// POST /jobs/{id}/input/multipart fills its sandbox afterwards. A
// workflow cannot be built that way. The spool is written ONCE -- the
// transfer's completion is what releases the hold, and the schedd
// refuses a second spool for the same job -- so a sandbox that is not
// complete at submit time is a sandbox that never will be. Worse, the
// manager job's transfer_input_files is computed from the DAG at submit
// time and a file not in that list is SKIPPED at spool time rather than
// rejected, so the two-step shape would not even fail loudly: it would
// accept the upload and silently drop it. The request boundary is
// therefore the sandbox boundary, and this endpoint takes everything in
// one call.
//
// That is what multipart/form-data is for here. It is not the smaller
// convenience it is on /jobs/{id}/input/multipart: it is the only shape
// in which a large shared input can reach a workflow at all. A DAG's
// spooled directory is the one place a reference database, a genome or
// an instrument calibration can be uploaded ONCE and then named by
// basename from every node job, instead of once per job -- and that file
// is binary and far too large to be a JSON string. Large parts are
// streamed: Go spills them to temp files, dagman.OpaqueFile keeps them
// there, and they go to the schedd without ever being held in memory.
//
// application/json is accepted too, for the workflow that is only text.
// It is the same request in the shape POST /jobs already uses, which is
// what a script with a heredoc and a curl wants, and it is exactly the
// MCP tool's arguments so the two surfaces can be read side by side.
const (
	// dagJSONMaxBytes bounds a JSON submission's body.
	//
	// The inline ceiling dagman.Prepare enforces is on the DAG plus the
	// decoded file contents; this is on the encoded request, and is
	// larger because JSON escaping can nearly double a text file and
	// because the body carries field names too. A caller who needs more
	// than this is a caller who should be uploading, which is what the
	// refusal says.
	dagJSONMaxBytes = 4 << 20

	// dagMultipartMaxBytes bounds a multipart submission's body: the DAG,
	// every script and submit description, and every uploaded input.
	//
	// It is the same ceiling POST /jobs/{id}/input/multipart uses, for
	// the same reason -- this is a sandbox upload, and a workflow's
	// sandbox should not be allowed to be larger than an ordinary job's.
	dagMultipartMaxBytes = 100 << 20

	// dagFormMemoryBytes is how much of a multipart form Go keeps in
	// memory; everything above it spills to a temp file.
	//
	// Deliberately small. The parts this endpoint reads as text are
	// kilobytes, and the parts that are not are exactly the ones that
	// must never be held: a 100 MiB in-memory threshold, which is what
	// the sibling upload endpoint passes, means a 100 MiB allocation per
	// concurrent submission.
	dagFormMemoryBytes = 1 << 20

	// dagInlineFileMaxBytes decides which uploaded parts are read.
	//
	// A part at or under this that is valid UTF-8 is a file the analysis
	// can work with: a node submit description, a PRE/POST script, a
	// splice. Anything else is staged by name and streamed, and the
	// analysis is told it exists but not what is in it (dagman.Input's
	// Opaque). The size half bounds what is held; the UTF-8 half keeps a
	// binary blob out of a text parser.
	dagInlineFileMaxBytes = 1 << 20

	// dagExecutableField is the multipart field name that forces 0755,
	// the same convention POST /jobs/{id}/input/multipart uses.
	//
	// It only ADDS to what the DAG says. A PRE script or a node's
	// executable is made runnable from the parse whatever field name it
	// arrived under; this is for the file the parse cannot attribute --
	// a helper a script calls by name, say -- which would otherwise
	// arrive 0644 and fail with EACCES in the middle of the run.
	dagExecutableField = "executable"
)

// DagSubmitRequest is a workflow submitted as JSON. The multipart form
// carries the same fields under the same names, one per form value, with
// the files as file parts instead of a map.
type DagSubmitRequest struct {
	// Dag is the DAG description file's contents. Required.
	Dag string `json:"dag"`
	// Files are the files the DAG references, as name -> contents: node
	// submit files, PRE/POST scripts, small inputs. Names must be bare:
	// a spooled sandbox is one flat directory.
	Files map[string]string `json:"files,omitempty"`
	// DagName is the file name the DAG is written as. Default
	// "workflow.dag".
	DagName string `json:"dag_name,omitempty"`
	// BatchName sets JobBatchName, as condor_q -batch shows it.
	BatchName string `json:"batch_name,omitempty"`
	// MaxIdle, MaxJobs, MaxPre and MaxPost throttle DAGMan. Zero is
	// unset.
	MaxIdle int `json:"max_idle,omitempty"`
	MaxJobs int `json:"max_jobs,omitempty"`
	MaxPre  int `json:"max_pre,omitempty"`
	MaxPost int `json:"max_post,omitempty"`
	// Append is extra submit-file lines for the DAGMan manager job.
	Append string `json:"append,omitempty"`
	// Instrument defaults to TRUE, which is why it is a pointer: the
	// flag exists only to turn instrumentation off, and an absent field
	// must not read as false. See dagman.Submission.Instrument for the
	// one case where off is the right answer.
	Instrument *bool `json:"instrument,omitempty"`
	// DryRun checks the workflow and submits nothing.
	DryRun bool `json:"dry_run,omitempty"`
}

// DagFinding is one thing the analysis noticed, in the shape a page can
// show: severity, the line of the caller's own DAG it is about, and the
// included or spliced file that line belongs to when it is not the
// top-level one.
type DagFinding struct {
	Severity string `json:"severity"`
	Message  string `json:"message"`
	Line     int    `json:"line,omitempty"`
	Source   string `json:"source,omitempty"`
}

// DagSubmitResponse is a submitted workflow.
//
// It answers "what now?" as well as "what happened", because a caller
// holding only a cluster id cannot find the workflow's own jobs: DAGMan
// submits each node as its own cluster, and DAGManJobId is the only
// thing linking them to the manager. Handing over the constraint and
// the paths is the difference between a page that shows the workflow and
// a page that queries the manager job again and concludes it has no
// jobs.
type DagSubmitResponse struct {
	ClusterID int    `json:"cluster_id"`
	JobID     string `json:"job_id"`
	DagName   string `json:"dag_name"`
	// Schedd and Assignment are multi-AP only, as on JobSubmitResponse:
	// the access point the workflow went to, and why.
	Schedd     string               `json:"schedd,omitempty"`
	Assignment *apassign.Assignment `json:"assignment,omitempty"`
	// InputFiles is what was staged into the workflow's spool directory,
	// which is also what the manager job declared. Nothing can be added
	// to it.
	InputFiles []string `json:"input_files"`
	// Deferred are files the DAG will read once it is running and that
	// are not staged now -- a sub-DAG an earlier node writes, a submit
	// file a script generates. Expected, not missing.
	Deferred []string `json:"deferred,omitempty"`
	// Notes and Findings are the same analysis twice: rendered lines to
	// show, and the structured form to act on.
	Notes    []string     `json:"notes,omitempty"`
	Findings []DagFinding `json:"findings,omitempty"`
	// NodeConstraint selects the workflow's node jobs.
	NodeConstraint string `json:"node_constraint"`
	// DotFile and StatusFile are what the instrumentation will write
	// into the spool; empty when instrument was false, in which case
	// there is no graph and no per-node state to read.
	DotFile    string `json:"dot_file,omitempty"`
	StatusFile string `json:"status_file,omitempty"`
	// DagmanLog is DAGMan's own log, by name, inside the spool that
	// Links.Output returns.
	DagmanLog string `json:"dagman_log"`
	// Links are where to go next, ready to use.
	Links DagSubmitLinks `json:"links"`
}

// DagSubmitLinks are the endpoints that follow a workflow, so a caller
// does not have to assemble them (and get the node query wrong).
type DagSubmitLinks struct {
	// Job is the manager job's ad: DAGMan publishes its node counts
	// there, so this is "how far along is the workflow".
	Job string `json:"job"`
	// Watch is the manager job's SSE stream, so a page waiting on the
	// workflow does not poll.
	Watch string `json:"watch"`
	// Dag is the workflow's structure and per-node state, read from what
	// the instrumentation writes. Empty when instrument was false.
	Dag string `json:"dag,omitempty"`
	// Nodes lists the node jobs in the queue.
	Nodes string `json:"nodes"`
	// Output is the whole spool, including DagmanLog and whatever the
	// nodes produced: node outputs come back to the DAG's directory, not
	// to a node job's sandbox, which is gone.
	Output string `json:"output"`
}

// DagDryRunResponse is a workflow that was checked and not submitted.
type DagDryRunResponse struct {
	DryRun  bool   `json:"dry_run"`
	DagName string `json:"dag_name"`
	// SubmitFile is the DAGMan manager job's submit file as it would be
	// sent, with the site's submit policy already in it.
	SubmitFile string       `json:"submit_file"`
	InputFiles []string     `json:"input_files"`
	Deferred   []string     `json:"deferred,omitempty"`
	Notes      []string     `json:"notes,omitempty"`
	Findings   []DagFinding `json:"findings,omitempty"`
	// Fatal and Errors are the workflow's own verdict: a dry run reports
	// every fatal finding rather than stopping at the first, because the
	// caller asked what is wrong with this workflow and one error hides
	// the other four.
	Fatal  bool     `json:"fatal"`
	Errors []string `json:"errors,omitempty"`
}

// dagErrorResponse is the ordinary error body with the analysis added.
//
// Embedded, not replaced: a client that reads error/message/code off
// every failure keeps working, and one that can show a caller which line
// of their DAG is wrong now can. A malformed workflow is the case where
// the difference matters -- "this workflow cannot start" with no line
// number is a riddle.
type dagErrorResponse struct {
	ErrorResponse
	Findings []DagFinding `json:"findings,omitempty"`
	Notes    []string     `json:"notes,omitempty"`
}

// handleSubmitDag serves POST /api/v1/jobs/dag.
func (s *Handler) handleSubmitDag(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		s.writeError(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}

	// Authentication first, and in multi-AP mode the assignment with it:
	// nothing about the request is read before the caller is known, and
	// the workflow goes to the access point the caller's assignment
	// names, exactly as POST /jobs does.
	var (
		ctx    context.Context
		member string
		assign *apassign.Assignment
	)
	if s.multi != nil {
		var ok bool
		if ctx, member, assign, ok = s.dagSubmitTarget(w, r); !ok {
			return
		}
		s.multi.svc.NoteWrite(member)
		defer s.multi.svc.NoteWrite(member)
	} else {
		var err error
		var needsRedirect bool
		ctx, needsRedirect, err = s.requireAuthentication(r)
		if err != nil {
			if needsRedirect {
				s.redirectToLogin(w, r)
				return
			}
			s.writeError(w, http.StatusUnauthorized, fmt.Sprintf("Authentication failed: %v", err))
			return
		}
	}

	req, opaque, cleanup, err := s.readDagSubmission(w, r)
	if cleanup != nil {
		// After the spool, not after the parse: an opaque upload is a
		// temp file that is still being read while the sandbox is sent.
		defer cleanup()
	}
	if err != nil {
		s.writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	instrument := true
	if req.Instrument != nil {
		instrument = *req.Instrument
	}
	prep, err := dagman.Prepare(dagman.Submission{
		DagName:    req.DagName,
		Dag:        req.Dag,
		Files:      req.Files,
		Opaque:     opaque,
		BatchName:  req.BatchName,
		MaxIdle:    req.MaxIdle,
		MaxJobs:    req.MaxJobs,
		MaxPre:     req.MaxPre,
		MaxPost:    req.MaxPost,
		Append:     req.Append,
		Instrument: instrument,
		DagmanPath: s.dagmanPath,
		Layout:     s.dagmanLayout(ctx),
		ExtraEnv:   s.dagmanEnv,
		Policy:     s.submitPolicy,
	})
	if err != nil {
		// Everything Prepare refuses is about what the caller sent: a
		// name the spool cannot carry, more inline bytes than this path
		// is for, a node description that sets an attribute site policy
		// owns. The last of those is the same ControlledAttributeError
		// POST /jobs already answers 400 to, so every one of them is a
		// 400 here and the message is the explanation.
		s.writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	if req.DryRun {
		s.writeJSON(w, http.StatusOK, DagDryRunResponse{
			DryRun:     true,
			DagName:    prep.DagName,
			SubmitFile: prep.SubmitFile,
			InputFiles: prep.Report.Required,
			Deferred:   prep.Report.Deferred,
			Notes:      prep.Notes,
			Findings:   dagFindings(prep),
			Fatal:      prep.Report.Fatal(),
			Errors:     prep.Report.Errors(),
		})
		return
	}
	if prep.Report.Fatal() {
		// A workflow DAGMan provably cannot start. Refused rather than
		// submitted, because the alternative is a scheduler-universe job
		// that holds or exits immediately and a user left to find out
		// why from a .dagman.out file they have to fetch.
		s.writeDagError(w, http.StatusBadRequest, prep,
			"This workflow cannot start:\n  - "+strings.Join(prep.Report.Errors(), "\n  - "))
		return
	}

	// submitApplied, not submitJob: dagman.Prepare has already applied
	// the site's submit policy to the manager's submit file, and
	// applying it twice is refused (see submitApplied).
	clusterID, procAds, err := s.submitApplied(ctx, prep.SubmitFile)
	if err != nil {
		s.writeSubmitFailure(ctx, w, err)
		return
	}
	if err := s.scheddFor(ctx).SpoolJobFilesFromFS(ctx, procAds, prep.FS()); err != nil {
		// The submit succeeded, so a DAGMan job is sitting in the queue
		// held for input it will never get. Remove it, and say plainly
		// whether that worked: the manager job exists either way, and
		// whether it is still there decides what the caller has to do
		// next.
		removed := s.removeDagJob(ctx, clusterID)
		s.logger.Error(logging.DestinationHTTP, "spooling a workflow failed",
			"cluster", clusterID, "removed", removed,
			"user", htcondor.GetAuthenticatedUserFromContext(ctx), "error", err)
		msg := fmt.Sprintf("The schedd accepted the DAGMan job but spooling the workflow failed: %v.", err)
		if removed {
			msg += fmt.Sprintf(" The DAGMan job %d.0 was removed.", clusterID)
		} else {
			msg += fmt.Sprintf(" The DAGMan job %d.0 could NOT be removed and is still in the queue, "+
				"held and unable to run; remove it with DELETE /api/v1/jobs/%d.0.", clusterID, clusterID)
		}
		s.writeError(w, http.StatusBadGateway, msg)
		return
	}

	s.logger.Info(logging.DestinationHTTP, "workflow submitted",
		"cluster", clusterID, "dag", prep.DagName, "staged", len(prep.Names()),
		"user", htcondor.GetAuthenticatedUserFromContext(ctx), "access_point", routedSchedd(ctx))

	s.writeJSON(w, http.StatusCreated, s.dagSubmitResponse(ctx, clusterID, prep, member, assign))
}

// dagSubmitTarget is multi-AP authentication plus assignment for a
// workflow: the same chain POST /jobs uses, so a workflow and a job from
// the same caller land on the same access point.
func (s *Handler) dagSubmitTarget(w http.ResponseWriter, r *http.Request) (context.Context, string, *apassign.Assignment, bool) {
	ctx, user, ok := s.multiAPCaller(w, r)
	if !ok {
		return nil, "", nil, false
	}
	m, a, err := s.multi.svc.SubmitTarget(ctx, s.jobAssignRequest(ctx, r, user), r.URL.Query().Get("schedd"))
	if err != nil {
		s.multiAPError(w, err)
		return nil, "", nil, false
	}
	ctx = multiap.WithTarget(ctx, multiap.Target{Member: m})
	// The workflow is owned by whoever the AP says this credential is.
	if v := s.multi.svc.VerifyCaller; v != nil {
		if err := v(ctx, m, user); err != nil {
			s.multiAPError(w, err)
			return nil, "", nil, false
		}
	}
	return ctx, m.Name, &a, true
}

// dagSubmitResponse renders a submitted workflow, links and all.
func (s *Handler) dagSubmitResponse(ctx context.Context, clusterID int, prep *dagman.Prepared,
	member string, assign *apassign.Assignment) DagSubmitResponse {
	jobID := s.jobPathID(ctx, clusterID, 0)
	esc := url.PathEscape(jobID)
	constraint := dagman.NodeConstraint(clusterID)
	resp := DagSubmitResponse{
		ClusterID:      clusterID,
		JobID:          jobID,
		DagName:        prep.DagName,
		Schedd:         member,
		Assignment:     assign,
		InputFiles:     prep.Report.Required,
		Deferred:       prep.Report.Deferred,
		Notes:          prep.Notes,
		Findings:       dagFindings(prep),
		NodeConstraint: constraint,
		DotFile:        prep.Instrumentation.DotFile,
		StatusFile:     prep.Instrumentation.StatusFile,
		DagmanLog:      dagman.OutName(prep.DagName),
		Links: DagSubmitLinks{
			Job:    "/api/v1/jobs/" + esc,
			Watch:  "/api/v1/jobs/" + esc + "/watch",
			Nodes:  "/api/v1/jobs?constraint=" + url.QueryEscape(constraint),
			Output: "/api/v1/jobs/" + esc + "/output",
		},
	}
	// Only when something will write the files it reads. A link to a
	// view that can only answer "this workflow was not instrumented"
	// sends a page looking for a graph that does not exist.
	if prep.Instrumentation.DotFile != "" || prep.Instrumentation.StatusFile != "" {
		resp.Links.Dag = "/api/v1/jobs/" + esc + "/dag"
	}
	return resp
}

// removeDagJob removes a manager job whose spool failed, and reports
// whether it is really gone. "0 jobs removed" is not a success.
func (s *Handler) removeDagJob(ctx context.Context, clusterID int) bool {
	jobID := fmt.Sprintf("%d.0", clusterID)
	res, err := s.scheddFor(ctx).RemoveJobsByID(ctx, []string{jobID}, "spooling the workflow failed")
	return err == nil && res != nil && res.Success > 0
}

// dagFindings is the analysis in the structured shape.
func dagFindings(prep *dagman.Prepared) []DagFinding {
	if prep.Report == nil {
		return nil
	}
	out := make([]DagFinding, 0, len(prep.Report.Findings))
	for _, f := range prep.Report.Findings {
		out = append(out, DagFinding{
			Severity: f.Severity.String(),
			Message:  f.Message,
			Line:     f.Line,
			Source:   f.Source,
		})
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

// writeDagError is writeError with the analysis attached. See
// dagErrorResponse.
func (s *Handler) writeDagError(w http.ResponseWriter, status int, prep *dagman.Prepared, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	body := dagErrorResponse{
		ErrorResponse: ErrorResponse{Error: http.StatusText(status), Message: message, Code: status},
		Findings:      dagFindings(prep),
		Notes:         prep.Notes,
	}
	if err := json.NewEncoder(w).Encode(body); err != nil {
		s.logger.Error(logging.DestinationHTTP, "Failed to encode a workflow error response", "error", err)
	}
}

// readDagSubmission reads the request in whichever shape it arrived.
//
// It returns the request, the uploads whose contents were not read, and
// a cleanup the caller must defer until after the spool -- an opaque
// upload is a temp file Go made, and it is still being read while the
// sandbox goes to the schedd.
func (s *Handler) readDagSubmission(w http.ResponseWriter, r *http.Request) (
	*DagSubmitRequest, []dagman.OpaqueFile, func(), error) {
	ct := r.Header.Get("Content-Type")
	mediaType, _, err := mime.ParseMediaType(ct)
	if err != nil && strings.TrimSpace(ct) != "" {
		return nil, nil, nil, fmt.Errorf("unreadable Content-Type %q: %w", ct, err)
	}
	if mediaType == "multipart/form-data" {
		return s.readDagMultipart(w, r)
	}
	// JSON is the default, including for a request that sent no
	// Content-Type at all: it is the shape POST /jobs uses, so a caller
	// that forgot the header gets the error it expects rather than a
	// complaint about multipart boundaries.
	if mediaType != "" && mediaType != "application/json" {
		return nil, nil, nil, fmt.Errorf("Content-Type %q is not accepted here; send application/json, "+
			"or multipart/form-data when the workflow has files to upload", mediaType)
	}
	setBodyLimit(w, r, dagJSONMaxBytes)
	var req DagSubmitRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		return nil, nil, nil, fmt.Errorf("invalid request body: %w", err)
	}
	return &req, nil, nil, nil
}

// readDagMultipart reads a multipart submission: the options as form
// values, the sandbox as file parts.
func (s *Handler) readDagMultipart(w http.ResponseWriter, r *http.Request) (
	*DagSubmitRequest, []dagman.OpaqueFile, func(), error) {
	// Bound the body before parsing so a hostile client cannot stream
	// gigabytes through ParseMultipartForm. setBodyLimit caps the total;
	// the argument below is only the in-memory threshold above which
	// parts spill to temp files, which is why it is small. gosec G120
	// still flags the call because its taint tracker does not see
	// through setBodyLimit; the cap above is the real defense.
	setBodyLimit(w, r, dagMultipartMaxBytes)
	if err := r.ParseMultipartForm(dagFormMemoryBytes); err != nil { //nolint:gosec // body bounded by setBodyLimit above
		return nil, nil, nil, fmt.Errorf("could not read the multipart form: %w", err)
	}
	cleanup := func() { _ = r.MultipartForm.RemoveAll() }

	req := &DagSubmitRequest{
		Dag:       r.FormValue("dag"),
		DagName:   r.FormValue("dag_name"),
		BatchName: r.FormValue("batch_name"),
		Append:    r.FormValue("append"),
		Files:     map[string]string{},
	}
	for _, f := range []struct {
		name string
		into *int
	}{
		{"max_idle", &req.MaxIdle}, {"max_jobs", &req.MaxJobs},
		{"max_pre", &req.MaxPre}, {"max_post", &req.MaxPost},
	} {
		v := strings.TrimSpace(r.FormValue(f.name))
		if v == "" {
			continue
		}
		n, err := strconv.Atoi(v)
		if err != nil {
			return nil, nil, cleanup, fmt.Errorf("%s must be a whole number, not %q", f.name, v)
		}
		*f.into = n
	}
	if v := strings.TrimSpace(r.FormValue("instrument")); v != "" {
		b, err := strconv.ParseBool(v)
		if err != nil {
			return nil, nil, cleanup, fmt.Errorf("instrument must be true or false, not %q", v)
		}
		req.Instrument = &b
	}
	if v := strings.TrimSpace(r.FormValue("dry_run")); v != "" {
		b, err := strconv.ParseBool(v)
		if err != nil {
			return nil, nil, cleanup, fmt.Errorf("dry_run must be true or false, not %q", v)
		}
		req.DryRun = b
	}

	opaque, err := dagUploads(r.MultipartForm, req.Files)
	if err != nil {
		return nil, nil, cleanup, err
	}
	return req, opaque, cleanup, nil
}

// dagUploads sorts the file parts into the two kinds a workflow has.
//
// A small text part is read into files, where the analysis, the submit
// lint and the site's submit policy can all see it -- that is what a
// node submit description or a PRE script has to be. Everything else is
// left on disk and staged by name: the bytes go straight from Go's temp
// file to the schedd, which is the whole reason a shared dataset can
// ride along with the workflow that uses it.
//
// The part's FILENAME is the name it is staged under, not its field
// name. A browser's FormData sets it from the file the user picked,
// which is the name their DAG will say.
func dagUploads(form *multipart.Form, files map[string]string) ([]dagman.OpaqueFile, error) {
	var opaque []dagman.OpaqueFile
	for field, headers := range form.File {
		for _, fh := range headers {
			name := fh.Filename
			if _, dup := files[name]; dup {
				return nil, fmt.Errorf("file %q was uploaded twice; a spooled sandbox is one flat "+
					"directory, so one would silently overwrite the other", name)
			}
			// Names are checked here as well as in Prepare so the
			// diagnostic can say which upload, and so a traversal-shaped
			// name never reaches a map key.
			if err := dagman.CheckName(name, "uploaded file"); err != nil {
				return nil, err
			}
			if fh.Size <= dagInlineFileMaxBytes && field != dagExecutableField {
				body, text, err := readIfText(fh)
				if err != nil {
					return nil, fmt.Errorf("could not read the uploaded file %q: %w", name, err)
				}
				if text {
					files[name] = body
					continue
				}
			}
			mode := fsModeRegular
			if field == dagExecutableField {
				mode = fsModeExecutable
			}
			opaque = append(opaque, dagman.OpaqueFile{
				Name: name,
				Size: fh.Size,
				Mode: mode,
				Open: func() (io.ReadCloser, error) { return fh.Open() },
			})
		}
	}
	return opaque, nil
}

// fsModeRegular and fsModeExecutable are the two modes a staged file can
// have. Zero means "let the DAG decide" (dagman.StagedMode).
const (
	fsModeRegular    fs.FileMode = 0
	fsModeExecutable fs.FileMode = 0o755
)

// readIfText reads a part and reports whether it is text.
//
// Valid UTF-8 is the test, because what "text" means here is "the submit
// parser, the lint and the policy splicer can work on it". A part that
// is not gets staged untouched, which is right for a tarball and right
// for anything else nothing here understands.
func readIfText(fh *multipart.FileHeader) (string, bool, error) {
	f, err := fh.Open()
	if err != nil {
		return "", false, err
	}
	defer func() { _ = f.Close() }()
	body, err := io.ReadAll(io.LimitReader(f, dagInlineFileMaxBytes+1))
	if err != nil {
		return "", false, err
	}
	if int64(len(body)) > dagInlineFileMaxBytes || !utf8.Valid(body) {
		return "", false, nil
	}
	return string(body), true, nil
}

// dagmanLayout is what the routed access point's own configuration says
// about its DAGMan installation, asked of the schedd once per AP.
//
// The same discovery the MCP server does, through the same cache type,
// because the two must agree: a workflow submitted through REST and one
// submitted through submit_dag run the same condor_dagman on the same
// access point, and an operator who sets nothing should get the right
// one either way.
func (s *Handler) dagmanLayout(ctx context.Context) dagman.Layout {
	return s.dagmanLayouts.Get(ctx, routedSchedd(ctx), func(ctx context.Context) dagman.Layout {
		// A nil *Schedd must not reach DiscoverLayout as an interface: a
		// typed nil is not nil, and the method call would panic instead
		// of falling back to the defaults.
		schedd := s.scheddFor(ctx)
		if schedd == nil {
			return dagman.Layout{}
		}
		return dagman.DiscoverLayout(ctx, schedd, func(msg string, args ...any) {
			s.logger.Debug(logging.DestinationHTTP, msg, args...)
		})
	})
}
