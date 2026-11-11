package httpserver

import (
	"bytes"
	"encoding/json"
	"io"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"

	"github.com/bbockelm/golang-htcondor/logging"
	"github.com/bbockelm/golang-htcondor/webapi/dagman"
)

func dagTestHandler(t *testing.T) *Handler {
	t.Helper()
	lg, err := logging.New(&logging.Config{OutputPath: "stderr"})
	if err != nil {
		t.Fatalf("logger: %v", err)
	}
	return &Handler{logger: lg}
}

// readSubmission runs the request through the reader the handler uses,
// and returns what Prepare would be handed.
func readSubmission(t *testing.T, r *http.Request) (*DagSubmitRequest, []dagman.OpaqueFile) {
	t.Helper()
	h := dagTestHandler(t)
	w := httptest.NewRecorder()
	req, opaque, cleanup, err := h.readDagSubmission(w, r)
	if cleanup != nil {
		t.Cleanup(cleanup)
	}
	if err != nil {
		t.Fatalf("readDagSubmission: %v", err)
	}
	return req, opaque
}

func TestDagSubmitReadsJSON(t *testing.T) {
	body := `{"dag":"JOB A a.sub\n","files":{"a.sub":"executable = /bin/true\nqueue\n"},
	          "dag_name":"w.dag","batch_name":"b","max_idle":3,"instrument":false,"dry_run":true}`
	r := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/api/v1/jobs/dag", strings.NewReader(body))
	r.Header.Set("Content-Type", "application/json")
	req, opaque := readSubmission(t, r)
	if req.Dag == "" || req.Files["a.sub"] == "" || req.DagName != "w.dag" ||
		req.BatchName != "b" || req.MaxIdle != 3 || !req.DryRun {
		t.Fatalf("JSON submission read wrong: %+v", req)
	}
	if req.Instrument == nil || *req.Instrument {
		t.Errorf("instrument=false was not read: %v", req.Instrument)
	}
	if len(opaque) != 0 {
		t.Errorf("a JSON submission produced %d uploads", len(opaque))
	}
}

// TestDagSubmitInstrumentDefaultsOn. The flag exists only to turn
// instrumentation OFF, so an absent field must not read as false --
// which is why it is a pointer and not a bool.
func TestDagSubmitInstrumentDefaultsOn(t *testing.T) {
	r := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/api/v1/jobs/dag",
		strings.NewReader(`{"dag":"JOB A a.sub\n"}`))
	r.Header.Set("Content-Type", "application/json")
	req, _ := readSubmission(t, r)
	if req.Instrument != nil {
		t.Fatalf("an absent instrument field decoded to %v", *req.Instrument)
	}
}

// multipartBody builds a form the way a browser's FormData would.
func multipartBody(t *testing.T, fields map[string]string, files []struct{ field, name, body string }) (string, io.Reader) {
	t.Helper()
	var buf bytes.Buffer
	mw := multipart.NewWriter(&buf)
	for k, v := range fields {
		if err := mw.WriteField(k, v); err != nil {
			t.Fatalf("WriteField %s: %v", k, err)
		}
	}
	for _, f := range files {
		w, err := mw.CreateFormFile(f.field, f.name)
		if err != nil {
			t.Fatalf("CreateFormFile %s: %v", f.name, err)
		}
		if _, err := io.WriteString(w, f.body); err != nil {
			t.Fatalf("write %s: %v", f.name, err)
		}
	}
	if err := mw.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	return mw.FormDataContentType(), &buf
}

// TestDagSubmitReadsMultipart is the shape that matters: one request
// carrying the workflow AND everything it will ever need, because a
// workflow's sandbox cannot be added to after submission.
func TestDagSubmitReadsMultipart(t *testing.T) {
	binary := string([]byte{0xff, 0xfe, 0x00, 0x01, 0x80})
	ct, body := multipartBody(t,
		map[string]string{
			"dag":        "JOB A a.sub\n",
			"dag_name":   "w.dag",
			"max_jobs":   "5",
			"dry_run":    "true",
			"batch_name": "run-7",
		},
		[]struct{ field, name, body string }{
			{"file", "a.sub", "executable = /bin/true\nqueue\n"},
			{"file", "genome.fa", binary},
			{"executable", "helper", "#!/bin/sh\n"},
		})
	r := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/api/v1/jobs/dag", body)
	r.Header.Set("Content-Type", ct)
	req, opaque := readSubmission(t, r)

	if req.DagName != "w.dag" || req.MaxJobs != 5 || !req.DryRun || req.BatchName != "run-7" {
		t.Fatalf("form values read wrong: %+v", req)
	}
	// A small text part is read, so the analysis, the lint and site
	// policy can all see it.
	if req.Files["a.sub"] == "" {
		t.Errorf("the submit description was not read as text: %v", req.Files)
	}
	// A binary part is not, and is never held: it is staged by name and
	// streamed from the temp file Go spilled it to.
	var names []string
	for _, o := range opaque {
		names = append(names, o.Name)
		if _, read := req.Files[o.Name]; read {
			t.Errorf("%s was both read and streamed", o.Name)
		}
	}
	if !slices.Contains(names, "genome.fa") {
		t.Errorf("a binary upload was read as text; uploads = %v, files = %v", names, keysOf(req.Files))
	}
	// The `executable` field name forces 0755 for the file the parse
	// cannot attribute; it would otherwise arrive 0644 and fail with
	// EACCES in the middle of the run.
	var helper *dagman.OpaqueFile
	for i := range opaque {
		if opaque[i].Name == "helper" {
			helper = &opaque[i]
		}
	}
	if helper == nil {
		t.Fatalf("the executable part was not staged: %v", names)
	}
	if helper.Mode != 0o755 {
		t.Errorf("the executable part was staged %o", helper.Mode)
	}
}

// TestDagSubmitStreamsUploadsToPrepare is the end of that road: the
// bytes the request carried come out of the sandbox Prepare builds.
func TestDagSubmitStreamsUploadsToPrepare(t *testing.T) {
	const genome = "ACGT\x00\xffACGT"
	dag := "JOB A {\n  executable = /bin/sh\n  transfer_executable = false\n" +
		"  transfer_input_files = genome.fa\n}\n"
	ct, body := multipartBody(t, map[string]string{"dag": dag},
		[]struct{ field, name, body string }{{"file", "genome.fa", genome}})
	r := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/api/v1/jobs/dag", body)
	r.Header.Set("Content-Type", ct)
	req, opaque := readSubmission(t, r)

	prep, err := dagman.Prepare(dagman.Submission{
		Dag: req.Dag, Files: req.Files, Opaque: opaque, Instrument: true,
	})
	if err != nil {
		t.Fatalf("Prepare: %v", err)
	}
	f, err := prep.FS().Open("genome.fa")
	if err != nil {
		t.Fatalf("open the staged upload: %v", err)
	}
	defer func() { _ = f.Close() }()
	got, err := io.ReadAll(f)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if string(got) != genome {
		t.Errorf("the upload reached the sandbox as %q, want %q", got, genome)
	}
	if !strings.Contains(prep.SubmitFile, "genome.fa") {
		t.Errorf("the upload is not in transfer_input_files, so the spool would skip it:\n%s",
			prep.SubmitFile)
	}
}

// TestDagSubmitUploadNamesCannotEscapeTheSandbox. The filename comes
// from the client, and a spooled sandbox is flat: a name with a path in
// it would not fail, it would land somewhere else.
//
// Two things stop it, and the test asserts the OUTCOME so that either
// one failing is a failure here. mime/multipart already reduces a part's
// filename to its base, and dagman.CheckName refuses what is left if it
// still is not a file name -- which is what catches ".." and "", the
// names basename-ing produces and does not fix.
func TestDagSubmitUploadNamesCannotEscapeTheSandbox(t *testing.T) {
	t.Run("a traversal is reduced to a plain name", func(t *testing.T) {
		ct, body := multipartBody(t, map[string]string{"dag": "JOB A a.sub\n"},
			[]struct{ field, name, body string }{{"file", "../../etc/passwd", "x"}})
		r := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/api/v1/jobs/dag", body)
		r.Header.Set("Content-Type", ct)
		req, opaque := readSubmission(t, r)
		for _, name := range append(keysOf(req.Files), opaqueNames(opaque)...) {
			if strings.ContainsAny(name, `/\`) || name == ".." {
				t.Errorf("an upload was staged as %q, which is not inside the sandbox", name)
			}
		}
	})
	// Not "" -- mime/multipart reads a part with no filename as a form
	// VALUE rather than a file, so it never reaches the sandbox at all.
	for _, name := range []string{"..", "a b", `a"b`} {
		t.Run("refuses "+name, func(t *testing.T) {
			ct, body := multipartBody(t, map[string]string{"dag": "JOB A a.sub\n"},
				[]struct{ field, name, body string }{{"file", name, "x"}})
			r := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/api/v1/jobs/dag", body)
			r.Header.Set("Content-Type", ct)
			h := dagTestHandler(t)
			_, _, cleanup, err := h.readDagSubmission(httptest.NewRecorder(), r)
			if cleanup != nil {
				t.Cleanup(cleanup)
			}
			if err == nil {
				t.Errorf("an upload named %q was accepted", name)
			}
		})
	}
}

// TestDagSubmitRejectsAnUnknownContentType, rather than guessing. A
// body that is neither JSON nor a form is a client bug, and "invalid
// character '-'" from the JSON decoder is not a diagnosis.
func TestDagSubmitRejectsAnUnknownContentType(t *testing.T) {
	r := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/api/v1/jobs/dag", strings.NewReader("JOB A a.sub"))
	r.Header.Set("Content-Type", "text/plain")
	h := dagTestHandler(t)
	if _, _, _, err := h.readDagSubmission(httptest.NewRecorder(), r); err == nil {
		t.Fatal("text/plain was accepted")
	} else if !strings.Contains(err.Error(), "multipart/form-data") {
		t.Errorf("the refusal does not say what to send instead: %v", err)
	}
}

// TestDagSubmitResponseLeadsSomewhere. A caller holding only a cluster
// id cannot find the workflow's own jobs: DAGMan submits each node as
// its own cluster and DAGManJobId is the only link. Everything the
// response hands over exists to close that gap.
func TestDagSubmitResponseLeadsSomewhere(t *testing.T) {
	h := dagTestHandler(t)
	prep, err := dagman.Prepare(dagman.Submission{
		Dag:        "JOB A {\n  executable = /bin/sh\n  transfer_executable = false\n}\n",
		DagName:    "flow.dag",
		Instrument: true,
	})
	if err != nil {
		t.Fatalf("Prepare: %v", err)
	}
	resp := h.dagSubmitResponse(t.Context(), 42, prep, "", nil)

	if resp.JobID != "42.0" || resp.ClusterID != 42 {
		t.Errorf("job id = %q / %d", resp.JobID, resp.ClusterID)
	}
	if resp.NodeConstraint != "DAGManJobId == 42" {
		t.Errorf("node_constraint = %q", resp.NodeConstraint)
	}
	if resp.DagmanLog != "flow.dagman.out" {
		t.Errorf("dagman_log = %q, want flow.dagman.out", resp.DagmanLog)
	}
	for name, got := range map[string]string{
		"job":    resp.Links.Job,
		"watch":  resp.Links.Watch,
		"nodes":  resp.Links.Nodes,
		"output": resp.Links.Output,
		"dag":    resp.Links.Dag,
	} {
		if got == "" {
			t.Errorf("links.%s is empty", name)
		}
	}
	if !strings.Contains(resp.Links.Nodes, "DAGManJobId") {
		t.Errorf("links.nodes does not select the node jobs: %q", resp.Links.Nodes)
	}

	// With no instrumentation there is no graph, so there must be no
	// link to the view that reads one: it would send a page looking for
	// a file nobody will write.
	off, err := dagman.Prepare(dagman.Submission{
		Dag: "JOB A {\n  executable = /bin/sh\n  transfer_executable = false\n}\n", Instrument: false})
	if err != nil {
		t.Fatalf("Prepare: %v", err)
	}
	if link := h.dagSubmitResponse(t.Context(), 42, off, "", nil).Links.Dag; link != "" {
		t.Errorf("an uninstrumented workflow still linked to %q", link)
	}
}

// TestDagErrorCarriesTheFindings. "This workflow cannot start" with no
// line number is a riddle; the body is a superset of the ordinary error
// so a client that reads error/message/code keeps working.
func TestDagErrorCarriesTheFindings(t *testing.T) {
	prep, err := dagman.Prepare(dagman.Submission{Dag: "SPLICE S missing.dag\nJOB A a.sub\n"})
	if err != nil {
		t.Fatalf("Prepare: %v", err)
	}
	if !prep.Report.Fatal() {
		t.Fatal("the premise is gone: this DAG is no longer fatal")
	}
	w := httptest.NewRecorder()
	dagTestHandler(t).writeDagError(w, http.StatusBadRequest, prep, "This workflow cannot start")

	var body struct {
		Error    string       `json:"error"`
		Message  string       `json:"message"`
		Code     int          `json:"code"`
		Findings []DagFinding `json:"findings"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode: %v -- %s", err, w.Body.String())
	}
	if body.Code != http.StatusBadRequest || body.Error == "" || body.Message == "" {
		t.Errorf("the ordinary error fields are not all there: %+v", body)
	}
	var fatal bool
	for _, f := range body.Findings {
		fatal = fatal || f.Severity == "error"
	}
	if !fatal {
		t.Errorf("no fatal finding reached the caller: %+v", body.Findings)
	}
}

// TestDagSubmitRouteIsNotAJobID. "dag" is not a job id, and the
// /api/v1/jobs/ subtree's dispatcher would try to route it as one; the
// exact pattern has to win.
func TestDagSubmitRouteIsNotAJobID(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/v1/jobs/", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("subtree"))
	})
	mux.HandleFunc("/api/v1/jobs/dag", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("dag"))
	})
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/api/v1/jobs/dag", nil))
	if w.Body.String() != "dag" {
		t.Errorf("/api/v1/jobs/dag went to %q", w.Body.String())
	}
	// And the read endpoint underneath it is untouched.
	w = httptest.NewRecorder()
	mux.ServeHTTP(w, httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/api/v1/jobs/42.0/dag", nil))
	if w.Body.String() != "subtree" {
		t.Errorf("/api/v1/jobs/42.0/dag went to %q", w.Body.String())
	}
}

func opaqueNames(fs []dagman.OpaqueFile) []string {
	out := make([]string, 0, len(fs))
	for _, f := range fs {
		out = append(out, f.Name)
	}
	return out
}

// TestOpenAPIDocumentsDagSubmit. The spec is the contract site apps are
// told to read instead of guessing, so an endpoint missing from it may
// as well not exist -- and a $ref to a schema nobody wrote is worse than
// no documentation, because a generator stops on it.
func TestOpenAPIDocumentsDagSubmit(t *testing.T) {
	var doc map[string]any
	if err := json.Unmarshal([]byte(openAPISchema), &doc); err != nil {
		t.Fatalf("the OpenAPI document is not valid JSON: %v", err)
	}
	paths, _ := doc["paths"].(map[string]any)
	entry, ok := paths["/jobs/dag"].(map[string]any)
	if !ok {
		t.Fatal("POST /jobs/dag is not documented")
	}
	post, _ := entry["post"].(map[string]any)
	reqBody, _ := post["requestBody"].(map[string]any)
	content, _ := reqBody["content"].(map[string]any)
	for _, ct := range []string{"application/json", "multipart/form-data"} {
		if _, ok := content[ct]; !ok {
			t.Errorf("%s is not documented; a caller cannot know the one-request upload exists", ct)
		}
	}
	comps, _ := doc["components"].(map[string]any)
	schemas, _ := comps["schemas"].(map[string]any)
	for _, want := range []string{
		"DagSubmitRequest", "DagSubmitResponse", "DagDryRunResponse", "DagError", "DagFinding",
	} {
		if _, ok := schemas[want]; !ok {
			t.Errorf("schema %s is missing", want)
		}
	}
	var walk func(any)
	walk = func(v any) {
		switch node := v.(type) {
		case map[string]any:
			for k, vv := range node {
				if k == "$ref" {
					if ref, ok := vv.(string); ok {
						name := strings.TrimPrefix(ref, "#/components/schemas/")
						if _, ok := schemas[name]; !ok {
							t.Errorf("dangling $ref %q", ref)
						}
					}
					continue
				}
				walk(vv)
			}
		case []any:
			for _, vv := range node {
				walk(vv)
			}
		}
	}
	walk(doc)
}

// TestDagSubmitIsServedInMultiAP. Multi-AP mode serves only an
// allowlist of /api/ routes and answers 501 to everything else, so a new
// endpoint that nobody adds to it is dead there -- and "dag" sits in the
// /api/v1/jobs/ namespace, where the default for a POST is refusal.
func TestDagSubmitIsServedInMultiAP(t *testing.T) {
	if !multiAPAllowed(http.MethodPost, "/api/v1/jobs/dag") {
		t.Error("POST /api/v1/jobs/dag is refused in multi-AP mode")
	}
	// Only POST: nothing else is defined at that path, and a GET must
	// not be read as a request for the job whose id is "dag".
	for _, m := range []string{http.MethodGet, http.MethodDelete, http.MethodPatch} {
		if multiAPAllowed(m, "/api/v1/jobs/dag") {
			t.Errorf("%s /api/v1/jobs/dag is allowed", m)
		}
	}
	// And the read endpoint underneath an actual job id still is.
	if !multiAPAllowed(http.MethodGet, "/api/v1/jobs/42.0/dag") {
		t.Error("GET /api/v1/jobs/{id}/dag is refused in multi-AP mode")
	}
}
