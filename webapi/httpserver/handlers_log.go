package httpserver

import (
	"archive/tar"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"path/filepath"
	"strings"
	"time"

	htcondor "github.com/bbockelm/golang-htcondor"
	"github.com/bbockelm/golang-htcondor/logging"
	"github.com/bbockelm/golang-htcondor/userlog"
)

// maxUserLogSize bounds how many bytes we will read from a job's user-log
// file before truncating. Logs larger than this are reported with
// truncated=true; the parser still gets a valid prefix.
const maxUserLogSize = 1 << 20 // 1 MiB

// JobLogResponse is the JSON shape returned by GET /api/v1/jobs/{id}/log.
// It mirrors the stdout/stderr endpoints — explicit fetch, no streaming.
type JobLogResponse struct {
	JobID     string          `json:"jobId"`
	Filename  string          `json:"filename"`
	Truncated bool            `json:"truncated"`
	Events    []userlog.Event `json:"events"`
}

// handleJobLog handles GET /api/v1/jobs/{id}/log. It reads UserLog from the
// job ad, fetches the corresponding file from the sandbox tarball, parses
// it with userlog.Parse, and returns the structured event list.
func (s *Handler) handleJobLog(w http.ResponseWriter, r *http.Request, cluster, proc int) {
	if r.Method != http.MethodGet {
		s.writeError(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}

	// Authenticate before any schedd calls so the per-user SecurityConfig
	// is on the context — same lesson as stdout/stderr.
	ctx, needsRedirect, err := s.requireAuthentication(r)
	if err != nil {
		if needsRedirect {
			s.redirectToLogin(w, r)
			return
		}
		s.writeError(w, http.StatusUnauthorized, fmt.Sprintf("Authentication failed: %v", err))
		return
	}

	constraint := fmt.Sprintf("ClusterId == %d && ProcId == %d", cluster, proc)
	jobAds, _, err := s.schedd.QueryWithOptions(ctx, constraint, &htcondor.QueryOptions{
		Projection: []string{"ClusterId", "ProcId", "JobStatus", "UserLog", "Iwd"},
	})
	if err != nil {
		s.logger.Error(logging.DestinationHTTP, "Failed to query job for log", "error", err)
		s.writeError(w, http.StatusInternalServerError, "Failed to query job")
		return
	}
	if len(jobAds) == 0 {
		s.writeError(w, http.StatusNotFound, fmt.Sprintf("Job not found: %d.%d", cluster, proc))
		return
	}

	logExpr, ok := jobAds[0].Lookup("UserLog")
	if !ok {
		s.writeError(w, http.StatusNotFound, "Job has no UserLog configured")
		return
	}
	logPath, err := logExpr.Eval(nil).StringValue()
	if err != nil || logPath == "" {
		s.writeError(w, http.StatusBadRequest, "Job UserLog attribute is empty or invalid")
		return
	}
	logName := filepath.Base(logPath)

	sandboxCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()

	body, truncated, err := s.fetchSandboxFileBytes(sandboxCtx, constraint, logName, maxUserLogSize)
	if err != nil {
		if errors.Is(err, errSandboxFileNotFound) {
			s.writeError(w, http.StatusNotFound, "Log file not found in job sandbox")
			return
		}
		s.logger.Error(logging.DestinationHTTP, "Failed to fetch log file", "error", err, "job", fmt.Sprintf("%d.%d", cluster, proc))
		s.writeError(w, http.StatusInternalServerError, fmt.Sprintf("Failed to fetch log: %v", err))
		return
	}

	events, parseErr := userlog.Parse(bytes.NewReader(body))
	// userlog.Parse returns (events_so_far, err) on malformed input; we
	// surface what we got plus a parse_error field so the UI can render
	// the prefix and show the user what went wrong.
	resp := JobLogResponse{
		JobID:     fmt.Sprintf("%d.%d", cluster, proc),
		Filename:  logName,
		Truncated: truncated,
		Events:    events,
	}
	if parseErr != nil {
		s.writeJSON(w, http.StatusOK, struct {
			JobLogResponse
			ParseError string `json:"parseError"`
		}{resp, parseErr.Error()})
		return
	}
	s.writeJSON(w, http.StatusOK, resp)
}

// errSandboxFileNotFound is returned by fetchSandboxFileBytes when the
// sandbox tarball was retrieved successfully but did not contain a file
// named filename.
var errSandboxFileNotFound = errors.New("sandbox file not found")

// fetchSandboxFileBytes downloads the job sandbox via ReceiveJobSandbox,
// scans the tar stream for a file whose basename matches filename, and
// returns up to maxBytes of its content. The bool is true if the file
// exceeded maxBytes and was truncated.
func (s *Handler) fetchSandboxFileBytes(ctx context.Context, constraint, filename string, maxBytes int64) ([]byte, bool, error) {
	pipeReader, pipeWriter := io.Pipe()

	sandboxErrChan := s.schedd.ReceiveJobSandbox(ctx, constraint, pipeWriter)
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

	tarReader := tar.NewReader(pipeReader)
	var (
		out       []byte
		truncated bool
		found     bool
		extractEr error
	)

	for {
		header, err := tarReader.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			extractEr = fmt.Errorf("read tar: %w", err)
			break
		}
		if filepath.Base(header.Name) != filename {
			continue
		}
		found = true
		buf := &bytes.Buffer{}
		// Cap the read at maxBytes+1 so we can detect overflow.
		n, copyErr := io.CopyN(buf, tarReader, maxBytes+1)
		if copyErr != nil && !errors.Is(copyErr, io.EOF) {
			extractEr = fmt.Errorf("read file: %w", copyErr)
			break
		}
		if n > maxBytes {
			truncated = true
			out = buf.Bytes()[:maxBytes]
		} else {
			out = buf.Bytes()
		}
		break
	}

	_ = pipeReader.Close()
	err := <-finalErrChan
	if found && err != nil && strings.Contains(err.Error(), "closed pipe") {
		err = nil
	}
	if err != nil {
		return nil, false, fmt.Errorf("download sandbox: %w", err)
	}
	if extractEr != nil {
		return nil, false, extractEr
	}
	if !found {
		return nil, false, errSandboxFileNotFound
	}
	return out, truncated, nil
}
