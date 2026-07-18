package httpserver

import (
	"context"
	"fmt"
	"net/http"
	"strconv"
	"time"

	htcondor "github.com/bbockelm/golang-htcondor"
	"github.com/bbockelm/golang-htcondor/logging"
	"github.com/bbockelm/golang-htcondor/ratelimit"
)

// PeekedStreamResponse is the JSON shape returned for one of the
// requested streams. `bytes` is the raw text the starter sent (the
// caller is responsible for handling NUL/binary content if it shows
// up — stdout/stderr are nearly always UTF-8). `offset` is the
// absolute file offset *after* this read; pass it back as
// `stdout_offset` / `stderr_offset` on the next call to follow.
type PeekedStreamResponse struct {
	Text   string `json:"text"`
	Offset int64  `json:"offset"`
}

// PeekResponse mirrors htcondor.PeekResult on the wire. Fields that
// weren't requested (or that the starter elected not to return) are
// omitted entirely so the SPA can detect "stream wasn't transferred"
// without inferring from a zero-length string.
type PeekResponse struct {
	Stdout *PeekedStreamResponse `json:"stdout,omitempty"`
	Stderr *PeekedStreamResponse `json:"stderr,omitempty"`
}

// peekDefaultMaxBytes caps the per-call byte budget when the client
// doesn't supply max_bytes. Larger than condor_tail's default (1024)
// because a UI poll wants a meatier snapshot, smaller than would
// stress the starter's transfer queue.
const peekDefaultMaxBytes int64 = 64 * 1024

// peekHardMaxBytes is the upper limit we accept from a client. The
// starter has its own caps, but we guard against absurd request
// sizes here so a runaway browser tab can't ask for gigabytes.
const peekHardMaxBytes int64 = 4 * 1024 * 1024

// handleJobPeek serves GET /api/v1/jobs/{id}/peek for live-tailing
// stdout / stderr of a running job. The flow is condor_tail's:
// the htcondor package's PeekJobOutput call goes via the schedd's
// GET_JOB_CONNECT_INFO + STARTER_PEEK round trip; this handler is a
// thin parser/encoder around it.
//
// Query parameters:
//   - stream:        "stdout" | "stderr" | "both" (default "both")
//   - stdout_offset: int64; -1 (default) = tail-from-end
//   - stderr_offset: int64; -1 (default) = tail-from-end
//   - max_bytes:     int64; capped at peekHardMaxBytes
func (s *Handler) handleJobPeek(w http.ResponseWriter, r *http.Request, cluster, proc int) {
	if r.Method != http.MethodGet {
		s.writeError(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}

	ctx, needsRedirect, err := s.requireAuthentication(r)
	if err != nil {
		if needsRedirect {
			s.redirectToLogin(w, r)
			return
		}
		s.writeError(w, http.StatusUnauthorized, fmt.Sprintf("Authentication failed: %v", err))
		return
	}

	q := r.URL.Query()

	stream := q.Get("stream")
	if stream == "" {
		stream = "both"
	}
	wantStdout := stream == "stdout" || stream == "both"
	wantStderr := stream == "stderr" || stream == "both"
	if !wantStdout && !wantStderr {
		s.writeError(w, http.StatusBadRequest, "stream must be one of stdout, stderr, both")
		return
	}

	stdoutOffset, err := parseSignedInt64Default(q.Get("stdout_offset"), -1)
	if err != nil {
		s.writeError(w, http.StatusBadRequest, "stdout_offset must be an integer (use -1 to tail)")
		return
	}
	stderrOffset, err := parseSignedInt64Default(q.Get("stderr_offset"), -1)
	if err != nil {
		s.writeError(w, http.StatusBadRequest, "stderr_offset must be an integer (use -1 to tail)")
		return
	}

	maxBytes, err := parseSignedInt64Default(q.Get("max_bytes"), peekDefaultMaxBytes)
	if err != nil || maxBytes <= 0 {
		s.writeError(w, http.StatusBadRequest, "max_bytes must be a positive integer")
		return
	}
	if maxBytes > peekHardMaxBytes {
		maxBytes = peekHardMaxBytes
	}

	// Bound the whole round-trip — it includes a schedd RPC + a
	// starter session resume. 30s leaves slack for a busy schedd
	// without making the SPA wait forever on a hung starter.
	peekCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()

	result, err := s.schedd.PeekJobOutput(peekCtx, cluster, proc, htcondor.PeekRequest{
		Stdout:       wantStdout,
		StdoutOffset: stdoutOffset,
		Stderr:       wantStderr,
		StderrOffset: stderrOffset,
		MaxBytes:     maxBytes,
	})
	if err != nil {
		if ratelimit.IsRateLimitError(err) {
			s.writeError(w, http.StatusTooManyRequests, fmt.Sprintf("Rate limit exceeded: %v", err))
			return
		}
		if isAuthenticationError(err) {
			s.writeError(w, http.StatusUnauthorized, fmt.Sprintf("Authentication failed: %v", err))
			return
		}
		// The most common failure mode is the job not running yet
		// (or just finished) — getJobConnectInfo returns an error
		// the schedd shapes around it. Surface as 409 so the SPA
		// can distinguish "ask again later" from a 5xx.
		s.logger.Info(logging.DestinationGeneral,
			"peek failed",
			"job", fmt.Sprintf("%d.%d", cluster, proc),
			"err", err.Error())
		s.writeError(w, http.StatusConflict,
			fmt.Sprintf("Cannot peek at job %d.%d: %v (job may not be running yet)", cluster, proc, err))
		return
	}

	resp := PeekResponse{}
	if result.Stdout != nil {
		resp.Stdout = &PeekedStreamResponse{
			Text:   string(result.Stdout.Bytes),
			Offset: result.Stdout.Offset,
		}
	}
	if result.Stderr != nil {
		resp.Stderr = &PeekedStreamResponse{
			Text:   string(result.Stderr.Bytes),
			Offset: result.Stderr.Offset,
		}
	}
	s.writeJSON(w, http.StatusOK, resp)
}

// parseSignedInt64Default parses an int64 from a query string, with
// an empty input falling back to def. Used for the offset/max_bytes
// params where "" means "use the default" rather than rejecting.
func parseSignedInt64Default(raw string, def int64) (int64, error) {
	if raw == "" {
		return def, nil
	}
	return strconv.ParseInt(raw, 10, 64)
}
