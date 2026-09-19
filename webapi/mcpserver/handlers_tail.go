// Tailing a running job's output.
//
// get_job_stdout and get_job_stderr read the job ad's Out/Err and fetch
// the whole file, which is the right answer once a job has finished and
// the wrong one while it is running: the file lives on the execute node,
// and what a caller watching a job wants is the end of it, now, without
// moving megabytes.
//
// This is condor_tail's path instead -- GET_JOB_CONNECT_INFO to find the
// starter, then STARTER_PEEK -- exposed the way the REST endpoint at
// /api/v1/jobs/{id}/peek exposes it, including the offsets that let a
// caller poll for what is new rather than re-reading the same tail.

package mcpserver

import (
	"context"
	"fmt"
	"strings"
	"time"

	htcondor "github.com/bbockelm/golang-htcondor"
)

const (
	// tailDefaultMaxBytes is the per-call budget when the caller does
	// not say. Sized for a model's context rather than a terminal's
	// scrollback: a few hundred lines is a readable answer, a megabyte
	// is not.
	tailDefaultMaxBytes int64 = 16 * 1024

	// tailHardMaxBytes bounds what a caller may ask for. The starter has
	// its own caps; this keeps one tool call from spending a context
	// window.
	tailHardMaxBytes int64 = 256 * 1024

	// tailTimeout bounds the round trip to the starter, which is a
	// different machine that may be unreachable or busy.
	tailTimeout = 30 * time.Second
)

func tailTool() Tool {
	return Tool{
		Name: "tail_job_output",
		Description: "Read the END of a RUNNING job's stdout/stderr, from the execute node, without waiting for the job to finish. " +
			"This is the tool for watching a job make progress or diagnosing one that is stuck.\n" +
			"For a job that has already completed, use get_job_stdout / get_job_stderr instead: those read the transferred " +
			"output files, and this one talks to the starter, which no longer exists once the job ends.\n" +
			"To follow a job, call it again with the offsets from the previous result (stdout_offset / stderr_offset in the " +
			"metadata) and you get only what was appended since. Poll no more than every 5 seconds; each call is a round " +
			"trip to the execute node.",
		InputSchema: map[string]interface{}{
			"type": "object",
			"properties": map[string]interface{}{
				"job_id": map[string]interface{}{
					"type":        "string",
					"description": "Job ID in format 'cluster.proc' (e.g. '123.0')",
				},
				"stream": map[string]interface{}{
					"type":        "string",
					"description": "Which stream to read: 'stdout', 'stderr' or 'both' (default 'both').",
				},
				"max_bytes": map[string]interface{}{
					"type": "integer",
					"description": fmt.Sprintf("Byte budget shared across the requested streams (default %d, maximum %d). "+
						"The tail of the file is what you get, so a small budget still shows the most recent output.",
						tailDefaultMaxBytes, tailHardMaxBytes),
				},
				"stdout_offset": map[string]interface{}{
					"type": "integer",
					"description": "Resume stdout at this absolute byte offset, from a previous call's metadata. " +
						"Omit (or -1) to read the tail of whatever is there now.",
				},
				"stderr_offset": map[string]interface{}{
					"type":        "integer",
					"description": "Resume stderr at this absolute byte offset. Omit (or -1) for the tail.",
				},
			},
			"required": []string{"job_id"},
		},
	}
}

func (s *Server) toolTailJobOutput(ctx context.Context, args map[string]interface{}) (interface{}, error) {
	jobID, _ := args["job_id"].(string)
	wantStdout, wantStderr := true, true
	switch strings.ToLower(strings.TrimSpace(stringArg(args, "stream"))) {
	case "", "both":
	case "stdout":
		wantStderr = false
	case "stderr":
		wantStdout = false
	default:
		return nil, fmt.Errorf("stream must be 'stdout', 'stderr' or 'both'")
	}

	maxBytes := int64(intArg(args, "max_bytes", int(tailDefaultMaxBytes)))
	if maxBytes <= 0 {
		maxBytes = tailDefaultMaxBytes
	}
	if maxBytes > tailHardMaxBytes {
		maxBytes = tailHardMaxBytes
	}
	stdoutOffset := int64(intArg(args, "stdout_offset", -1))
	stderrOffset := int64(intArg(args, "stderr_offset", -1))

	cluster, proc, err := s.requireOwnRunningJob(ctx, jobID,
		"this tool reads from the execute node, so use get_job_stdout / get_job_stderr "+
			"for a job that is not running")
	if err != nil {
		return nil, err
	}

	peekCtx, cancel := context.WithTimeout(ctx, tailTimeout)
	defer cancel()

	result, err := s.getSchedd().PeekJobOutput(peekCtx, cluster, proc, htcondor.PeekRequest{
		Stdout:       wantStdout,
		StdoutOffset: stdoutOffset,
		Stderr:       wantStderr,
		StderrOffset: stderrOffset,
		MaxBytes:     maxBytes,
		// Same answer as the shell path and the REST terminal: an API
		// server that cannot accept inbound connections needs the broker
		// to relay, or the execute node is told to dial an address
		// nothing routes to.
		CCBStreaming: s.ccbStreaming,
	})
	if err != nil {
		return nil, fmt.Errorf("reading output from the execute node: %w", err)
	}

	var text strings.Builder
	metadata := map[string]interface{}{"job_id": jobID}
	appendStream := func(label string, stream *htcondor.PeekedStream, offsetKey string) {
		if stream == nil {
			return
		}
		metadata[offsetKey] = stream.Offset
		metadata[label] = string(stream.Bytes)
		fmt.Fprintf(&text, "%s (through byte %d):\n", label, stream.Offset)
		if len(stream.Bytes) == 0 {
			text.WriteString("(nothing new)\n")
			return
		}
		text.Write(stream.Bytes)
		if !strings.HasSuffix(string(stream.Bytes), "\n") {
			text.WriteString("\n")
		}
	}
	if wantStdout {
		appendStream("stdout", result.Stdout, "stdout_offset")
	}
	if wantStderr {
		appendStream("stderr", result.Stderr, "stderr_offset")
	}

	return withStructured(map[string]interface{}{
		"content":  []map[string]interface{}{{"type": "text", "text": text.String()}},
		"metadata": metadata,
	}, metadata), nil
}
