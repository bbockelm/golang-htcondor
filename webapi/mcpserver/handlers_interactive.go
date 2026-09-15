// Interactive sessions: a long-lived job the caller runs commands in,
// exposed as four tools that between them look like `exec` on a remote
// machine.
//
// The design point is that no state is carried by the connection. A
// session is named by the caller, the name is stored on the job, and
// every tool takes that name as an argument — so the same four tools
// work over stdio, over HTTP with a session header, and over a
// sessionless transport that reconnects between every call. Nothing
// here reads the MCP session id.
//
// Liveness is a lease rather than a socket, for the same reason: an
// agent may think for minutes between calls, and a gap in the
// conversation must not be read as "nobody is there". See
// webapi/interactive.Manager.

package mcpserver

import (
	"context"
	"fmt"
	"os/user"
	"strings"
	"time"

	htcondor "github.com/bbockelm/golang-htcondor"
	"github.com/bbockelm/golang-htcondor/webapi/interactive"
)

// interactiveTools is the tool catalog for interactive sessions,
// appended to the list handleListTools returns.
//
// The descriptions carry three things a model cannot infer and gets
// wrong by default: that a session costs a held slot until stopped,
// that each exec is a fresh shell, and that the session name is the
// only handle there is.
func interactiveTools() []Tool {
	sessionArg := map[string]interface{}{
		"type":        "string",
		"description": "Session name. Letters, digits, '.', '_' or '-'; up to 64 characters. This is the only handle to the session — pass the same name on every call.",
	}
	return []Tool{
		{
			Name: "interactive_session_start",
			Description: "Start a persistent interactive session: a job that holds a slot and waits, so you can run commands inside it. " +
				"Use this when you need several commands to run on the same machine with the same files — compiling then testing, " +
				"inspecting a dataset, debugging why a batch job fails — instead of submitting a batch job per command.\n" +
				"The session is idle when this returns; interactive_session_exec waits for it to start. " +
				"It holds its requested CPUs and memory until you stop it, so stop it when you are done and request only what you need. " +
				"An unused session is reclaimed automatically once its lease runs out (default 30 minutes); every call on the session extends the lease.",
			InputSchema: map[string]interface{}{
				"type": "object",
				"properties": map[string]interface{}{
					"session":   sessionArg,
					"cpus":      map[string]interface{}{"type": "integer", "description": "CPU cores to request (default 1, max 64)"},
					"memory_mb": map[string]interface{}{"type": "integer", "description": "Memory in MB (default 1024)"},
					"disk_mb":   map[string]interface{}{"type": "integer", "description": "Scratch disk in MB (default 1024)"},
					"gpus":      map[string]interface{}{"type": "integer", "description": "GPUs to request (default 0)"},
					"lease_seconds": map[string]interface{}{
						"type":        "integer",
						"description": "How long the session survives with no calls on it (default 1800). Each call resets the countdown.",
					},
					"requirements": map[string]interface{}{
						"type": "string",
						"description": "ClassAd expression narrowing which machines the session may run on, e.g. " +
							"\"TARGET.HasCVMFS == true\" or \"GLIDEIN_Site == \\\"Wisconsin\\\"\". " +
							"ANDed with any site-wide requirement the operator sets, which always applies. " +
							"Narrowing too far leaves the session queued with nothing to match it.",
					},
					"submit_lines": map[string]interface{}{
						"type": "string",
						"description": "Extra HTCondor submit commands, one per line, for what the other arguments do not cover " +
							"(e.g. \"container_image = docker://rockylinux:9\", \"+ProjectName = \\\"MyProject\\\"\"). " +
							"The commands that make the job a session -- executable, batch_name, universe, the transfer " +
							"settings and queue -- are refused, because redefining them produces a session that submits " +
							"and then cannot be attached to.",
					},
				},
				"required": []string{"session"},
			},
		},
		{
			Name: "interactive_session_exec",
			Description: "Run one shell command inside an interactive session and return its exit code, stdout and stderr. " +
				"Waits for the session's job to start running if it has not yet.\n" +
				"Each call is a FRESH shell: the working directory resets to the job's scratch directory and environment changes do not carry over. " +
				"Chain dependent steps in one call with '&&' (e.g. \"cd data && ls\") rather than across calls. Files written to the scratch directory DO persist for the life of the session.\n" +
				"The command runs on the execute machine as the job's user, not on the access point. " +
				"To get code into a session, write it with a heredoc (\"cat > run.py <<'EOF' ... EOF\") or fetch it from a URL with curl inside the job.",
			InputSchema: map[string]interface{}{
				"type": "object",
				"properties": map[string]interface{}{
					"session": sessionArg,
					"command": map[string]interface{}{
						"type":        "string",
						"description": "Shell command to run, interpreted by /bin/sh inside the job.",
					},
					"timeout_seconds": map[string]interface{}{
						"type":        "integer",
						"description": "Kill the command after this long (default 300, max 1800). On timeout you still get the output produced so far.",
					},
					"wait_seconds": map[string]interface{}{
						"type":        "integer",
						"description": "How long to wait for the session's job to start running before giving up (default 120, max 900). The job is waiting for a slot in the pool; this is not the command's own timeout.",
					},
				},
				"required": []string{"session", "command"},
			},
		},
		{
			Name:        "interactive_session_list",
			Description: "List your interactive sessions with their state (starting, ready, held) and the job backing each one. Sessions started by an earlier conversation are listed too — they live in the job queue, not in this connection.",
			InputSchema: map[string]interface{}{
				"type":       "object",
				"properties": map[string]interface{}{},
			},
		},
		{
			Name:        "interactive_session_stop",
			Description: "Stop an interactive session and release its slot. Do this as soon as you are finished with a session; anything left in its scratch directory is lost, so copy out what you need first.",
			InputSchema: map[string]interface{}{
				"type": "object",
				"properties": map[string]interface{}{
					"session": sessionArg,
				},
				"required": []string{"session"},
			},
		},
	}
}

// liveJobCaller resolves who is asking into the identity pair the
// session manager needs -- and, since they answer the same question,
// every other tool that reaches into a running job.
//
// Admins are deliberately NOT exempted here, unlike the query tools.
// Owner scope on a query is about what you may read; a session is a
// live shell inside somebody else's job, and "troubleshooting" is not
// a reason to hand an agent one. An admin who needs that has
// condor_ssh_to_job.
func (s *Server) liveJobCaller(ctx context.Context) (interactive.Caller, error) {
	actor := htcondor.GetAuthenticatedUserFromContext(ctx)
	if actor == "" {
		// No actor on the context means one of two very different
		// things, and the difference is s.delegated. Behind HTTP every
		// call is on somebody's behalf, so an unidentifiable caller
		// must be refused. Run from a shell over stdio, the server IS
		// the user -- it holds their credentials and the schedd
		// authenticates it as them -- and refusing there made all four
		// tools unusable on that transport while still listing them.
		// Every other owner-scoped tool in this package already draws
		// the line this way.
		if s.delegated {
			return interactive.Caller{}, fmt.Errorf("authentication required")
		}
		me, err := user.Current()
		if err != nil || me.Username == "" {
			return interactive.Caller{}, fmt.Errorf("cannot determine the local user to act as: %w", err)
		}
		return interactive.Caller{Actor: me.Username, Owner: me.Username}, nil
	}
	return interactive.Caller{Actor: actor, Owner: ownerFromActor(actor)}, nil
}

// interactiveManager returns the session manager, or an error naming
// why this server has none.
func (s *Server) interactiveManager() (*interactive.Manager, error) {
	if s.interactive == nil {
		return nil, fmt.Errorf("interactive sessions are not available on this server")
	}
	return s.interactive, nil
}

func (s *Server) toolInteractiveSessionStart(ctx context.Context, args map[string]interface{}) (interface{}, error) {
	mgr, err := s.interactiveManager()
	if err != nil {
		return nil, err
	}
	caller, err := s.liveJobCaller(ctx)
	if err != nil {
		return nil, err
	}
	name, _ := args["session"].(string)

	spec := interactive.CreateSpec{
		Name:         strings.TrimSpace(name),
		Cpus:         intArg(args, "cpus", 0),
		MemoryMB:     intArg(args, "memory_mb", 0),
		DiskMB:       intArg(args, "disk_mb", 0),
		Gpus:         intArg(args, "gpus", 0),
		Lease:        time.Duration(intArg(args, "lease_seconds", 0)) * time.Second,
		Requirements: strings.TrimSpace(stringArg(args, "requirements")),
		SubmitLines:  stringArg(args, "submit_lines"),
	}
	info, err := mgr.Create(ctx, caller, spec)
	if err != nil {
		return nil, err
	}

	return map[string]interface{}{
		"content": []map[string]interface{}{
			{
				"type": "text",
				"text": fmt.Sprintf(
					"Started interactive session %q (job %s). It is queued and will be ready once it matches a slot.\n"+
						"Run commands with interactive_session_exec using session=%q — that call waits for the job to start.\n"+
						"The session holds its slot until you call interactive_session_stop, or until %s with no calls on it.",
					info.Name, info.JobID, info.Name, leaseDescription(info.LeaseExpires)),
			},
		},
		"metadata": interactiveInfoMetadata(*info),
	}, nil
}

func (s *Server) toolInteractiveSessionExec(ctx context.Context, args map[string]interface{}) (interface{}, error) {
	mgr, err := s.interactiveManager()
	if err != nil {
		return nil, err
	}
	caller, err := s.liveJobCaller(ctx)
	if err != nil {
		return nil, err
	}
	name, _ := args["session"].(string)
	command, _ := args["command"].(string)

	result, err := mgr.Exec(ctx, caller, strings.TrimSpace(name), interactive.ExecRequest{
		Command:      command,
		Timeout:      time.Duration(intArg(args, "timeout_seconds", 0)) * time.Second,
		WaitForReady: time.Duration(intArg(args, "wait_seconds", 0)) * time.Second,
	})
	if err != nil {
		return nil, err
	}

	return map[string]interface{}{
		"content": []map[string]interface{}{
			{"type": "text", "text": formatExecResult(result)},
		},
		"metadata": map[string]interface{}{
			"job_id":           result.JobID,
			"exit_code":        result.ExitCode,
			"duration_ms":      result.Duration.Milliseconds(),
			"timed_out":        result.TimedOut,
			"stdout_truncated": result.StdoutTruncated,
			"stderr_truncated": result.StderrTruncated,
		},
	}, nil
}

func (s *Server) toolInteractiveSessionList(ctx context.Context, _ map[string]interface{}) (interface{}, error) {
	mgr, err := s.interactiveManager()
	if err != nil {
		return nil, err
	}
	caller, err := s.liveJobCaller(ctx)
	if err != nil {
		return nil, err
	}
	infos, err := mgr.List(ctx, caller)
	if err != nil {
		return nil, err
	}

	var sb strings.Builder
	if len(infos) == 0 {
		sb.WriteString("No interactive sessions. Start one with interactive_session_start.")
	} else {
		fmt.Fprintf(&sb, "%d interactive session(s):\n", len(infos))
		for _, info := range infos {
			fmt.Fprintf(&sb, "- %s: %s (job %s)", info.Name, info.Status, info.JobID)
			if info.HoldReason != "" {
				fmt.Fprintf(&sb, " — held: %s", info.HoldReason)
			}
			if !info.LeaseExpires.IsZero() {
				fmt.Fprintf(&sb, ", lease %s", leaseDescription(info.LeaseExpires))
			}
			sb.WriteString("\n")
		}
	}

	rows := make([]map[string]interface{}, 0, len(infos))
	for _, info := range infos {
		rows = append(rows, interactiveInfoMetadata(info))
	}
	return map[string]interface{}{
		"content":  []map[string]interface{}{{"type": "text", "text": sb.String()}},
		"metadata": map[string]interface{}{"sessions": rows},
	}, nil
}

func (s *Server) toolInteractiveSessionStop(ctx context.Context, args map[string]interface{}) (interface{}, error) {
	mgr, err := s.interactiveManager()
	if err != nil {
		return nil, err
	}
	caller, err := s.liveJobCaller(ctx)
	if err != nil {
		return nil, err
	}
	name, _ := args["session"].(string)
	info, err := mgr.Stop(ctx, caller, strings.TrimSpace(name))
	if err != nil {
		return nil, err
	}
	return map[string]interface{}{
		"content": []map[string]interface{}{
			{"type": "text", "text": fmt.Sprintf("Stopped interactive session %q (job %s); its slot is being released.", info.Name, info.JobID)},
		},
		"metadata": interactiveInfoMetadata(*info),
	}, nil
}

func interactiveInfoMetadata(info interactive.Info) map[string]interface{} {
	m := map[string]interface{}{
		"session":    info.Name,
		"job_id":     info.JobID,
		"job_status": info.JobStatus,
		"status":     info.Status,
		"attached":   info.Attached,
	}
	if info.HoldReason != "" {
		m["hold_reason"] = info.HoldReason
	}
	if !info.LeaseExpires.IsZero() {
		m["lease_expires"] = info.LeaseExpires.UTC().Format(time.RFC3339)
	}
	if !info.SubmittedAt.IsZero() {
		m["submitted_at"] = info.SubmittedAt.UTC().Format(time.RFC3339)
	}
	return m
}

// formatExecResult renders a command's outcome for a model to read.
//
// Exit code first, because it is the part that decides what the caller
// does next and the part most easily lost at the end of a long stdout.
// Streams are labeled and empty ones are called out rather than
// omitted: "(no output)" is information, and a missing section reads
// as a truncated answer.
func formatExecResult(r *interactive.ExecResult) string {
	var sb strings.Builder
	if r.TimedOut {
		fmt.Fprintf(&sb, "Command timed out and was killed after %s. Output produced before then:\n", r.Duration.Round(time.Second))
	} else {
		fmt.Fprintf(&sb, "exit code %d (%s)\n", r.ExitCode, r.Duration.Round(time.Millisecond))
	}
	sb.WriteString("\nstdout:\n")
	sb.WriteString(streamSection(r.Stdout, r.StdoutTruncated, r.MaxOutputBytes))
	sb.WriteString("\nstderr:\n")
	sb.WriteString(streamSection(r.Stderr, r.StderrTruncated, r.MaxOutputBytes))
	return sb.String()
}

func streamSection(body string, truncated bool, limit int) string {
	if body == "" {
		return "(no output)\n"
	}
	if !strings.HasSuffix(body, "\n") {
		body += "\n"
	}
	if truncated {
		if limit <= 0 {
			limit = interactive.DefaultMaxOutputBytes
		}
		body += fmt.Sprintf("[truncated at %d bytes — rerun with a narrower command, or redirect to a file and read it in pieces]\n", limit)
	}
	return body
}

// leaseDescription renders a lease expiry as a duration from now,
// which is what a caller acts on ("I have 28 minutes").
func leaseDescription(expires time.Time) string {
	if expires.IsZero() {
		return "its lease expires"
	}
	d := time.Until(expires).Round(time.Minute)
	if d <= 0 {
		return "expired"
	}
	return fmt.Sprintf("%s from now", d)
}
