// WebSocket bridge for condor_ssh_to_job, intended to drive a browser-based
// terminal (xterm.js or similar). The protocol is intentionally minimal and
// matches the convention most browser-terminal libraries already speak:
//
//   - Binary frames in either direction carry raw stdio bytes.
//       client -> server : keystrokes (stdin)
//       server -> client : terminal output (stdout/stderr merged)
//
//   - Text frames carry small JSON control messages.
//       {"type":"resize","cols":N,"rows":M}    — TIOCSWINSZ on the SSH session
//       {"type":"signal","name":"INT"}         — POSIX signal name to deliver
//       {"type":"close"}                       — request graceful shutdown
//
// On error or remote close, the server sends a final text frame
// {"type":"exit","code":N,"reason":"..."} and closes the WebSocket with a
// normal close frame.

package httpserver

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	htcondor "github.com/bbockelm/golang-htcondor"
	"github.com/bbockelm/golang-htcondor/logging"
	"github.com/gorilla/websocket"
	"golang.org/x/crypto/ssh"
)

// wsControlMsg is the JSON shape exchanged in WebSocket text frames.
type wsControlMsg struct {
	Type string `json:"type"`
	// Resize fields
	Cols int `json:"cols,omitempty"`
	Rows int `json:"rows,omitempty"`
	// Signal field
	Name string `json:"name,omitempty"`
	// Exit fields (server -> client only)
	Code   int    `json:"code,omitempty"`
	Reason string `json:"reason,omitempty"`
}

// sshUpgrader is configured per-handler so that origin policy can be tuned
// later without touching every call site. We accept any origin for now to
// match the rest of the API's CORS behavior; production deployments behind
// an OIDC proxy should override this.
var sshUpgrader = websocket.Upgrader{
	ReadBufferSize:  4096,
	WriteBufferSize: 4096,
	CheckOrigin: func(_ *http.Request) bool {
		return true
	},
}

// handleJobSSH bridges a WebSocket client to an interactive SSH session
// inside the job's sandbox. Path: /api/v1/jobs/{cluster}.{proc}/ssh
func (s *Handler) handleJobSSH(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		s.writeError(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}

	// Extract {cluster}.{proc} from the path.
	const prefix = "/api/v1/jobs/"
	rest := strings.TrimPrefix(r.URL.Path, prefix)
	rest = strings.TrimSuffix(rest, "/ssh")
	cluster, proc, err := parseJobID(rest)
	if err != nil {
		s.writeError(w, http.StatusBadRequest, fmt.Sprintf("invalid job id: %v", err))
		return
	}

	// Authentication. We deliberately authenticate BEFORE the WebSocket
	// upgrade so that 401 surfaces as a clean HTTP response — once the
	// upgrade has happened the only signal we can give the client is a
	// close frame, which most browser libraries surface poorly.
	ctx, needsRedirect, err := s.requireAuthentication(r)
	if err != nil {
		if needsRedirect {
			s.redirectToLogin(w, r)
			return
		}
		s.writeError(w, http.StatusUnauthorized, fmt.Sprintf("Authentication failed: %v", err))
		return
	}

	username := htcondor.GetAuthenticatedUserFromContext(ctx)
	s.logger.Info(logging.DestinationHTTP, "SSH-to-job request",
		"user", username, "cluster", cluster, "proc", proc)

	// Detect interactive-terminal jobs by JobBatchName so the bridge can
	// keep the watchdog happy. We do this ahead of the SSH dial — a
	// quick schedd query is much cheaper than the Cedar handshake, and
	// failing here just means "no heartbeat" (worst case the user types
	// continuously and the watchdog inside the job exits after the
	// freshness window).
	interactive := s.jobIsInteractiveByID(ctx, cluster, proc)

	// Open the SSH client BEFORE the WebSocket upgrade so that any failure
	// here can return a proper HTTP error. This makes the happy path "open
	// SSH session, then upgrade and bridge" — the WebSocket only exists if
	// we already have a working SSH client.
	openCtx, cancelOpen := context.WithTimeout(ctx, 30*time.Second)
	defer cancelOpen()

	schedd := s.getSchedd()
	if schedd == nil {
		s.writeError(w, http.StatusServiceUnavailable, "schedd not configured")
		return
	}

	sshClient, err := schedd.OpenJobShell(openCtx, cluster, proc, nil)
	if err != nil {
		s.logger.Error(logging.DestinationHTTP, "OpenJobShell failed",
			"user", username, "cluster", cluster, "proc", proc, "error", err)
		s.writeError(w, http.StatusBadGateway, fmt.Sprintf("failed to open job shell: %v", err))
		return
	}

	// Open the SSH session and request a PTY before we hand off to the WS,
	// for the same reason as above: any error here should be a clean 502.
	session, err := sshClient.NewSession()
	if err != nil {
		_ = sshClient.Close()
		s.writeError(w, http.StatusBadGateway, fmt.Sprintf("failed to open SSH session: %v", err))
		return
	}

	// Initial PTY size. The browser will resize immediately, so 80x24 is
	// just a safe placeholder.
	cols, rows := initialPtyDimsFromQuery(r.URL.Query())
	modes := ssh.TerminalModes{
		ssh.ECHO:          1,
		ssh.TTY_OP_ISPEED: 38400,
		ssh.TTY_OP_OSPEED: 38400,
	}
	if err := session.RequestPty("xterm-256color", rows, cols, modes); err != nil {
		_ = session.Close()
		_ = sshClient.Close()
		s.writeError(w, http.StatusBadGateway, fmt.Sprintf("failed to request PTY: %v", err))
		return
	}

	stdin, err := session.StdinPipe()
	if err != nil {
		_ = session.Close()
		_ = sshClient.Close()
		s.writeError(w, http.StatusBadGateway, fmt.Sprintf("failed to attach stdin: %v", err))
		return
	}
	stdout, err := session.StdoutPipe()
	if err != nil {
		_ = session.Close()
		_ = sshClient.Close()
		s.writeError(w, http.StatusBadGateway, fmt.Sprintf("failed to attach stdout: %v", err))
		return
	}
	// Merge stderr into stdout so the terminal renders both. Some servers
	// emit warnings on stderr that the user wants to see.
	stderr, err := session.StderrPipe()
	if err != nil {
		_ = session.Close()
		_ = sshClient.Close()
		s.writeError(w, http.StatusBadGateway, fmt.Sprintf("failed to attach stderr: %v", err))
		return
	}

	if err := session.Shell(); err != nil {
		_ = session.Close()
		_ = sshClient.Close()
		s.writeError(w, http.StatusBadGateway, fmt.Sprintf("failed to start shell: %v", err))
		return
	}

	// All systems go: upgrade.
	wsConn, err := sshUpgrader.Upgrade(w, r, nil)
	if err != nil {
		// Upgrader already wrote an HTTP error response.
		_ = session.Close()
		_ = sshClient.Close()
		return
	}

	bridgeSSHToWebSocket(ctx, s, wsConn, sshClient, session, stdin, stdout, stderr,
		bridgeOptions{
			JobID:       fmt.Sprintf("%d.%d", cluster, proc),
			Interactive: interactive,
		})
}

// bridgeOptions carries per-request behavior into bridgeSSHToWebSocket.
// Kept as a struct so the next knob (e.g. "max session duration") doesn't
// have to grow the call signature.
type bridgeOptions struct {
	JobID       string
	Interactive bool // run the heartbeat goroutine
}

// jobIsInteractiveByID looks up the job's JobBatchName and reports whether
// it's one of our interactive terminals. Returns false (no heartbeat)
// for any error path — the bridge still works, the watchdog just won't
// be kept alive, which is the right safe default.
func (s *Handler) jobIsInteractiveByID(ctx context.Context, cluster, proc int) bool {
	schedd := s.getSchedd()
	if schedd == nil {
		return false
	}
	constraint := fmt.Sprintf("ClusterId == %d && ProcId == %d", cluster, proc)
	ads, _, err := schedd.QueryWithOptions(ctx, constraint, &htcondor.QueryOptions{
		Projection: []string{"JobBatchName"},
		Limit:      1,
	})
	if err != nil || len(ads) == 0 {
		return false
	}
	return jobIsInteractive(ads[0])
}

func initialPtyDimsFromQuery(q map[string][]string) (cols, rows int) {
	cols, rows = 80, 24
	if vs := q["cols"]; len(vs) > 0 {
		if v, err := strconv.Atoi(vs[0]); err == nil && v > 0 && v <= 1000 {
			cols = v
		}
	}
	if vs := q["rows"]; len(vs) > 0 {
		if v, err := strconv.Atoi(vs[0]); err == nil && v > 0 && v <= 1000 {
			rows = v
		}
	}
	return cols, rows
}

// bridgeSSHToWebSocket runs until either side closes. It owns sshClient and
// session and will close both on return.
//
//nolint:gocyclo // single linear protocol loop; splitting fragments the lifecycle
func bridgeSSHToWebSocket(
	ctx context.Context,
	s *Handler,
	wsConn *websocket.Conn,
	sshClient *ssh.Client,
	session *ssh.Session,
	stdin io.WriteCloser,
	stdout io.Reader,
	stderr io.Reader,
	opts bridgeOptions,
) {
	defer func() {
		_ = session.Close()
		_ = sshClient.Close()
		_ = wsConn.Close()
	}()

	// Limit how big a single client message can be. 64 KiB is plenty for
	// stdin and dwarfs any sensible JSON control message.
	wsConn.SetReadLimit(64 * 1024)

	// Heartbeat plumbing for interactive jobs. lastKeystroke is only
	// non-nil when the job's JobBatchName marked it as interactive; the
	// reader checks for nil before storing.
	//
	// We bootstrap lastKeystroke to "now" so the first tick of the
	// heartbeat goroutine fires regardless of whether the user has
	// typed yet — the user just attached, they're clearly active.
	var lastKeystroke *atomic.Int64
	if opts.Interactive {
		lastKeystroke = new(atomic.Int64)
		lastKeystroke.Store(time.Now().UnixNano())
		stop := s.startInteractiveHeartbeat(ctx, sshClient, opts.JobID, lastKeystroke)
		defer stop()

		// On disconnect from an interactive session, condor_rm the job.
		// The watchdog inside the job would also reap it after ~120s
		// of stale heartbeat, but users expect closing the browser tab
		// (or hitting "End session" in the UI) to free the slot
		// immediately. We do this from a deferred closure so it runs
		// once the bridge has torn down — `s.removeJobOnDisconnect`
		// uses a fresh context (not `ctx`, which is dying) and a
		// short timeout, since by then the WS handler is exiting and
		// any remaining schedd I/O is best-effort.
		defer s.removeJobOnDisconnect(opts.JobID)

		// Drop a `.shutdown` sentinel via the still-open ssh.Client
		// before we tear it down. The watchdog polls for that file
		// and exits within POLL_INTERVAL seconds, which is faster
		// than condor_rm's schedd round-trip and works even if
		// condor_rm is somehow lossy (e.g., schedd backlog). LIFO
		// order matters: this defer is declared AFTER the close-all
		// defer at the top of the function, so it runs first — the
		// sshClient is still alive when we open this last session.
		defer s.sendInteractiveShutdownSignal(sshClient, opts.JobID)
	}

	// Channel to surface the wait result without blocking the bridges.
	waitCh := make(chan error, 1)
	go func() { waitCh <- session.Wait() }()

	// Client-initiated close: the reader signals here when it gets a
	// {"type":"close"} control frame so the writer can flush a final
	// {"type":"exit"} frame even if the remote shell hasn't terminated.
	closeReq := make(chan struct{}, 1)

	// Reader: WebSocket -> SSH stdin / control. Runs in its own goroutine.
	readerDone := make(chan struct{})
	go func() {
		defer close(readerDone)
		for {
			msgType, payload, err := wsConn.ReadMessage()
			if err != nil {
				return
			}
			switch msgType {
			case websocket.BinaryMessage:
				if lastKeystroke != nil {
					// Stamp every inbound keystroke. The heartbeat
					// goroutine reads this to decide whether to send.
					lastKeystroke.Store(time.Now().UnixNano())
				}
				if _, werr := stdin.Write(payload); werr != nil {
					return
				}
			case websocket.TextMessage:
				var ctrl wsControlMsg
				if jerr := json.Unmarshal(payload, &ctrl); jerr != nil {
					s.logger.Warn(logging.DestinationHTTP, "ssh-ws: bad control frame",
						"error", jerr, "payload_len", len(payload))
					continue
				}
				switch ctrl.Type {
				case "resize":
					if ctrl.Cols > 0 && ctrl.Rows > 0 {
						_ = session.WindowChange(ctrl.Rows, ctrl.Cols)
					}
				case "signal":
					if sig := mapSignal(ctrl.Name); sig != "" {
						_ = session.Signal(sig)
					}
				case "close":
					// Best-effort: ask the remote shell to exit; signal
					// the writer to flush the exit frame regardless.
					//
					// We deliberately do NOT return from the reader
					// here — that would race the parent's select on
					// readerDone vs. writerDone and tear the WebSocket
					// down before the exit frame goes out. The writer
					// will finish, the parent's defer will close the
					// WebSocket, and our next ReadMessage will return
					// the resulting error and exit the goroutine.
					_ = session.Signal(ssh.SIGHUP)
					_ = stdin.Close()
					select {
					case closeReq <- struct{}{}:
					default:
					}
				}
			default:
				// Ignore ping/pong/close — the gorilla library handles them.
			}
		}
	}()

	// Two writers: stdout and stderr both flow into binary WS frames.
	// We serialize all WS writes through a single goroutine to satisfy
	// gorilla/websocket's "one concurrent writer" requirement.
	type wsMsg struct {
		typ  int
		data []byte
	}
	out := make(chan wsMsg, 16)

	pipeReader := func(r io.Reader, label string) {
		buf := make([]byte, 32*1024)
		for {
			n, rerr := r.Read(buf)
			if n > 0 {
				cp := make([]byte, n)
				copy(cp, buf[:n])
				select {
				case out <- wsMsg{typ: websocket.BinaryMessage, data: cp}:
				case <-ctx.Done():
					return
				}
			}
			if rerr != nil {
				if rerr != io.EOF {
					s.logger.Debug(logging.DestinationHTTP, "ssh-ws: pipe read error",
						"stream", label, "error", rerr)
				}
				return
			}
		}
	}
	go pipeReader(stdout, "stdout")
	go pipeReader(stderr, "stderr")

	// Writer goroutine: drains `out` to the WebSocket and emits the final
	// exit frame.
	writerDone := make(chan struct{})
	go func() {
		defer close(writerDone)
		for {
			select {
			case msg, ok := <-out:
				if !ok {
					return
				}
				if err := wsConn.WriteMessage(msg.typ, msg.data); err != nil {
					return
				}
			case waitErr := <-waitCh:
				code, reason := translateWaitErr(waitErr)
				exitMsg := wsControlMsg{Type: "exit", Code: code, Reason: reason}
				if b, jerr := json.Marshal(exitMsg); jerr == nil {
					_ = wsConn.WriteMessage(websocket.TextMessage, b)
				}
				_ = wsConn.WriteMessage(websocket.CloseMessage,
					websocket.FormatCloseMessage(websocket.CloseNormalClosure, "session ended"))
				return
			case <-closeReq:
				// Client asked to close. Emit a synthetic exit frame so
				// the browser sees a clean termination, then close the
				// WebSocket. Use code=0 since we don't have a real
				// exit-status from the shell.
				exitMsg := wsControlMsg{Type: "exit", Code: 0, Reason: "client-closed"}
				if b, jerr := json.Marshal(exitMsg); jerr == nil {
					_ = wsConn.WriteMessage(websocket.TextMessage, b)
				}
				_ = wsConn.WriteMessage(websocket.CloseMessage,
					websocket.FormatCloseMessage(websocket.CloseNormalClosure, "client closed"))
				return
			case <-ctx.Done():
				return
			}
		}
	}()

	// Wait for *either* the reader to finish (WS closed) or the writer to
	// finish (session ended). When one ends we tear everything down.
	select {
	case <-readerDone:
	case <-writerDone:
	}
}

// translateWaitErr converts session.Wait()'s error into the exit code we
// surface to the client. crypto/ssh returns *ExitError for normal exits and
// *ExitMissingError when the server closed without sending an exit-status,
// which is a common case for users typing `exit` in a shell.
func translateWaitErr(err error) (int, string) {
	if err == nil {
		return 0, ""
	}
	var ee *ssh.ExitError
	if errors.As(err, &ee) {
		return ee.ExitStatus(), ee.Signal()
	}
	var em *ssh.ExitMissingError
	if errors.As(err, &em) {
		return 0, "no-exit-status"
	}
	return -1, err.Error()
}

// mapSignal converts a friendly signal name from the JSON control frame
// into the SSH protocol's signal token. See RFC 4254 §6.10. Accepts both
// "INT" and "SIGINT" forms, case-insensitively.
func mapSignal(name string) ssh.Signal {
	switch strings.TrimPrefix(strings.ToUpper(name), "SIG") {
	case "INT":
		return ssh.SIGINT
	case "TERM":
		return ssh.SIGTERM
	case "QUIT":
		return ssh.SIGQUIT
	case "HUP":
		return ssh.SIGHUP
	case "KILL":
		return ssh.SIGKILL
	case "USR1":
		return ssh.SIGUSR1
	case "USR2":
		return ssh.SIGUSR2
	}
	return ""
}
