// htcondor-jupyter-helper is the worker-side counterpart of the JupyterLab
// reverse-tunnel feature in golang-htcondor. It runs *inside* the HTCondor
// job sandbox (Docker universe) and:
//
//   1. Reads a one-shot bearer token from a file (then unlink()'s the file
//      so subsequent processes in the sandbox cannot read it).
//   2. Optionally daemonizes (double-fork via re-exec) so it can be invoked
//      as a PreCmd that returns immediately while the actual tunnel keeps
//      running in the background.
//   3. Dials the web app's tunnel endpoint over a websocket, presenting
//      the bearer token in an Authorization header.
//   4. Wraps the websocket with hashicorp/yamux as the *server* side and
//      accepts streams. Each stream is forwarded to a local Unix domain
//      socket where JupyterLab is listening.
//
// Daemonization design: when invoked with --daemonize and the magic env var
// _HTCONDOR_JUPYTER_DAEMON_STAGE2 is *not* set, we are in stage 1. Stage 1
// reads the token file (and unlinks it), re-execs ourselves with
// --daemon-stage-2, passes the token in an env var, redirects stdio to a
// log file in the sandbox, sets a new session leader (Setsid: true), and
// exits 0. Stage 2 reads the token from env, unsets the env var, and runs
// the tunnel in the foreground until killed.

package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"flag"
	"fmt"
	"log"
	"net"
	"net/url"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/bbockelm/golang-htcondor/jupytertunnel"
	"github.com/bbockelm/golang-htcondor/version"
)

const (
	envDaemonStage2   = "_HTCONDOR_JUPYTER_DAEMON_STAGE2"
	envDaemonToken    = "_HTCONDOR_JUPYTER_TOKEN"
	envDaemonCABundle = "_HTCONDOR_JUPYTER_CA_BUNDLE_B64"
)

func main() {
	var (
		upstream    = flag.String("upstream", "", "websocket URL of the web app's tunnel endpoint, e.g. wss://app/api/v1/jupyter/instances/<id>/tunnel")
		tokenFile   = flag.String("token-file", "", "path to a file containing the bearer token (will be deleted after read)")
		socketPath  = flag.String("socket", "", "path to the Unix domain socket where JupyterLab will be listening")
		insecure    = flag.Bool("insecure-skip-verify", false, "skip TLS certificate verification (DEV ONLY)")
		caFile      = flag.String("ca-file", "", "PEM file with extra trusted CAs (in addition to the system pool); used to trust the demo's auto-generated CA")
		daemonize   = flag.Bool("daemonize", false, "fork into the background, print pid, and exit 0 (suitable for PreCmd)")
		logFile     = flag.String("log-file", "", "redirect daemon stdout/stderr here (default: <socket-dir>/jupyter-helper.log)")
		idleTimeout = flag.Duration("idle-timeout", 0, "close the tunnel and exit if no yamux stream has been accepted within this window (e.g. 30m). Zero = no timeout.")
		showVer     = flag.Bool("version", false, "print version and exit")
	)
	flag.Parse()

	if *showVer {
		info := version.Get()
		fmt.Printf("htcondor-jupyter-helper %s (commit %s)\n", info.Version, info.Commit)
		return
	}

	stage2 := os.Getenv(envDaemonStage2) == "1"

	if *daemonize && !stage2 {
		runStage1(*upstream, *tokenFile, *socketPath, *logFile, *insecure, *caFile, *idleTimeout)
		return
	}

	var (
		token   string
		caBytes []byte
	)
	if stage2 {
		// Daemonized child: token + CA bundle ride through env so the
		// child doesn't have to reopen the original on-disk files.
		// Putting them on argv would leak them via /proc/<pid>/cmdline;
		// the on-disk path stopped being reliable when we discovered
		// the daemonized child sometimes runs with a different cwd
		// than the launcher script.
		token = os.Getenv(envDaemonToken)
		_ = os.Unsetenv(envDaemonToken)
		if token == "" {
			log.Fatalf("daemon stage 2 missing %s in env", envDaemonToken)
		}
		if encoded := os.Getenv(envDaemonCABundle); encoded != "" {
			_ = os.Unsetenv(envDaemonCABundle)
			b, err := base64.StdEncoding.DecodeString(encoded)
			if err != nil {
				log.Fatalf("decode CA bundle from env: %v", err)
			}
			caBytes = b
		}
	} else {
		// Foreground mode (rare; mostly used for tests): read both off
		// disk ourselves.
		if *tokenFile == "" {
			fmt.Fprintln(os.Stderr, "missing required flags. usage:")
			flag.PrintDefaults()
			os.Exit(2)
		}
		t, err := readAndUnlinkTokenFile(*tokenFile)
		if err != nil {
			log.Fatalf("read token file: %v", err)
		}
		token = t
		if *caFile != "" {
			b, err := os.ReadFile(*caFile) //nolint:gosec // operator-controlled flag
			if err != nil {
				log.Fatalf("read ca file %s: %v", *caFile, err)
			}
			caBytes = b
		}
	}

	runTunnel(token, *upstream, *socketPath, *insecure, caBytes, *idleTimeout)
}

// runStage1 does all the work that can fail loudly — reading the token
// file, reading + parsing the CA bundle, dialing the upstream over TLS
// to confirm the cert chain validates — and only THEN daemonizes. The
// goal is "any failure here surfaces as a non-zero exit code that the
// wrapper script catches", instead of dying inside the daemon where
// the only signal is a stale jupyter-helper.log nobody reads.
//
// We also stop relying on the daemonized child being able to reopen
// disk paths: token + CA bytes are passed through env vars. Earlier
// versions read --ca-file in stage 2 and hit "no such file or
// directory" because the daemon's cwd diverged from the launcher's
// (likely a setsid-related quirk).
func runStage1(upstream, tokenFile, socketPath, logFile string, insecure bool, caFile string, idleTimeout time.Duration) {
	if upstream == "" || tokenFile == "" || socketPath == "" {
		fmt.Fprintln(os.Stderr, "missing required flags. usage:")
		flag.PrintDefaults()
		os.Exit(2)
	}

	token, err := readAndUnlinkTokenFile(tokenFile)
	if err != nil {
		log.Fatalf("read token file: %v", err)
	}

	// Read + parse the CA bundle now while we're still in the
	// foreground. A missing or unparseable file becomes a clean
	// non-zero exit instead of a daemon stderr message.
	var caBytes []byte
	if caFile != "" {
		b, err := os.ReadFile(caFile) //nolint:gosec // operator-controlled flag
		if err != nil {
			log.Fatalf("read ca file %s: %v", caFile, err)
		}
		// Sanity-check it parses, so a bad PEM doesn't pass the
		// pre-flight only to fail the daemon's own load later.
		test := x509.NewCertPool()
		if !test.AppendCertsFromPEM(b) {
			log.Fatalf("ca file %s contains no usable PEM certificates", caFile)
		}
		caBytes = b
	}

	// TLS pre-flight: open a TCP+TLS connection to the upstream host
	// and verify the cert chain. We deliberately don't do the
	// WebSocket upgrade — that would consume the registry's
	// "tunnel-connected" event and mark the instance as already
	// connected, breaking the daemon's subsequent dial.
	if err := verifyUpstreamTLS(upstream, caBytes, insecure); err != nil {
		log.Fatalf("upstream TLS verification failed: %v", err)
	}

	binary, err := os.Executable()
	if err != nil {
		log.Fatalf("os.Executable: %v", err)
	}

	// Build the stage-2 argv. We keep --daemonize off so stage 2 falls
	// through to the tunnel directly.
	args := []string{
		filepath.Base(binary),
		"--upstream", upstream,
		"--socket", socketPath,
		// Stage 2 reads the token from env, not the file, but we still
		// pass --token-file so usage messages and ps listings stay
		// honest. The flag is harmless since stage2 short-circuits it.
		"--token-file", tokenFile,
	}
	if insecure {
		args = append(args, "--insecure-skip-verify")
	}
	if idleTimeout > 0 {
		// Pass-through so stage 2's tunnel loop honors the same
		// timeout the operator (or launcher script) requested.
		args = append(args, "--idle-timeout", idleTimeout.String())
	}
	// Note: no --ca-file in stage-2 args. CA bytes ride through env
	// (envDaemonCABundle) — the daemon would otherwise try to open
	// the file from a possibly-different cwd than the launcher had.

	// Pick a log file. Default: jupyter-helper.log next to the UDS so the
	// user can find it after the job ends.
	if logFile == "" {
		logFile = filepath.Join(filepath.Dir(socketPath), "jupyter-helper.log")
	}
	logFD, err := os.OpenFile(logFile, os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0o600)
	if err != nil {
		log.Fatalf("open log file %s: %v", logFile, err)
	}
	defer logFD.Close()

	devNull, err := os.OpenFile(os.DevNull, os.O_RDWR, 0)
	if err != nil {
		log.Fatalf("open /dev/null: %v", err)
	}
	defer devNull.Close()

	env := append(os.Environ(),
		envDaemonStage2+"=1",
		envDaemonToken+"="+token,
	)
	if len(caBytes) > 0 {
		env = append(env, envDaemonCABundle+"="+base64.StdEncoding.EncodeToString(caBytes))
	}

	procAttr := &os.ProcAttr{
		Dir:   "",
		Env:   env,
		Files: []*os.File{devNull, logFD, logFD},
		Sys: &syscall.SysProcAttr{
			Setsid: true, // detach from controlling terminal
		},
	}

	proc, err := os.StartProcess(binary, args, procAttr)
	if err != nil {
		log.Fatalf("start daemon: %v", err)
	}
	pid := proc.Pid // capture before Release; Release zeros the field
	if err := proc.Release(); err != nil {
		log.Printf("warning: release daemon: %v", err)
	}

	fmt.Printf("htcondor-jupyter-helper daemonized; pid=%d log=%s\n", pid, logFile)
	os.Exit(0)
}

// verifyUpstreamTLS does a stripped-down TLS handshake against the
// upstream host. It's a smoke test: we want any "x509: certificate not
// trusted" / "connection refused" / "no route to host" failures to
// surface in stage 1 (which exits non-zero, which fails the wrapper
// script's `set -e`), not in the daemon's log file.
//
// We deliberately do NOT do the WebSocket upgrade or any HTTP request:
// that would hit the API server's tunnel handler, which would then
// register us as the live tunnel for this instance. When we close the
// connection the registry would tear the instance down and the
// daemon's actual dial moments later would fail.
func verifyUpstreamTLS(upstream string, caBytes []byte, insecure bool) error {
	u, err := url.Parse(upstream)
	if err != nil {
		return fmt.Errorf("parse upstream %q: %w", upstream, err)
	}
	if u.Scheme != "wss" && u.Scheme != "https" {
		return nil // plain ws / http: nothing to verify
	}
	host := u.Host
	if !strings.Contains(host, ":") {
		host = host + ":443"
	}

	var pool *x509.CertPool
	if len(caBytes) > 0 {
		pool = x509.NewCertPool()
		_ = pool.AppendCertsFromPEM(caBytes)
	}
	cfg := &tls.Config{
		//nolint:gosec // explicit operator opt-in via flag
		InsecureSkipVerify: insecure,
		RootCAs:            pool,
		MinVersion:         tls.VersionTLS12,
		ServerName:         strings.Split(host, ":")[0],
	}
	d := &net.Dialer{Timeout: 10 * time.Second}
	conn, err := tls.DialWithDialer(d, "tcp", host, cfg)
	if err != nil {
		return err
	}
	return conn.Close()
}

// readAndUnlinkTokenFile reads the token file and removes it before
// returning. We deliberately remove *after* a successful read so a transient
// read error doesn't leave us with no way to recover.
func readAndUnlinkTokenFile(path string) (string, error) {
	raw, err := os.ReadFile(path) //nolint:gosec // path comes from operator-controlled flag
	if err != nil {
		return "", err
	}
	if rmErr := os.Remove(path); rmErr != nil {
		log.Printf("warning: unlink %s: %v", path, rmErr)
	}
	tok := string(raw)
	for len(tok) > 0 && (tok[len(tok)-1] == '\n' || tok[len(tok)-1] == '\r') {
		tok = tok[:len(tok)-1]
	}
	return tok, nil
}

func runTunnel(token, upstream, socketPath string, insecure bool, caBytes []byte, idleTimeout time.Duration) {
	if upstream == "" || socketPath == "" {
		fmt.Fprintln(os.Stderr, "missing required flags")
		os.Exit(2)
	}
	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()

	// Build an extra-trusted CA pool from the in-memory bundle if
	// supplied. Stage 1 reads the file (or stage 2 reads the bytes
	// from env); either way we never touch the disk here, so a
	// daemon with a divergent cwd doesn't fail the second time around.
	var rootCAs *x509.CertPool
	if len(caBytes) > 0 {
		rootCAs = x509.NewCertPool()
		if !rootCAs.AppendCertsFromPEM(caBytes) {
			log.Fatalf("CA bundle contains no usable PEM certificates")
		}
		log.Printf("trusting %d-byte CA bundle from stage 1", len(caBytes))
	}

	cfg := jupytertunnel.HelperConfig{
		UpstreamURL:           upstream,
		Token:                 token,
		SocketPath:            socketPath,
		HandshakeTimeout:      30 * time.Second,
		TLSInsecureSkipVerify: insecure,
		TLSRootCAs:            rootCAs,
		IdleTimeout:           idleTimeout,
		Logger: func(f string, args ...any) {
			log.Printf(f, args...)
		},
	}

	if err := jupytertunnel.RunHelperTunnel(ctx, cfg); err != nil {
		log.Printf("tunnel exited: %v", err)
		os.Exit(1)
	}
}
