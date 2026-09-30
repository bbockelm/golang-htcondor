// Package vscode builds the HTCondor job that runs a VS Code server
// inside a sandbox, reached through the API server's job proxy.
//
// The server listens on a Unix socket in the job's scratch directory,
// never on a TCP port. A port bound to 127.0.0.1 in a sandbox is
// reachable by any local user on the execute node unless the job has
// its own network namespace, which no pool can be assumed to
// configure; a socket is protected by file permissions. That is also
// why the server runs with authentication disabled and no secret is
// minted anywhere in this design: the socket's permissions ARE the
// authorization, and reaching it at all requires the schedd to agree
// the caller owns the job.
package vscode

import (
	"errors"
	"fmt"
	"strings"
	"time"
)

// BatchPrefix marks a job as a VS Code session by JobBatchName.
//
// JobBatchName rather than a custom attribute, following the
// interactive package: it is what `condor_q -batch` already displays,
// so a user sees their sessions in the queue without being told where
// to look.
const BatchPrefix = "htcondor-api-vscode-"

// AppAttr is a custom job attribute marking a job as one of ours, and
// AppAttrValue its value.
//
// The JobBatchName carries the same fact and is what `condor_q -batch`
// shows a human, but it cannot be queried portably: finding an app by
// it means a prefix match, while this is an equality constraint every
// schedd understands. That matters because the alternative -- fetching
// the caller's jobs and filtering here -- silently loses an app to the
// query limit for anyone with a few hundred jobs in the queue, which is
// an ordinary number.
const (
	AppAttr      = "HTCondorAPIApp"
	AppAttrValue = "code-server"
)

// SocketName is the socket the server listens on, relative to the
// job's scratch directory. The proxy addresses a session by it, so it
// is part of the URL and cannot vary per session without the caller
// being told.
const SocketName = "vscode.sock"

// MaxSocketPath is the practical ceiling on a Unix socket address.
// sun_path is 108 bytes on Linux and 104 on macOS, and both ends of an
// SSH forward are bound by it. An HTCondor scratch directory can fill
// most of that on its own, and the kernel's complaint is an
// uninformative "open failed" at the far end -- so the launcher checks
// it in the sandbox, where the real path is known, and refuses to
// start rather than leaving the proxy to report a mystery.
const MaxSocketPath = 100

// RecommendedImage is a published code-server image, offered as a
// default an operator can override. We do not build or maintain an
// image: this project ships no container, and nothing here builds one
// for you.
//
// codercom/code-server is code-server's own image, tracks its releases
// closely and publishes amd64 and arm64. The obvious alternatives are
// worth knowing about:
//
//   - gitpod/openvscode-server has not had a release since 2025-10.
//   - linuxserver/code-server is built around s6-overlay, which wants
//     to be PID 1 and supervise services. A job's executable is not
//     PID 1 in that sense, so it is a poor shape for this even though
//     it is the most popular image on Docker Hub.
//
// Pinned, not `latest`: a session whose editor changes under it
// between one day and the next is a support problem nobody can
// reproduce. Bump it deliberately.
//
// A site that wants its own toolchain should build its own image --
// extensions baked in are free in every session, while extensions
// installed by hand are reinstalled each time unless the session has a
// home directory mounted. The build_container tool does that from a
// definition file or Dockerfile and stages the .sif to OSDF; this
// package does not do it for you.
const RecommendedImage = "docker://codercom/code-server:4.139.1-debian"

// DefaultServerCommand is the program the launcher execs. Anything
// that serves the VS Code UI over a Unix socket and emits relative
// URLs will do: code-server and openvscode-server both qualify, and
// neither can be told the path it is served under, which is why the
// proxy strips its prefix and redirects to a trailing slash.
const DefaultServerCommand = "code-server"

// ScriptArgs configures the in-sandbox launcher.
type ScriptArgs struct {
	// ServerCommand is the program to exec. Empty means
	// DefaultServerCommand.
	ServerCommand string

	// Workdir is the folder the editor opens, relative to the scratch
	// directory when not absolute. Empty means the scratch directory.
	Workdir string

	// ExtraArgs are appended to the server command verbatim.
	ExtraArgs []string
}

// LaunchScript renders the shell script that runs inside the job.
//
// It is transferred as a file rather than passed as a command, because
// anything sent through condor_ssh_to_job is word-split on IFS and
// rejoined with spaces (condor_ssh_to_job_shell_setup runs `eval
// ${SSH_ORIGINAL_COMMAND}` unquoted), so a multi-line script would
// arrive as one line. Here it is the job's executable, which has no
// such problem -- but the constraint is worth remembering for anything
// this grows into.
func LaunchScript(a ScriptArgs) string {
	cmd := a.ServerCommand
	if cmd == "" {
		cmd = DefaultServerCommand
	}
	workdir := a.Workdir
	if workdir == "" {
		workdir = "."
	}

	var extra string
	if len(a.ExtraArgs) > 0 {
		extra = " " + strings.Join(a.ExtraArgs, " ")
	}

	return fmt.Sprintf(`#!/bin/sh
# Auto-generated by htcondor-api. Runs a VS Code server on a Unix
# socket in this job's scratch directory.
set -eu

SCRATCH="${_CONDOR_SCRATCH_DIR:-$PWD}"
cd "$SCRATCH"

# Where the socket goes, and why it is not simply in the sandbox.
#
# A Unix socket address is capped at ~%[3]d bytes of sun_path, for
# bind() as much as for connect(), and an HTCondor scratch directory
# routinely exceeds that. A glidein is the normal case rather than the
# corner: an EP inside a SLURM job nests its own execute/dir_N under
# the host batch system's, and the path runs past the limit before
# anything of ours is added.
#
# Binding by bare name against the working directory would keep the
# address short -- but code-server resolves --socket to an absolute
# path before binding, so the long path comes back and it dies with
# "listen EINVAL". Measured against code-server 4.139.1; do not
# "simplify" this back to a relative path without re-checking.
#
# So a sandbox too deep to name gets its socket in a short private
# directory instead, and the job publishes the address either way. The
# far end has no working directory of its own to resolve against --
# sshd resolves what it is given against its own -- so it reads the
# address rather than guessing one.
ABS="$SCRATCH/%[2]s"
ABSLEN=$(printf '%%s' "$ABS" | wc -c | tr -d ' ')
SOCKDIR=""
if [ "$ABSLEN" -le %[3]d ]; then
	# Short enough to say plainly, and it stays inside the sandbox,
	# so HTCondor cleans it up with everything else.
	SOCK="$ABS"
else
	# /tmp rather than $TMPDIR. HTCondor commonly points TMPDIR AT the
	# job's scratch directory, which is the very path that is too long
	# -- so honouring it here would pick the one place guaranteed not
	# to work. TMPDIR is tried second, for a site that has no /tmp.
	SOCKDIR=""
	for base in /tmp "${TMPDIR:-}"; do
		[ -n "$base" ] || continue
		candidate="$base/.condor-app-$$"
		# A stale directory from a reused pid would otherwise make the
		# mkdir fail and take the session with it.
		rm -rf "$candidate" 2>/dev/null
		if mkdir "$candidate" 2>/dev/null; then
			SOCKDIR="$candidate"
			break
		fi
	done
	if [ -z "$SOCKDIR" ]; then
		echo "vscode: $ABS is $ABSLEN bytes, over the ~%[3]d a Unix socket address" >&2
		echo "vscode: allows, and no short directory could be created to hold one" >&2
		exit 1
	fi
	# 0700: the directory is the only thing standing between this
	# socket and any other user on the execute node.
	chmod 700 "$SOCKDIR"
	SOCK="$SOCKDIR/s"
	SOCKLEN=$(printf '%%s' "$SOCK" | wc -c | tr -d ' ')
	if [ "$SOCKLEN" -gt %[3]d ]; then
		echo "vscode: even $SOCK is $SOCKLEN bytes; no short enough directory exists here" >&2
		exit 1
	fi
fi
rm -f "$SOCK" "%[2]s.path"
printf '%%s' "$SOCK" > "%[2]s.path"

if ! command -v %[1]s >/dev/null 2>&1; then
	echo "vscode: %[1]s is not installed in this job's environment" >&2
	echo "vscode: use a container image that provides it, or install it in the job" >&2
	exit 1
fi

# Where the server keeps its state, its extensions and its config.
#
# Left to itself it writes under $HOME, which in a container is often
# unwritable -- and when it IS writable, it may be a real shared home,
# in which case one session's extensions and state outlive it and reach
# the next. So: use $HOME when the job actually has a usable one, which
# is the case a mounted home directory produces and where a user
# genuinely wants their extensions to persist; fall back to the scratch
# directory otherwise, where the state dies with the job.
if [ -n "${HOME:-}" ] && [ -d "${HOME:-}" ] && [ -w "${HOME:-}" ]; then
	STATE="$HOME/.local/share/code-server"
else
	STATE="$SCRATCH/.code-server"
fi
mkdir -p "$STATE/extensions"

# The socket's permissions are the authorization -- the server runs
# with auth disabled because nothing else can open it.
#
# Both umask and --socket-mode, because they cover different things.
# umask applies before the socket exists -- so there is no instant
# where it is world-writable -- and to everything else the job writes.
# --socket-mode pins the socket itself at 0600.
#
# Note that code-server chmods the socket after binding whether or not
# --socket-mode is given; passing it only chooses the value. Measured,
# because the obvious conclusion is the wrong one: dropping the flag
# does NOT avoid the chmod. A filesystem that refuses chmod on a socket
# therefore kills code-server outright with "EINVAL ... chmod" whatever
# we pass -- a Docker Desktop bind mount does exactly that, while a
# real execute node's local /tmp does not.
umask 077

exec %[1]s \
	--auth none \
	--disable-telemetry \
	--disable-update-check \
	--socket "$SOCK" \
	--socket-mode 600 \
	--user-data-dir "$STATE" \
	--extensions-dir "$STATE/extensions" \
	--config "$STATE/config.yaml"%[5]s \
	%[4]s
`, cmd, SocketName, MaxSocketPath, shellQuote(workdir), extra)
}

// shellQuote wraps s for /bin/sh. The workdir reaches here from a
// caller, and an unquoted one would be a command injection into the
// job's own executable.
func shellQuote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}

// SubmitArgs configures the session job.
type SubmitArgs struct {
	// SessionID names the session; it goes in the JobBatchName.
	SessionID string

	// Universe is "container" or "vanilla". A container image is the
	// practical choice, since the server has to come from somewhere.
	Universe string
	Image    string

	Cpus     int
	MemoryMB int
	DiskMB   int

	// MaxLifetime is the ceiling the sandbox cannot talk its way out
	// of. Zero means no ceiling, which is almost never what an
	// operator wants -- see PeriodicRemoveExpr.
	MaxLifetime time.Duration

	// ExtraRequirements is the operator's interactive-requirements
	// expression, ANDed with ours.
	ExtraRequirements string

	// CallerSubmitLines are the user's own submit commands; validated
	// by the caller. ExtraSubmitLines are the operator's, appended
	// last so operator policy wins.
	CallerSubmitLines string
	ExtraSubmitLines  string
}

// BatchName is the JobBatchName for a session.
func BatchName(sessionID string) string { return BatchPrefix + sessionID }

// SessionIDFromBatchName recovers a session id, reporting false for a
// job that is not one of ours.
func SessionIDFromBatchName(batchName string) (string, bool) {
	if !strings.HasPrefix(batchName, BatchPrefix) {
		return "", false
	}
	id := strings.TrimPrefix(batchName, BatchPrefix)
	if id == "" {
		return "", false
	}
	return id, true
}

// PeriodicRemoveExpr is the lifetime ceiling.
//
// It has to be the schedd's job, not the sandbox's. Traffic through
// the session is not a liveness signal: an editor left open in a
// browser talks to its server forever whether or not a human is there,
// so an idle timer measured on the wire reaps a closed tab and never
// an abandoned one. periodic_remove is evaluated by the schedd and
// holds whatever the sandbox, the server or the browser are doing.
func PeriodicRemoveExpr(d time.Duration) string {
	if d <= 0 {
		return ""
	}
	return fmt.Sprintf("periodic_remove = (time() - JobStartDate) > %d", int(d.Seconds()))
}

// ExecutableName is the launcher script's name in the sandbox.
const ExecutableName = "vscode-launch.sh"

// ErrNoImage is returned for a container-universe session with no
// image.
var ErrNoImage = errors.New("vscode: a container-universe session needs an image")

// BuildSubmitFile renders the session job.
//
// Container universe is the default, and close to the only sensible
// choice: the server is a ~220 MB download that has to be on the
// EXECUTE node, so it comes from an image the node can cache, not from
// transfer_input_files and certainly not from this server's own
// binary. Vanilla stays for a site that pre-installs it, where the
// launcher's `command -v` check is the thing that reports its absence.
func BuildSubmitFile(a SubmitArgs) (string, error) {
	universe := a.Universe
	if universe == "" {
		universe = "container"
	}
	if universe == "container" && strings.TrimSpace(a.Image) == "" {
		// Caught here rather than at the schedd, which would answer a
		// missing container_image with something far less specific.
		return "", ErrNoImage
	}

	var sb strings.Builder
	fmt.Fprintf(&sb, "# Auto-generated by htcondor-api for VS Code session %s\n", a.SessionID)

	switch universe {
	case "container":
		fmt.Fprintf(&sb, "universe = container\n")
		// An explicit scheme, or HTCondor reads a bare "repo:tag" as a
		// sandbox directory (image_type_from_string).
		fmt.Fprintf(&sb, "container_image = %s\n\n", containerImageRef(a.Image))
	default:
		// Vanilla: the server has to already be on the execute node,
		// which is the launcher's `command -v` check.
		fmt.Fprintf(&sb, "universe = vanilla\n\n")
	}

	fmt.Fprintf(&sb, "executable = %s\n", ExecutableName)
	fmt.Fprintf(&sb, "transfer_executable = true\n")
	// Replace the image's ENTRYPOINT with our launcher rather than
	// being appended to it.
	//
	// Without this the launcher never runs at all. HTCondor follows
	// docker's own rule: with an entrypoint, the executable is passed
	// as its FIRST ARGUMENT. codercom/code-server's entrypoint is
	//
	//     ["/usr/bin/entrypoint.sh", "--bind-addr", "0.0.0.0:8080", "."]
	//
	// so the container starts code-server with the image's own
	// arguments and our script arrives as a folder to open: a server
	// on a TCP port with authentication on, none of our flags, and no
	// socket for the proxy to reach. It looks like the editor simply
	// never connects.
	fmt.Fprintf(&sb, "docker_override_entrypoint = true\n\n")
	fmt.Fprintf(&sb, "should_transfer_files = YES\n")
	fmt.Fprintf(&sb, "when_to_transfer_output = ON_EXIT\n\n")

	if a.Cpus > 0 {
		fmt.Fprintf(&sb, "request_cpus = %d\n", a.Cpus)
	}
	if a.MemoryMB > 0 {
		fmt.Fprintf(&sb, "request_memory = %d\n", a.MemoryMB)
	}
	if a.DiskMB > 0 {
		fmt.Fprintf(&sb, "request_disk = %d\n", a.DiskMB)
	}
	sb.WriteString("\n")

	if extra := strings.TrimSpace(a.ExtraRequirements); extra != "" {
		fmt.Fprintf(&sb, "requirements = %s\n\n", extra)
	}

	// Name the batch so the queue says what this job is. Without it a
	// session shows up as a bare vscode-launch.sh among the user's real
	// work, which is what made the Jupyter ones look strange.
	fmt.Fprintf(&sb, "batch_name = %s\n", BatchName(a.SessionID))
	// Queried on; see AppAttr. The batch name stays because it is what
	// a human sees in condor_q.
	fmt.Fprintf(&sb, "+%s = %q\n", AppAttr, AppAttrValue)

	if expr := PeriodicRemoveExpr(a.MaxLifetime); expr != "" {
		fmt.Fprintf(&sb, "%s\n", expr)
	}

	fmt.Fprintf(&sb, "log    = vscode.log\n")
	fmt.Fprintf(&sb, "output = vscode.out\n")
	fmt.Fprintf(&sb, "error  = vscode.err\n")

	// The user's lines, then the operator's last so operator policy
	// overrides both the builder and the user.
	appendLines(&sb, a.CallerSubmitLines)
	appendLines(&sb, a.ExtraSubmitLines)

	fmt.Fprintf(&sb, "queue\n")
	return sb.String(), nil
}

func appendLines(sb *strings.Builder, lines string) {
	for _, line := range strings.Split(lines, "\n") {
		if strings.TrimSpace(line) == "" {
			continue
		}
		sb.WriteString(line)
		sb.WriteString("\n")
	}
}

// containerImageRef gives a bare repo:tag an explicit scheme.
func containerImageRef(image string) string {
	if image == "" {
		return image
	}
	if strings.Contains(image, "://") || strings.HasSuffix(image, ".sif") ||
		strings.HasPrefix(image, "/") || strings.HasPrefix(image, "./") {
		return image
	}
	return "docker://" + image
}
