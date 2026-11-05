# Interactive sessions and apps

Browser terminals, JupyterLab and VS Code are ordinary HTCondor jobs
reached through this server. Part of the
[HTTP API + MCP server](server.md) documentation.

## VS Code sessions

A VS Code session is an ordinary job running a `code-server` inside its sandbox,
reached through the job proxy. Users launch one from **Interactive** in the web
UI, or through `POST /api/v1/apps`; `GET /api/v1/apps` lists their own.

There is no registry and nothing persisted. A session *is* a job, marked by its
`JobBatchName`, so a restarted daemon finds them again with a query and a user
sees them in `condor_q -batch` alongside their real work.

### The image

The server is roughly a 220 MB download, which belongs on the execute node and
is cached there — so it comes from a container image, never from
`transfer_input_files`. This project ships no image and builds none for you.

Point `HTTP_API_VSCODE_IMAGE` at one you trust. `codercom/code-server` is
code-server's own, tracks its releases and publishes amd64 and arm64; pin a
version rather than `latest`, or a session's editor changes under it between one
day and the next. Note that `linuxserver/code-server`, though the most popular on
Docker Hub, is built around s6-overlay, which wants to be PID 1 supervising
services — a poor shape for a job's executable.

Building your own is worth it for a group with its own toolchain: extensions
baked into an image are present in every session at no cost, while extensions a
user installs by hand are reinstalled each time unless the session has a home
directory mounted. The `build_container` MCP tool builds from a definition file
or a Dockerfile inside a job and stages the `.sif` to your object store, which
`HTTP_API_VSCODE_IMAGE` can then name.

### How it is reached, and why that matters on a glidein

The server listens on a **Unix socket** in the job's scratch directory, not a TCP
port. A port bound to `127.0.0.1` in a sandbox is reachable by any local user on
the execute node unless the job has its own network namespace, which no pool can
be assumed to configure. The socket's permissions are the authorization, which is
what makes running the server with its own authentication disabled safe.

A Unix socket address is capped at about 100 bytes, for binding as much as for
connecting, and an HTCondor scratch directory routinely exceeds that on its own —
a glidein nests its `execute/dir_N` under the host batch system's.

So a session whose sandbox path fits keeps its socket inside the sandbox, where
HTCondor cleans it up with everything else; one whose path does not gets a socket
in a short private directory under `/tmp` (mode 0700, owned by the job's user),
and publishes where it put it. Nothing is required of an operator either way, but
it explains why a session works in a sandbox far too deep to name, and why you
may see a `/tmp/.condor-app-<pid>` directory on an execute node. The job cannot
remove that directory itself — it `exec`s the server, so no cleanup of its own
can run — so a killed session leaves one behind holding a dead socket.

`/tmp` is used rather than `$TMPDIR`, because HTCondor commonly points `TMPDIR`
at the job's scratch directory, which is the one place guaranteed not to work.

### Lifetime

`HTTP_API_JUPYTER_MAX_LIFETIME_SEC` applies to these too: both are a browser app
in a job, and an operator who has decided how long one may live has decided for
the other. It is enforced by the schedd with `periodic_remove`, so it holds
whatever the sandbox or the browser are doing — which matters, because an editor
left open in a tab talks to its server indefinitely and so never looks idle.

`HTTP_API_INTERACTIVE_REQUIREMENTS` is ANDed into the job's requirements, to keep
sessions off machines where attaching to them cannot work.


## JupyterLab

A JupyterLab session is a job too, started from **Interactive** in the
web UI or with `POST /api/v1/jupyter/instances`, and reached through a
tunnel the job dials back. Four knobs bound its life; the full text of
each is in [Configuration](server-config.md).

| Knob | Default | Purpose |
| --- | --- | --- |
| `HTTP_API_JUPYTER_MAX_LIFETIME_SEC` | `28800` (8h) | Wall-clock ceiling from when the job starts running, enforced by the schedd's `periodic_remove`. Applies to VS Code sessions too. `0` disables. |
| `HTTP_API_JUPYTER_KERNEL_IDLE_SEC` | `3600` | How long a kernel may sit without executing before it is culled. Measured from kernel execution, not HTTP traffic, so a tab polling in the background does not look busy. `0` disables. |
| `HTTP_API_JUPYTER_START_GRACE_SEC` | `14400` (4h) | How long the job may wait to start before the schedd removes it. Cannot be turned off; out-of-range values fall back or clamp, each with a warning. |
| `HTTP_API_JUPYTER_RECONNECT_GRACE_SEC` | `300` | How long a session whose tunnel dropped is kept for its helper to dial back. Cannot be turned off. |

`HTTP_API_INTERACTIVE_REQUIREMENTS` is ANDed into the requirements of
every interactive job, to keep sessions off machines where attaching to
them cannot work.
