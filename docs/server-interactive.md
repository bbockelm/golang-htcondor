# Interactive sessions and apps

Browser terminals, JupyterLab and VS Code are ordinary HTCondor jobs
reached through this server. Part of the
[HTTP API + MCP server](server.md) documentation.

## Sites that forbid condor_ssh_to_job

Some sites do not allow anyone into a running job, by policy. At such a
site every feature here that reaches into a sandbox is dead on arrival:
it submits a job, waits for it, and fails at the connect with a
permission error that reads like a bug in this server. One setting says
so:

```
HTTP_API_SSH_TO_JOB = false
```

It withdraws:

- the **SSH gateway** — no listener is started, and the certificate and
  consent endpoints that serve it refuse;
- `/api/v1/jobs/{id}/ssh`, the **terminal on the job page**, which the
  console then leaves out rather than offering one that cannot connect;
- `/api/v1/jobs/{id}/proxy/…`, the **job proxy**, which rides the same
  transport — and with it the **VS Code** application, which is reached
  through it;
- the **Terminal** application;
- `exec_in_job`, `interactive_session_start` and
  `interactive_session_exec` over **MCP**. `interactive_session_list`
  and `_stop` stay: they read the queue and remove a job, touching no
  sandbox, and withdrawing them would leave an agent holding sessions it
  could not clean up.

**JupyterLab is not withdrawn.** Its traffic goes through a tunnel the
job dials back to this server — a connection out of the sandbox rather
than into it — so it works at a site that forbids `condor_ssh_to_job`
entirely.

Nothing that only *reads* a job is affected: the queue, the history,
output files and the live tail all go through the schedd and the
starter's peek interface, not through a shell.

Setting this leaves `HTTP_API_INTERACTIVE_VSCODE` and
`HTTP_API_INTERACTIVE_TERMINAL` with nothing to decide; they are forced
off and need not be set. Unlike those two, this one is **read at
startup**: the gateway's listener is built then, and a setting that
closed the tool surface while leaving the port open would be the worst
of both. Changing it needs a restart, and a reconfigure says so.

## Which applications this access point offers

All three are offered unless the installation says otherwise:

```
# Offer notebooks and terminals, but not VS Code.
HTTP_API_INTERACTIVE_VSCODE = false
```

| Knob | Default | What it governs |
| --- | --- | --- |
| `HTTP_API_INTERACTIVE_JUPYTER` | `true` | JupyterLab sessions |
| `HTTP_API_INTERACTIVE_VSCODE` | `true` | VS Code sessions |
| `HTTP_API_INTERACTIVE_TERMINAL` | `true` | Terminal sessions, wherever they are started from |

What a disabled application refuses is the **creation** of a session.
Listing, fetching, the proxy and the tunnel, and deleting all keep
working, so sessions already running drain on their own lifetimes
instead of being stranded holding slots, and their owners can still
reach and stop them. An operator who needs them gone sooner removes the
jobs, which was always the tool for that.

In the web console, an application that is not offered has no section on
the **Interactive** page — unless the user still has a session in it,
which is listed without the launch form. With none of the three offered
the page says so and the **Interactive** item leaves the navigation
altogether; the page itself stays reachable if typed, so a leftover
session can still be found.

A terminal session has three front doors — the web console, the MCP
`interactive_session_start` tool, and `ssh` to the
[gateway](server-ssh-gateway.md), which makes one for a user who has none —
and `HTTP_API_INTERACTIVE_TERMINAL` closes all three, because they are
one thing: a long-lived job the caller runs commands in. A site that turns terminals off because its policy forbids
interactive shells, and then finds an agent starting them, has been
given a setting that does not mean what it says. Only starting is
withdrawn on each: `interactive_session_list`, `_exec` and `_stop` keep
working on a session that already exists, and `ssh` still attaches to
one — and to any job, as `ssh 12345.0@gateway` always did. Tools a site
wants gone for other reasons remain
[`HTTP_API_MCP_DISABLED_TOOLS`](server-agents.md#disabling-tools)'
business.

All three are applied on SIGHUP (or `condor_reconfig`). Restarting the
daemon to stop new notebooks being made would drop every notebook
already running, which is precisely what these settings take care not to
do.

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
