# HTCondor MCP Server

A Model Context Protocol (MCP) server for managing HTCondor jobs. This server exposes HTCondor functionality as MCP tools that can be used by AI assistants and other MCP clients.

## Features

- **Job Submission**: Submit jobs via MCP tool with HTCondor submit file
- **Job Queries**: List and retrieve job details with ClassAd constraints and projections
- **Job Management**: Remove, edit, hold, and release jobs
- **Interactive Sessions**: Run commands inside a long-lived job, like `exec` on a remote machine
- **Authentication**: Token-based authentication forwarded to HTCondor schedd
- **Demo Mode**: Built-in mini HTCondor setup for testing and development
- **MCP Protocol**: Full MCP protocol support for seamless AI integration

## What is MCP?

The Model Context Protocol (MCP) is an open standard that enables AI assistants to securely interact with external data sources and tools. MCP servers expose specific capabilities (called "tools" and "resources") that AI assistants can discover and use.

## Installation

```bash
cd cmd/htcondor-mcp
go build
```

## Usage

### Normal Mode (with existing HTCondor)

```bash
# Uses HTCondor configuration from environment
./htcondor-mcp
```

The server will:
1. Read HTCondor configuration from standard locations
2. Connect to the configured schedd
3. Listen on stdin/stdout for MCP protocol messages

### Demo Mode (standalone mini HTCondor)

```bash
# Starts mini HTCondor automatically
./htcondor-mcp --demo
```

Demo mode will:
1. Create a temporary directory for mini HTCondor
2. Write minimal HTCondor configuration
3. Start `condor_master` as a subprocess
4. Start the MCP server
5. Clean up on Ctrl+C or SIGTERM

## MCP Tools

The server provides the following MCP tools:

### submit_job

Submit an HTCondor job using a submit file.

**Input:**
- `submit_file` (string, required): HTCondor submit file content

**Example:**
```json
{
  "name": "submit_job",
  "arguments": {
    "submit_file": "executable = /bin/echo\ntransfer_executable = False\narguments = Hello World\nqueue"
  }
}
```

**Two submit-language rules:** a system-path executable requires
`transfer_executable = False` (submit_job rejects it otherwise, since HTCondor
would spool-copy an executable that is not there and the job would hold), and
`$(...)` is macro expansion, not shell substitution — to run shell commands,
upload a script with `upload_job_input` and name it as the `executable`.
submit_job warns about `$(...)` references nothing defines.

### query_jobs

Query HTCondor jobs with optional constraints and projections.

**Input:**
- `constraint` (string, optional): ClassAd constraint expression (default: 'true')
- `projection` (array of strings, optional): Attributes to include in results

**Example:**
```json
{
  "name": "query_jobs",
  "arguments": {
    "constraint": "Owner == \"alice\"",
    "projection": ["ClusterId", "ProcId", "JobStatus", "Owner"]
  }
}
```

### get_job

Get details of a specific HTCondor job by ID.

**Input:**
- `job_id` (string, required): Job ID in format 'cluster.proc' (e.g., '123.0')

**Example:**
```json
{
  "name": "get_job",
  "arguments": {
    "job_id": "123.0"
  }
}
```

### remove_job

Remove (delete) a specific HTCondor job.

**Input:**
- `job_id` (string, required): Job ID in format 'cluster.proc'
- `reason` (string, optional): Reason for removal

### remove_jobs

Remove multiple HTCondor jobs matching a constraint.

**Input:**
- `constraint` (string, required): ClassAd constraint to select jobs
- `reason` (string, optional): Reason for removal

### edit_job

Edit attributes of a specific HTCondor job.

**Input:**
- `job_id` (string, required): Job ID in format 'cluster.proc'
- `attributes` (object, required): Attributes to update as key-value pairs

**Example:**
```json
{
  "name": "edit_job",
  "arguments": {
    "job_id": "123.0",
    "attributes": {
      "JobPrio": 10,
      "UserNote": "High priority job"
    }
  }
}
```

### hold_job

Hold a specific HTCondor job.

**Input:**
- `job_id` (string, required): Job ID in format 'cluster.proc'
- `reason` (string, optional): Reason for holding

### release_job

Release a held HTCondor job.

**Input:**
- `job_id` (string, required): Job ID in format 'cluster.proc'
- `reason` (string, optional): Reason for release

### get_version

Report the build identity of the running server: its version, the git
commit it was built from (and whether that tree was dirty), and the
versions of the golang-htcondor, ClassAd, and CEDAR libraries linked in.
Read-only, no arguments. Use it to confirm which code is actually
deployed — for example, after a redeploy.

### query_pool

Describe the pool, as `condor_status` does: execute slots and their
state, CPUs/GPUs/memory claimed and unclaimed, machines, and the pool's
schedds, submitters, negotiator and collector. Read-only; offered when the
server has a collector.

**Input:**
- `ad_type` (string, optional): `slots` (default), `schedd`, `submitter`, `negotiator` or `collector`
- `mode` (string, optional): `summary` (default) or `list`
- `constraint` (string, optional): ClassAd expression selecting ads
- `group_by` (array, optional): summary only; attributes to count by (default for slots: `State`, `Activity`)
- `projection` (array, optional): list only; attributes to return (default: a working set per ad type; `["*"]` for all)
- `limit` (integer, optional): list only; default 50, ceiling 500

A summary covers every matching ad. For slots it reports slot types and,
for `Cpus`, `Memory` and `GPUs`, the total and how much is in claimed,
unclaimed and other-state slots. Each slot contributes its own value: a
partitionable slot advertises what it has left and each dynamic slot what
it holds, so the totals are the matched machines' capacity unless the
constraint excludes dynamic slots. Slots that do not advertise an
attribute are counted under `missing`, not added as zero. Claim ids and
other private attributes are never returned and cannot be named in any
argument.

### get_access_point_policy

Report the access point's configuration that decides how a user's jobs are
submitted and treated, one sentence per setting, each marked when the site
changed it from HTCondor's default. Read-only, no arguments (in multi-AP
mode, `schedd` names an access point other than the caller's home one).

The values are asked of the schedd (`DC_CONFIG_VAL`, READ-level), never
taken from this server's own configuration, and only from an allowlist:

- **Submission limits**: `MAX_JOBS_PER_SUBMISSION`, `MAX_JOBS_PER_OWNER`,
  `MAX_JOBS_SUBMITTED`, `MAX_RUNNING_SCHEDULER_JOBS_PER_OWNER` (which caps
  concurrent DAGs per user).
- **Submit requirements**: `SUBMIT_REQUIREMENT_NAMES` and, per name, the
  expression, its `_REASON` and `_IS_WARNING`.
- **Job transforms**: `JOB_TRANSFORM_NAMES` and, per name, a summary --
  its `REQUIREMENTS` and the attributes it sets, defaults, copies, renames
  or deletes -- never the transform text.
- **Request defaults**: `JOB_DEFAULT_REQUEST{CPUS,MEMORY,DISK,GPUS}`.
- **Hold, remove and release policy**: `SYSTEM_PERIODIC_{HOLD,REMOVE,RELEASE}`,
  their `_NAMES` lists and named forms, each with its `_REASON` (and
  `_SUBCODE` for holds), and `SYSTEM_MAX_RELEASES`.
- **File transfer**: `MAX_TRANSFER_INPUT_MB`, `MAX_TRANSFER_OUTPUT_MB`,
  `MAX_CONCURRENT_UPLOADS`, `MAX_CONCURRENT_DOWNLOADS`.
- **DAGMan**: `DAGMAN_MAX_JOBS_IDLE`, `DAGMAN_MAX_JOBS_SUBMITTED`,
  `DAGMAN_MAX_PRE_SCRIPTS`, `DAGMAN_MAX_POST_SCRIPTS`, with the effective
  value when `HTTP_API_DAGMAN_ENVIRONMENT` overrides one.
- **Features**: `SCHEDD_ALLOW_LATE_MATERIALIZE`, `SCHEDD_ENABLE_SSH_TO_JOB`,
  `START_SCHEDULER_UNIVERSE`, `JOB_EPOCH_HISTORY` (whether it is set, never
  the path), `LOCAL_CREDMON_PROVIDER_NAMES`, `CLIENT_CREDMON_PROVIDER_NAMES`,
  `SUBMIT_ADD_LOCAL_CREDMON_PROVIDERS`, `SUBMIT_ADD_LOCAL_CREDMON_PROVIDER_NAMES`,
  `SUBMIT_TEMPLATE_NAMES`.

Each access point is read at most once every 10 minutes. A setting the
schedd cannot report is shown as unknown; the call fails only when the
schedd cannot be reached at all. Every submission through this server
takes its `JOB_DEFAULT_REQUEST*` values from the same reading, falling
back to the server's own configuration when the schedd cannot be asked.

## Interactive Sessions

Four tools turn a job into something you can run commands in, rather than
something you submit and wait for. Use them when several steps need the same
machine and the same files -- compile then test, inspect a dataset, debug a
job that keeps failing.

### interactive_session_start

Submits a job that holds a slot and waits, named by the caller.

**Input:**
- `session` (string, required): the session name, and the only handle to it
- `cpus`, `memory_mb`, `disk_mb`, `gpus` (integers, optional): the resource request
- `lease_seconds` (integer, optional): idle time before the session is reclaimed (default 1800)

### interactive_session_exec

Runs one command inside the session and returns its exit code, stdout and
stderr. Waits for the job to start running if it has not yet.

**Input:**
- `session` (string, required)
- `command` (string, required): run by `/bin/sh` inside the job's sandbox
- `timeout_seconds` (integer, optional): default 300, max 1800
- `wait_seconds` (integer, optional): how long to wait for a slot, default 120

### interactive_session_list / interactive_session_stop

List the caller's sessions, and end one. Stopping releases the slot and
discards the sandbox.

### How a session stays alive

There is no connection to hang liveness on: an MCP client may be silent for
minutes, and under a sessionless transport it may not even reach the same
server process twice. So a session is addressed by **name**, and kept alive by
a **lease**:

- The name is stored on the job, as its `JobBatchName`
  (`htcondor-api-interactive-session-<name>`), which makes the job queue the
  registry -- and makes sessions visible in `condor_q -batch`. A server that
  restarts re-adopts a session the first time a client names it; a session
  started in one conversation is usable from the next.
- Every call that names a session extends its lease. Silence past the lease
  reclaims the slot. A heartbeat runs for as long as the lease does, regardless
  of whether anyone is interacting with the session -- an agent thinking for ten
  minutes is not an idle session.
- Inside the job, a watchdog exits when the heartbeat file goes stale, which is
  what bounds the damage if the API server dies holding sessions.

### What a session is not

Each `exec` is a fresh shell. The working directory resets to the job's scratch
directory and environment changes do not carry over, so dependent steps belong
in one call (`cd data && ls`), not two. Files written to the scratch directory
do persist for the life of the session -- that is the part that makes a session
worth having over a batch job per command.

## MCP Resources

### condor://schedd/status

Returns the current status and information about the HTCondor schedd from the collector.

## Integration with AI Assistants

### VS Code with GitHub Copilot

Add to your `.vscode/mcp.json`:

```json
{
  "mcpServers": {
    "htcondor": {
      "command": "/path/to/htcondor-mcp",
      "args": ["--demo"]
    }
  }
}
```

### Claude Desktop

Add to your Claude Desktop configuration:

```json
{
  "mcpServers": {
    "htcondor": {
      "command": "/path/to/htcondor-mcp"
    }
  }
}
```

## Authentication

The MCP server authenticates callers at the transport: an HTTP caller presents
a bearer token (an OAuth2 token from the built-in issuer, or a pool IDTOKEN that
the schedd verifies), and a stdio caller is whoever the process runs as, using
ambient HTCondor configuration and filesystem auth.

In demo mode, the server uses a signing key for token generation. In normal mode, it uses the HTCondor configuration to locate tokens and signing keys.

## Configuration

The server reads HTCondor configuration from standard locations:
- `CONDOR_CONFIG` environment variable
- `/etc/condor/condor_config`
- `~/.condor/user_config`

Key configuration parameters:
- `SCHEDD_NAME`: Name of the schedd to connect to
- `COLLECTOR_HOST`: Collector address for schedd discovery
- `SEC_TOKEN_POOL_SIGNING_KEY_FILE`: Path to token signing key
- `TRUST_DOMAIN`: Trust domain for tokens
- `UID_DOMAIN`: UID domain for user identification

## Comparison with HTTP API

| Feature | HTTP API | MCP Server |
|---------|----------|------------|
| Protocol | REST/HTTP | MCP (JSON-RPC over stdio) |
| Transport | Network (TCP) | stdio pipes |
| Authentication | Bearer tokens | Token in tool arguments |
| Discovery | OpenAPI schema | MCP tools/resources list |
| Use Case | Web clients, curl | AI assistants, MCP clients |
| Deployment | Standalone server | Subprocess of client |

## Development

### Building

```bash
go build -o htcondor-mcp cmd/htcondor-mcp/main.go
```

### Testing

```bash
# Test in demo mode
./htcondor-mcp --demo

# Send MCP messages via stdin (initialize protocol)
echo '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"test","version":"1.0"}}}' | ./htcondor-mcp
```

## License

See LICENSE file in the repository root.

## Related

- [HTCondor HTTP API Server](../httpserver/README.md)
- [Model Context Protocol Specification](https://modelcontextprotocol.io/)
- [HTCondor Documentation](https://htcondor.readthedocs.io/)
