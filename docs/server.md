# HTTP API + MCP server

In addition to the Go library, this repo ships two long-running servers
built on top of it:

| Binary | Purpose | Protocol |
| --- | --- | --- |
| `htcondor-api` | RESTful HTTP API for jobs, plus the web UI and admin pages | HTTP / JSON |
| `htcondor-mcp` | [Model Context Protocol](https://modelcontextprotocol.io/) server for LLM agents | MCP (stdio) |

Both share the same underlying engine — the schedd, collector and file
transfer pieces from the Go library — but expose it through different
surfaces. The HTTP API suits humans (the browser SPA), scripts (`curl`,
CI, monitoring) and other services. The MCP server is for LLM agents
that already speak MCP. `htcondor-api` can serve MCP as well, at
`/mcp`.

This page takes an administrator from a package to a running,
configured server. Each larger feature has a page of its own:

| Page | What it covers |
| --- | --- |
| [Authentication and authorization](server-auth.md) | Who may sign in, identity mapping, groups, superuser mode and project leads, OAuth2 clients |
| [Configuration reference](server-config.md) | Every `HTTP_API_*` setting |
| [API surface](server-api.md) | Endpoint groupings and example calls |
| [SSH gateway](server-ssh-gateway.md) | An SSH port that drops users into their jobs |
| [Interactive sessions and apps](server-interactive.md) | JupyterLab and VS Code sessions |
| [Agents: MCP, site skills, chat](server-agents.md) | Enabling MCP, publishing site documentation to agents, the chat assistant |
| [Metrics and usage statistics](server-metrics.md) | `/metrics`, what is counted, the admin Usage page |
| [Runtime and drain estimates](server-estimates.md) | How long a job will run; when a node would be empty |
| [Web UI branding](server-branding.md) | Making the pages say who runs this access point |
| [Placement](server-placement.md) | Onboarding users through `condor_placementd` |
| [Reaching jobs behind CCB](server-networking.md) | Connecting into jobs on firewalled execute nodes |
| [Multi-AP mode](server-multi-ap.md) | One server fronting several access points |

## Install

Three ways to get the binary. They are alternatives — pick one.

### RPM (EL8/EL9)

Every tagged release attaches an RPM per architecture:

```bash
sudo dnf install ./htcondor-api-<version>.x86_64.rpm
```

It installs the binary at `/usr/sbin/htcondor-api` and a config drop-in
at `/etc/condor/config.d/50-htcondor-api.conf`. Installing does not
enable the daemon: the `DAEMON_LIST` / `DC_DAEMON_LIST` lines ship
commented out, next to commented examples for shared port, OAuth2,
authorization and site policy. The drop-in is `%config(noreplace)`, so
your edits survive an upgrade and the package's version arrives as
`.rpmnew`.

The drop-in also documents how to generate the two secrets the server
needs and that neither the package nor the daemon creates: the
`HTTP_API_KEK_FILE` and the OAuth2 client secret. See
[Configure it](#configure-it).

To build one from the repo — `PKG_ARCH` is a Go arch name, so an RPM
for either architecture can be built from any host:

```bash
# nfpm's version is pinned in .github/tools, where Dependabot maintains it.
(cd .github/tools && GOWORK=off go build -o "$HOME/go/bin/nfpm" github.com/goreleaser/nfpm/v2/cmd/nfpm)

make rpm-prod                      # production binary, then package it
make rpm PKG_ARCH=arm64            # package an already-built bin/htcondor-api
```

### Container image

Pre-built, multi-arch (amd64/arm64):

```bash
docker pull ghcr.io/bbockelm/golang-htcondor:latest
docker pull ghcr.io/bbockelm/golang-htcondor:v1.0.0
docker pull ghcr.io/bbockelm/golang-htcondor:devel  # main branch
```

Each image is about 15 MB and contains only the `htcondor-api` binary
plus minimal runtime dependencies.

### From source

```bash
make build
sudo install -m 0755 bin/htcondor-api /usr/sbin/htcondor-api
```

## Try it: demo mode

```bash
./htcondor-api -demo
```

Demo mode starts a `condor_master` of its own as a subprocess in a temp
directory, provisions an `admin` IDP user, and serves the API and the
bundled SPA — admin pages and chat assistant included — at
`https://localhost:8080`. A second, non-admin IDP user, `user`, is
provisioned the same way. Both random passwords are printed to stdout
on first start (`UserPassword:` for the second).

It needs an HTCondor installation on `PATH`: `condor_master` is looked
up there, and its directory decides the release directory. What it does
*not* need is a configured pool — no `condor_config` of your own, no
collector, and no account on an access point.

The same flag works for the MCP binary:

```bash
./htcondor-mcp -demo
```

With a `condor_placementd` on `PATH`, demo mode also starts one so the
placement features can be tried locally; see
[Placement](server-placement.md#trying-it-in-demo-mode).

### Running demo mode as root

Demo mode is meant to be run as an ordinary user, and as one it needs
nothing from the machine. Root is the only case in which HTCondor
changes uid, and it then needs two system accounts to exist: **`condor`**,
which the daemons open their logs as, and **`nobody`**, which every demo
identity's jobs run as (`AP_GENERIC_OS_USERS`, since `admin`, `user` and
`newbie` are IdP accounts in no passwd file). Both are checked before
`condor_master` is launched, and a missing one is reported by name.

Note that every demo identity's jobs then run as the same account and
so are not isolated from each other. Running as an ordinary user avoids
this entirely.

## Run it for real

### Under `condor_master` (recommended)

Letting `condor_master` start and supervise `htcondor-api` shares the
pool's `condor_shared_port` listener and respects the standard HTCondor
lifecycle hooks, including `condor_reconfig`.

```condor
# /etc/condor/config.d/50-htcondor-api.conf

HTTP_API       = /usr/sbin/htcondor-api
DAEMON_LIST    = $(DAEMON_LIST), HTTP_API
DC_DAEMON_LIST = +HTTP_API
HTTP_API_ARGS  = -local-name http_api
```

Restart `condor_master` after installing — a `condor_reconfig` is
insufficient, because `DC_DAEMON_LIST` is only consulted when daemons
start:

```bash
sudo condor_restart -master
```

Requests then reach the server through the shared port on the HTCondor
host:

```bash
$ curl http://localhost:9618/healthz
{"status":"ok"}
```

#### Its own HTTP port

The shared port carries HTTP, but it is the pool's CEDAR port: it is not
where you point a browser, and not where a certificate for this server's
hostname belongs. So whenever the server is behind shared port — the
endpoint `condor_master` hands down, or one it registers with
`condor_shared_port` itself when no socket is inherited — it *also* binds
its own address:

```condor
HTTP_API_LISTEN_ADDR = :443
```

Binding 443 needs the privilege, which the server re-raises for that bind
alone before going back to `condor`. The log names the address it took:

```
serving HTTP on its own address alongside the shared-port endpoint address=[::]:443
```

`-listen` on the command line overrides `HTTP_API_LISTEN_ADDR`, for trying
an address without editing the configuration. Turning `USE_SHARED_PORT`
off is not a way to get this port — it only costs the pool its shared-port
routing to this daemon.

### Standalone

```bash
# Auto-discover the schedd via the configured COLLECTOR_HOST.
./htcondor-api

# Or specify explicitly.
./htcondor-api -collector collector.example.com:9618
./htcondor-api -schedd myschedd -collector collector.example.com:9618
./htcondor-api -schedd-addr "<192.168.1.100:9618?addrs=192.168.1.100-9618>"
```

Selected flags:

| Flag | Default | Purpose |
| --- | --- | --- |
| `-listen` | `:8080` | Listen address. |
| `-collector` | from config | Override `COLLECTOR_HOST`. |
| `-schedd` | from config | Override `SCHEDD_NAME`. |
| `-schedd-addr` | — | Schedd Sinful directly (skips name lookup). |
| `-demo` | off | Start with a mini HTCondor in a temp dir. |
| `-user-header` | — | Trust the named HTTP header for the username (demo and behind-a-trusted-proxy use only). |

The server starts with minimal configuration: missing log paths fall
back to stdout, an unset `TILDE` defaults `LOCAL_DIR` to `/usr`, and an
unspecified schedd is auto-discovered from a local address file or the
collector.

## Configure it

Settings live in HTCondor config (`condor_config_val`-readable) and are
prefixed `HTTP_API_*`. They are read from the same files the rest of
the pool uses, so a drop-in under `/etc/condor/config.d/` is the usual
place.

Set these first:

| Knob | Why |
| --- | --- |
| `HTTP_API_KEK_FILE` | Master Key Encryption Key, under which the server seals its long-lived secrets. The RPM's drop-in names one, and the daemon then refuses to start until that file exists — neither the package nor the daemon will create it: `openssl rand -hex 32 > <path> && chmod 0600 <path>`. Left unset entirely, those secrets sit in the database in plaintext and startup says so. |
| `HTTP_API_BASE_URL` | The externally-visible URL. OAuth2 redirects and share links are built from it. |
| `HTTP_API_LISTEN_ADDR` | Listen address; default `:8080`. Bound in addition to the shared-port endpoint under `condor_master`, and the address a browser uses — see [Its own HTTP port](#its-own-http-port). |
| `HTTP_API_SIGNING_KEY` | Pool signing key, for minting per-request tokens. Defaults to `SEC_TOKEN_POOL_SIGNING_KEY_FILE`. |
| `HTTP_API_DB_PATH` | SQLite database holding sessions, OAuth2 state, the IDP, templates and API keys. Default `$(LOCAL_DIR)/htcondor-api.db`. |

Then decide who may sign in. Four group knobs gate the surfaces
separately, each taking a comma-separated list and admitting a user who
holds **any** of the named groups:

```
HTTP_API_WEBUI_ACCESS_GROUP = ap2001-login, chtc_staff   # the web interface
HTTP_API_MCP_ACCESS_GROUP   = ap2001-login               # driving the AP through MCP
HTTP_API_WEBUI_ADMIN_GROUP  = chtc_staff                 # the admin pages
HTTP_API_SUPERUSER_GROUP    = chtc_admin                 # acting as another user
```

Where those groups come from — the token, the host's account database,
or a file — and how a token's subject becomes a local account is
[Authentication and authorization](server-auth.md). An access point
that signs people in through an upstream OIDC provider configures it
with the `HTTP_API_OAUTH2_*` knobs described there.

Every other setting is in the [configuration
reference](server-config.md).

Two things commonly need no configuration at all: routing job-queue
reads to an [htcondordb](#further-reading) mirror, which is discovered
through the pool's collector, and the schedd and collector rate limits,
which this server inherits from the library. Both are covered in the
[configuration reference](server-config.md).

## Check it works

```bash
# Liveness, no credential needed.
curl http://localhost:8080/readyz

# Ping the schedd and collector as yourself.
curl http://localhost:8080/api/v1/ping -H "Authorization: Bearer $TOKEN"

# Submit a job.
curl -X POST http://localhost:8080/api/v1/jobs \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"submit_file":"executable=/bin/echo\narguments=Hello\nqueue"}'
```

More in [API surface](server-api.md).

## Further reading

- [httpserver/README.md](../webapi/httpserver/README.md) — full HTTP API
  reference, demo-mode internals, security model.
- [mcpserver/README.md](../webapi/mcpserver/README.md) — MCP tool catalog
  and integration notes.
- [SECURITY_CONFIG.md](../design_notes/SECURITY_CONFIG.md) — operator-facing
  security configuration guide.
- [docs/library.md](library.md) — embedding the underlying Go
  library in your own service.
- [htcondordb](https://github.com/bbockelm/htcondordb) — the job-queue
  mirror several features read from, including runtime and drain
  estimates and multi-AP mode.
