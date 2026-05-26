# HTTP API + MCP server

In addition to the Go library, this repo ships two long-running
servers built on top of it:

| Binary | Purpose | Protocol |
| --- | --- | --- |
| `htcondor-api` | RESTful HTTP API for jobs + admin UI | HTTP / JSON |
| `htcondor-mcp` | [Model Context Protocol](https://modelcontextprotocol.io/) server for LLM agents | MCP (stdio) |

Both share the same underlying engine (the schedd / collector / file
transfer pieces from the Go library) but expose it through different
surfaces. The HTTP API is suitable for humans (browser SPA), scripts
(`curl`, CI, monitoring), and other services. The MCP server is for
LLM agents that already speak MCP (Claude Code, etc.).

This document is the entry point; deeper detail lives in
[httpserver/README.md](../httpserver/README.md) and
[mcpserver/README.md](../mcpserver/README.md).

## Install

From the repo:

```bash
make build
sudo install -m 0755 bin/htcondor-api /usr/sbin/htcondor-api
```

Or grab a pre-built image (multi-arch, amd64/arm64):

```bash
docker pull ghcr.io/bbockelm/golang-htcondor:latest
docker pull ghcr.io/bbockelm/golang-htcondor:v1.0.0
docker pull ghcr.io/bbockelm/golang-htcondor:devel  # main branch
```

Each image is ~15 MB and contains only the `htcondor-api` binary
plus minimal runtime dependencies.

## Quickstart

### Demo mode (no HTCondor required)

```bash
./htcondor-api -demo
```

Demo mode spins up a mini HTCondor (`condor_master` as a subprocess
in a temp directory), provisions an `admin` IDP user (the random
password is printed to stdout on first start), and starts the API
server at `https://localhost:8080`. The bundled SPA — including the
admin pages and the chat assistant — is served from `/`.

The same flag works for the MCP binary:

```bash
./htcondor-mcp -demo
```

### Against a real HTCondor pool

```bash
# Auto-discover schedd via the configured COLLECTOR_HOST.
./htcondor-api

# Or specify explicitly.
./htcondor-api -collector collector.example.com:9618
./htcondor-api -schedd myschedd -collector collector.example.com:9618
./htcondor-api -schedd-addr "<192.168.1.100:9618?addrs=192.168.1.100-9618>"
```

CLI options (selected):

| Flag | Default | Purpose |
| --- | --- | --- |
| `-listen` | `:8080` | Listen address. |
| `-collector` | from config | Override `COLLECTOR_HOST`. |
| `-schedd` | from config | Override `SCHEDD_NAME`. |
| `-schedd-addr` | — | Schedd Sinful directly (skips name lookup). |
| `-demo` | off | Start with mini HTCondor in a temp dir. |
| `-user-header` | — | Trust the named HTTP header for the username (demo + behind-a-trusted-proxy use only). |

The server starts with minimal configuration: missing log paths fall
back to stdout, an unset `TILDE` defaults `LOCAL_DIR` to `/usr`, and
an unspecified schedd is auto-discovered from a local address file
or the collector.

## Authentication

Three authentication channels, in precedence order:

1. **API key** — `Authorization: Bearer htca-v1-{key_id}-{secret}`.
   Admin-mintable bearer tokens for non-interactive callers
   (Prometheus, scripts, CI). Scopes gate access — currently just
   `metrics` for `/metrics`. Mint via the admin UI at
   `/admin/api-keys`, or `POST /api/v1/admin/api-keys`.
2. **OAuth2 / OIDC** — for browsers and MCP clients. The server
   embeds its own IDP (`/idp/*`) and also accepts upstream OIDC
   providers via `HTTP_API_OAUTH2_*` config.
3. **Schedd JWT / pool token** — for `condor_*`-tool–style clients
   that already hold a valid HTCondor token.

A separate browser-session cookie is used for the SPA UI; it sits
on top of (2) — the IDP issues the token; the cookie carries the
session.

## API surface

Endpoint groupings — full reference + request/response shapes are in
[httpserver/README.md](../httpserver/README.md) and the OpenAPI doc
at `/openapi.json`.

**Jobs** (authenticated, owner-scoped)
- `POST /api/v1/jobs` — submit a job
- `GET /api/v1/jobs` — list with `constraint` / `projection`
- `GET /api/v1/jobs/{id}` — retrieve one
- `PUT /api/v1/jobs/{id}/input` — upload input tarball
- `GET /api/v1/jobs/{id}/output` — download output tarball

**Templates** (browser-submission UI)
- `GET /api/v1/templates` — list
- `POST /api/v1/templates` — save a custom template
- `DELETE /api/v1/templates/{id}` — remove

**Health & metrics**
- `GET /healthz` — liveness, always 200 if the process is up
- `GET /api/v1/ping` — schedd + collector probe
- `GET /metrics` — Prometheus exposition (requires the `metrics`
  scope unless `HTTP_API_METRICS_PUBLIC=true`)

**Admin** (gated on `WebUIAdminGroup` membership)
- `/api/v1/admin/oauth2/clients`, `/api/v1/admin/oauth2/tokens`
- `/api/v1/admin/api-keys`, `/api/v1/admin/api-keys/{key_id}`
- `/api/v1/admin/logs`, `/api/v1/admin/condor-config`

**Chat assistant** (when `HTTP_API_LLM_API_KEY_FILE` is set)
- `POST /api/v1/chat` — AI-SDK v6 UI-message stream
- `GET /api/v1/chat/info` — feature probe

**MCP** (when enabled via `HTTP_API_ENABLE_MCP=true`)
- The full MCP surface is exposed at `/mcp/*` for cooperative
  agents. The standalone `htcondor-mcp` binary speaks the same MCP
  protocol over stdio. See [mcpserver/README.md](../mcpserver/README.md).

## Example calls

```bash
# Submit a job (Bearer token from your HTCondor IDP or external OIDC).
curl -X POST http://localhost:8080/api/v1/jobs \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"submit_file":"executable=/bin/echo\narguments=Hello\nqueue"}'

# List your jobs.
curl 'http://localhost:8080/api/v1/jobs?constraint=Owner=="alice"' \
  -H "Authorization: Bearer $TOKEN"

# Get health.
curl http://localhost:8080/api/v1/ping

# Scrape metrics with an API key (mint via /admin/api-keys).
curl http://localhost:8080/metrics \
  -H "Authorization: Bearer htca-v1-...."
```

## Running under `condor_master`

The recommended production mode is letting `condor_master` start and
supervise `htcondor-api` so it shares the pool's
`condor_shared_port` listener and respects standard HTCondor
lifecycle hooks.

```condor
# /etc/condor/config.d/50-htcondor-api.conf

HTTP_API       = /usr/sbin/htcondor-api
DAEMON_LIST    = $(DAEMON_LIST), HTTP_API
DC_DAEMON_LIST = +HTTP_API
HTTP_API_ARGS  = -local-name http_api
```

Restart `condor_master` after installing (a `condor_reconfig` is
insufficient — `DC_DAEMON_LIST` is only consulted when daemons start):

```bash
sudo condor_restart -master
```

After restart, requests can reach the server through the shared
port on the HTCondor host:

```bash
$ curl http://localhost:9618/healthz
{"status":"ok"}
```

## Configuration

Settings live in HTCondor config (`condor_config_val`-readable) and
are prefixed `HTTP_API_*`. Frequently-used knobs:

| Knob | Purpose |
| --- | --- |
| `HTTP_API_LISTEN` | Listen address; default `:8080`. |
| `HTTP_API_BASE_URL` | Externally-visible URL for OAuth2 redirects + share links. |
| `HTTP_API_DB_PATH` | Unified SQLite DB (sessions, OAuth2, IDP, templates, API keys). Default `$(LOCAL_DIR)/htcondor-api.db`. |
| `HTTP_API_SIGNING_KEY` | Pool signing key for minting per-request tokens. Defaults to `SEC_TOKEN_POOL_SIGNING_KEY_FILE`. |
| `HTTP_API_KEK_FILE` | Path to the master Key Encryption Key (32 raw bytes or 64-char hex; mode 0600/0400). Generate with `openssl rand -hex 32 > <path> && chmod 0600 <path>`. |
| `HTTP_API_WEBUI_ADMIN_GROUP` | Group name whose members can reach the admin pages. Unset disables the admin UI. |
| `HTTP_API_METRICS_PUBLIC` | `true` to disable the API-key gate on `/metrics`. Default off — Prometheus must present an API key with the `metrics` scope. |
| `HTTP_API_ENABLE_MCP` | Enable the `/mcp/*` endpoints. Required by the chat assistant. |
| `HTTP_API_LLM_API_KEY_FILE` | Path to a 0600-mode file with the Anthropic API key. Enables the chat assistant. |
| `HTTP_API_LLM_API_URL` | Override the upstream Anthropic Messages endpoint (proxy / gateway). |
| `HTTP_API_LLM_MODEL` | Override the default Claude model. |
| `HTTP_API_LLM_OPERATOR_INSTRUCTIONS_FILE` | Site-policy text appended to every chat system prompt. |

Schedd / collector rate limiting (also applies to the HTTP server,
since it reuses the library):

```
SCHEDD_QUERY_RATE_LIMIT          = 10
SCHEDD_QUERY_PER_USER_RATE_LIMIT = 5
COLLECTOR_QUERY_RATE_LIMIT          = 20
COLLECTOR_QUERY_PER_USER_RATE_LIMIT = 10
```

See [design_notes/RATE_LIMITING.md](../design_notes/RATE_LIMITING.md)
for full semantics.

## Further reading

- [httpserver/README.md](../httpserver/README.md) — full HTTP API
  reference, demo-mode internals, security model.
- [mcpserver/README.md](../mcpserver/README.md) — MCP tool catalog
  and integration notes.
- [SECURITY_CONFIG.md](../SECURITY_CONFIG.md) — operator-facing
  security configuration guide.
- [docs/library.md](library.md) — embedding the underlying Go
  library in your own service.
