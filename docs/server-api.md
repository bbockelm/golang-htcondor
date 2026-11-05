# API surface

Endpoint groupings. The full reference — request and response shapes —
is in [httpserver/README.md](../webapi/httpserver/README.md) and the
OpenAPI document at `/openapi.json`. Part of the
[HTTP API + MCP server](server.md) documentation.


**Jobs** (authenticated, owner-scoped)
- `POST /api/v1/jobs` — submit a job
- `GET /api/v1/jobs` — list with `constraint` / `projection`
- `GET /api/v1/jobs/{id}` — retrieve one
- `PUT /api/v1/jobs/{id}/input` — upload input tarball
- `GET /api/v1/jobs/{id}/output` — download output tarball
- `GET /api/v1/jobs/{id}/runtime-estimate` — how long the job is likely
  to run; see [Runtime estimates](server-estimates.md#runtime-estimates)
- `POST /api/v1/jobs/runtime-estimates` — the same for up to 5000 jobs at
  once; see [Runtime estimates](server-estimates.md#runtime-estimates)

**Pool** (authenticated; every signed-in user)
- `GET /api/v1/pool/drain-estimates` — when each execute node would be
  empty if drained now; see [Drain estimates](server-estimates.md#drain-estimates)

**Templates** (browser-submission UI)
- `GET /api/v1/templates` — list
- `POST /api/v1/templates` — save a custom template
- `DELETE /api/v1/templates/{id}` — remove

**Health & metrics**
- `GET /healthz` — liveness, always 200 if the process is up
- `GET /api/v1/ping` — schedd + collector probe, **as the caller**. Needs a
  credential and answers 401 without one: it reports an identity, an
  authentication method, a session id and the daemon's valid commands, and
  unauthenticated it answered for the service account. Use `/readyz` for an
  unauthenticated health check — it reads the periodic pinger's cached
  result and is what the Kubernetes probes use. Without a credential it
  reports each daemon's status only; an admin session or an API key with
  the `metrics` scope also gets the names, addresses and error text behind
  them.
- `GET /api/v1/schedd/ping`, `GET /api/v1/collector/ping` — the same, one
  daemon each
- `GET /metrics` — Prometheus exposition (requires the `metrics`
  scope unless `HTTP_API_METRICS_PUBLIC=true`)


**Admin** (gated on `WebUIAdminGroup` membership)
- `/api/v1/admin/oauth2/clients`, `/api/v1/admin/oauth2/tokens`
- `/api/v1/admin/api-keys`, `/api/v1/admin/api-keys/{key_id}`
- `/api/v1/admin/logs`, `/api/v1/admin/condor-config`
- `GET /api/v1/admin/usage` — call statistics by tool or endpoint, user
  and client. `?kind=mcp|rest` picks the kind (default `mcp`);
  `?name=`, `?user=`, `?client=` narrow them. See
  [Usage statistics](server-metrics.md#usage-statistics)

**Placement** — see [Placement](server-placement.md#api-endpoints).

**Chat assistant** — see
[Agents](server-agents.md#chat-assistant).

**MCP** (when enabled via `HTTP_API_ENABLE_MCP=true`)
- The OAuth2 endpoints do not depend on this; see
  [When OAuth2 is served](server-auth.md#when-oauth2-is-served).
- The full MCP surface is exposed at `/mcp/*` for cooperative
  agents. The standalone `htcondor-mcp` binary speaks the same MCP
  protocol over stdio. See [mcpserver/README.md](../webapi/mcpserver/README.md).

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

# Get health. /readyz needs no credential; /api/v1/ping pings as you.
curl http://localhost:8080/readyz
curl http://localhost:8080/api/v1/ping \
  -H "Authorization: Bearer $TOKEN"

# Scrape metrics with an API key (mint via /admin/api-keys).
curl http://localhost:8080/metrics \
  -H "Authorization: Bearer htca-v1-...."
```
