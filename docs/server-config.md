# Configuration reference

Every `HTTP_API_*` setting, with the sections that explain them. Part of
the [HTTP API + MCP server](server.md) documentation.

Settings live in HTCondor config (`condor_config_val`-readable) and are
prefixed `HTTP_API_*`. The handful an access point usually has to set is
on the [server page](server.md#configure-it).

## The htcondordb mirror

Job-queue routing to an [htcondordb](server.md#further-reading) mirror needs no
configuration in the common case, **including when this server runs on a
different host or pod from the mirror and the schedd**: discovery goes
through the pool's collector, which spans hosts. The local address file is
only a fallback for a co-located mirror whose ad is not getting through.
With neither a collector nor `HTTP_API_DBMIRROR_ADDRESS`, routing is simply
off rather than failing — an address file that resolves on every host would
otherwise switch it on for deployments that never asked.

## Knobs

| Knob | Purpose |
| --- | --- |
| `HTTP_API_LISTEN_ADDR` | Listen address; default `:8080`. Bound in addition to the shared-port endpoint under `condor_master`. `-listen` on the command line overrides it. |
| `HTTP_API_BASE_URL` | Externally-visible URL for OAuth2 redirects + share links. |
| `HTTP_API_DB_PATH` | Unified SQLite DB (sessions, OAuth2, IDP, templates, API keys). Default `$(LOCAL_DIR)/htcondor-api.db`. |
| `HTTP_API_SIGNING_KEY` | Pool signing key for minting per-request tokens. Defaults to `SEC_TOKEN_POOL_SIGNING_KEY_FILE`. |
| `HTTP_API_KEK_FILE` | Path to the master Key Encryption Key (32 raw bytes or 64-char hex; mode 0600/0400). Generate with `openssl rand -hex 32 > <path> && chmod 0600 <path>`. |
| `HTTP_API_WEBUI_ACCESS_GROUP` | Comma-separated group(s) permitted to log in to the web interface. Unset falls back to `HTTP_API_MCP_ACCESS_GROUP`. Reloaded on SIGHUP. See [Authorization groups](server-auth.md#authorization-groups). |
| `HTTP_API_WEBUI_ADMIN_GROUP` | Comma-separated group(s) whose members can reach the admin pages. Unset disables the admin UI. Reloaded on SIGHUP. |
| `HTTP_API_WEBUI_SITE_NAME` / `HTTP_API_WEBUI_SITE_TAGLINE` | What the pages call this access point. Reloaded on SIGHUP. See [Web UI branding](server-branding.md). |
| `HTTP_API_WEBUI_FOOTER_LOGOS` | JSON array of `{"src", "alt", "href"}` for the footer's institutional band. Unset keeps the shipped CHTC/Morgridge/UW band; `[]` removes it. Reloaded on SIGHUP. |
| `HTTP_API_WEBUI_BRANDING_DIR` | Directory of the site's images, served read-only under `/branding/`. Reloaded on SIGHUP. |
| `HTTP_API_WEBUI_CUSTOM_CSS` | Stylesheet served at `/branding.css` and loaded after the app's own, so `--color-brand-*` can be redefined. Reloaded on SIGHUP. |
| `HTTP_API_WEBUI_FAVICON` | URL for the browser tab icon. Reloaded on SIGHUP. |
| `HTTP_API_SITE_APPS_DIR` | Directory of `<id>.zip` site-app bundles and their `<id>.yaml` policy files. Unset disables site apps entirely. See [Site apps](server-site-apps.md). |
| `HTTP_API_SITE_APPS_RELOAD_INTERVAL` | How often that directory is rescanned, as a Go duration. Default one minute. |
| `HTTP_API_WEBUI_APP_ONLY_GROUP` | Comma-separated group(s) whose members land in their site app rather than the dashboard, with the console navigation collapsed. Presentation only; it restricts nothing. Reloaded on SIGHUP. See [Site apps](server-site-apps.md#app-only-sessions). |
| `HTTP_API_PROJECT_LEADS_FILE` | File naming each project's leads, who may use superuser mode on jobs whose `ProjectName` they lead. Re-read when it changes and on SIGHUP. See [Project leads](server-auth.md#project-leads). |
| `HTTP_API_PROJECT_LEADS_GROUP` | Group-name pattern containing `{project}`, e.g. `{project}-leads`; members of the group it names for a project lead that project. Reloaded on SIGHUP. See [Project leads](server-auth.md#project-leads). |
| `HTTP_API_METRICS_PUBLIC` | `true` to disable the API-key gate on `/metrics`. Default off — Prometheus must present an API key with the `metrics` scope. |
| `HTTP_API_TOOL_STATS_FLUSH_INTERVAL` | How often the usage counters are written to the application database (e.g. `5m`). Default `5m`; they are also written at shutdown. Governs both kinds. See [Usage statistics](server-metrics.md#usage-statistics). |
| `HTTP_API_TOOL_STATS_MAX_LABEL_VALUES` | Cap on distinct values per `/metrics` label for usage statistics. Default `1000`; past it the quietest values render as `other`, while the database keeps them all. |
| `HTTP_API_UTILIZATION_MAX_JOBS` | Most finished jobs one Utilization analysis (`GET /api/v1/utilization`) may read; a larger `limit` is clamped to it. Default `1000000`. An analysis holds about 250 bytes per job while it runs, so the default is about a quarter of a gigabyte at peak; the cached result is the answer, not the jobs. Read at startup. |
| `HTTP_API_RUNTIME_ESTIMATE_INTERVAL` | How often [runtime estimates](server-estimates.md#runtime-estimates) read newly completed jobs from the htcondordb mirror (a duration, e.g. `5m`). Default `5m`; `0` turns runtime estimates off entirely. Without a mirror they are off whatever this says. Read at startup. |
| `HTTP_API_RUNTIME_ESTIMATE_BACKFILL` | How much job history runtime estimates read at startup, and how long a group of similar jobs is remembered without a new completion. Default `168h`. At most 500,000 of the newest records are read; the log says when that cap is hit. Read at startup. |
| `HTTP_API_TOOL_STATS_MAX_SERIES` | Cap on distinct call combinations held in memory and in the database, per kind. Default `10000`; past it new combinations fold into `other`. This is what bounds memory and disk. |
| `HTTP_API_REST_STATS` | `false` turns off the counting of REST API requests, keeping the MCP counting. Default on. See [REST API requests](server-metrics.md#rest-api-requests). |
| `HTTP_API_TOOL_STATS_OMIT_USER` | `true` renders every `/metrics` user label as `omitted`, for a site that does not want account names on a scrapeable endpoint. The database still records them. See [Usernames on /metrics](server-metrics.md#usernames-on-metrics). |
| `HTTP_API_ENABLE_MCP` | Enable the MCP endpoint (`/mcp`), the `/mcp/oauth2/*` spelling of the OAuth2 endpoints, and the `mcp:read`/`mcp:write` scopes in OAuth2 metadata. Required by the chat assistant. OAuth2 itself is served whenever the web UI **or** MCP is enabled, so a web UI with this off still logs people in and serves the device flow. |
| `HTTP_API_MCP_TOKEN_EXCHANGE_ISSUERS` | JSON array of trusted external issuers for RFC 8693 token exchange (see [Token exchange](server-auth.md#token-exchange-rfc-8693)). Unset disables external exchange. |
| `HTTP_API_MCP_CIMD` | Resolve an `https://` MCP `client_id` as a Client ID Metadata Document (a public client). Default `true`; set `false` to require DCR. See [MCP OAuth2 clients](server-auth.md#mcp-oauth2-clients). |
| `HTTP_API_MCP_CIMD_ALLOWED_HOSTS` | Comma/space list of host or `.domain` patterns a CIMD `client_id` may point at. Empty = any host (SSRF guards still apply). Recommended for production: without it, unauthenticated callers choose which public hosts this server fetches from. |
| `HTTP_API_MCP_DCR` | Accept dynamic client registration (RFC 7591) at `/oauth2/register` (and `/mcp/oauth2/register` where MCP is on). Default `true`; set `false` when every client is seeded, operator-provisioned or CIMD. Registrations are then refused with 403 and the endpoint is not advertised. See [MCP OAuth2 clients](server-auth.md#mcp-oauth2-clients). |
| `HTTP_API_MCP_WATCH_MAX_WAIT` | Cap on how long the MCP `check_watches`/`watch_jobs` tools may block in-call before returning (a duration, e.g. `15s`). This number is advertised to the agent in the tool schema, so it has to be one the whole path can deliver, not just this server. Unset = `45s`, or the value derived from `HTTP_API_MCP_MAX_REQUEST_DURATION` where that is tighter. 45s is not a server limit — the server will hold a request for 14m30s by default — it is what an MCP client is observed to wait for before abandoning the call, which returns *nothing at all* to the agent rather than a timeout it could act on. **Set this lower when a gateway or proxy with a tighter timeout sits in front of this server**; set it higher only when you know the clients reaching this deployment are configured for a longer tool timeout. |
| `HTTP_API_OAUTH2_REDIRECT_URL` | The redirect URI registered with the identity provider. Unset = derived from the issuer plus this server's callback path, which is `/mcp/oauth2/callback` on a server whose only surface is MCP and `/oauth2/callback` everywhere else. Both paths are served wherever MCP is on, so an authorization started before an upgrade still lands; but the URI the server *sends* must be registered at the IdP, so a build that gains the web UI needs `/oauth2/callback` added there (or this knob set to keep the old one). |
| `HTTP_API_CREDD_ADDRESS` | Single-AP mode only (refused in multi-AP mode, where each access point's schedd names its own). Pins the credd this server talks to (a sinful, e.g. `<10.0.0.5:9618?sock=credd>`), overriding discovery. Normally unnecessary: the credd is read from the schedd itself, which publishes its own credd as `CredDIpAddr` in its ad and address file — the same binding `DCSchedd::getCreddAddress` uses. Set this when fronting a remote schedd that does not advertise it, since a credd that is not the submitting schedd's accepts credentials and leaves jobs held anyway. |
| `HTTP_API_REQUIRED_CREDENTIALS` | OAuth service credentials that must exist before a job may be submitted (comma- or space-separated, e.g. `scitokens`). Some access points hold every job submitted without them, whatever the job actually uses. Each submit path checks the caller's credentials first and stores a placeholder for any that is missing, so a person using the web UI does not get a held job for a reason unrelated to what they asked for; a real credential obtained later through the OAuth flow replaces the placeholder. Presence is cached per user for 5 minutes. Best effort: if the credd is unavailable or refuses, the submit still proceeds and the reason is logged. Unset = nothing is required. |
| `HTTP_API_MCP_MAX_REQUEST_DURATION` | Hard stop on an MCP request that is still making progress (a duration, e.g. `5m`). Unset = 15m. While an MCP request runs its write deadline is moved forward, so `HTTP_API_WRITE_TIMEOUT` — which is an absolute deadline meant for ordinary replies — does not decide how long a deliberately waiting tool may wait. A request that stops making progress is still cut off on its last window; this is the backstop for one that never finishes at all. |
| `HTTP_API_ADVERTISE` | Advertise this API server to the collector (a `HTCondorAPI` ad: endpoint, schedd, mirror health, versions). Default `true`; `daemon.Advertise` is a no-op without `COLLECTOR_HOST`, so this only matters to opt out when a collector is configured. |
| `HTTP_API_DBMIRROR_NAME` | Pin job-queue routing to the htcondordb mirror advertising this `Name`. Set it when more than one mirror advertises to the pool: nothing in the ad says which schedd each one mirrors, so without a pin the freshest is chosen, which is a guess. |
| `HTTP_API_DBMIRROR_ADDRESS` | Dial this sinful string instead of the mirror's advertised `MyAddress`, for one reachable only over NAT, a tunnel, or a Kubernetes Service. Freshness still comes from the collector ad — this changes where to connect, not whether the mirror is current enough to trust — and it applies whether the mirror was found through the collector or not. |
| `HTTP_API_DBMIRROR_REQUIRED` | Never fall back to the schedd. A read the mirror cannot serve fails instead of becoming load on the access point you were trying to protect. See [the routing notes](../webapi/httpserver/README.md#configuration) for which failures are 503 and which are 400. |
| `HTTP_API_SCHEDD_CONSTRAINT` | ScheddAd constraint selecting the access points of [multi-AP mode](server-multi-ap.md). Unset = one schedd. Read at startup. |
| `HTTP_API_HUB_NAME` / `HTTP_API_HUB_ADDRESS` | Name the federation hubs (one `Name`, or several separated by commas or spaces), or dial one at this sinful string, instead of discovering every `HTCondorDB` ad that carries `FederationConstraint`. The address goes with at most one name. Multi-AP mode only. Read at startup. |
| `HTTP_API_HUB_FAIL_AFTER` | With [two hubs](server-multi-ap.md#two-hubs), how many `federation_sources` reads of the active hub must fail in a row before reads move to another. Default 2. Read at startup. |
| `HTTP_API_HUB_SWITCH_SECONDS` | With two hubs, how long another hub must hold more fresh access points before reads move to it, and the least time between two such switches. Default 120. Read at startup. |
| `HTTP_API_HUB_SWITCH_MARGIN` | With two hubs, how many more fresh access points another hub must hold to count as fresher. Default 1. Read at startup. |
| `HTTP_API_HUB_SETTLE_SECONDS` | With two hubs, how long after a switch the new hub's access points are reported `settling` and a by-id miss on it is asked of the access point. Default 90. Read at startup. |
| `HTTP_API_MULTI_AP_STALE` | `include` (default) or `exclude` a degraded access point's rows in list reads. Either way it is named in `sources.degraded`. |
| `HTTP_API_JOB_ID_CODEC` | Text form of a job id in URLs and SSH gateway usernames. Default and only built-in: `at` (`123.0@ap40.example.org`). |
| `HTTP_API_BULK_FRESH_SECONDS` | Opt in to letting a multi-AP bulk action skip an access point on the hub's word that nothing there matches, when the hub's copy is at most this many seconds behind. Default 0: every access point is contacted. |
| `HTTP_API_AP_ASSIGNMENT` | Multi-AP mode: ordered chain of [AP assignment](server-multi-ap.md#ap-assignment) backends, `static`, `mapfile` and `rest`, separated by commas or spaces. Default `static`. An unknown name refuses to start. Read at startup. |
| `HTTP_API_AP_ASSIGNMENT_DEFAULT` | Access point for a user no backend has an answer for, and the one `static` assigns. Unset = such a user cannot submit (403). |
| `HTTP_API_AP_ASSIGNMENT_MAPFILE` | The `mapfile` backend's file. Re-read when it changes and on reconfigure; one that does not parse at startup refuses to start, and a bad edit keeps the last good map. |
| `HTTP_API_AP_ASSIGNMENT_REST_URL` | Base URL of the site's assignment service, for the `rest` backend; `/v1/assignment` is appended. `https` unless loopback. |
| `HTTP_API_AP_ASSIGNMENT_REST_TOKEN_FILE` | File whose contents are sent as `Authorization: Bearer` to the assignment service. Re-read when it changes. Unset = no header. |
| `HTTP_API_AP_ASSIGNMENT_STALE_SECONDS` | How long a user's last known good assignment is used while a backend is failing. Default 3600; `0` never uses one. |
| `HTTP_API_DBMIRROR_TOKEN_SUBJECT` | Identity the token this server presents to the mirror asserts. Default `condor@<trust domain>`. Set it when the mirror authorizes a different name. |
| `HTTP_API_IDENTITY_MAP` | Map the token subject to a local account (`gecos,username`). See [Local identity mapping](server-auth.md#local-identity-mapping). |
| `HTTP_API_IDENTITY_MAP_PASSWD_FILE` | Account file backing the mapping index. Default `/etc/passwd`. |
| `HTTP_API_IDENTITY_MAP_TTL` | How long the account index and group answers are reused. Default `5m`. |
| `HTTP_API_GROUP_SOURCE` | Comma-separated: `token` (default), `system`, and/or `file:<path>`. Local sources are unioned; `token` may not be mixed with them. See [Local identity mapping](server-auth.md#local-identity-mapping). |
| `HTTP_API_OAUTH2_USERNAME_CLAIM` | Claim carrying the username, e.g. `eppn`. Default `sub`. |
| `HTTP_API_OAUTH2_SCOPES` | Space-separated scopes requested from the provider. Default `openid profile email`. Every one must be approved for this client at the provider: CILogon rejects an unapproved scope outright, where it used to ignore it silently, and that refusal fails every login. `offline_access` is added to whatever is set here unless `HTTP_API_UPSTREAM_REFRESH` is `off`; that one is added by this server, so a refusal of it is absorbed rather than failing logins. |
| `HTTP_API_UPSTREAM_REFRESH` | `auto` (default), `on` or `off`. Whether to ask the provider for `offline_access` and keep the refresh token it returns, which is what lets group membership be re-checked between logins where groups come from the token. `on` is `auto` plus a warning per login when the provider returns no refresh token. `off` neither asks nor stores. |
| `HTTP_API_OAUTH2_REQUIREMENTS` | ClassAd expression over the token's claims; the login proceeds only if it is true. See [Local identity mapping](server-auth.md#local-identity-mapping). |
| `HTTP_API_IDENTITY_MAP_STRIP_DOMAIN` | `true` to also match the local part of a scoped subject. Pair with `HTTP_API_OAUTH2_REQUIREMENTS`. |
| `HTTP_API_DAGMAN_PATH` | Absolute path to `condor_dagman` on the **access point**, for the `submit_dag` tool. **Normally unnecessary — discovered from the schedd's `BIN`; set it only if that discovery is refused.** The server asks the schedd for `BIN` once (a READ-level `condor_config_val` query) and uses `$(BIN)/condor_dagman`; this knob overrides that, and `/usr/bin/condor_dagman` is the fallback when neither is available. `condor_submit_dag` normally finds the binary with `which` on the submitting machine, which is no help here: this server submits to a schedd it shares no filesystem with. |
| `HTTP_API_DAGMAN_ENVIRONMENT` | Extra environment for the DAGMan manager job, as whitespace-separated `KEY=VALUE` pairs. The schedd gives a scheduler-universe job only the environment its ad carries, and `getenv` cannot help because it would capture *this server's* environment rather than the access point's. `PATH` is set for you (PRE/POST scripts need it). Set `CONDOR_CONFIG` here if the access point keeps its configuration somewhere other than the default. A DAG's own `ENV SET` pairs are merged in too, underneath this: what an operator configures here wins, so a workflow cannot redirect `CONDOR_CONFIG` or `BEARER_TOKEN_FILE` by writing one line of DAG. `ENV GET` is reported as a warning and not honoured — it copies variables from the submitting process's environment, which here is this server's, not the access point's. |
| `HTTP_API_MCP_SKILLS_DIR` | Directory of site-authored Markdown skills to publish to agents. Re-read periodically and on SIGHUP. See [Site skills](server-agents.md#site-skills). |
| `HTTP_API_MCP_SKILLS_RELOAD_INTERVAL` | How often to re-read `HTTP_API_MCP_SKILLS_DIR` so a checkout updated underneath the daemon is noticed without a reconfigure (a duration, e.g. `1m`). Default `5m`; `0` disables the poll and leaves reloads to `condor_reconfig`. The check is stat-only until something actually changes. Read at startup. |
| `HTTP_API_JUPYTER_MAX_LIFETIME_SEC` | Wall-clock ceiling on a JupyterLab session, from when it starts running. Enforced by the schedd (`periodic_remove`), so it holds whatever the sandbox or the browser are doing. Default 28800 (8h); `0` disables. |
| `HTTP_API_JUPYTER_KERNEL_IDLE_SEC` | How long a JupyterLab kernel may sit without executing before it is culled and the server shuts down. Measured from kernel execution, not HTTP traffic, so a tab polling in the background does not look busy. Default 3600; `0` disables. |
| `HTTP_API_JUPYTER_START_GRACE_SEC` | How long a JupyterLab job may wait to start executing, from when it is submitted. Past it the schedd removes the job (`periodic_remove`, with the remove reason "JupyterLab session did not start within …"), and the token it would have connected with expires 10 minutes later, so a job never starts with a token that is already dead. A job that ran and went back to the queue (evicted, or held and released) is removed too, as "JupyterLab session was interrupted and cannot restart": it would rerun with a token its first run spent. Default 14400 (4h). Cannot be turned off: `0`, negative or unreadable values fall back to the default, and values above 604800 (7 days) are clamped, each with a warning. |
| `HTTP_API_JUPYTER_RECONNECT_GRACE_SEC` | How long a session whose tunnel dropped is kept for its helper to dial back. Meanwhile the session stays listed and its proxy answers 503 with `Retry-After`; past it the session is closed and a late redial is refused, which ends the job. Default 300. Cannot be turned off: `0`, negative or unreadable values fall back to the default, and values above 3600 are clamped, each with a warning. |
| `HTTP_API_VSCODE_IMAGE` | Container image a VS Code session runs. Any transfer scheme works, so a `.sif` staged on OSDF can be named directly. Set, it wins outright and a caller cannot override it; unset, a caller may name an image, which grants nothing new since they can already submit a job with any image. Defaults to a published code-server image. See [VS Code sessions](server-interactive.md#vs-code-sessions). |
| `HTTP_API_MCP_READ_ONLY` | Serve MCP with no tool that changes anything, for every caller whatever their scopes. Default `false`. `mcp:write` is neither advertised nor granted while it is on. Applied on SIGHUP. See [A read-only access point](server-agents.md#a-read-only-access-point). |
| `HTTP_API_MCP_DISABLED_TOOLS` | MCP tools this access point does not offer, as glob patterns separated by commas or whitespace. Applied on SIGHUP. See [Disabling tools](server-agents.md#disabling-tools). |
| `HTTP_API_MCP_REDACT_SECRETS` | Mask credential-shaped text in MCP tool results. Default `true`. Applied on SIGHUP. See [Masking credentials in tool results](server-agents.md#masking-credentials-in-tool-results). |
| `HTTP_API_MCP_REDACT_DISABLED_RULES` | Masking rules to turn off, as glob patterns over rule ids separated by commas or whitespace. Applied on SIGHUP. |
| `HTTP_API_TRUSTED_PROXIES` | Comma-separated CIDRs (or bare addresses) whose `X-Forwarded-For` / `X-Real-IP` are honored when recording a client address. Unset means none are, and the peer address is logged. |
| `HTTP_API_LLM_API_KEY_FILE` | Path to a file with the LLM API key. Enables the chat assistant. The file must not be world-accessible: 0600, 0400, or 0440 (what a Kubernetes secret volume is under `fsGroup`). |
| `HTTP_API_LLM_API_URL` | Override the upstream Anthropic Messages endpoint (proxy / gateway). The full URL of the `/v1/messages` route. |
| `HTTP_API_LLM_MODEL` | Override the default Claude model. With a gateway, the model name as the gateway knows it. |
| `HTTP_API_LLM_AUTH_SCHEME` | How the key is sent: `x-api-key` (default; what api.anthropic.com reads) or `bearer` (`Authorization: Bearer`, what an OpenAI-style gateway fronting the Messages API, such as Envoy AI Gateway or LiteLLM, authenticates). |
| `HTTP_API_LLM_OPERATOR_INSTRUCTIONS_FILE` | Site-policy text appended to every chat system prompt, last, so it outranks the standard prompts. Re-read on `condor_reconfig`, whether or not the path changed; a read that fails keeps the previous text. Like the API key file, it must not be world-accessible. |
| `PRIVATE_NETWORK_NAME` | This host's private network name. When it equals a daemon's advertised `PrivNet`, that daemon is dialed directly instead of through its CCB broker. Defaults to `$(FULL_HOSTNAME)`, as in C++. See [Reaching jobs behind CCB](server-networking.md). |
| `HOST_ALIAS` | The host name a client verifies this server's SSL certificate against, published as `alias=` on the advertised address. Defaults to `$(FULL_HOSTNAME)`, as in C++. Behind a shared port the address itself carries only the shared-port server's IP, and HTCondor host certificates have no IP SANs, so without the alias SSL authentication from another host fails the certificate check. Set it only when the certificate names something else — a load balancer, a CNAME. |
| `HTTP_API_SHARED_PORT` | Open an inbound HTCondor port (a port or `host:port`, e.g. `9618`) so this server can be reached by execute nodes behind a Condor Connection Broker. Off by default. See [Reaching jobs behind CCB](server-networking.md). |
| `HTTP_API_SHARED_PORT_ADDRESS` | The `host` or `host:port` execute nodes should dial to reach that port, when it differs from what this process binds — behind NAT, a container port map, or a Kubernetes Service. Defaults to `TCP_FORWARDING_HOST`, else `FULL_HOSTNAME`, paired with the listen port. |
| `HTTP_API_CCB_STREAMING` | Allow asking the broker to relay a CCB connection instead of being dialed back. Default: on unless running under `condor_master`. With `HTTP_API_SHARED_PORT` set this is the fallback, not the first choice. |
| `HTTP_API_CCB_LEARNED_TTL` | How long what this server learned about a broker (whether execute nodes can reach it, whether the broker can relay) is reused before being rechecked. Default `15m`. |

## Rate limiting

Schedd and collector rate limits apply to this server too, since it
reuses the library:

```
SCHEDD_QUERY_RATE_LIMIT          = 10
SCHEDD_QUERY_PER_USER_RATE_LIMIT = 5
COLLECTOR_QUERY_RATE_LIMIT          = 20
COLLECTOR_QUERY_PER_USER_RATE_LIMIT = 10
```

See [design_notes/RATE_LIMITING.md](../design_notes/RATE_LIMITING.md)
for full semantics.
