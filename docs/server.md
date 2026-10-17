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
[httpserver/README.md](../webapi/httpserver/README.md) and
[mcpserver/README.md](../webapi/mcpserver/README.md).

## Install

### RPM (EL8/EL9)

Every tagged release attaches an RPM per architecture:

```bash
sudo dnf install ./htcondor-api-<version>.x86_64.rpm
```

It installs the binary at `/usr/sbin/htcondor-api` and a config drop-in at
`/etc/condor/config.d/50-htcondor-api.conf`. Installing does not enable the
daemon: the `DAEMON_LIST` / `DC_DAEMON_LIST` lines ship commented out, next to
commented examples for shared port, OAuth2, authorization and site policy. It
is `%config(noreplace)`, so your edits survive an upgrade and the package's
version arrives as `.rpmnew`.

The drop-in configures `HTTP_API_KEK_FILE`, so the daemon will refuse to start
until that file exists; it documents how to generate it, and the OAuth2 client
secret. Neither is created by the package or by the daemon.

To build one from the repo -- `PKG_ARCH` is a Go arch name, so an RPM for
either architecture can be built from any host:

```bash
# nfpm's version is pinned in .github/tools, where Dependabot maintains it.
(cd .github/tools && GOWORK=off go build -o "$HOME/go/bin/nfpm" github.com/goreleaser/nfpm/v2/cmd/nfpm)

make rpm-prod                      # production binary, then package it
make rpm PKG_ARCH=arm64            # package an already-built bin/htcondor-api
```

### From source

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
   (Prometheus, scripts, CI). Scopes gate access: `metrics` for
   `/metrics`, `condor:/READ` and `condor:/WRITE` for the routes that
   reach HTCondor. A key acts as its creator only if it carries a
   `condor:/*` scope; a `metrics`-only key is refused everywhere but
   `/metrics` and `/readyz`. Mint via the admin UI at
   `/admin/api-keys`, or `POST /api/v1/admin/api-keys`.
2. **OAuth2 / OIDC** — for browsers and MCP clients. The server
   embeds its own IDP (`/idp/*`) and also accepts upstream OIDC
   providers via `HTTP_API_OAUTH2_*` config. An access token this
   server issued is held to its granted scopes on the REST routes that
   reach HTCondor, as an API key is: `condor:/READ` for reads and
   `condor:/WRITE` for writes, or, on a grant with no `condor:/*`
   scope, `mcp:read` / `mcp:write`. The job and Jupyter proxies, job
   SSH and `/warm` run code in the job and need WRITE whatever the
   method. A token granted none of these is refused.
3. **Schedd JWT / pool token** — for `condor_*`-tool–style clients
   that already hold a valid HTCondor token.

**When OAuth2 is served.** The OAuth2 authorization server — its
metadata at `/.well-known/oauth-authorization-server`, the
`/oauth2/*` endpoints (authorize, token, device authorization and
verification, introspect, revoke, register, the SSO callback) and the
admin client and token pages — is served whenever the **web UI or MCP**
is enabled. `HTTP_API_ENABLE_MCP` gates only MCP: with it off, a server
with the web UI still serves all of the above, but not `/mcp`, not the
`/mcp/oauth2/*` spelling of the endpoints, not the protected-resource
documents for `/mcp`, and does not advertise `mcp:read` / `mcp:write`.
The web UI counts as enabled when it is compiled in (the
`embed_frontend` build). The endpoints are advertised under
`/mcp/oauth2/` only on a server whose only surface is MCP; both
spellings are routed wherever MCP is on.

A separate browser-session cookie is used for the SPA UI; it sits
on top of (2) — the IDP issues the token; the cookie carries the
session.

### Local identity mapping

By default a session's identity is the subject claim from the token, and
group membership is whatever the token asserts. That suits a container,
which holds no account database. On a host where this server runs under
`condor_master` beside a real one, either half can come from the system
instead. The two switches are independent.

**Subject to local account.** `HTTP_API_IDENTITY_MAP` names an ordered
list of strategies; the first to answer wins.

| Knob | Default | Effect |
| --- | --- | --- |
| `HTTP_API_IDENTITY_MAP` | unset (no mapping) | Comma-separated strategy list, e.g. `gecos,username`. `gecos` matches the token subject against accounts' GECOS names; `username` treats the subject as a login name; `placementd` asks condor_placementd (see [placementd as an identity mapping](#placementd-as-an-identity-mapping)). An unparseable list makes the server refuse to start rather than fall back to an unmapped identity. |
| `HTTP_API_IDENTITY_MAP_PASSWD_FILE` | system default | Read accounts from this file instead of `/etc/passwd`. Both the index and the re-check use it, so it is self-consistent. |
| `HTTP_API_IDENTITY_MAP_TTL` | `5m` | How long the account index and group answers are reused. The index is rebuilt lazily on the first login after it expires. |
| `HTTP_API_IDENTITY_MAP_STRIP_DOMAIN` | `false` | Also try the local part of a scoped subject: `bockelman@wisc.edu` matches a GECOS of `bockelman`. The full subject is tried first, so this only ever adds a fallback. |

Once mapping is on, the session's subject becomes the **local account
name** -- the name HTCondor knows -- so owner-scoping matches actual job
ownership. The asserted subject is logged beside it.

Three behaviours worth knowing before turning this on:

- **A mapping failure denies the login.** There is no fallback to the
  token's claim and no bypass list: the weaker basis must not engage
  exactly when the stronger one breaks.
- **Ambiguity refuses rather than guesses.** If two accounts claim the
  same identity, neither is chosen. Shadowed pairs are named in the
  startup log, so an ordering like `gecos,username` is a choice rather
  than a surprise.
- **`gecos` matches the GECOS *name*, not the raw field** -- everything
  up to the first comma, which is what `os/user` reports on every
  platform. For `tannenba:x:20013:20013:tatannen:...` the value matched
  is `tatannen`; for `...:Tannenbaum, Todd,,:...` it is `Tannenbaum`.

**GECOS can be user-writable.** `chfn` lets a user change their own
full name where `/etc/login.defs` allows it (`CHFN_RESTRICT`; check the
host, not the distribution's reputation). There, a local user who sets
their name to someone else's subject either makes that subject
ambiguous, so its owner cannot log in, or -- when the owner's account
carries no matching GECOS -- becomes the account it maps to. On such a
host set `CHFN_RESTRICT rwh` (room and phone numbers only) in
`/etc/login.defs`. Accounts served by SSSD or another directory cannot
be changed this way. Where token subjects are login names, put
`username` first (`username,gecos`): a subject that is somebody's login
name then never consults GECOS at all. The shadowed pairs in the
startup log are worth watching either way.

An ePPN is scoped (`bockelman@wisc.edu`) and a GECOS or login name
usually is not, so the two cannot match without
`HTTP_API_IDENTITY_MAP_STRIP_DOMAIN`.

It strips **whatever** domain the token carried, so
`bockelman@wisc.edu` and `bockelman@elsewhere.example` reach the same
account. Which providers may issue such a token is decided by
[`HTTP_API_OAUTH2_REQUIREMENTS`](#local-identity-mapping), not here --
enable this only alongside one. The server logs a warning at startup if
stripping is on with no requirements expression configured.

The index is built from the passwd file **and** from SSSD, when an SSSD
socket is reachable. A directory-backed deployment therefore needs no
local copy of its accounts -- a container with only its own `/etc/passwd`
still indexes the whole directory, provided the SSSD domain sets
`enumerate = true` (off by default, and discouraged for very large
directories). A local entry wins a name collision, since that is the one
`os/user` resolves.

Naming a file with `HTTP_API_IDENTITY_MAP_PASSWD_FILE` turns the merge
off: the file becomes the whole account database. That keeps the index and
the re-check reading the same source, which is what makes an
operator-supplied file self-consistent.

Every candidate the index produces is re-checked by name against the live
database before it is believed, and that lookup *does* reach a directory.
So an incomplete index can fail to find somebody, but cannot promote
anybody.

**Group membership.** `HTTP_API_GROUP_SOURCE` decides where groups come
from, independently of the mapping above. It takes a comma-separated list;
whitespace around each entry is ignored.

| Knob | Default | Effect |
| --- | --- | --- |
| `HTTP_API_GROUP_SOURCE` | `token` | Comma-separated list of `token`, `system` (or `unix`), and `file:<path>`. |

| Source | Reads |
| --- | --- |
| `token` | The token's groups claim. Correct for a container, which holds no account database. |
| `system` | Unix groups for the mapped account, following this host's `nsswitch.conf`. |
| `file:<path>` | An `/etc/group`-format file. |

Several **local** sources are a union, the way glibc merges NSS services --
an account can hold directory groups and hand-maintained ones at once, and
stopping at the first source that answers would drop half of somebody's
membership:

```
HTTP_API_GROUP_SOURCE = system, file:/etc/htcondor-api/groups
```

`token` cannot be combined with a local source; the server refuses to start
if it is. They are different trust bases -- one is what the identity
provider asserted, the other is what this machine's account database says
-- and unioning them would let a provider add a caller to any group the
local policy checks.

**`file:<path>`** exists for memberships the directory does not carry, such
as a staff or admin group that is not in LDAP. The format is `group(5)`,
deliberately, so `getent group <name>` output can be pasted in unchanged:

```
chtc_staff:*:40388:ckoch5,aowen4,bbockelm
ap2001-login:*:40428:bbockelm,qwang377
```

Only the group name and the member list are used; the password and gid
fields are ignored. Like `/etc/group` itself it lists supplementary members
only. The file is re-read when it changes, so an edit takes effect without
restarting the daemon. A file that cannot be read marks the answer
*possibly incomplete* rather than reporting that nobody is in any group --
the difference matters, because the latter is an authorization decision.

With `system`, membership is re-read on every refresh, so a user removed
from a group upstream stops passing without waiting for their refresh
token to lapse (see [Refresh-grant
re-authorization](#refresh-grant-re-authorization)). A read that could
not consult every configured NSS service is treated as *possibly
incomplete*: the login proceeds, because that is what `id` would report,
but it never revokes an existing grant -- an outage must not log out
everyone whose token happens to refresh during it.

Group resolution follows this host's `nsswitch.conf`. A build with cgo
resolves through `getgrouplist(3)`, so every configured service is
consulted; a build without cgo speaks `files` and `sss` natively and
marks the answer incomplete if the line names anything else.

**Which logins are accepted.** `HTTP_API_OAUTH2_REQUIREMENTS` is a
ClassAd expression evaluated against the token's claims, the same way a
schedd evaluates a job's `Requirements` against a machine ad.

| Knob | Default | Effect |
| --- | --- | --- |
| `HTTP_API_OAUTH2_REQUIREMENTS` | unset (accept any) | ClassAd expression over the claims. The login proceeds only if it evaluates to `true`. |

The claims become the ad: a string stays a string, a JSON array becomes a
list, a nested object becomes a nested ad addressable as `outer.inner`,
and `null` becomes `UNDEFINED`. A claim name that is not a bare
identifier is still available through the quoted-attribute syntax, as in
`'urn:oid:1.3.6.1'`.

```
# Only this campus's IDP.
HTTP_API_OAUTH2_REQUIREMENTS = idp == "https://login.wisc.edu/idp/shibboleth"

# ...and only members, who authenticated with MFA.
HTTP_API_OAUTH2_REQUIREMENTS = idp == "https://login.wisc.edu/idp/shibboleth" && \
                               regexp("MEMBER@wisc.edu", affiliation) && \
                               acr == "https://refeds.org/profile/mfa"

# ...or by assurance level, which arrives as a list.
HTTP_API_OAUTH2_REQUIREMENTS = member("https://refeds.org/assurance/IAP/low", eduPersonAssurance)
```

This expresses what an issuer check cannot: a federation such as CILogon
fronts many institutions behind one issuer, so `iss` does not answer
"which campus".

Two properties worth knowing:

- **It fails closed.** Only `true` admits a login. `UNDEFINED`, an error,
  and a non-boolean result all refuse. So a policy naming a claim the IDP
  stopped sending -- or misspelling one -- denies everybody rather than
  silently admitting everybody the moment it stopped meaning anything.
- **A malformed expression stops the daemon at startup**, rather than
  failing at the first person's login.

A refused login gets 403, and the log records the expression and which
claims the IDP returned -- names only, since the values identify the user
and the path is reachable unauthenticated.

**Which claim carries the username.** Some providers put the login-ish
value somewhere other than `sub`.

| Knob | Default | Effect |
| --- | --- | --- |
| `HTTP_API_OAUTH2_USERNAME_CLAIM` | `sub` | Claim read as the asserted subject, e.g. `eppn` or `preferred_username`. This is the value identity mapping receives. |

### Client addresses behind a proxy

A forwarded header is a claim made by whoever connected, and anyone can make one. This server therefore reads `X-Forwarded-For` and `X-Real-IP` **only** from peers named in `HTTP_API_TRUSTED_PROXIES`:

```
HTTP_API_TRUSTED_PROXIES = 10.42.0.0/16, 192.168.1.10
```

Unset, no forwarded header is believed and the peer address is what appears in the access log. Behind an ingress that is the ingress -- which is honest, since the server genuinely does not know who is behind it, rather than a value the caller chose.

Where the proxy's address cannot be known in advance -- a Kubernetes ingress gets a fresh pod address on every restart -- trust everything:

```
HTTP_API_TRUSTED_PROXIES = 0.0.0.0/0, ::/0
```

That is a deliberate choice to believe the header, spoofable and all, in exchange for seeing past the ingress. Sound only where nothing but the ingress can reach the server's port; if the pod is directly reachable, any caller can write what it likes into the log.

Configured, the `X-Forwarded-For` chain is walked from the **right**, discarding hops that are themselves trusted proxies; the first address that is not one is the client. Taking the leftmost entry is the common shortcut and is wrong exactly when it matters: proxies *append*, so a caller that sends its own `X-Forwarded-For` puts a value of its choosing at the front of the list, ahead of what the ingress observed.

This is separate from `HTTP_API_USER_HEADER_TRUSTED_PROXIES`, which decides who may assert an *identity* -- a much larger grant than being believed about an address, and deliberately not the same list.

### Authorization groups

Four knobs decide who may do what. Each takes a **comma-separated list**
and admits a user holding **any** of the named groups; surrounding
whitespace is trimmed, and an empty value means "no group required".
Matching is case-insensitive.

| Knob | Gates |
| --- | --- |
| `HTTP_API_WEBUI_ACCESS_GROUP` | Logging in to the web interface. Unset falls back to `HTTP_API_MCP_ACCESS_GROUP`. |
| `HTTP_API_MCP_ACCESS_GROUP` | Driving this access point through MCP. |
| `HTTP_API_WEBUI_ADMIN_GROUP` | The admin pages. Unset disables the admin UI. |
| `HTTP_API_SUPERUSER_GROUP` | Superuser mode (see below). Unset disables the feature. |

`HTTP_API_MCP_READ_GROUP` and `HTTP_API_MCP_WRITE_GROUP` narrow MCP
further, and take lists on the same terms. The write group also decides
`condor:/WRITE`: a user it denies `mcp:write` is denied that too.

Web interface access and MCP access are **separate**. They were one knob,
so granting somebody the browser necessarily granted them MCP; a site can
now let its staff open the pages without also letting them drive the AP
through an agent:

```
HTTP_API_MCP_ACCESS_GROUP   = ap2001-login
HTTP_API_WEBUI_ACCESS_GROUP = ap2001-login, chtc_staff
HTTP_API_WEBUI_ADMIN_GROUP  = chtc_staff
HTTP_API_SUPERUSER_GROUP    = chtc_admin
```

`HTTP_API_WEBUI_ACCESS_GROUP` falls back to `HTTP_API_MCP_ACCESS_GROUP`
when unset, so a deployment that was using the MCP group to gate the
browser keeps that behaviour rather than being silently opened.

All of these are re-read on **`condor_reconfig` / SIGHUP** -- each is only
a membership test on a request, with nothing built from it. A login
already granted keeps its grant until it refreshes, at which point the
policy is re-run against the new lists, so tightening a group takes effect
on the next refresh rather than mid-request. One exception:
`HTTP_API_SUPERUSER_GROUP` can be *changed* or *emptied* live, but cannot
switch the feature **on**, because superuser mode builds its signing
identity at startup; the log says so if you try.

A browser refused by these gets an HTML page naming the groups to ask for,
rather than the API's JSON error body.

### Superuser mode

An administrator can act on another user's jobs *as that user*: remove,
hold, release, tail output, and ssh-to-job. Off unless configured.

| Config | Default | Effect |
| --- | --- | --- |
| `HTTP_API_SUPERUSER_GROUP` | *(unset)* | Group(s) whose members may use superuser mode. Unset disables the feature. |
| `HTTP_API_SUPERUSER_FALLBACK_IDENTITY` | `condor@$(UID_DOMAIN)` | Identity used when the operator is not themselves a usable queue superuser. Only needs setting where the schedd does not run as `condor`. |

Two things must both be true or the feature stays off, and the server logs
which one is missing:

- the group above is set, or [project leads](#project-leads) are configured, **and**
- a pool signing key is configured — the server mints the credential it acts
  under, so without a key there is nothing to act with.

`HTTP_API_SUPERUSER_GROUP` is deliberately **not**
`HTTP_API_WEBUI_ADMIN_GROUP`. That group means "may read the admin pages";
this one means "may act as anyone on this access point". Point it at your
web-admin group if you want them to match — the difference is that it is then
a decision rather than a side effect.

**Using it.** A permitted operator turns the mode on from the sidebar and
confirms. A red banner then appears on every page, cannot be dismissed, and
counts down; the mode turns itself off after 30 minutes, and a server restart
turns it off for everyone. Actions on the operator's *own* jobs are unaffected
and are not treated as impersonation. Membership is re-checked on every action:
an armed operator who has since left `HTTP_API_SUPERUSER_GROUP` (and leads no
project) gets a 403 on their next action, and the mode is turned off.

**Job applications are closed while the mode is on.** VS Code, JupyterLab and
anything else served through `/api/v1/jobs/{id}/proxy/` or
`/api/v1/jupyter/instances/{id}/proxy/` are served from this server's own
origin, so script the job sends back runs in the browser with the viewer's
session. While the session is armed -- as a superuser or as a project lead --
those routes, and `/api/v1/jobs/{id}/warm`, answer 403 for every job,
including the operator's own. Every request is checked, so turning the mode on
with an app already open refuses that app's next request and its next
WebSocket upgrade. A connection already established before the mode was
turned on is not closed, and script already loaded in an open app tab keeps
running: close app tabs before turning the mode on.

**Which identity acts.** If the operator is themselves listed in the schedd's
`QUEUE_SUPER_USERS`, the server authenticates as them, and the schedd's own
log records

```
QmgmtSetEffectiveOwner real=<operator> ... effective to <owner>
```

Otherwise it falls back to `condor@$(UID_DOMAIN)`, or to
`HTTP_API_SUPERUSER_FALLBACK_IDENTITY` where that is set. The default suits a
schedd running as the `condor` user, because HTCondor recognises the daemon's
own OS user as the condor identity — but only when it is not a personal
condor, where that check is disabled entirely. Point the knob at whoever the
pool runs as in that case.

Being listed in `QUEUE_SUPER_USERS` is necessary but not sufficient: the
schedd resolves the caller to a user record *first* and refuses one it cannot
resolve, so an operator who has never submitted a job cannot act. That is
checked when the mode is armed, and the operator is told to run
`condor_qusers -add <user>` rather than left with an action that silently does
nothing. The set is read from the
schedd with `DC_CONFIG_VAL` at startup and every 15 minutes — never per
action — so adding an operator to `QUEUE_SUPER_USERS` takes effect within one
refresh.

**What gets recorded.** Every action is logged with both identities. Hold,
release and remove additionally write the operator's name into the job's
reason attribute, which persists into history and is visible to the job's
owner:

```
Removed by alice@example.org via the web UI (superuser mode, acting for bob@example.org) (by user condor@example.org)
```

The trailing `(by user ...)` is appended by the schedd itself. When the
operator is a queue superuser it names them; when the fallback identity is
used it names `condor`, and the leading text is then the only record in the
job ad of which human acted.

**Bulk actions** are split by job owner and performed once per owner, each
under its own impersonation, so every job acted on belongs to the identity the
server authenticated as. A constraint spanning more than 25 owners is refused
rather than fanned out.

### Project leads

Superuser mode confined to one project's jobs. A *project* is the job ad's
`ProjectName`. A lead of project P may turn on the mode exactly as a superuser
does, and while it is on may act on other users' jobs whose `ProjectName` is P
-- and on no others. `HTTP_API_SUPERUSER_GROUP` does not need to be set.

| Config | Default | Effect |
| --- | --- | --- |
| `HTTP_API_PROJECT_LEADS_FILE` | *(unset)* | File naming each project's leads (format below). |
| `HTTP_API_PROJECT_LEADS_GROUP` | *(unset)* | Group-name pattern containing `{project}`: members of the group it names for P lead P. |

The file has one project per line, then its leads, separated by whitespace or
commas. A lead starting with `%` is a group (the sudoers convention); anything
else is a username. `#` starts a comment anywhere on a line, so a project or
lead whose name contains `#` cannot be configured.

```
# project     leads
Physics       alice, bob
CS101         %cs101-tas carol
```

With `HTTP_API_PROJECT_LEADS_GROUP = {project}-leads`, members of
`Physics-leads` lead `Physics`, with no file entry needed. Both sources can be
used together; a session leads the union. The pattern needs fixed text around
`{project}`; a bare `{project}` is refused.

> **The pattern trusts whoever names groups.** Anyone who can create a group
> called `<P>-leads` in your identity provider (or `HTTP_API_GROUP_SOURCE`)
> becomes a lead of project P. Where users can create their own groups, use
> the file instead.

Whether a job is in a project is decided by the schedd, evaluating
`ProjectName == "<project>"` against the whole job ad; ClassAd `==` ignores
case for ASCII letters only. A bare username (`bob`) matches that name in any
domain; one with a domain (`bob@other.org`) matches only that identity, which
includes a bare session name that becomes it once `UID_DOMAIN` is appended (as
after local identity mapping), and never the same name in another domain. Both
compare case-insensitively. Groups are the session's, from
`HTTP_API_GROUP_SOURCE`, matched case-insensitively. A project name containing
a quote, a backslash or a control character is ignored.

**What a lead can do**, while the mode is on: hold, release and remove another
user's job in a project they lead, tail its output, and ssh to it. Bulk hold
and release reach the lead's own jobs plus their projects' jobs, whatever the
constraint says. A job with no `ProjectName`, or one in another project, is
refused with a 403, and so is a job that does not exist (with the same
message, so a lead cannot probe for jobs) and a job owned by a queue superuser
or by the fallback identity. Queue superusers are matched by name without the
domain, against both the job's `Owner` and its `User`, so
`alice@other.org` in `QUEUE_SUPER_USERS` protects every job owned by `alice`;
with `QUEUE_SUPER_USERS` unset, the schedd's default of `root` and `condor`
counts. Until the server has read `QUEUE_SUPER_USERS` from the schedd at
least once, every action a lead takes on another user's job is refused ("the
schedd's queue superusers have not been read"); the read is retried every few
seconds until it succeeds, so this lasts only while the schedd is
unreachable. Each refusal is logged to the security log. ssh-to-job gives the
lead the member's sandbox, including any credentials in it. Hold and release
reasons name the project:

```
Held by alice@example.org via the web UI (project lead for Physics, acting for bob@example.org) (by user condor@example.org)
```

**What a lead cannot do:** open any job application while the mode is on,
the same as a superuser (see [Superuser mode](#superuser-mode)).

**Reading.** Without turning the mode on, a lead may list (and open) their own
jobs plus their projects' jobs by choosing *Everyone* on the jobs page, the way
an admin may list all jobs. The same scope covers the job's live status and its
match analysis, including `?source=archive` for a finished job. That read
scope needs no signing key. For now the job log, DAG, sandbox and output
panels stay owner-only for leads.

**Revoking.** Leadership is re-checked on every action, not when the mode was
turned on: removing a lead from the file takes effect within a few seconds, or
immediately on `condor_reconfig`, and a lead who loses all their projects has
the mode turned off on their next action. A job watch a lead opened on a
project's job is re-checked every minute and ends once they can no longer read
the job. A session that turned the mode on as
a lead stays project-scoped for that arm even if its user is later added to
`HTTP_API_SUPERUSER_GROUP`. Group membership is the session's as of login,
for leads as for `HTTP_API_SUPERUSER_GROUP`.

**Prerequisites** are superuser mode's: a pool signing key and, where the
schedd does not run as `condor`, `HTTP_API_SUPERUSER_FALLBACK_IDENTITY`. Leads
are normally not in `QUEUE_SUPER_USERS`, so they act through the fallback
identity, and the reason text and this server's audit log are the record of
which lead acted. An unreadable leads file is logged and grants nobody
anything; it does not stop the server. Both settings are re-read on
`condor_reconfig`, but like `HTTP_API_SUPERUSER_GROUP` they cannot switch
superuser mode on in a daemon that started with it off.

### Refresh-grant re-authorization

A refresh grant re-runs the authorization decision rather than
replaying it, so an entitlement someone loses stops applying without
waiting for their refresh token to lapse. Three knobs:

| Config | Default | Effect |
| --- | --- | --- |
| `HTTP_API_OAUTH2_MAX_GRANT_LIFETIME` | `720h` (30d) | Caps a grant's total age, measured from consent, no matter how often it is refreshed. Requires a unit suffix. |
| `HTTP_API_OAUTH2_REVOCATION_ORACLES` | `schedd-userrec` | Comma-separated oracle list consulted on each refresh. |
| `HTTP_API_OAUTH2_REFRESH_TOKEN_LIFESPAN` | `720h` (30d) | Unchanged: how long one refresh token lives. Every refresh resets it, which is why the cap above exists. |

Recognized oracles:

- `schedd-userrec` (default) — honors `condor_qusers -disable <user>
  -reason "..."`, revoking the grant and surfacing the reason. Reads
  the schedd's per-user record at READ authorization; disabling
  requires ADMINISTRATOR, so the API server can observe the decision
  without being able to make it. A user with **no** record is treated
  as unknown, not denied, because the schedd creates records lazily on
  first submit.
- `schedd-userrec-strict` — as above, but a user with no record is
  revoked. Correct only where every user is provisioned up front with
  `condor_qusers -add <user>`, which creates a record without the user
  submitting anything. On an ordinary pool this locks out every new
  user.
- `schedd-acl` — probes `ALLOW_READ` / `ALLOW_WRITE` with
  `DC_SEC_QUERY` and strips refused scopes. Never revokes outright: it
  cannot see identity, and reports nothing useful where those ACLs are
  wildcards. Costs up to two extra schedd round trips per refresh.
- `none` — disable all oracles. The grant lifetime cap still applies.
  This spelling exists because an unset config value and one set to
  blank are indistinguishable, and both mean "use the defaults"; there
  has to be a way to say "none" out loud.

Oracles fail open: a schedd that is unreachable, or that has no record
of the user, yields no opinion rather than a revocation, so a daemon
outage does not log everyone out.

Note the group list an oracle-free deployment relies on is captured at
consent, so re-running group policy catches an operator changing
`MCP_WRITE_GROUP` but not a user being removed from that group
upstream. Removals are caught by the oracles, by
`POST /api/v1/admin/oauth2/revoke`, and ultimately by the lifetime cap.

### MCP OAuth2 clients

Clients of the MCP OAuth2 endpoint can register and authenticate several ways.
The admin UI at `/admin/clients` lists every client and lets an operator edit
its permitted grant types (and, for `client_credentials`, its service
identity); other fields are read-only.

- **Dynamic Client Registration (DCR, RFC 7591)** — `POST /oauth2/register`
  (also `/mcp/oauth2/register` wherever MCP is on).
  A client registers itself and gets a confidential `client_id` + secret. It
  may declare only the `authorization_code`, `refresh_token` and device-code
  grants and the `code` response type; anything else is refused with
  `invalid_client_metadata`. `client_credentials` and token exchange are
  enabled by an operator in the admin UI, never by self-registration.
  Registration is unauthenticated, so it is limited to 30 per hour from one
  address, and a registered client that has obtained no token within a week
  is deleted unless an operator has annotated it or changed its grants.
  `HTTP_API_MCP_DCR=false` turns registration off.
- **Client ID Metadata Document (CIMD)** — instead of registering, a client
  identifies itself by an `https://` URL as its `client_id`; the server fetches
  a client-metadata document from that URL and treats it as a **public** client
  (no secret, PKCE required). This is where the MCP spec is heading, away from
  DCR. The fetch is hardened against SSRF (https-only, private/link-local/cloud-
  metadata addresses refused, no redirects, timeout + size cap), and the
  document must be self-consistent (its `client_id` equals the URL). On by
  default; see the knobs below to disable or restrict it. **In production,
  set `HTTP_API_MCP_CIMD_ALLOWED_HOSTS`** to the hosts of the clients you
  expect: unset, any caller can make this server fetch from any public host
  (each source address is limited to 20 uncached lookups a minute).
- **`client_credentials`** — a confidential client acting as itself, with no end
  user. Enable the grant in the admin UI and set a **service identity**: that
  identity becomes the subject of the short-lived HTCondor IDTOKEN minted for
  the client's requests, which the schedd then authorizes via `ALLOW_<LEVEL>`
  like any other principal. A client with no service identity configured is
  refused a `client_credentials` token rather than minting one for an ambiguous
  subject. Not available to public clients.

### Token exchange (RFC 8693)

The MCP OAuth2 endpoint supports the token-exchange grant
(`urn:ietf:params:oauth:grant-type:token-exchange`), so a gateway or agent can
trade one token for another rather than re-running an interactive flow. It is
**opt-in per client**: enable the `token_exchange` grant on a confidential
client in the admin UI (`/admin/clients`). Exchange is always **delegation** —
the issued token acts as the subject but records the exchanging client as its
actor — and **scope-down only**: the result can never exceed the subject's
authorization.

Two kinds of `subject_token` are accepted:

- **A token this server issued** (`subject_token_type` =
  `urn:ietf:params:oauth:token-type:access_token`): the result acts as that
  token's subject, bounded by that token's granted scopes. No configuration
  needed. The subject's grant is re-checked first exactly as a refresh would
  be (lifetime cap, group policy, revocation oracles), and the result stays
  bound to it: revoking or narrowing that grant, or its ending, applies to
  the exchanged token too, and the exchanged token expires no later than the
  grant's lifetime cap. A token that was itself obtained by exchange cannot
  be exchanged again.
- **A JWT from a trusted external issuer** (`subject_token_type` =
  `urn:ietf:params:oauth:token-type:jwt` or `…:id_token`): accepted only when
  the issuer is listed in `HTTP_API_MCP_TOKEN_EXCHANGE_ISSUERS`. The token's
  signature is verified against the issuer's JWKS (RS256/ES256), and its
  `iss`/`aud`/`exp`/`nbf` are checked. The local identity is namespaced as
  `<sub>@<identity_domain>` (so two issuers cannot collide), and the result is
  bounded by the issuer's `allowed_scopes` **and** the exchanging client's own
  scopes, then by the same group policy and revocation oracles a login gets
  (with `HTTP_API_GROUP_SOURCE=system`, groups come from the mapped account,
  not the token).

`HTTP_API_MCP_TOKEN_EXCHANGE_ISSUERS` is a JSON array; unset disables external
exchange (the our-own-token path still works). Each entry:

```
HTTP_API_MCP_TOKEN_EXCHANGE_ISSUERS = [ \
  {"issuer":"https://idp.example.org", \
   "jwks_uri":"https://idp.example.org/.well-known/jwks.json", \
   "audience":"htcondor-mcp", \
   "identity_domain":"idp.example.org", \
   "allowed_scopes":["condor:/READ","mcp:read"]} ]
```

| Field | Meaning |
| --- | --- |
| `issuer` | Exact `iss` the token must carry. Required. |
| `jwks_uri` | HTTPS URL of the issuer's signing keys (fetched with SSRF protections, cached). Required. |
| `audience` | Value the token's `aud` must include. Required. |
| `identity_domain` | Local identity is `<sub>@this`. Defaults to the issuer's host. |
| `allowed_scopes` | Ceiling of scopes a token from this issuer may obtain. |

### Requests from other sites

Every state-changing request -- anything that is not GET, HEAD, OPTIONS or
TRACE -- must come from this site. If it carries an `Origin` header naming
somewhere else, it is refused with 403 before it reaches a route.

A request with no `Origin` is allowed: `curl`, scripts and the MCP stdio
client do not send one, and a browser cannot suppress it on a cross-site
request. A request carrying an `Authorization` header is also allowed,
because a browser does not attach one by itself -- a request that has one
was built by code that already held the credential, which is not the
situation this is about. A forged header simply fails to authenticate.

**Why it is not just cookies.** Session cookies are `SameSite=Lax`, which
already blocks a cross-site POST, so cookie deployments were never
exposed. But `SameSite` governs cookies, and `HTTP_API_USER_HEADER`
authenticates with a header a trusted proxy attaches to *every* request a
browser makes through it, cross-site included. In that mode, without this
check, a page on any site could submit, hold or remove a reader's jobs.

`HTTP_API_BASE_URL` is accepted alongside the request's own `Host`, so a
deployment whose SPA is served from a different origin keeps working.

## SSH gateway

An SSH port on the API server that authenticates with the OAuth2 device flow
and drops the caller into an HTCondor job. Users get an interactive terminal
without an account on the access point.

```
HTTP_API_SSH_GATEWAY_ADDRESS = :2222
HTTP_API_SSH_HOST_KEY_FILE = /etc/condor/htcondor-api/ssh_host_key
```

A user connects with a stock `ssh` and sees:

```
$ ssh 12345.0@ap.example.edu -p 2222
Approve at https://ap.example.edu/mcp/oauth2/device/verify?user_code=WDJB-MJHT (code WDJB-MJHT), then press Enter:
```

Approve in the browser, press Enter, and the session opens. Clients that
render the longer RFC 4256 instruction show the URL and code on their own
lines above that prompt; OpenSSH on Linux shows only the prompt, which is why
everything needed to act is repeated there.

No client configuration, no key to distribute: the prompt is an ordinary
RFC 4256 keyboard-interactive challenge, which every SSH client already
renders. Approving in the browser lets the session continue by itself.

### What the username selects

The username carries no identity — the OAuth2 grant does — so it names the
target instead:

| `ssh <this>@gateway` | reaches |
| --- | --- |
| `12345.0`, or `12345` | that job, proc 0 if omitted |
| `+work` | your interactive session called `work`, **started if you have none** |
| anything else, including a bare `ssh gateway` | your **default** session |

The `+` is required to name a session, and a bare `ssh gateway` reaches the
same `default` session from every machine you own. That is the point: the
username is whatever your local machine calls you, and your laptop login has
nothing to do with your HTCondor session — reading it as one would give you a
different session from a laptop, a login node and a container.

`+` is used because a POSIX username cannot contain it, so no local login can
be mistaken for an explicit request. A word like `session-` would need an
escape hatch for the account actually called `session-manager`; this needs
none.

It also reaches a session whose name looks like a job id, which is otherwise
unreachable because job ids are tried first: `ssh +12345.0@gateway`.

While a newly created session waits in the queue, the terminal shows what it is
waiting for and how long it has been waiting. Ctrl-C stops waiting; it does
**not** remove the job, so reconnecting picks the session up once it starts.

### The approval screen

Where the web UI is built into the binary, the approval link opens a screen
for the workspace the `ssh` command asked for rather than a generic "allow
this device" page. The `ssh` client sends the workspace name along with the
device authorization, and the verification endpoint redirects to
`/ssh/approve`.

If you already have a workspace by that name, the screen says what it is
doing — queued, running, or held and why — and offers the sign-in alone.
If you do not, it shows the same resource form as the **Interactive** page
(CPUs, memory, disk, GPUs, extra submit lines), opened on what
`HTTP_API_SSH_GATEWAY_SESSION_*` would have submitted. One button creates the
workspace **and** approves the sign-in. Nothing is submitted if you refuse,
and nothing is approved if the submission fails.

The browser submits the job, as you, before the approval is recorded, so the
gateway finds the workspace waiting and attaches to it. Creating on demand
from the gateway remains the fallback for a deployment with no web UI and for
an approval that created nothing; it cannot produce a second job, because the
first one to submit a given name wins and the other attaches to it.

The code is shown large at the top of the screen. It is the check that
catches a login somebody else started: a code that matches nothing in your
terminal is not yours to approve.

A deployment without the web UI keeps the server-rendered consent page, and so
does every device code that is not an SSH login.

### Host key and CA key

Both are long-lived and both are dangerous to lose: replacing a host key trips
`StrictHostKeyChecking` for every user at once, and replacing the CA key
invalidates every certificate it signed. They come from, in order:

1. `HTTP_API_SSH_HOST_KEY_FILE` / `HTTP_API_SSH_CA_KEY_FILE` — a path to an
   OpenSSH private key you staged (`ssh-keygen -t ed25519 -N '' -f <path>`).
   World-readable is refused; group-readable is fine, because a kubelet
   `fsGroup` mount turns 0400 into 0440. Passphrase-protected keys are refused
   with an error saying how to strip it.
2. Otherwise the daemon generates one and keeps it **sealed in the application
   database**, which requires `HTTP_API_KEK_FILE`.

There is deliberately no setting carrying the key bytes themselves:
`/proc/<pid>/environ` and crash dumps both leak the environment, and HTCondor
configuration is public to anyone who can run `condor_config_val`.

A stored key that cannot be decrypted is a **startup error**, never silently
replaced — the usual cause is a swapped `HTTP_API_KEK_FILE`, which is
recoverable, while a new host key is indistinguishable from an attack. Enabling
the gateway with neither a key file nor a KEK is also a startup error rather
than a port that quietly is not there.

**Running more than one replica?** Use the key file. A database-minted key
belongs to one database, so replicas would present different host keys.

### Knobs

| Knob | Purpose |
| --- | --- |
| `HTTP_API_SSH_GATEWAY_ADDRESS` | Where to listen, e.g. `:2222`. Empty disables the gateway. |
| `HTTP_API_SSH_GATEWAY_ISSUER` | OAuth2 issuer the device flow runs against. Defaults to the server's own issuer; set it when this process cannot reach its own public URL. |
| `HTTP_API_SSH_HOST_KEY_FILE` | Host key clients pin. Generated and sealed in the DB when unset. |
| `HTTP_API_SSH_CA_KEY_FILE` | CA key for signing user certificates. Same treatment; without it certificates are unavailable and the device flow still works. |
| `HTTP_API_SSH_GATEWAY_HOST` | The name(s) users actually `ssh` to, e.g. `ap.example.edu`, comma-separated. It is what the web UI prints as the `ssh` command, **and** what the host certificate and published `known_hosts` line are narrowed to — so list every name and alias in use. It cannot be derived, because the listen address is usually not what anybody types: a container listening on `:2222` sits behind a service publishing 22 on another address. Unset means no command is printed, and host verification falls back to a `*` pattern. |
| `HTTP_API_SSH_GATEWAY_LOCKOUT_THRESHOLD` | Failed logins one host may accumulate within the window before it is locked out. Default 10. |
| `HTTP_API_SSH_GATEWAY_LOCKOUT_NET_THRESHOLD` | The same budget for the surrounding network, shared by every host in it. Defaults to four times the host threshold. |
| `HTTP_API_SSH_GATEWAY_LOCKOUT_WINDOW` | How long failures are remembered. Needs a unit: `10m`. |
| `HTTP_API_SSH_GATEWAY_LOCKOUT_TIME` | How long the first lockout lasts; each subsequent one doubles. Default `15m`. |
| `HTTP_API_SSH_GATEWAY_LOCKOUT_MAX_TIME` | Where the doubling stops. Default `24h`. |
| `HTTP_API_SSH_GATEWAY_LOCKOUT_TRUSTED` | Addresses and CIDR blocks never counted and never locked out, separated by commas or spaces. A typo here is a startup error. |
| `HTTP_API_SSH_GATEWAY_LOCKOUT_DISABLE` | `true` turns the lockout off. |
| `HTTP_API_SSH_GATEWAY_SESSION_CPUS` | CPUs a session created on demand requests. Default 1. |
| `HTTP_API_SSH_GATEWAY_SESSION_MEMORY_MB` | Memory for the same. Default 1024. |
| `HTTP_API_SSH_GATEWAY_SESSION_DISK_MB` | Disk for the same. Default 8192 — a VS Code Remote server does not fit in less. |

The gateway needs OAuth2, which is served whenever the web UI or MCP is
enabled (see [When OAuth2 is served](#authentication)), since the device
flow is how it authenticates. Shell access needs no new scope: the schedd
registers `GET_JOB_CONNECT_INFO` at `WRITE`, so `condor:/WRITE` covers it.

If logins fail with *"could not start the login flow"*, the gateway cannot reach
its own device endpoint. It checks once shortly after startup and logs the URL
it tried — the usual cause is an unset `HTTP_API_OAUTH2_ISSUER`, which leaves
the default `http://localhost:8080` pointing at nothing.

### Locking out what keeps knocking

A public SSH port attracts traffic from people who are not users, so
the gateway counts failed logins per source and refuses new connections
from one that fails too often -- fail2ban's idea, without the log
scraping. It is on by default.

Counting happens at two granularities, because one is not enough. Per
host alone is free to evade over IPv6, where one allocation holds more
addresses than anyone could enumerate; per network alone would let a
single bad machine on a campus lock out the campus. So a host has its
own budget and the network around it has a larger shared one, and
tripping either is enough. A host is a `/32` on IPv4 and a `/64` on
IPv6, since one machine there routinely has several addresses; a
network is a `/24` and a `/48`. Once a host is locked out its further
failures stop counting anywhere, so it cannot spend its neighbours'
budget on their behalf.

Not every failure weighs the same:

| What happened | Weight |
| --- | --- |
| A login that began and was not finished -- the code expired, the browser said no | 1 |
| A certificate this deployment's CA did not sign, or one that did not verify | 1 |
| A **self-signed** certificate | 5 |
| Added when a failed login asked for a name a scanner works through -- `root`, `admin`, `ubuntu` | 3 |
| Authentication by a method this gateway never advertised -- password, GSSAPI | locked out at once |
| A refusal that is the gateway's own doing -- at its concurrency cap, issuer unreachable | 0 |
| `none` and `publickey` failures | 0 |

The last two rows are the ones that matter in practice. `none` is how
every SSH client asks what the server offers, and a client with a full
agent offers every key it holds before its certificate -- counting
either would lock out the people this is meant to protect. And an
issuer outage must not be mistaken for an attack, or a degraded gateway
locks out everybody who tried to reach it during the outage.

Asking for password authentication, on the other hand, is unambiguous:
this gateway never offers it, so no real client asks. That is the
strongest signal there is, and it is what most scanners trip on.

The username is a weaker one and is only ever added to a login that
*already failed*. `ssh root@gateway` is not by itself evidence of
anything here: an unprefixed username means "my default session", so
that is exactly what a real person gets from a container, and a real
person finishes the login. An explicit `+root` is somebody naming a
session and is never counted.

A lockout lasts `15m`, and doubles each time the same source comes back
for another, up to a day. Knocking while locked out does not extend it.

**Two caveats worth knowing.** The list lives in memory, so a restart
clears it and each replica keeps its own -- a restarted gateway starts
counting again rather than staying protected. And it counts whatever
address the connection arrives from, which behind a load balancer that
does not preserve the client address is the balancer: on Kubernetes
that means `externalTrafficPolicy: Local` on the gateway's Service, or
one bad client locks out everyone.

Put the office and the monitoring host in
`HTTP_API_SSH_GATEWAY_LOCKOUT_TRUSTED` so testing the gateway cannot
lock you out of it.

### Behind a load balancer

The gateway has to see each client's own address. It terminates the TCP
connection itself and does not accept the PROXY protocol, so nothing
upstream can tell it who the client is: pass the connection through at
layer 4 with the source address intact (`externalTrafficPolicy: Local`
on a Kubernetes Service, or no SNAT on the path). Behind anything that
rewrites the source -- a TCP proxy, SNAT, a NAT gateway -- every client
arrives from the same address, and everything counted per source is
counted for the whole site at once:

- At most four logins may be waiting at the approval prompt from one
  address. The fifth person to connect is refused until one of those
  finishes or its device code expires.
- The failure budget is shared. One user's abandoned logins lock
  everyone out, for `15m` the first time and up to a day.

Listing the balancer in `HTTP_API_SSH_GATEWAY_LOCKOUT_TRUSTED` stops the
lockouts by turning them off for every client behind it, and leaves the
four-login limit in place.

### Certificates, for scripts and for not approving every connection

`BatchMode=yes` refuses keyboard-interactive outright, so a script cannot use
the device flow at all — and nobody wants a browser prompt per connection
either. A certificate is obtained once and then works until it expires.

The gateway signs them with a CA key resolved exactly like the host key:
`HTTP_API_SSH_CA_KEY_FILE`, else generated and sealed in the database. Without
either, certificates are simply unavailable and the device flow still works —
losing convenience, not access.

That response also carries `gateway_host` and `gateway_port` when
`HTTP_API_SSH_GATEWAY_HOST` names one, so a client can find the gateway without
being told where it is. Both are omitted when it is unset: the listen address is
not the answer, since a container on `:2222` usually sits behind a service
publishing 22 somewhere else, and a guess would send clients to a closed port.
The port is reported only when the operator wrote one — `ap.example.edu:2222` —
and a client should read its absence as the SSH default rather than as an
instruction.

The common deployment is worth spelling out. A container binds
`HTTP_API_SSH_GATEWAY_ADDRESS = :2222` and a service publishes it as
`ap.example.edu` on port 22. Set `HTTP_API_SSH_GATEWAY_HOST = ap.example.edu`
and nothing else: the port is not 2222 as far as any client is concerned, and
the listen address is never consulted for what is advertised. Write
`ap.example.edu:8022` only if that is the port users really type.

Leaving it unset is logged as a warning at startup, because what it costs is
otherwise silent: no address is advertised, so every client has to be told by
hand; the host certificate is issued for every name rather than this one; and
the web UI prints no `ssh` command for a session.

```bash
# The CA, so your client trusts the gateway's host key.
curl -H "Authorization: Bearer $TOKEN" https://ap.example.edu/api/v1/ssh/ca

# A certificate for a key you already have.
curl -X POST -H "Authorization: Bearer $TOKEN" \
     -d "{\"public_key\": \"$(cat ~/.ssh/id_ed25519.pub)\"}" \
     https://ap.example.edu/api/v1/ssh/certificate
```

Save the `certificate` field as `~/.ssh/id_ed25519-cert.pub`, beside the private
key; `ssh` finds it on its own. Add the `known_hosts_line` to `~/.ssh/known_hosts`
and the gateway's host key verifies without pinning it by hand: the gateway
presents a host certificate signed by the same CA, so trusting the CA is enough.

Set `HTTP_API_SSH_GATEWAY_HOST` to the name users reach the gateway by, and both
the certificate's principals and the published `known_hosts_line` narrow to it.
That is worth doing: a line reading `@cert-authority * <ca>` tells the client to
trust this CA for **any** host, so naming yours confines what a stolen CA key
could vouch for. Several names are comma-separated, and a port is tolerated and
ignored — list every name and alias in use, because one left out stops verifying.

Left unset, the certificate lists no principals and the line uses `*`. A server
that does not know the names it is reached by cannot do better: it binds `:2222`
behind whatever the operator put in front of it, and a certificate naming the
wrong name fails closed for everyone.

Each configured name appears in the line twice, as `name` and `[name]:*`, because
OpenSSH looks a host up as `[name]:port` for any port but 22 — and this gateway
defaults to 2222.

The bare host key is still offered alongside it, so a client that pinned the key
before certificates existed keeps connecting and notices nothing. A client that
holds the CA line negotiates the certificate instead; OpenSSH prefers whichever
algorithm it already knows something about for that host.

Certificates last 12 hours by default and never more than 24. That is not
conservatism for its own sake: **there is no revocation**. No CRL, no OCSP, no
list to add a stolen key to. The lifetime is the only control, which is the
reason not to make it generous.

Three properties worth knowing, because they differ from how OpenSSH
certificates usually work:

- **The principal is the account, and the request cannot choose it.** The name
  signed is the one the access point resolved for the caller.
- **The username is not checked against the principal.** On this gateway the
  username names the job to reach, so requiring a match would mean a
  certificate per job.
- **Bare public keys are never accepted**, only certificates. A key on its own
  carries no identity and no expiry, so accepting one would mean this server
  keeping a list of whose key is whose — and a list that never forgets a
  compromised key.

### Limits worth knowing

- **`scp` and `sftp` work**, and so does anything else that asks for a
  subsystem: the gateway forwards the request to the job, whose sshd serves its
  own `Subsystem` directive. This was documented as impossible, on the belief
  that the forced command in `condor_ssh_to_job_shell_setup` turns a subsystem
  request into `eval sftp`. It does not — a probe against a real job gets a
  genuine `SSH_FXP_VERSION` reply from a real `sftp-server`.
- **The device flow needs somewhere to prompt.** `BatchMode=yes` declines
  keyboard-interactive outright, and a client with no terminal has nowhere to
  show the code; both want a certificate instead. A remote terminal is not
  required — `ssh -T` is fine, as long as the *local* end can prompt.
- **Ten sessions per job.** The sshd HTCondor starts uses OpenSSH's default
  `MaxSessions`, and every terminal for one job shares it. Port and socket
  forwards do not count against it.
- Each `ssh` is its own device authorization, so each asks for approval.
- **Port forwards reach whatever the job can.** `ssh -L` and socket
  forwards are dialled from inside the job, as `condor_ssh_to_job -L`
  does, to any host and port or socket path the job could reach itself.
  They carry the user's own authority over their own job, not the
  server's.

## Disabling tools

Some tools cannot work at some sites for reasons this server cannot see.
Where policy forbids `condor_ssh_to_job`, for example, the tools built on
it will fail however the pool is configured. Offering them anyway costs
an agent a turn to discover that, and the error it gets back describes a
permission problem rather than a decision somebody made.

`HTTP_API_MCP_DISABLED_TOOLS` names the tools this access point does not
offer:

```
# One tool, a family, or both. Commas or whitespace, either is fine.
HTTP_API_MCP_DISABLED_TOOLS = exec_in_job interactive_session_*
```

Patterns are shell-style globs matched against the tool name. A disabled
tool is left out of `tools/list` and refused if called anyway — a client
may be holding a catalogue from before the setting changed. The refusal
names this parameter, so whoever reads the agent's transcript knows where
the decision lives, and tells the agent not to retry.

Applied on SIGHUP (or `condor_reconfig`), including for sessions already
connected: a tool withdrawn because policy changed stops working without
waiting for agents to reconnect. Clearing the setting restores the tools.

A pattern that is not a valid glob is logged as an error and ignored,
leaving the tools it was meant to disable still offered — check the log
after setting one.

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

## Site skills

A site can publish its own documentation to agents: how work is actually
done here, which generic HTCondor knowledge does not cover. Point the
server at a directory -- typically a checkout of the documentation
repository -- and every Markdown file in it becomes a skill.

```
HTTP_API_MCP_SKILLS_DIR = /etc/condor/skills
```

```
git clone https://git.example.edu/ap/skills /etc/condor/skills
```

The server re-reads that directory every five minutes, so keeping the
library current is a matter of keeping the checkout current -- a cron
`git pull`, a git-sync sidecar, a config-management run. Nothing has to
signal the daemon afterwards.

**What is loaded.** Every `*.md` file underneath the directory, at any
depth. Hidden directories and hidden files are skipped, so a git checkout
works directly -- `.git` alone holds thousands of files, none of them
documentation. Symbolic links are not followed: a link is the one way a
file outside the configured directory could be served from inside it.
Files larger than 1 MiB are skipped, as is anything past 2000 skills,
which indicates the server has been pointed at the wrong directory.

**Front matter.** An optional YAML header supplies the catalogue entry:

```markdown
---
name: Submitting GPU jobs
description: How to request a GPU on this access point.
---

Use `request_gpus = 1` and the local GPU partition...
```

`summary` is accepted as an alias for `description`. A file with no front
matter still loads: its name falls back to the first Markdown heading and
then the filename, and its description to the first paragraph. A file
named `SKILL.md` takes its parent directory's name, so a skill laid out as
a directory reads as `gpu-jobs` rather than `gpu-jobs/SKILL`.

**How agents see them.** Both as tools and as resources, because a client
that lists resources up front can show the catalogue without calling
anything, while an agent that has decided it needs guidance looks for a
tool:

| Surface | What |
| --- | --- |
| `skills_list` | The catalogue, with an optional `query` filter. |
| `skills_get` | One skill in full, by id or name. |
| `skill://index.json` | The catalogue as a resource. |
| `skill://<id>` | One skill as a Markdown resource. |

When any skill is published, the MCP `initialize` response gains a **Site
skills** section that names each one with its description and tells the
agent to consult the relevant skill *before* using other tools. The
catalogue is inlined rather than merely pointed at, because an agent reads
the instructions before deciding anything -- a bare "call `skills_list`"
is advice it has no reason to take until it has already guessed.

**Order and length.** The `initialize` text is the access point's name,
then `MCP_INSTRUCTIONS`, then the Site skills section, then under 2 KB of
built-in guidance on submitting and monitoring jobs. Site text comes first
because some clients pass only the beginning to the model (Claude Code
keeps about the first 2 KB), so keep `MCP_INSTRUCTIONS` and skill
descriptions short. The longer built-in guidance is served by the
`doc_guide` tool, one topic at a time.

**Reloading.** Two paths, and the difference between them matters if you
are automating around it.

*The poll.* Every `HTTP_API_MCP_SKILLS_RELOAD_INTERVAL` (default `5m`) the
server checks the directory and re-reads it if anything changed. The check
is stat-only -- one `stat` per Markdown file, comparing path, size and
modification time against what is loaded -- so the normal outcome, nothing
changed, costs almost nothing and a short interval is affordable. It also
does not touch the published library or the `initialize` text when nothing
changed, which matters because rebuilding that text invalidates the cached
per-scope MCP servers.

Set the interval to `0` to turn the poll off and drive reloads yourself.

*`condor_reconfig` / SIGHUP.* Re-reads unconditionally, without consulting
the stat check, and takes effect at once. It is the right tool when you
have just changed the directory and want to know now, and the only one
that catches the case the poll cannot see: a file rewritten with the same
size and modification time.

A reload that fails -- the directory momentarily missing, an automount that
has not returned -- keeps the previously loaded set rather than leaving
agents with nothing, on either path. Clearing the setting does unpublish
them. Agents already connected keep the instructions they were given: MCP
delivers those once, at initialize, so a reload reaches sessions that
connect after it.

## API surface

Endpoint groupings — full reference + request/response shapes are in
[httpserver/README.md](../webapi/httpserver/README.md) and the OpenAPI doc
at `/openapi.json`.

**Jobs** (authenticated, owner-scoped)
- `POST /api/v1/jobs` — submit a job
- `GET /api/v1/jobs` — list with `constraint` / `projection`
- `GET /api/v1/jobs/{id}` — retrieve one
- `PUT /api/v1/jobs/{id}/input` — upload input tarball
- `GET /api/v1/jobs/{id}/output` — download output tarball
- `GET /api/v1/jobs/{id}/runtime-estimate` — how long the job is likely
  to run; see [Runtime estimates](#runtime-estimates)
- `POST /api/v1/jobs/runtime-estimates` — the same for up to 5000 jobs at
  once; see [Runtime estimates](#runtime-estimates)

**Pool** (authenticated; every signed-in user)
- `GET /api/v1/pool/drain-estimates` — when each execute node would be
  empty if drained now; see [Drain estimates](#drain-estimates)

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

### MCP tool-call statistics

`/metrics` also reports what the MCP surface is being asked to do, in
the same `htcondor_api` namespace as the HTTP metrics:

| Metric | Type | Labels | Answers |
| --- | --- | --- | --- |
| `htcondor_api_mcp_tool_calls_total` | counter | `tool`, `user`, `client`, `outcome` | what is called, by whom, from which harness |
| `htcondor_api_mcp_tool_duration_seconds` | histogram | `tool`, `client`, `outcome` | how long it takes |
| `htcondor_api_mcp_tool_users` | gauge | `tool` | how many distinct people use each tool |
| `htcondor_api_mcp_tool_last_call_timestamp_seconds` | gauge | `tool` | whether a tool is used at all |

`outcome` is `ok`, `error`, `refused` (disabled by
`HTTP_API_MCP_DISABLED_TOOLS`) or `unknown_tool` (the client named a tool
this server does not have — a stale catalogue, or an agent inventing a
name). A refusal is kept apart from an error on purpose: one is a policy
decision, the other a malfunction.

`client` is what the harness called itself in the MCP `initialize`
handshake, falling back to the HTTP `User-Agent` and then to `unknown`. The
server assigns the session that links an `initialize` to the calls that
follow, so a client that declares itself is attributed to what it said
rather than to its HTTP library. With `HTTP_API_MCP_TRANSPORT=sdk` only
the `User-Agent` is available, because that transport answers
`initialize` itself.

These statistics cover the HTTP MCP surface. The standalone
`condor-mcp` stdio server records nothing: it has no database to persist
to and serves no `/metrics`.
The duration histogram carries no `user` label: how long a tool takes is
a property of the tool and the pool, and a histogram costs fourteen
series per label combination.

**If the stored totals cannot be read, nothing is written.** A flush
replaces a series' whole total rather than adding to it, which is only
correct when the server was seeded from the rows it is about to
overwrite. So a server whose startup read failed keeps counting in
memory but persists nothing, and says so in the log; each flush retries
the read, and on success merges what it counted in the meantime with
what was stored. A single unreadable row is skipped and reported rather
than abandoning the whole read.

**These counters survive a restart.** They are written to the
application database every `HTTP_API_TOOL_STATS_FLUSH_INTERVAL`
(default 5 minutes) and again at shutdown, and read back at startup, so
`/metrics` reports the lifetime of the deployment rather than of the
process. This is deliberately unlike a textbook Prometheus counter,
which resets on restart and is handled by `rate()`; it is here so the
numbers mean something before Prometheus exists.

The durable table keeps the **verbatim** user and client, where
`/metrics` renders a bounded label space (see below), so it answers
questions directly:

```sql
-- Who uses this server, and for what?
SELECT actor, tool, SUM(calls) AS calls,
       ROUND(SUM(duration_sum_seconds), 1) AS seconds
  FROM mcp_tool_stats GROUP BY actor, tool ORDER BY calls DESC LIMIT 20;

-- Which harnesses are in use?
SELECT client, SUM(calls) AS calls FROM mcp_tool_stats
 GROUP BY client ORDER BY calls DESC;

-- What is failing?
SELECT tool, outcome, SUM(calls) AS calls FROM mcp_tool_stats
 WHERE outcome <> 'ok' GROUP BY tool, outcome ORDER BY calls DESC;
```

A Prometheus label value is a time series, so each of `tool`, `user` and
`client` is capped at 1000 distinct values on `/metrics`
(`HTTP_API_TOOL_STATS_MAX_LABEL_VALUES`). Past the cap the quietest
values render as `other`, ordered by call volume so the busiest keep
their identity.

Separately — and this is the bound that protects memory and disk — the
server holds at most `HTTP_API_TOOL_STATS_MAX_SERIES` (default 10000)
distinct combinations, plus one overflow bucket. The flush writes
exactly what is held, so this caps the table too. Past it, new
combinations fold into `other` rather than being dropped: the totals
stay right and only the detail stops. An unknown tool is recorded under
the name the caller sent, truncated to 64 characters, which is why this
bound exists at all.

### The admin Usage page

The web UI's **Usage** page (`/admin/usage`, admin only) shows the same
counts with real user and client names: totals, then calls per tool, per
user and per client, each split by outcome with distinct users or
clients, mean duration, an approximate p95 and the time of the last
call. Clicking a row, or choosing from the selectors, narrows every
table to that tool, user or client.

It reads `GET /api/v1/admin/usage`, which answers from the live
in-memory counts, so it includes calls not yet written to the database.
On a server with no application database it returns
`{"enabled": false}`. Rows look like:

```json
{"name": "query_jobs", "calls": 412, "ok": 400, "error": 9, "refused": 0,
 "unknown_tool": 3, "users": 7, "clients": 2, "avg_seconds": 0.21,
 "p95_seconds": 0.5, "last_call": "2026-10-08T14:02:11Z"}
```

`p95_seconds` is the upper edge of the duration bucket holding the 95th
percentile. When that lies past the last edge (300 s), it is `null` and
`p95_over_seconds` gives the edge instead. `users` and `clients` do not
count calls that carried no identity (`unknown`) or the overflow bucket
(`other`). The response also carries `totals`, `by_tool`, `by_user`,
`by_client`, the `filter` in force, and `options` (every tool, user
and client, unfiltered).

### Usernames on /metrics

The `user` label puts real account names on `/metrics`, alongside what
each one ran and when. That endpoint can be served unauthenticated with
`HTTP_API_METRICS_PUBLIC`, and is otherwise reachable with an API key
carrying the `metrics` scope — a credential this server deliberately
treats as low-value, on the reasoning that the worst it permits is a
scrape. Publishing a roster of who uses the access point changes that
trade.

Set `HTTP_API_TOOL_STATS_OMIT_USER=true` to render every user label as
`omitted`. Counts and every other metric are unaffected, and the
application database still records the real name, so the admin page and
the SQL queries above keep working — both are gated on more than a
metrics key.

**Admin** (gated on `WebUIAdminGroup` membership)
- `/api/v1/admin/oauth2/clients`, `/api/v1/admin/oauth2/tokens`
- `/api/v1/admin/api-keys`, `/api/v1/admin/api-keys/{key_id}`
- `/api/v1/admin/logs`, `/api/v1/admin/condor-config`
- `GET /api/v1/admin/usage` — MCP tool-call statistics by tool, user and
  client (`?tool=`, `?user=`, `?client=` narrow them); see
  [MCP tool-call statistics](#mcp-tool-call-statistics)

**Placement** (admin-gated; only when a `condor_placementd` is reachable)
- `GET /api/v1/placement/status` — feature probe; answers even with no
  daemon, so the UI can hide the page instead of erroring
- `GET /api/v1/placement/users` — mapped identities + their live tokens
- `GET /api/v1/placement/tokens` — issued tokens (`valid_only=true` for
  unexpired ones)
- `GET /api/v1/placement/authorizations` — grantable authorizations,
  with the label/color/description from the daemon's map file
- `POST /api/v1/placement/login` — mint an IDToken. The response is the
  only time the token exists in retrievable form.

- `GET /api/v1/placement/records/projects` — every project the map file
  names, with its schedd project record's state
- `GET /api/v1/placement/records/{accounts|projects}/{name}` — the schedd
  record behind a placement account or project, with its job counters
- `POST /api/v1/placement/records/{accounts|projects}/{name}/{suspend|unsuspend}`
  — `DISABLE_USERREC` / `ENABLE_USERREC` on the schedd; the reason is
  `suspended by <admin> via web UI`. Only names the placementd hands out.

  These are admin-only on purpose: the placementd registers its commands
  at ADMINISTRATOR and this server talks to it as the AP's own identity,
  so an endpoint any signed-in user could reach would let them mint a
  bearer token for anyone in the map file. The server finds the daemon
  via `PLACEMENTD_ADDRESS_FILE` (or `$(LOG)/.placementd_address`), then
  the collector; finding none simply disables the group. It looks again
  when a connection fails (a restarted placementd has a new address) and
  when the feature is next asked for, so a placementd started or upgraded
  later is picked up without restarting this server.

**Placement onboarding** (any signed-in session; see
[Placement onboarding](#placement-onboarding))
- `GET /api/v1/placement/me` — the session's placement identity, the
  projects and authorizations it may request, and whether the schedd has
  the account or a project disabled
- `POST /api/v1/placement/me/token` — `{project, authorizations[],
  user_code?}`; needs an `X-Requested-With` header. Returns the token, or
  with `user_code` hands it to that device request instead.
- `GET /api/v1/placement/me/device/{user_code}`,
  `POST /api/v1/placement/me/device/{user_code}/deny`
- `POST /api/v1/placement/me/project` -- `{project}`; selects the project
  of a session signed in through the `placementd` identity mapping
- `GET /api/v1/placement/me` and `POST /api/v1/placement/me/token` also
  accept a bearer access token holding the `placement` scope
- `POST /auth/device_authorization`, `GET /auth/code`,
  `POST /auth/cancel_device` — placement-webapp's device flow, for
  `placement-client`

**Chat assistant** (when `HTTP_API_LLM_API_KEY_FILE` is set)
- `POST /api/v1/chat` — AI-SDK v6 UI-message stream. The body's `scope`
  (`mine` or `everyone`) is the page's Mine/Everyone view; the server
  grants `everyone` only to a caller the page's own endpoint would show
  other users' jobs, and the assistant's tools act on other users' jobs
  only for an administrator with the right to change them.
- `GET /api/v1/chat/info` — feature probe
- `GET /api/v1/chat/scope?page=<page>&scope=<mine|everyone>` — which jobs
  the assistant would see for this caller on that page

**MCP** (when enabled via `HTTP_API_ENABLE_MCP=true`)
- The OAuth2 endpoints do not depend on this; see
  [When OAuth2 is served](#authentication).
- The full MCP surface is exposed at `/mcp/*` for cooperative
  agents. The standalone `htcondor-mcp` binary speaks the same MCP
  protocol over stdio. See [mcpserver/README.md](../webapi/mcpserver/README.md).

### Runtime estimates

`GET /api/v1/jobs/{id}/runtime-estimate` estimates how long a job will run
from the runtimes of **the same owner's** similar jobs that have already
completed, and the MCP `get_job` tool carries the same answer as
`runtime_estimate`. It needs the [htcondordb](#further-reading) mirror:
history is read from the mirror's archive every
`HTTP_API_RUNTIME_ESTIMATE_INTERVAL` (default `5m`), never from the
schedd, because a background `condor_history` scan would cost the access
point more than the estimates are worth. Without a mirror the feature is
off; with a mirror that is stale or has a history gap, the estimates in
memory keep answering and the read is retried next interval.

Each completed job is filed under a ladder of groups, from most to least
specific: its cluster, its exact command line (directories, URLs and
hashes dropped), the same command line with every number masked, its
batch name less any run number, its submit directory, its program, and
the owner's jobs as a whole. Every group holds only that owner's jobs,
and only jobs of the same universe (`JobUniverse`; an ad without one
counts as vanilla) that are, like the job asked about, DAG nodes (`DAGManJobId` set) or not, and run
in a container or not: a DAG node is never estimated from its owner's
standalone jobs, nor a container job from bare ones, even ones running
the same command. A job runs in a container when `WantContainer` or
`WantDocker` is true or it names an image in `ContainerImage`,
`DockerImage` or `SingularityImage`; which image does not matter, so
moving to a new image keeps the history. For an interpreter (`python`,
`bash -c`, `apptainer exec`, ...) the program is the script it runs. An
estimate is the median of the most recent 100 runtimes in one group — a
single earlier run is enough, since they are the owner's own jobs. An
owner with no recently finished job of the same kind gets no estimate
(`insufficient_history`): other users' jobs never stand in. Which group
answers is chosen per owner by how well each has predicted that owner's
jobs so far. Each completed job is scored as it would have
been estimated when it was submitted and when it started, from only the
jobs that had finished by then, so the record matches the moment a
question is actually asked. The likely range (`p10_seconds` to
`p90_seconds`) comes from those past estimation errors — the owner's,
pooled with the access point's for the same group level, or the access
point's at every level while those are too few, at the same point in a
job's life (waiting or running) — widened to the group's own spread when
that is larger. Those errors only size the range around an estimate
drawn from the owner's own jobs. Only completed jobs that exited 0 count;
DAGMan and other scheduler/local-universe jobs are left out, and are
never estimated themselves. Nothing about another job — its command, id
or owner — is ever returned.

```json
{
  "job_id": "1234.0",
  "available": true,
  "estimate_seconds": 2710,
  "p10_seconds": 1840,
  "p90_seconds": 5120,
  "basis": {"level": "template", "sample_count": 64},
  "rough": false,
  "elapsed_seconds": 900,
  "remaining_seconds": 1810,
  "exceeded_history": false,
  "model": {"trained_through": "2026-10-10T17:42:11Z", "jobs_ingested": 48213}
}
```

The web UI's job page shows it under the job's status, as "Expected run
time", for a waiting or running job when there is an estimate, and
nothing otherwise.

`elapsed_seconds` and `remaining_seconds` appear only for a running job.
A running job that has outlived the typical run is re-estimated from the
runs in its group that lasted at least as long; once it has outlived
nearly all of them, `exceeded_history` is true and no remaining time is
given. When there is no estimate the response is still 200, with
`available: false` and a `reason`: `disabled`, `model_warming_up` (the
history has not been read yet), `insufficient_history` (the owner has no
recently finished job of the same kind), or
`not_estimated` (a scheduler- or local-universe job, such as a DAG's
DAGMan job, whose runtime is never estimated).

`rough` is true when the answer came from one of the broad groups — the
same program whatever its arguments, or the owner's jobs as a whole —
which on a replayed access point were within a factor of two of the actual runtime only a quarter to a third of the time, against
about three quarters for the others; the web UI labels those "rough
guess". `basis.new_command` is true when none of the owner's recently
completed jobs ran the same program.

`memory` says what the runs of the group that answered peaked at, in MiB,
so a page that shows both describes one group:

```json
"memory": {
  "sample_count": 64, "p10_mib": 910, "p25_mib": 1040, "p50_mib": 1210,
  "p75_mib": 1500, "p90_mib": 1980,
  "peak_mib": 6200, "requested_mib": 2048, "above_requested": 9,
  "rough": false, "above_usual": true
}
```

A run's peak is `ResidentSetSize_RAW` (KiB) when the record has it, else
`MemoryUsage` evaluated, as the Utilization page reads it; a run with
neither counts for its runtime and is left out of `memory`, which is
absent when no run in the group has a peak. `peak_mib` is the job's own
peak so far (for a finished job, its peak), `requested_mib` its
`RequestMemory` and `above_requested` how many of the group's runs peaked
above that. `above_usual` is true when a running job, answered from a
specific group (not `rough`) with at least 5 known peaks, has already
peaked at both 1.25 times the group's `p90_mib` and 256 MiB above it;
HTCondor only ever raises a running job's figure, so that excess has
already happened. The jobs listing marks such a job "More memory than
usual". A job that has left the queue is answered from its history
record (with `above_usual` false), which is what the archived job's page
shows.

`POST /api/v1/jobs/runtime-estimates` with `{"jobs": ["1234.0", "1234.1",
...]}` answers for up to 5000 jobs at once (more is a 413), which is how
the web UI's jobs listing asks: once per refresh for the waiting and
running jobs it shows. The answer is `{"available": true, "estimates":
{"1234.0": {...}, ...}, "model": {...}}`, each estimate shaped like the
single-job answer without `job_id` and `model`. Only jobs the caller may
read that are waiting or running are answered; any other id is simply
absent. A server without the feature, or one that has not read its
history yet, answers `{"available": false, "reason": "disabled"}` (or
`"model_warming_up"`) without looking anything up. It is a read, and an
API key or token with only `condor:/READ` may use it.

Metrics, all prefixed `htcondor_api_runtime_estimate_`: `enabled`,
`jobs_ingested_total`, `last_refresh_timestamp_seconds`,
`trained_through_timestamp_seconds`, `refresh_errors_total`,
`refresh_truncations_total`, `keys{level}`, `owners`, and the estimator's
running record of itself, `scored_total{level}` and
`within_2x_total{level}`: every completed job is first scored against the
estimate it would have got when it was submitted, so
`within_2x_total / scored_total` is live accuracy at submit.

### Drain estimates

`GET /api/v1/pool/drain-estimates` answers, for every execute node that is
running jobs or draining, "if this node were drained now, when would it be
empty?" A drain lets each job run until it finishes or its retirement limit
runs out, whichever comes first, then evicts it. The web UI's Pool page
shows it as the "Empty if drained now" column and in its summary cards.

Two numbers go into each job's answer:

- **Its retirement deadline**, known for every job: the startd publishes
  `RetirementTimeRemaining` on each claimed slot, counted from the ad's
  `MyCurrentTime`. A job with a minute or less left (a 30-second limit, or
  one that has already run out — backfill slots have none) is counted in
  `evicted_on_drain` and leaves at its deadline.
- **When it would finish**, known only for jobs submitted from this access
  point (matched by the schedd name in the slot's `GlobalJobId`), from the
  [runtime estimates](#runtime-estimates). On a shared pool most jobs come
  from elsewhere and have none.

So a node whose jobs all have a known end gets `likely_empty_seconds`; one
that also runs jobs nobody can estimate gets `at_least_seconds` (the
estimated part) and `unknown_up_to_seconds` (the latest retirement deadline
among the rest). `at_most_seconds` is the startd's own
`ExpectedMachineGracefulDrainingCompletion` when it publishes one, else the
latest deadline. `exceeded` counts jobs running longer than comparable jobs
have. With runtime estimates off (`HTTP_API_RUNTIME_ESTIMATE_INTERVAL=0`, or
no mirror), the response has the same shape with `estimates_available:
false` and the retirement bounds alone.

```json
{
  "generated_at": "2026-10-11T19:10:00Z",
  "age_seconds": 12,
  "stale": false,
  "estimates_available": true,
  "access_point": "ap2001.chtc.wisc.edu",
  "summary": {"machines": 1, "jobs_running": 4, "jobs_estimated": 2, "jobs_from_this_ap": 2,
              "cores_freeing_next_hour": 8, "draining_nodes": 0, "draining_likely_empty_within_2h": 0},
  "machines": [{
    "machine": "e2231.chtc.wisc.edu", "draining": false,
    "jobs_total": 4, "jobs_estimated": 2, "jobs_from_this_ap": 2,
    "jobs_unknown_end": 2, "jobs_unknown_from_other_aps": 2,
    "likely_empty_seconds": 5400, "likely_empty_at": "2026-10-11T20:40:00Z",
    "at_least_seconds": 5400, "at_most_seconds": 259200, "at_most_at": "2026-10-14T19:10:00Z",
    "unknown_up_to_seconds": 233000, "evicted_on_drain": 0, "exceeded": 0,
    "expected_ends": [{"seconds": 2700, "usually_by_seconds": 5400, "cpus": 4},
                      {"seconds": 5400, "usually_by_seconds": 8100, "cpus": 4}]
  }]
}
```

`?machine=NAME` answers for one node and adds `slots`, one per running job:
`name`, `owner` (`RemoteOwner`), `submitted_from` (the schedd in its
`GlobalJobId`), `from_this_ap`, `running_seconds`, `expected_end` and
`usually_by` (about 90% of comparable jobs are done by then) when estimated,
`exceeded`, `retirement_deadline` and `evicted_on_drain`. Without it the
slots are left out, since a large pool has one per running job.

The answer covers every user's jobs and every signed-in user may read it,
so it is not computed as any of them: one computation, run as this daemon,
reads the claimed slots from the collector and this access point's running
jobs (`JobStatus == 2`, from the htcondordb mirror when there is one, else
one schedd query), and is served to everyone for a minute. A request only
waits for that answer. If a refresh fails, the last good answer is served
with `stale: true` and an `error`; if the running jobs cannot be read, the
answer has the retirement bounds and an `error` saying the estimates are
missing. Not available in multi-AP mode.

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

## Reaching jobs behind CCB

Anything that reaches *into* a running job — a shell, `tail_job_output`,
`exec_in_job`, an interactive session — connects to the starter on the execute
node. When that node is firewalled, its address carries a Condor Connection
Broker contact and the connection has to go through the broker.

### When you are already on their network

Before any of that: if this server sits on the same private network as the
execute nodes — a pod beside the pool is the usual case — it can open a TCP
connection to them directly, and the broker is only in the way.

HTCondor's convention for saying so is `PRIVATE_NETWORK_NAME`. A daemon
publishes its own as `PrivNet` in the address it advertises, and a client whose
name matches dials the daemon directly instead of through its broker:

```
PRIVATE_NETWORK_NAME = pool-internal
```

Set it to the same value the execute nodes use. When it matches, this server
uses the daemon's `PrivAddr` if the address carries one, and otherwise dials the
advertised address with the broker contact dropped — the same two cases C++
HTCondor implements.

Nothing has to listen inbound, so `HTTP_API_SHARED_PORT` and everything under it
becomes unnecessary, and the dial no longer depends on the broker's version.

A direct dial that fails falls back to the broker rather than failing the
request, since a private network can be partly reachable. That failure is
remembered for `HTTP_API_CCB_LEARNED_TTL` so the timeout is not paid on every
dial, and is per network — one unreachable node steers the rest to the broker
until the TTL expires. A success clears it.

The parameter defaults to `$(FULL_HOSTNAME)`, matching C++. That is harmless:
it only matches a remote `PrivNet` when the daemon really is on this host.

CCB offers two ways through, and on a host that is itself firewalled neither is
automatic:

- **Connection reversal** (the default). The broker tells the starter to dial
  *us*. That needs this server to be reachable from the execute node — which an
  API server in a container, behind NAT, or in a Kubernetes pod is not. The
  failure is silent: the starter connects to an address nothing routes to and
  the request times out without naming CCB.
- **Streaming**, where the broker relays both directions itself. No inbound path
  needed, but it requires a broker running HTCondor 25.13 or newer, and *which*
  broker a given dial uses is decided by the execute node, not by this server.

Setting `HTTP_API_SHARED_PORT` gives this server the inbound path, using the
same mechanism the access point already uses for `condor_ssh_to_job`: one port,
multiplexed. Each dial registers an unguessable id and advertises
`<host:port?sock=ID>` as its reverse-connect address, so any number of
concurrent sessions share the one port. No `condor_shared_port` daemon is
involved — the routing happens inside this process.

```
# The port execute nodes will connect back to.
HTTP_API_SHARED_PORT = 9618

# Only when that is not what they should dial -- a Kubernetes Service, a
# published container port, a NAT.
HTTP_API_SHARED_PORT_ADDRESS = htcondor-api.example.org:9618
```

With it set, connection reversal through that port is tried first, because it
works with every broker version. If the execute node turns out not to be able
to reach it after all, the server falls back to streaming (unless
`HTTP_API_CCB_STREAMING = false`), and remembers the answer per broker for
`HTTP_API_CCB_LEARNED_TTL` so later requests do not pay the timeout again. A
broker too old to relay is likewise remembered and not asked again.

Open the port in the host firewall, and check the log line at startup — it
prints the address being advertised, which is the thing that is wrong when this
does not work:

```
HTCondor shared port open for CCB connection reversal listen=9618 advertised=htcondor-api.example.org:9618
```

## Multi-AP mode

One server can front every access point whose schedd ad matches a
collector constraint, instead of one schedd:

```
HTTP_API_SCHEDD_CONSTRAINT = regexp("^ap[0-9]+\\.example\\.org$", Name)
```

Reads come from a federation hub: an htcondordb running with
`HTCONDORDB_FEDERATE_SCHEDD_CONSTRAINT` that fans every access point's own
htcondordb (its spoke) into one catalog. See the htcondordb federation
documentation for running one; give it the same constraint. Actions go to
the schedd of the access point the job is on, as you. New work goes to the
access point your [assignment](#ap-assignment) names.

What it serves:

| Request | Answer |
| --- | --- |
| `GET /api/v1/jobs`, MCP `query_jobs` | Your queued jobs on every access point, from the hub. `?schedd=` (MCP `schedd`) limits it to one. Pages continue with `next_page_token`. |
| `GET /api/v1/jobs/archive`, MCP `query_job_archive` | Your completed jobs, newest first by `EnteredHistoryTime`. Pages continue with `next_page_token`; `before_cluster`/`before_proc` are refused, because a cluster id is unique only within one access point. |
| `GET /api/v1/jobs/{id}`, MCP `get_job` | One of your jobs, queued or completed (`archived`). |
| MCP `aggregate_jobs` | Counts over `jobs` or `history`; group by `ScheddName` for a per-access-point count. |
| `GET /api/v1/aps`, MCP `list_access_points` | The access points, whether each is in the collector, how current the hub's copy of each is, and whether it trusts this server (`trust`). |
| One job: `DELETE`/`PATCH /api/v1/jobs/{id}`, `POST .../hold`, `.../release`, `.../warm`; `GET .../stdout`, `.../stderr`, `.../log`, `.../peek`, `.../dag`, `.../files/{name}`, `.../output`, `.../watch`, `.../ssh`; `PUT .../input`, `POST .../input/multipart`, `.../input/share`, `.../output/share`; `/api/v1/jobs/{id}/proxy/...` | As in single-AP mode, against the job's own access point. `{id}` must be complete. |
| MCP `remove_job`, `hold_job`, `release_job`, `edit_job`, `get_job_stdout`, `get_job_stderr`, `get_job_output`, `upload_job_input`, `create_input_upload_url`, `create_output_download_url`, `tail_job_output`, `exec_in_job` | As in single-AP mode, against the job's access point. `job_id` must be complete, or bare with `schedd`. |
| Bulk: `POST /api/v1/jobs/hold`, `.../release`, `DELETE /api/v1/jobs`, `PATCH /api/v1/jobs`, MCP `remove_jobs` | Run on every access point; see below. |
| `GET /api/v1/share/output`, `PUT /api/v1/share/input` | A share URL acts on the access point it was minted for. |
| `POST /api/v1/jobs`, MCP `submit_job`, `submit_dag`, `build_container` | Submit, as you, to your home access point, or with `?schedd=` (MCP `schedd`) to one of its alternates; see [AP assignment](#ap-assignment). The answer carries complete job ids. |
| `/api/v1/creds/user`, `/api/v1/creds/service[/...]`, MCP `list_service_credentials`, `get_credential_status`, `store_service_credential`, `delete_service_credential` | Your home access point's credd, or with `?schedd=` (MCP `schedd`) that of any access point in the set. The response header `X-HTCondor-Access-Point` (MCP: `schedd`) names it. |
| `GET /api/v1/templates` and the rest of `/api/v1/templates` | Submit templates, from this server's own database. |
| `POST /api/v1/interactive/terminal`, `POST /api/v1/jupyter/instances`, `POST /api/v1/apps`, MCP `interactive_session_start` | Start a terminal, a JupyterLab, an app or a named session on your home access point for that kind of work, or with `?schedd=` (MCP `schedd`) on an alternate; see [interactive work](#interactive-work-in-multi-ap-mode). The answer names the access point (`schedd`) and the complete job id. |
| `GET /api/v1/interactive/terminal`, `GET /api/v1/jupyter/instances[/{id}]`, `GET /api/v1/apps[/{id}]`, `DELETE /api/v1/apps/{id}`, the JupyterLab tunnel, events and proxy, MCP `interactive_session_exec`, `interactive_session_list`, `interactive_session_stop` | As in single-AP mode, against the access point each one is on. |
| MCP `watch_jobs`, `check_watches`, `cancel_watch`, `create_watch_url`; `POST /api/v1/watches/{id}/share`, `GET /api/v1/share/watch` | Watches over your jobs on every access point; see below. |
| `GET /api/v1/jobs/watch` | Changes to your jobs on every access point, from the hub's jobs stream; each event's `key` is the complete job id. |
| `GET /api/v1/dashboard`, `.../dashboard/activity`, `.../dashboard/activity/stream` | Your jobs on every access point, from the hub, in total and per access point (`aps`), with the `sources` block; see below. |
| `GET /api/v1/issues`, MCP `analyze_issues` | Held jobs and failed run attempts on every access point, from the hub; every example and cluster names its access point (`schedd`, `schedds`). Run attempts need the hub to federate `epoch_history`; without it the answer says so in `notes`. |
| `GET /api/v1/jobs/epochs`, `.../transfers`, MCP `query_job_epochs`, `query_transfer_history` | Run-attempt and transfer records; see below. |
| `GET /api/v1/metrics/job_metrics` | Resource-usage samples of your jobs on every access point, from the hub; see below. |
| `GET /api/v1/jobs/{id}/match-analysis`, MCP `analyze_job_match` | The job's ad from its access point, the slots from the collector. `{id}` must be complete. |
| `GET /api/v1/collector/...` (not `advertise`), MCP `query_pool` | The pool's collector, which the access points share. |

Everything else -- drain estimates and runtime estimates (they read one
schedd's running jobs), any other method on `/api/v1/metrics/job_metrics`
and any other table under `/api/v1/metrics/`,
the single-schedd status routes (`/api/v1/ping`, `/api/v1/schedd/ping`,
`/api/v1/dbmirror/*`; `/api/v1/aps` and `/readyz` describe the access
points and the hub) and chat -- answers **501** ("not available in
multi-AP mode yet"), and the MCP catalogue offers only the tools above
plus `whoami`, `get_version`, `doc_*` and `skills_*`. Superuser mode is
not available.

**Watches.** One evaluator follows every registered watch over the hub,
and the hub's jobs table is followed as one change stream for every access
point (resumed from its position after a dropped connection). A watch's
constraint selects among your jobs on every access point -- add
`ScheddName` to it to watch one -- and each job it tracks and reports
carries its access point (`schedd`): the same `cluster.proc` on two access
points is two jobs. A job that leaves the queue is reported finished from
its history record, or from its last ad on the hub's stream saying it
completed or was removed, on any access point. Its *absence* from the
queue counts as finished only for an access point the hub reports
`fresh`, with a measured staleness, its jobs stream connected and
error-free, and its jobs table caught up: `JobsSynced` true in the
`federation_sources` rows read just before and just after the queue read,
with the same `JobsSyncedAt` (a hub too old to publish `JobsSynced` is
instead not trusted within ten minutes of the access point's `LastReset`).
It also counts only once that read reflects the access point from after
the job was last seen there (allowing for the reported staleness, a
minute for the hub's row refresh and one hub state interval). A stale,
absent, retiring or untrusted access point, a disconnected, failing or
replaying stream, or an unreachable hub never yields a "finished" on
absence; the watch waits, and fires once the history record arrives or
the access point is current again. A watch entry stored before access
points were recorded resolves from a history record when exactly one
access point has that `cluster.proc`, and otherwise waits. A watch URL is about its owner's jobs
on every access point, so it carries `"s": "*"` inside its signature: a
multi-AP server refuses a watch URL without it, and a single-AP server one
with it. An identity outside `UID_DOMAIN` cannot register or share a
watch.

**Dashboard.** `jobs_by_status` and `jobs_total` count your jobs on every
access point; `aps` gives each access point's counts and its state on the
hub. The activity answer's lists carry `schedd` and `job_id` on each job,
and its `aps` give each access point's `finished_recently`: history
records in the last hour plus jobs the hub's stream saw leave the queue
whose last ad said they completed or were removed. A delete alone is not
counted: it is also what retiring (`.retire`) or replaying an access
point looks like, and a job that leaves held or idle has not been shown
to have finished. An access point that is not fresh has its count marked
`finished_partial`. Hub reads have no cross-user view, so
`owned_by_me=false` is not honoured.

**Run attempts and transfers.** With the hub federating `epoch_history`
(`HTCONDORDB_FEDERATE_TABLES = jobs history syncstatus epoch_history`),
`/api/v1/jobs/epochs` and `.../transfers` (and their MCP tools) read your
records on every access point from it, newest first, each with `schedd`
and `job_id`; `?schedd=` and `?job_id=` narrow them (a bare `123.0` is
accepted when one access point has that job of yours). Transfer records
are the run-attempt records whose `EpochAdType` is `INPUT`, `OUTPUT` or
`CHECKPOINT`. Without `epoch_history` on the hub, a request naming a job
or an access point is sent to that access point's schedd, as in single-AP
mode, and each record carries `ScheddName`; one naming neither is a
**501** with `"reason": "epoch_history_not_federated"` -- answering it
would scan every access point's history file on every request, with no
order or page token across them.

**Resource usage.** With the hub federating `job_metrics` (each spoke
running with `HTCONDORDB_JOB_METRICS`, and the hub with
`HTCONDORDB_FEDERATE_TABLES = jobs history syncstatus job_metrics`),
`GET /api/v1/metrics/job_metrics` takes the same `constraint`,
`group_by`, `bucket`, `agg`, `since` and `until` as in single-AP mode and
aggregates your samples on every access point. Every caller,
administrators included, reads only their own (`User`), on member access
points only. `?job_id=` reads one job's samples: a complete id, or a
bare `123.0` when one access point has that job of yours (on two it is a
**409** with the `candidates`); the answer's `job` names the complete id.
`?schedd=` reads one access point's, and settles a bare `job_id`. A
`group_by` naming `ClusterId` or `ProcId` gains `ScheddName` before
them, since the same `cluster.proc` on two access points is two jobs;
`group_by=ScheddName` aggregates per access point. The answer carries the `sources` block. A hub that does not
federate `job_metrics` answers `{"enabled": false}` with the `sources`
block, as single-AP mode answers without the sampler. One aggregate is
bounded at 30 seconds and 20000 rows, as in single-AP mode. A sample its
access point's htcondordb never tied to its job carries no `User`, so no
read returns it -- not even one naming that job -- and it is missing from
the job page's graphs. The job page draws its resource-usage graphs from
this, by the job's complete id, and says so when the job's access point
records no usage (`not_kept`).

The dashboard, the issues view, run-attempt reads and resource usage also
name, in their `sources` block, each access point whose stream of the
table they read (`jobs`, `history`, `epoch_history`, `job_metrics`) is
disconnected, failing, still catching up or not federated, with a
`reason` naming the table, so a short answer says which access points it
is short of. An access point whose own htcondordb keeps no such table at
all (the hub reports `<Table>Missing`, e.g. a spoke without
`HTCONDORDB_JOB_METRICS` or epoch history) has no rows to be short of:
it is listed in `not_kept` (`schedd`, `table`, `reason`) instead, and
still counts as fresh. Only those two tables are optional; an access
point the hub reports has no `jobs`, `history` or `syncstatus` table is
degraded.

**Actions need a complete id.** A mutation, a sandbox read, a share URL or
an SSH connection naming only `123.0` is a **400** with
`"reason": "incomplete_job_id"` and your jobs with that number as
`candidates` -- it is never resolved for you, because the hub may know
your finished `123.0` on ap1 and not yet the `123.0` you just submitted on
ap3, and a wrong guess on remove cannot be undone. An access point the id
names but this server cannot act on is its own error, never "job not
found": `unknown_access_point` (404, not in the set),
`access_point_absent` (503, not in the collector right now) or
`access_point_untrusted` (503, "this access point does not trust this API
server's tokens"). Action responses carry the complete `job_id`.

**Bulk actions** run on every access point with bounded concurrency and a
per-access-point timeout, and report each:

```json
{"message": "Bulk job hold completed on every access point",
 "constraint": "JobStatus == 1",
 "results": {"total": 4, "success": 4, "not_found": 0, "permission_denied": 0,
             "bad_status": 0, "already_done": 0, "error": 0},
 "jobs_edited": 0,
 "complete": true,
 "aps": [
   {"schedd": "ap1.example.org", "status": "acted", "results": {"total": 2, "success": 2, ...}},
   {"schedd": "ap2.example.org", "status": "skipped",
    "reason": "the federation hub's copy of this access point is 3s behind (within 30s) and holds no matching job"},
   {"schedd": "ap3.example.org", "status": "failed", "error": "..."}]}
```

`status` is `acted`, `no_match`, `skipped`, `failed`, `unreachable` (not in
the collector; not contacted) or `untrusted` (not contacted). By default
every usable access point is contacted. Setting
`HTTP_API_BULK_FRESH_SECONDS` above 0 lets the hub narrow the fan-out: an
access point is then skipped only when it is provably empty -- the hub
reports it fresh with a measured lag within that many seconds, its jobs
stream connected and error-free, and it holds no row that could match your
scoped constraint there (a row the hub cannot evaluate, such as one
missing `Owner` or using a function the hub lacks, counts as a possible
match) -- and this server has not changed anything on it within the
tolerance plus a minute. That last record is per process: it is lost on a
restart and not shared between replicas, so a skip can miss a change
another replica made moments ago. A stale, absent or unmeasured source,
or a hub that does not answer within 5 seconds, is never proof. The
fan-out runs to the end even if the client disconnects (bounded at five
minutes) and is logged per access point. The answer is 200; 404 when
every access point was accounted for and nothing matched; 502 when no
access point could be acted on; 503 when no access point is known yet.
`complete: false` means some access point was not covered -- see `aps`.
The constraint is confined to your jobs per access point exactly as in
single-AP mode, and one that does not parse is a 400 before anything is
contacted.

**Administrators** are scoped per access point: this server's own grant
(admin group, `mcp:admin`, `mcp:superuser`, `MCP_ADMIN_USERS`) is
necessary, and the caller must also be in that access point's
`QUEUE_SUPER_USERS`, read from it. A queue superuser on ap1 reads and acts
on other users' jobs there and nowhere else. Hub reads have no admin view.
Project leads see their own jobs only.

**Trust.** Every member is probed when it joins, when its address changes
and every ten minutes (an untrusted one every minute): a token minted from
the signing key for `htcondor-api-trust-probe@UID_DOMAIN` must be accepted
and reported back as exactly that identity, and the member must report a
`UID_DOMAIN` equal to this server's. A member that refuses the token,
reports another identity, or will not or cannot report a matching
`UID_DOMAIN` is `untrusted` in `/api/v1/aps` and in every `sources` block;
actions on it fail fast, and bulk actions report it. A member that does
not answer at all stays `unknown`. Only trusted members identify callers
(a bearer token's identity is asked of them); a request routed to an
access point is identified by that access point alone.

**Each access point's own verdict.** A refresh revokes a grant only when
every trusted member's user record (`condor_qusers -disable`) says so. A
user disabled on one access point is still refused there: requests routed
to it -- actions, sandbox reads, SSH, share URLs, bulk legs -- answer 403
`"reason": "access_point_denied"`, while the other access points serve
them. Verdicts are reused for a minute.

**Identity in queries.** Routed reads and actions are confined on the
`User` attribute (`owner@UID_DOMAIN`), not the bare `Owner`, and an
identity in another domain is refused.

**Per-access-point state.** Rate limits (`SCHEDD_QUERY_RATE_LIMIT`,
`SCHEDD_QUERY_PER_USER_RATE_LIMIT`) apply per access point, so one busy
access point does not spend the others' budget. Share URLs carry the
access point inside their signature; a multi-AP server refuses one without
it. Job transports, DAG structures and per-job watches are kept per access
point.

**SSH gateway.** Connect to a job as its complete id:
`ssh 123.0@ap1.example.org@gateway.example.org` (OpenSSH splits the user
from the host at the last `@`). A bare `123.0` is refused with your
candidates. A session name (`ssh +work@gateway`, or a bare `ssh gateway`
for the default session) reaches that session on whichever access point it
is on, or starts it on your assigned one; see below.

**Proc-less ids.** `123@ap1.example.org` names a whole cluster for an input
upload (`PUT .../input`, `POST .../input/multipart`, `.../input/share`), as
`123` does with one schedd, and is a 400 everywhere else.

### Interactive work in multi-AP mode

Browser terminals, named interactive sessions (MCP and the SSH gateway),
JupyterLab and apps are placed like a submission: on the access point your
[assignment](#ap-assignment) names for that kind of work -- `interactive`
for terminals, sessions and apps, `jupyter` for JupyterLab -- or, with
`?schedd=` (the `schedd` argument of `interactive_session_start`), on one
of its alternates. From then on each is reached on the access point its
own record names, and the assignment is never asked again for it: a user
whose assignment moves keeps what they have where it is, and only new work
goes to the new access point.

- **Terminals** are named by their complete job id, which the `/ssh`
  bridge, its heartbeat and its disconnect cleanup route by.
- **Sessions** are named by the caller, and a name is unique per user
  across every access point, so `ssh +work@gateway` and
  `interactive_session_exec` always mean one job. Starting a session asks
  every access point that may hold one of your sessions -- those the
  federation hub lists, those this server has reached since it started,
  and the assigned one -- and refuses a name already in use anywhere;
  the per-user session limit counts every access point. A name found on
  two access points (two servers racing, say) is refused with both job
  ids rather than resolved: remove the one you do not want by its id.
  Exec, stop, the heartbeat and lease expiry go to the session's access
  point; if it cannot be reached the call fails naming it. Sessions this
  server did not start or has not reached since its last restart are
  found through the hub, so starting one, or finding one this server
  does not already know, needs the hub to answer. Each access point has
  15 seconds to answer a listing; one that does not is treated as
  unreachable. `interactive_session_list` reports each session's access
  point; one whose access point cannot be asked is reported from the hub,
  and from this server's own record of it, with `access_point_error`.
- **The SSH gateway** resolves a session name the same way, and starts a
  missing one on your assigned access point. It knows you only by your
  account, so an assignment rule on a group does not apply to a session it
  starts. Approving an SSH login with a workspace starts it the same way,
  with the groups your browser session recorded, and the approval screen
  names the access point.
- **JupyterLab** records the access point in the session's row
  (`jupyter_sessions.schedd`), and every status read -- including after a
  restart adopts the session -- goes there. A row written by a single-AP
  server has none; in multi-AP mode its job is not looked for on any
  access point (its cluster id names no access point), so it is listed
  without job status or job id until it expires, and is not reaped
  meanwhile. The reverse holds after switching back to one schedd: a row
  a multi-AP server wrote for another access point is not looked for on
  this one.
- **Apps** have ids of the form `<id>@<schedd>` in this mode, so `GET` and
  `DELETE /api/v1/apps/{id}` go straight to the app's access point. A bare
  id is located through the hub, and one found on two access points is a
  409.

Lists (`GET /api/v1/interactive/terminal`, `GET /api/v1/apps`) come from
the hub, with a `sources` block, like every other multi-AP read.
`GET /api/v1/aps?kind=interactive` (or `jupyter`) reports where that kind
of work would go; the web UI's interactive page uses it to name the access
point and offer the alternates.

### AP assignment

Which access point a user's **new** work goes to is decided by an ordered
chain of backends, `HTTP_API_AP_ASSIGNMENT`. The first backend to answer
wins; an unknown backend name refuses to start the server.

```
HTTP_API_AP_ASSIGNMENT          = mapfile, rest
HTTP_API_AP_ASSIGNMENT_DEFAULT  = ap01.example.org
HTTP_API_AP_ASSIGNMENT_MAPFILE  = /etc/condor/ap-assignment.map
```

An answer names a home access point and, optionally, alternates. A
submission goes to the home access point; `?schedd=` on `POST
/api/v1/jobs` (or the `schedd` argument of `submit_job`, `submit_dag` and
`build_container`), and on the interactive surfaces above, may name the
home access point or an alternate, and anything else is **403**
`"reason": "target_not_allowed"`. Existing jobs
stay where they are: assignment happens once per submission, the answer
carries complete job ids, and every later step -- the input upload of a
two-step submit (`PUT .../input`, `upload_job_input`,
`create_input_upload_url`) above all -- addresses the job by that id. A
change to the assignment between the steps does not move the job. DAGMan's
node jobs land on the DAGMan job's access point.

Backends:

- **`static`** (the default) assigns everyone to
  `HTTP_API_AP_ASSIGNMENT_DEFAULT`; with no default nobody can submit. It
  answers for everyone, so it must be last in the chain.
- **`mapfile`** reads `HTTP_API_AP_ASSIGNMENT_MAPFILE`, in HTCondor mapfile
  syntax. Each line is a match, a principal, the home access point and
  optional alternates; the **first** matching line in file order wins:

  ```
  # match    principal                           schedd            alternates
  USER       alice@example.org                   ap12.example.org  ap13.example.org
  GROUP      cms                                 ap20.example.org
  USER       /@physics\.example\.org$/           ap30.example.org
  SUBJECT    /^svc-/                             ap31.example.org
  GROUP      "High Energy Physics"               ap32.example.org
  *          /.*/                                ap01.example.org
  ```

  `USER` matches the HTCondor identity (`alice@UID_DOMAIN`), with the
  domain compared without regard to case as HTCondor compares domains and
  the user part exactly; `GROUP` any of the caller's groups as the login
  recorded them (the web session's groups, or an OAuth2 grant's; a caller
  presenting an HTCondor token has none); `SUBJECT` the subject this
  server knows the caller by -- the web session's username or the OAuth2
  grant's subject, which is the name *after* identity mapping, not the
  upstream IdP's `sub`; `*` any of the three.

  A principal is a literal, compared exactly; a double-quoted literal
  (which may contain spaces, `\"` and `\\`); or a regular expression in
  slashes, optionally followed by `i` (ignore case) and `U` (ungreedy) as
  HTCondor accepts. This is HTCondor's *hash* mapfile convention
  (`CLASSAD_USER_MAPFILE_*`): unlike a classic `CERTIFICATE_MAPFILE`,
  where every principal is a regular expression, a principal here is an
  expression only between slashes. A literal containing `^`, `$` or `*` is
  logged as a probable mistake. Inside slashes `\/` is a slash and `\\`
  one backslash, exactly as HTCondor reads it. An expression is searched
  for, not anchored: write `^` and `$`. Go's RE2 syntax applies: PCRE2's
  minus backreferences and lookaround, and with `i` RE2 folds case by
  Unicode simple folding where PCRE2 without UTF mode folds ASCII only, so
  a non-ASCII principal may match where HTCondor's would not. A line or
  the rest of a line starting with `#` is a comment. `@include` is
  refused.

  The file is checked for changes every two seconds in the background,
  never while answering a request, and re-read on reconfigure. A file that
  does not parse refuses to start the server; an edit that does not parse
  keeps the last map that did and is logged.
- **`rest`** asks a site service:

  ```
  GET {HTTP_API_AP_ASSIGNMENT_REST_URL}/v1/assignment?user=alice%40example.org&subject=...&kind=job&group=cms&group=...
  Authorization: Bearer <contents of HTTP_API_AP_ASSIGNMENT_REST_TOKEN_FILE>

  200 {"schedd":"ap12.example.org","alternates":["ap13.example.org"],"ttl_seconds":300}
  404 {"result":"no_assignment"}  -> no answer: ask the next backend
  403 {"result":"denied"}         -> this user may not submit
  ```

  `kind` is `job`, `dag`, `container_build`, `interactive` (browser
  terminals, named sessions and apps) or `jupyter`. A 404 or 403 counts only
  with that body: a 404 page from a proxy or a mistyped path, or a 403 for
  some other reason, is an error -- otherwise it would send everyone to the
  default, or deny everyone. **Answer a bad or missing bearer token with
  401**, which is an error. Any other status, a body that is not the
  expected JSON or is over 64 KiB, a redirect (never followed), or no
  answer within 2 seconds is an error. The URL must be `https`, except to
  a literal loopback address (`127.0.0.1`, `[::1]`; not `localhost`).
  The token file is re-read when it changes; one that cannot be read keeps
  the token already read. Errors are logged without the query, which names
  the user.

Behavior common to every backend:

- **Errors do not fall through.** A failing backend never sends anyone to
  the next backend or the default. The user's last known good answer is
  used for up to `HTTP_API_AP_ASSIGNMENT_STALE_SECONDS` (default 3600)
  after it *expired* (its TTL ran out), so an answer with a long TTL is
  covered for the whole window too; after that, or with none, the answer
  is **503** `"reason": "assignment_unavailable"`. A reconfigure makes
  every answer stale but keeps it as last known good. Each backend has a
  hard 2-second timeout. A request whose caller disconnected is not
  counted as a backend failure.
- **The default** (`HTTP_API_AP_ASSIGNMENT_DEFAULT`) is used only when
  every backend has no answer. Without one, that user gets **403** "no
  access point is assigned to you" (`no_access_point_assigned`).
- **Answers are validated.** A home access point outside the AP set is a
  **503** (`assignment_invalid`) and an error in the log; an alternate
  outside the set is dropped and logged. Work is never submitted outside
  the set. A target that is in the set but not in the collector right now,
  or untrusted, is a **503** (`target_unavailable`); an alternate still
  takes work while the home access point is down.
- **Answers are cached** per user, kind, subject and groups for the
  answer's TTL (mapfile 60 s, rest 300 s unless `ttl_seconds` says
  otherwise; at most an hour), up to 10000 entries. An edited mapfile takes
  effect within its two-second check.
- **The access point's own verdict** applies as for actions: a user
  disabled on the target access point is refused there (403
  `access_point_denied`), and the job is owned by the identity that access
  point reports for your credential.

`GET /api/v1/aps` reports your `assignment` and marks each access point
with `submit` (home or alternate) and `home`; `GET /api/v1/auth/me` and
`GET /api/v1/whoami` carry the same `assignment`, and MCP `whoami` reports
`home_access_point` and `alternate_access_points`. The web UI's submit page
says which access point a batch will go to and offers the alternates.

**Credentials follow the access point.** Each access point's schedd names
its credd (`CredDIpAddr`), and a credential is only useful there. The
pre-submit credential check (`HTTP_API_REQUIRED_CREDENTIALS` and the
credd's own check) runs against the target access point's credd, and what
it finds is cached per credd. Moving a user's home access point does not
move stored credentials; the first submission to the new one asks for
them. `HTTP_API_CREDD_ADDRESS` names one credd for one schedd and refuses
to start a multi-AP server.

**Job ids.** A job is identified by schedd, cluster and proc together: two
access points each have a `123.0`. Every job in a response carries
`schedd`, `cluster` and `proc` as separate members, plus `job_id`, the
single-token form used in URLs (`123.0@ap40.example.org`; the text before
the first `@` is `cluster.proc`, the rest is the schedd name). An
incomplete id such as `123.0` is accepted by `GET /api/v1/jobs/{id}` and
`get_job` when exactly one of your jobs, queued or completed, has it; the
answer carries the complete id. Several matches are a **409** whose body
lists them:

```json
{"error": "Conflict", "code": 409,
 "message": "job 123.0 exists on 2 access points; name one",
 "candidates": [
   {"schedd": "ap1.example.org", "cluster": 123, "proc": 0, "job_id": "123.0@ap1.example.org", "archived": false},
   {"schedd": "ap2.example.org", "cluster": 123, "proc": 0, "job_id": "123.0@ap2.example.org", "archived": true}]}
```

**Freshness.** Every list response carries a `sources` block naming each
access point whose rows are not known to be current:

```json
"sources": {"aps": 52, "fresh": 50, "degraded": [
  {"schedd": "ap17.example.org", "state": "stale", "staleness_seconds": 412},
  {"schedd": "ap31.example.org", "state": "absent", "reason": "the federation hub does not hold this access point"}]}
```

`state` is the hub's (`stale`, `absent`, `untrusted`, `retiring`), or
`absent` for an access point the hub does not list. By default a degraded
access point's rows are included as the hub holds them;
`HTTP_API_MULTI_AP_STALE = exclude` leaves them out, and the access point is
still listed in `degraded`. Nothing is omitted silently. A single job on an
access point the hub does not hold fresh is read from that access point's
own htcondordb if it is current, else from its schedd as you; the response
says which (`source`: `hub`, `spoke` or `schedd`).

**Scope.** Every hub read is confined to your own jobs on the `User`
attribute (`owner@UID_DOMAIN`), whatever constraint you pass. An identity in a domain other than `UID_DOMAIN`
(compared case-insensitively, as HTCondor does) is refused with a 403
rather than read as the same name in `UID_DOMAIN`. The access points must share one `UID_DOMAIN`,
`TRUST_DOMAIN` and pool signing key: a bearer token's identity is
confirmed by asking an access point's schedd, and any one of them can
answer.

**The access point set** is polled from the collector every 60 seconds. An
access point whose ad disappears stays listed (`in_collector: false`)
with its last address; nothing is removed because the collector stopped
mentioning it.

**Health.** `/readyz` is ready when the hub answers and at least one
access point matches, and lists every access point's state to an admin
session or a `metrics` API key (anyone else gets the count); one access
point being down never makes the server unready. The collector ad carries
`ScheddConstraint` and `ScheddCount` instead of `ScheddName`.

The web UI shows an access point column and filter on the job and
archive lists, which access points are behind, and an Access Points page;
it offers no actions yet.

`HTTP_API_SCHEDD_CONSTRAINT` together with `-schedd`, `-schedd-addr` or
`SCHEDD_NAME` is a startup error. `UID_DOMAIN` and a collector are
required.

### Placement onboarding

When a `condor_placementd` is reachable, this server also does what CHTC's
placement-webapp did for users: someone signs in, picks a project and the
permissions they want, and gets a placement token for their AP account,
either in the browser at `/placement` (shown once, downloaded as
`Placement.token`; nothing is written to disk) or through the device flow
`placement-client` speaks, confirmed at `/placement/device`.

**The identity.** At sign-in the server takes the first non-empty claim
named by `HTTP_API_PLACEMENT_IDENTITY_CLAIMS` (default `sub`) from the
provider's userinfo, replaces each run of characters other than letters,
digits, `_`, `@`, `.` and `-` with `_`, and keeps at most 64 characters.
That is placement-webapp's `USERNAME_FIELDS` rule exactly, so existing map
file lines keep matching. Set the same claim list placement-webapp used,
for example `HTTP_API_PLACEMENT_IDENTITY_CLAIMS = eppn, sub`.

**People with no local account.** With [local identity
mapping](#local-identity-mapping) on, a sign-in that maps to no account is
normally refused. While a placementd is reachable it instead gets a
*placement-only* session: no username, and it reaches only `/placement`,
`/placement/device`, `GET /api/v1/auth/me`, `/api/v1/placement/me*`, the
device-flow paths and sign-out. Every other route answers 403 (or sends a
page load to `/placement`). `HTTP_API_WEBUI_ACCESS_GROUP` is not applied
to these sessions; whether they get a token is the placementd map file's
decision.

**What the token can be.** The server calls the placementd as itself, so
the user-facing endpoints never take an identity from the request: the
identity is always the session's, the requester is always the same
identity, and tokens for someone else (INSTRUCTOR) are not offered. A
request may name only the authorizations the placementd offers that
identity, and a project from its map file line. `WEBADMIN` is not
honored; the admin pages follow `HTTP_API_WEBUI_ADMIN_GROUP`.

**The device flow.** `POST /auth/device_authorization` without a
`grant_type` starts a request for a `client_id` listed in
`HTTP_API_PLACEMENT_DEVICE_CLIENTS`; with
`grant_type=urn:ietf:params:oauth:grant-type:device_code` it polls. The
responses are placement-webapp's byte for byte, including the success body
`{"access_token": "<token>\n", "expires_in": "<seconds>", "token_type":
"Placement"}`. A pending request lasts 30 minutes and is polled every 5
seconds. The approved token is kept, sealed with `HTTP_API_KEK_FILE` when
one is configured, until the client collects it once; it is then deleted,
and expired requests are swept.

**The standard device flow (placement-client).** New clients use this
server's own RFC 8628 device grant instead of the paths above. They read
`/.well-known/oauth-authorization-server` (so this server's OAuth2
authorization server must be on, which it is when the web UI or MCP is
enabled), ask the device authorization endpoint as the pre-registered
public client `placement_client` for the scope `placement` (and
`offline_access` to keep a refresh token), and send the person to the
verification page, where any signed-in session with an identity --
placement-only included -- approves it. The access token then calls `GET
/api/v1/placement/me` and `POST /api/v1/placement/me/token` with
`Authorization: Bearer`, and nothing else: every other route refuses it.
The identity it acts for is the one that approved it, recorded on the
grant. `placement` cannot be combined with any other scope, and is granted
through the device flow only. Each refresh re-reads the identity from the
placementd and ends the grant when the identity is gone or expired, or the
account's schedd user record is disabled. The legacy paths above keep
working for older clients.

### placementd as an identity mapping

With `placementd` in `HTTP_API_IDENTITY_MAP` (alone, or in the list, e.g.
`placementd,gecos`), a sign-in identity the placementd has authorized,
unexpired, with an account that holds `READ` or `WRITE`, signs in **as that
account**: the session's user is the account exactly as the placementd
names it, whose domain need not be `UID_DOMAIN`. `placementd` listed before
every other method is tried first; listed after them, it is tried when
they fail. An identity no method maps gets a placement-only session.

A person onboarded while signed in with a placement-only session gets full
access without signing in again: `GET /api/v1/auth/me` re-runs the
sign-in's mapping for the session, at most every 30 seconds, and once it
maps, replaces the session with a full one under a new session id.

Every token this server mints for such a session -- or for an OAuth2 grant
it authorizes -- names the account as its subject, carries `condor:/READ`
and `condor:/WRITE` only as far as the account holds them (other grants,
such as `INSTRUCTOR`, are not authorization levels and are left out), and
carries the session's selected project as the `project` claim, as the
placementd's own tokens do. A project switcher appears when the account has
more than one. The session never outlives the mapping's expiry. The account
is re-read at most every five minutes, on the next token: an identity
removed, expired or pointed at another account ends the session; changed
grants and projects are taken up. OAuth2 grants of the account are
re-checked the same way on refresh.

Some features need a local Unix account and are refused for these
sessions: credential storage in the credd (`/api/v1/creds/*`), the SSH
gateway and SSH certificates, superuser mode, token exchange of their
grants, and share links for accounts outside `UID_DOMAIN`. Owner-scoped
reads match the job's `Owner`, the part of the account before `@`, as for
every other caller.

| Knob | Purpose |
| --- | --- |
| `HTTP_API_PLACEMENT_IDENTITY_CLAIMS` | Userinfo claims, in order, the placement identity is taken from. Default `sub`. Read at startup. |
| `HTTP_API_PLACEMENT_DISPLAY_NAME_CLAIMS` | Claims, in order, the person is greeted by. Default `name`. Read at startup. |
| `HTTP_API_PLACEMENT_DEVICE_CLIENTS` | Comma-separated `client_id`s the device flow accepts. Default `placement_client,curl,`. Set empty to accept none. Read at startup. |
| `HTTP_API_PLACEMENT_SCHEDD_HOST` | `SCHEDD_HOST` shown with a token for `~/.condor/user_config`. Default: this server's schedd name. Read at startup. |
| `HTTP_API_PLACEMENT_COLLECTOR_HOST` | `COLLECTOR_HOST` shown with a token. Default: `COLLECTOR_HOST`. Read at startup. |

## Configuration

Settings live in HTCondor config (`condor_config_val`-readable) and
are prefixed `HTTP_API_*`.

Job-queue routing to an [htcondordb](#further-reading) mirror needs no
configuration in the common case, **including when this server runs on a
different host or pod from the mirror and the schedd**: discovery goes
through the pool's collector, which spans hosts. The local address file is
only a fallback for a co-located mirror whose ad is not getting through.
With neither a collector nor `HTTP_API_DBMIRROR_ADDRESS`, routing is simply
off rather than failing — an address file that resolves on every host would
otherwise switch it on for deployments that never asked.

Frequently-used knobs:

| Knob | Purpose |
| --- | --- |
| `HTTP_API_LISTEN` | Listen address; default `:8080`. |
| `HTTP_API_BASE_URL` | Externally-visible URL for OAuth2 redirects + share links. |
| `HTTP_API_DB_PATH` | Unified SQLite DB (sessions, OAuth2, IDP, templates, API keys). Default `$(LOCAL_DIR)/htcondor-api.db`. |
| `HTTP_API_SIGNING_KEY` | Pool signing key for minting per-request tokens. Defaults to `SEC_TOKEN_POOL_SIGNING_KEY_FILE`. |
| `HTTP_API_KEK_FILE` | Path to the master Key Encryption Key (32 raw bytes or 64-char hex; mode 0600/0400). Generate with `openssl rand -hex 32 > <path> && chmod 0600 <path>`. |
| `HTTP_API_WEBUI_ACCESS_GROUP` | Comma-separated group(s) permitted to log in to the web interface. Unset falls back to `HTTP_API_MCP_ACCESS_GROUP`. Reloaded on SIGHUP. See [Authorization groups](#authorization-groups). |
| `HTTP_API_WEBUI_ADMIN_GROUP` | Comma-separated group(s) whose members can reach the admin pages. Unset disables the admin UI. Reloaded on SIGHUP. |
| `HTTP_API_PROJECT_LEADS_FILE` | File naming each project's leads, who may use superuser mode on jobs whose `ProjectName` they lead. Re-read when it changes and on SIGHUP. See [Project leads](#project-leads). |
| `HTTP_API_PROJECT_LEADS_GROUP` | Group-name pattern containing `{project}`, e.g. `{project}-leads`; members of the group it names for a project lead that project. Reloaded on SIGHUP. See [Project leads](#project-leads). |
| `HTTP_API_METRICS_PUBLIC` | `true` to disable the API-key gate on `/metrics`. Default off — Prometheus must present an API key with the `metrics` scope. |
| `HTTP_API_TOOL_STATS_FLUSH_INTERVAL` | How often MCP tool-call counters are written to the application database (e.g. `5m`). Default `5m`; they are also written at shutdown. See [MCP tool-call statistics](#mcp-tool-call-statistics). |
| `HTTP_API_TOOL_STATS_MAX_LABEL_VALUES` | Cap on distinct values per `/metrics` label for tool statistics. Default `1000`; past it the quietest values render as `other`, while the database keeps them all. |
| `HTTP_API_UTILIZATION_MAX_JOBS` | Most finished jobs one Utilization analysis (`GET /api/v1/utilization`) may read; a larger `limit` is clamped to it. Default `1000000`. An analysis holds about 250 bytes per job while it runs, so the default is about a quarter of a gigabyte at peak; the cached result is the answer, not the jobs. Read at startup. |
| `HTTP_API_RUNTIME_ESTIMATE_INTERVAL` | How often [runtime estimates](#runtime-estimates) read newly completed jobs from the htcondordb mirror (a duration, e.g. `5m`). Default `5m`; `0` turns runtime estimates off entirely. Without a mirror they are off whatever this says. Read at startup. |
| `HTTP_API_RUNTIME_ESTIMATE_BACKFILL` | How much job history runtime estimates read at startup, and how long a group of similar jobs is remembered without a new completion. Default `168h`. At most 500,000 of the newest records are read; the log says when that cap is hit. Read at startup. |
| `HTTP_API_TOOL_STATS_MAX_SERIES` | Cap on distinct tool-call combinations held in memory and in the database. Default `10000`; past it new combinations fold into `other`. This is what bounds memory and disk. |
| `HTTP_API_TOOL_STATS_OMIT_USER` | `true` renders every `/metrics` user label as `omitted`, for a site that does not want account names on a scrapeable endpoint. The database still records them. See [Usernames on /metrics](#usernames-on-metrics). |
| `HTTP_API_ENABLE_MCP` | Enable the MCP endpoint (`/mcp`), the `/mcp/oauth2/*` spelling of the OAuth2 endpoints, and the `mcp:read`/`mcp:write` scopes in OAuth2 metadata. Required by the chat assistant. OAuth2 itself is served whenever the web UI **or** MCP is enabled, so a web UI with this off still logs people in and serves the device flow. |
| `HTTP_API_MCP_TOKEN_EXCHANGE_ISSUERS` | JSON array of trusted external issuers for RFC 8693 token exchange (see [Token exchange](#token-exchange-rfc-8693)). Unset disables external exchange. |
| `HTTP_API_MCP_CIMD` | Resolve an `https://` MCP `client_id` as a Client ID Metadata Document (a public client). Default `true`; set `false` to require DCR. See [MCP OAuth2 clients](#mcp-oauth2-clients). |
| `HTTP_API_MCP_CIMD_ALLOWED_HOSTS` | Comma/space list of host or `.domain` patterns a CIMD `client_id` may point at. Empty = any host (SSRF guards still apply). Recommended for production: without it, unauthenticated callers choose which public hosts this server fetches from. |
| `HTTP_API_MCP_DCR` | Accept dynamic client registration (RFC 7591) at `/oauth2/register` (and `/mcp/oauth2/register` where MCP is on). Default `true`; set `false` when every client is seeded, operator-provisioned or CIMD. Registrations are then refused with 403 and the endpoint is not advertised. See [MCP OAuth2 clients](#mcp-oauth2-clients). |
| `HTTP_API_MCP_WATCH_MAX_WAIT` | Cap on how long the MCP `check_watches`/`watch_jobs` tools may block in-call before returning (a duration, e.g. `15s`). This number is advertised to the agent in the tool schema, so it has to be one the whole path can deliver, not just this server. Unset = `45s`, or the value derived from `HTTP_API_MCP_MAX_REQUEST_DURATION` where that is tighter. 45s is not a server limit — the server will hold a request for 14m30s by default — it is what an MCP client is observed to wait for before abandoning the call, which returns *nothing at all* to the agent rather than a timeout it could act on. **Set this lower when a gateway or proxy with a tighter timeout sits in front of this server**; set it higher only when you know the clients reaching this deployment are configured for a longer tool timeout. |
| `HTTP_API_OAUTH2_REDIRECT_URL` | The redirect URI registered with the identity provider. Unset = derived from the issuer plus this server's callback path, which is `/mcp/oauth2/callback` on a server whose only surface is MCP and `/oauth2/callback` everywhere else. Both paths are served wherever MCP is on, so an authorization started before an upgrade still lands; but the URI the server *sends* must be registered at the IdP, so a build that gains the web UI needs `/oauth2/callback` added there (or this knob set to keep the old one). |
| `HTTP_API_CREDD_ADDRESS` | Single-AP mode only (refused in multi-AP mode, where each access point's schedd names its own). Pins the credd this server talks to (a sinful, e.g. `<10.0.0.5:9618?sock=credd>`), overriding discovery. Normally unnecessary: the credd is read from the schedd itself, which publishes its own credd as `CredDIpAddr` in its ad and address file — the same binding `DCSchedd::getCreddAddress` uses. Set this when fronting a remote schedd that does not advertise it, since a credd that is not the submitting schedd's accepts credentials and leaves jobs held anyway. |
| `HTTP_API_REQUIRED_CREDENTIALS` | OAuth service credentials that must exist before a job may be submitted (comma- or space-separated, e.g. `scitokens`). Some access points hold every job submitted without them, whatever the job actually uses. Each submit path checks the caller's credentials first and stores a placeholder for any that is missing, so a person using the web UI does not get a held job for a reason unrelated to what they asked for; a real credential obtained later through the OAuth flow replaces the placeholder. Presence is cached per user for 5 minutes. Best effort: if the credd is unavailable or refuses, the submit still proceeds and the reason is logged. Unset = nothing is required. |
| `HTTP_API_MCP_MAX_REQUEST_DURATION` | Hard stop on an MCP request that is still making progress (a duration, e.g. `5m`). Unset = 15m. While an MCP request runs its write deadline is moved forward, so `HTTP_API_WRITE_TIMEOUT` — which is an absolute deadline meant for ordinary replies — does not decide how long a deliberately waiting tool may wait. A request that stops making progress is still cut off on its last window; this is the backstop for one that never finishes at all. |
| `HTTP_API_ADVERTISE` | Advertise this API server to the collector (a `HTCondorAPI` ad: endpoint, schedd, mirror health, versions). Default `true`; `daemon.Advertise` is a no-op without `COLLECTOR_HOST`, so this only matters to opt out when a collector is configured. |
| `HTTP_API_DBMIRROR_NAME` | Pin job-queue routing to the htcondordb mirror advertising this `Name`. Set it when more than one mirror advertises to the pool: nothing in the ad says which schedd each one mirrors, so without a pin the freshest is chosen, which is a guess. |
| `HTTP_API_DBMIRROR_ADDRESS` | Dial this sinful string instead of the mirror's advertised `MyAddress`, for one reachable only over NAT, a tunnel, or a Kubernetes Service. Freshness still comes from the collector ad — this changes where to connect, not whether the mirror is current enough to trust — and it applies whether the mirror was found through the collector or not. |
| `HTTP_API_DBMIRROR_REQUIRED` | Never fall back to the schedd. A read the mirror cannot serve fails instead of becoming load on the access point you were trying to protect. See [the routing notes](../webapi/httpserver/README.md#configuration) for which failures are 503 and which are 400. |
| `HTTP_API_SCHEDD_CONSTRAINT` | ScheddAd constraint selecting the access points of [multi-AP mode](#multi-ap-mode). Unset = one schedd. Read at startup. |
| `HTTP_API_HUB_NAME` / `HTTP_API_HUB_ADDRESS` | Pin the federation hub by `Name`, or dial this sinful string, instead of discovering the `HTCondorDB` ad that carries `FederationConstraint`. Multi-AP mode only. |
| `HTTP_API_MULTI_AP_STALE` | `include` (default) or `exclude` a degraded access point's rows in list reads. Either way it is named in `sources.degraded`. |
| `HTTP_API_JOB_ID_CODEC` | Text form of a job id in URLs and SSH gateway usernames. Default and only built-in: `at` (`123.0@ap40.example.org`). |
| `HTTP_API_BULK_FRESH_SECONDS` | Opt in to letting a multi-AP bulk action skip an access point on the hub's word that nothing there matches, when the hub's copy is at most this many seconds behind. Default 0: every access point is contacted. |
| `HTTP_API_AP_ASSIGNMENT` | Multi-AP mode: ordered chain of [AP assignment](#ap-assignment) backends, `static`, `mapfile` and `rest`, separated by commas or spaces. Default `static`. An unknown name refuses to start. Read at startup. |
| `HTTP_API_AP_ASSIGNMENT_DEFAULT` | Access point for a user no backend has an answer for, and the one `static` assigns. Unset = such a user cannot submit (403). |
| `HTTP_API_AP_ASSIGNMENT_MAPFILE` | The `mapfile` backend's file. Re-read when it changes and on reconfigure; one that does not parse at startup refuses to start, and a bad edit keeps the last good map. |
| `HTTP_API_AP_ASSIGNMENT_REST_URL` | Base URL of the site's assignment service, for the `rest` backend; `/v1/assignment` is appended. `https` unless loopback. |
| `HTTP_API_AP_ASSIGNMENT_REST_TOKEN_FILE` | File whose contents are sent as `Authorization: Bearer` to the assignment service. Re-read when it changes. Unset = no header. |
| `HTTP_API_AP_ASSIGNMENT_STALE_SECONDS` | How long a user's last known good assignment is used while a backend is failing. Default 3600; `0` never uses one. |
| `HTTP_API_DBMIRROR_TOKEN_SUBJECT` | Identity the token this server presents to the mirror asserts. Default `condor@<trust domain>`. Set it when the mirror authorizes a different name. |
| `HTTP_API_IDENTITY_MAP` | Map the token subject to a local account (`gecos,username`). See [Local identity mapping](#local-identity-mapping). |
| `HTTP_API_IDENTITY_MAP_PASSWD_FILE` | Account file backing the mapping index. Default `/etc/passwd`. |
| `HTTP_API_IDENTITY_MAP_TTL` | How long the account index and group answers are reused. Default `5m`. |
| `HTTP_API_GROUP_SOURCE` | Comma-separated: `token` (default), `system`, and/or `file:<path>`. Local sources are unioned; `token` may not be mixed with them. See [Local identity mapping](#local-identity-mapping). |
| `HTTP_API_OAUTH2_USERNAME_CLAIM` | Claim carrying the username, e.g. `eppn`. Default `sub`. |
| `HTTP_API_OAUTH2_REQUIREMENTS` | ClassAd expression over the token's claims; the login proceeds only if it is true. See [Local identity mapping](#local-identity-mapping). |
| `HTTP_API_IDENTITY_MAP_STRIP_DOMAIN` | `true` to also match the local part of a scoped subject. Pair with `HTTP_API_OAUTH2_REQUIREMENTS`. |
| `HTTP_API_DAGMAN_PATH` | Absolute path to `condor_dagman` on the **access point**, for the `submit_dag` tool. **Normally unnecessary — discovered from the schedd's `BIN`; set it only if that discovery is refused.** The server asks the schedd for `BIN` once (a READ-level `condor_config_val` query) and uses `$(BIN)/condor_dagman`; this knob overrides that, and `/usr/bin/condor_dagman` is the fallback when neither is available. `condor_submit_dag` normally finds the binary with `which` on the submitting machine, which is no help here: this server submits to a schedd it shares no filesystem with. |
| `HTTP_API_DAGMAN_ENVIRONMENT` | Extra environment for the DAGMan manager job, as whitespace-separated `KEY=VALUE` pairs. The schedd gives a scheduler-universe job only the environment its ad carries, and `getenv` cannot help because it would capture *this server's* environment rather than the access point's. `PATH` is set for you (PRE/POST scripts need it). Set `CONDOR_CONFIG` here if the access point keeps its configuration somewhere other than the default. A DAG's own `ENV SET` pairs are merged in too, underneath this: what an operator configures here wins, so a workflow cannot redirect `CONDOR_CONFIG` or `BEARER_TOKEN_FILE` by writing one line of DAG. `ENV GET` is reported as a warning and not honoured — it copies variables from the submitting process's environment, which here is this server's, not the access point's. |
| `HTTP_API_MCP_SKILLS_DIR` | Directory of site-authored Markdown skills to publish to agents. Re-read periodically and on SIGHUP. See [Site skills](#site-skills). |
| `HTTP_API_MCP_SKILLS_RELOAD_INTERVAL` | How often to re-read `HTTP_API_MCP_SKILLS_DIR` so a checkout updated underneath the daemon is noticed without a reconfigure (a duration, e.g. `1m`). Default `5m`; `0` disables the poll and leaves reloads to `condor_reconfig`. The check is stat-only until something actually changes. Read at startup. |
| `HTTP_API_JUPYTER_MAX_LIFETIME_SEC` | Wall-clock ceiling on a JupyterLab session, from when it starts running. Enforced by the schedd (`periodic_remove`), so it holds whatever the sandbox or the browser are doing. Default 28800 (8h); `0` disables. |
| `HTTP_API_JUPYTER_KERNEL_IDLE_SEC` | How long a JupyterLab kernel may sit without executing before it is culled and the server shuts down. Measured from kernel execution, not HTTP traffic, so a tab polling in the background does not look busy. Default 3600; `0` disables. |
| `HTTP_API_JUPYTER_START_GRACE_SEC` | How long a JupyterLab job may wait to start executing, from when it is submitted. Past it the schedd removes the job (`periodic_remove`, with the remove reason "JupyterLab session did not start within …"), and the token it would have connected with expires 10 minutes later, so a job never starts with a token that is already dead. A job that ran and went back to the queue (evicted, or held and released) is removed too, as "JupyterLab session was interrupted and cannot restart": it would rerun with a token its first run spent. Default 14400 (4h). Cannot be turned off: `0`, negative or unreadable values fall back to the default, and values above 604800 (7 days) are clamped, each with a warning. |
| `HTTP_API_JUPYTER_RECONNECT_GRACE_SEC` | How long a session whose tunnel dropped is kept for its helper to dial back. Meanwhile the session stays listed and its proxy answers 503 with `Retry-After`; past it the session is closed and a late redial is refused, which ends the job. Default 300. Cannot be turned off: `0`, negative or unreadable values fall back to the default, and values above 3600 are clamped, each with a warning. |
| `HTTP_API_VSCODE_IMAGE` | Container image a VS Code session runs. Any transfer scheme works, so a `.sif` staged on OSDF can be named directly. Set, it wins outright and a caller cannot override it; unset, a caller may name an image, which grants nothing new since they can already submit a job with any image. Defaults to a published code-server image. See [VS Code sessions](#vs-code-sessions). |
| `HTTP_API_MCP_DISABLED_TOOLS` | MCP tools this access point does not offer, as glob patterns separated by commas or whitespace. Applied on SIGHUP. See [Disabling tools](#disabling-tools). |
| `HTTP_API_TRUSTED_PROXIES` | Comma-separated CIDRs (or bare addresses) whose `X-Forwarded-For` / `X-Real-IP` are honored when recording a client address. Unset means none are, and the peer address is logged. |
| `HTTP_API_LLM_API_KEY_FILE` | Path to a file with the LLM API key. Enables the chat assistant. The file must not be world-accessible: 0600, 0400, or 0440 (what a Kubernetes secret volume is under `fsGroup`). |
| `HTTP_API_LLM_API_URL` | Override the upstream Anthropic Messages endpoint (proxy / gateway). The full URL of the `/v1/messages` route. |
| `HTTP_API_LLM_MODEL` | Override the default Claude model. With a gateway, the model name as the gateway knows it. |
| `HTTP_API_LLM_AUTH_SCHEME` | How the key is sent: `x-api-key` (default; what api.anthropic.com reads) or `bearer` (`Authorization: Bearer`, what an OpenAI-style gateway fronting the Messages API, such as Envoy AI Gateway or LiteLLM, authenticates). |
| `HTTP_API_LLM_OPERATOR_INSTRUCTIONS_FILE` | Site-policy text appended to every chat system prompt. |
| `PRIVATE_NETWORK_NAME` | This host's private network name. When it equals a daemon's advertised `PrivNet`, that daemon is dialed directly instead of through its CCB broker. Defaults to `$(FULL_HOSTNAME)`, as in C++. See [Reaching jobs behind CCB](#reaching-jobs-behind-ccb). |
| `HTTP_API_SHARED_PORT` | Open an inbound HTCondor port (a port or `host:port`, e.g. `9618`) so this server can be reached by execute nodes behind a Condor Connection Broker. Off by default. See [Reaching jobs behind CCB](#reaching-jobs-behind-ccb). |
| `HTTP_API_SHARED_PORT_ADDRESS` | The `host` or `host:port` execute nodes should dial to reach that port, when it differs from what this process binds — behind NAT, a container port map, or a Kubernetes Service. Defaults to `TCP_FORWARDING_HOST`, else `FULL_HOSTNAME`, paired with the listen port. |
| `HTTP_API_CCB_STREAMING` | Allow asking the broker to relay a CCB connection instead of being dialed back. Default: on unless running under `condor_master`. With `HTTP_API_SHARED_PORT` set this is the fallback, not the first choice. |
| `HTTP_API_CCB_LEARNED_TTL` | How long what this server learned about a broker (whether execute nodes can reach it, whether the broker can relay) is reused before being rechecked. Default `15m`. |

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

- [httpserver/README.md](../webapi/httpserver/README.md) — full HTTP API
  reference, demo-mode internals, security model.
- [mcpserver/README.md](../webapi/mcpserver/README.md) — MCP tool catalog
  and integration notes.
- [SECURITY_CONFIG.md](../design_notes/SECURITY_CONFIG.md) — operator-facing
  security configuration guide.
- [docs/library.md](library.md) — embedding the underlying Go
  library in your own service.
