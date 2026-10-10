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
| `HTTP_API_IDENTITY_MAP` | unset (no mapping) | Comma-separated strategy list, e.g. `gecos,username`. `gecos` matches the token subject against accounts' GECOS names; `username` treats the subject as a login name. An unparseable list makes the server refuse to start rather than fall back to an unmapped identity. |
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
further, and take lists on the same terms.

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
user's job in a project they lead, tail its output, ssh to it, and warm its
connection ahead of time (`/warm`). Bulk hold
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

**What a lead cannot do:** open another user's interactive app through the job
proxy (VS Code and other proxied ports). The app is served from this server's
own origin, so code the job's owner controls would run in the lead's browser
with the lead's session. Global superusers keep that access.

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

- **Dynamic Client Registration (DCR, RFC 7591)** — `POST /mcp/oauth2/register`.
  A client registers itself and gets a confidential `client_id` + secret. It
  may declare only the `authorization_code`, `refresh_token` and device-code
  grants and the `code` response type; anything else is refused with
  `invalid_client_metadata`. `client_credentials` and token exchange are
  enabled by an operator in the admin UI, never by self-registration.
- **Client ID Metadata Document (CIMD)** — instead of registering, a client
  identifies itself by an `https://` URL as its `client_id`; the server fetches
  a client-metadata document from that URL and treats it as a **public** client
  (no secret, PKCE required). This is where the MCP spec is heading, away from
  DCR. The fetch is hardened against SSRF (https-only, private/link-local/cloud-
  metadata addresses refused, no redirects, timeout + size cap), and the
  document must be self-consistent (its `client_id` equals the URL). On by
  default; see the knobs below to disable or restrict it.
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

The gateway needs OAuth2 configured (`HTTP_API_ENABLE_MCP`), since the device
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
  result and is what the Kubernetes probes use.
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

  These are admin-only on purpose: the placementd registers its commands
  at ADMINISTRATOR and this server talks to it as the AP's own identity,
  so an endpoint any signed-in user could reach would let them mint a
  bearer token for anyone in the map file. The server finds the daemon
  via `PLACEMENTD_ADDRESS_FILE` (or `$(LOG)/.placementd_address`), then
  the collector; finding none simply disables the group.

**Chat assistant** (when `HTTP_API_LLM_API_KEY_FILE` is set)
- `POST /api/v1/chat` — AI-SDK v6 UI-message stream
- `GET /api/v1/chat/info` — feature probe

**MCP** (when enabled via `HTTP_API_ENABLE_MCP=true`)
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
| `HTTP_API_TOOL_STATS_MAX_SERIES` | Cap on distinct tool-call combinations held in memory and in the database. Default `10000`; past it new combinations fold into `other`. This is what bounds memory and disk. |
| `HTTP_API_TOOL_STATS_OMIT_USER` | `true` renders every `/metrics` user label as `omitted`, for a site that does not want account names on a scrapeable endpoint. The database still records them. See [Usernames on /metrics](#usernames-on-metrics). |
| `HTTP_API_ENABLE_MCP` | Enable the `/mcp/*` endpoints. Required by the chat assistant. |
| `HTTP_API_MCP_TOKEN_EXCHANGE_ISSUERS` | JSON array of trusted external issuers for RFC 8693 token exchange (see [Token exchange](#token-exchange-rfc-8693)). Unset disables external exchange. |
| `HTTP_API_MCP_CIMD` | Resolve an `https://` MCP `client_id` as a Client ID Metadata Document (a public client). Default `true`; set `false` to require DCR. See [MCP OAuth2 clients](#mcp-oauth2-clients). |
| `HTTP_API_MCP_CIMD_ALLOWED_HOSTS` | Optional comma/space list of host or `.domain` patterns a CIMD `client_id` may point at. Empty = any host (SSRF guards still apply). |
| `HTTP_API_MCP_WATCH_MAX_WAIT` | Cap on how long the MCP `check_watches`/`watch_jobs` tools may block in-call before returning (a duration, e.g. `15s`). This number is advertised to the agent in the tool schema, so it has to be one the whole path can deliver, not just this server. Unset = `45s`, or the value derived from `HTTP_API_MCP_MAX_REQUEST_DURATION` where that is tighter. 45s is not a server limit — the server will hold a request for 14m30s by default — it is what an MCP client is observed to wait for before abandoning the call, which returns *nothing at all* to the agent rather than a timeout it could act on. **Set this lower when a gateway or proxy with a tighter timeout sits in front of this server**; set it higher only when you know the clients reaching this deployment are configured for a longer tool timeout. |
| `HTTP_API_OAUTH2_REDIRECT_URL` | The redirect URI registered with the identity provider. Unset = derived from the issuer plus this server's callback path, which is `/oauth2/callback` when the web UI is compiled in and `/mcp/oauth2/callback` on an MCP-only build. Both paths are always served, so an authorization started before an upgrade still lands; but the URI the server *sends* must be registered at the IdP, so a build that gains the web UI needs `/oauth2/callback` added there (or this knob set to keep the old one). |
| `HTTP_API_CREDD_ADDRESS` | Pins the credd this server talks to (a sinful, e.g. `<10.0.0.5:9618?sock=credd>`), overriding discovery. Normally unnecessary: the credd is read from the schedd itself, which publishes its own credd as `CredDIpAddr` in its ad and address file — the same binding `DCSchedd::getCreddAddress` uses. Set this when fronting a remote schedd that does not advertise it, since a credd that is not the submitting schedd's accepts credentials and leaves jobs held anyway. |
| `HTTP_API_REQUIRED_CREDENTIALS` | OAuth service credentials that must exist before a job may be submitted (comma- or space-separated, e.g. `scitokens`). Some access points hold every job submitted without them, whatever the job actually uses. Each submit path checks the caller's credentials first and stores a placeholder for any that is missing, so a person using the web UI does not get a held job for a reason unrelated to what they asked for; a real credential obtained later through the OAuth flow replaces the placeholder. Presence is cached per user for 5 minutes. Best effort: if the credd is unavailable or refuses, the submit still proceeds and the reason is logged. Unset = nothing is required. |
| `HTTP_API_MCP_MAX_REQUEST_DURATION` | Hard stop on an MCP request that is still making progress (a duration, e.g. `5m`). Unset = 15m. While an MCP request runs its write deadline is moved forward, so `HTTP_API_WRITE_TIMEOUT` — which is an absolute deadline meant for ordinary replies — does not decide how long a deliberately waiting tool may wait. A request that stops making progress is still cut off on its last window; this is the backstop for one that never finishes at all. |
| `HTTP_API_ADVERTISE` | Advertise this API server to the collector (a `HTCondorAPI` ad: endpoint, schedd, mirror health, versions). Default `true`; `daemon.Advertise` is a no-op without `COLLECTOR_HOST`, so this only matters to opt out when a collector is configured. |
| `HTTP_API_DBMIRROR_NAME` | Pin job-queue routing to the htcondordb mirror advertising this `Name`. Set it when more than one mirror advertises to the pool: nothing in the ad says which schedd each one mirrors, so without a pin the freshest is chosen, which is a guess. |
| `HTTP_API_DBMIRROR_ADDRESS` | Dial this sinful string instead of the mirror's advertised `MyAddress`, for one reachable only over NAT, a tunnel, or a Kubernetes Service. Freshness still comes from the collector ad — this changes where to connect, not whether the mirror is current enough to trust — and it applies whether the mirror was found through the collector or not. |
| `HTTP_API_DBMIRROR_REQUIRED` | Never fall back to the schedd. A read the mirror cannot serve fails instead of becoming load on the access point you were trying to protect. See [the routing notes](../webapi/httpserver/README.md#configuration) for which failures are 503 and which are 400. |
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
| `HTTP_API_LLM_API_KEY_FILE` | Path to a 0600-mode file with the Anthropic API key. Enables the chat assistant. |
| `HTTP_API_LLM_API_URL` | Override the upstream Anthropic Messages endpoint (proxy / gateway). |
| `HTTP_API_LLM_MODEL` | Override the default Claude model. |
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
