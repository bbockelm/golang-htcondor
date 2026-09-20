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

- the group above is set, **and**
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
and are not treated as impersonation.

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
  A client registers itself and gets a confidential `client_id` + secret.
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
  needed.
- **A JWT from a trusted external issuer** (`subject_token_type` =
  `urn:ietf:params:oauth:token-type:jwt` or `…:id_token`): accepted only when
  the issuer is listed in `HTTP_API_MCP_TOKEN_EXCHANGE_ISSUERS`. The token's
  signature is verified against the issuer's JWKS (RS256/ES256), and its
  `iss`/`aud`/`exp`/`nbf` are checked. The local identity is namespaced as
  `<sub>@<identity_domain>` (so two issuers cannot collide), and the result is
  bounded by the issuer's `allowed_scopes` **and** the exchanging client's own
  scopes.

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
condor_reconfig            # picks up the checkout without a restart
```

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

**Reloading.** The library is re-read from disk on every
`condor_reconfig` / SIGHUP, not only when the setting changes, since the
usual reason to reload is that the checkout was updated while the path
stayed the same. A reload that fails -- the directory momentarily missing,
an automount that has not returned -- keeps the previously loaded set
rather than leaving agents with nothing. Clearing the setting does
unpublish them. Agents already connected keep the instructions they were
given: MCP delivers those once, at initialize.

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
- `GET /api/v1/ping` — schedd + collector probe
- `GET /metrics` — Prometheus exposition (requires the `metrics`
  scope unless `HTTP_API_METRICS_PUBLIC=true`)

**Admin** (gated on `WebUIAdminGroup` membership)
- `/api/v1/admin/oauth2/clients`, `/api/v1/admin/oauth2/tokens`
- `/api/v1/admin/api-keys`, `/api/v1/admin/api-keys/{key_id}`
- `/api/v1/admin/logs`, `/api/v1/admin/condor-config`

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
| `HTTP_API_WEBUI_ACCESS_GROUP` | Comma-separated group(s) permitted to log in to the web interface. Unset falls back to `HTTP_API_MCP_ACCESS_GROUP`. Reloaded on SIGHUP. See [Authorization groups](#authorization-groups). |
| `HTTP_API_WEBUI_ADMIN_GROUP` | Comma-separated group(s) whose members can reach the admin pages. Unset disables the admin UI. Reloaded on SIGHUP. |
| `HTTP_API_METRICS_PUBLIC` | `true` to disable the API-key gate on `/metrics`. Default off — Prometheus must present an API key with the `metrics` scope. |
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
| `HTTP_API_IDENTITY_MAP` | Map the token subject to a local account (`gecos,username`). See [Local identity mapping](#local-identity-mapping). |
| `HTTP_API_IDENTITY_MAP_PASSWD_FILE` | Account file backing the mapping index. Default `/etc/passwd`. |
| `HTTP_API_IDENTITY_MAP_TTL` | How long the account index and group answers are reused. Default `5m`. |
| `HTTP_API_GROUP_SOURCE` | Comma-separated: `token` (default), `system`, and/or `file:<path>`. Local sources are unioned; `token` may not be mixed with them. See [Local identity mapping](#local-identity-mapping). |
| `HTTP_API_OAUTH2_USERNAME_CLAIM` | Claim carrying the username, e.g. `eppn`. Default `sub`. |
| `HTTP_API_OAUTH2_REQUIREMENTS` | ClassAd expression over the token's claims; the login proceeds only if it is true. See [Local identity mapping](#local-identity-mapping). |
| `HTTP_API_IDENTITY_MAP_STRIP_DOMAIN` | `true` to also match the local part of a scoped subject. Pair with `HTTP_API_OAUTH2_REQUIREMENTS`. |
| `HTTP_API_MCP_SKILLS_DIR` | Directory of site-authored Markdown skills to publish to agents. Reloaded on SIGHUP. See [Site skills](#site-skills). |
| `HTTP_API_TRUSTED_PROXIES` | Comma-separated CIDRs (or bare addresses) whose `X-Forwarded-For` / `X-Real-IP` are honored when recording a client address. Unset means none are, and the peer address is logged. |
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

- [httpserver/README.md](../webapi/httpserver/README.md) — full HTTP API
  reference, demo-mode internals, security model.
- [mcpserver/README.md](../webapi/mcpserver/README.md) — MCP tool catalog
  and integration notes.
- [SECURITY_CONFIG.md](../design_notes/SECURITY_CONFIG.md) — operator-facing
  security configuration guide.
- [docs/library.md](library.md) — embedding the underlying Go
  library in your own service.
