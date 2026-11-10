# Placement

When a `condor_placementd` is reachable, this server onboards users onto
the access point: it issues placement tokens, maps placement identities
to accounts, and takes access requests. Part of the
[HTTP API + MCP server](server.md) documentation.

Which placementd is used, and what happens when there is none, is under
[Finding the placementd](#finding-the-placementd) below.

## Placement onboarding

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
mapping](server-auth.md#local-identity-mapping) on, a sign-in that maps to no account is
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
through the device flow only. It is deliberately absent from
`scopes_supported` in the discovery documents: `placement_client` knows the
scope and the device endpoint checks it against that client's own scope
list, while an MCP client asks for every scope the server advertises, so
advertising it would send `placement` to `/authorize` -- which refuses it --
and break every browser authorization. Each refresh re-reads the identity from the
placementd and ends the grant when the identity is gone or expired, or the
account's schedd user record is disabled. The legacy paths above keep
working for older clients.

## placementd as an identity mapping

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

The session's groups -- which decide the web UI's access and admin groups
and project leads -- follow `HTTP_API_GROUP_SOURCE`. With `token`, they are
the provider's groups claim. With a local source (`system`, `file:<path>`),
they are that source's groups for the part of the account before `@` when
the account is in `UID_DOMAIN`, and none for an account in any other
domain; the provider's groups claim is not used.

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
| `HTTP_API_PLACEMENTD_NAME` | The placementd to use, by the `Name` in its collector ad (or a sinful string). Unset: `PLACEMENTD_HOST` if set, else this access point's own placementd (address file, then a collector ad from this access point's host). Set it only for a placementd that serves this access point from another host. Read at startup. |

## Access requests

Somebody who signs in with an identity the placementd does not map sees
**Request access** on `/placement` instead of a dead end: the projects
they want, as free text, and a note. The request records the identity from
the session, never from the request, together with the provider's display
name and, when the provider marks it verified (`email_verified`), email
from sign-in. Names and emails from the provider are kept to 256
characters, without control or invisible formatting characters. Each
identity has at most one open request; it can be withdrawn while pending,
and a new one filed after a withdrawal or a denial. Someone whose mapping
has expired is told to ask an administrator to extend it instead: they are
already in the directory, which an approval cannot add them to again.

Filing is rate-limited: 3 at once per identity, then one every 10 minutes,
and 10 at once per client address, then one a minute. The client address
is the peer's, or the forwarded one from a proxy in
`HTTP_API_TRUSTED_PROXIES`. When no proxies are configured and the peer is
a loopback or private address (most likely an unconfigured proxy or
ingress), only the per-identity limit applies, and the server logs that
once. A note is at most 2 KB, a request names at most 10 projects of 64
characters each, and neither may contain control or invisible formatting
characters (bidirectional overrides, zero-width characters).

Administrators (`HTTP_API_WEBUI_ADMIN_GROUP`) see the requests on the
**Requests** tab of `/admin/placement`, with the number pending beside the
tab and beside Placement in the sidebar. **Approve** opens the Onboard user
form pre-filled with the identity, the requested projects that exist in
the directory (matched ignoring case; the others are listed), and `READ`
and `WRITE`. The account is suggested only for an identity whose domain is
listed in `HTTP_API_PLACEMENT_PREFILL_DOMAINS`: the part before the last
`@`, in `UID_DOMAIN`, as a map file `*` would give it. Otherwise the
administrator types it.

The account must be `user@domain`, with no whitespace, double quotes,
backslashes or commas, and its user part may not be `root`, `condor`,
`condor_pool` or a name (or `%group`) in `QUEUE_SUPER_USERS`, in any
domain. When the account does not exist, approving creates it with the
chosen grants. When it exists, the form shows the identities already on it
and its grants, and approving needs **Attach to this existing account**
checked (`attach_to_existing` in the API; without it the server answers 409
with the account). Attaching never changes the account: its grants are
those of every identity on it, and are changed from the Directory. An
expiry, when given, must be in the future.

Approving makes one directory change through the placementd, recorded as
the approving administrator's with the comment `access request #<id>`.
While it runs, the request is held (`approving`): the requester cannot
withdraw it and another administrator cannot deny it. It is marked
approved, with the account and the change set, only once the change
committed, and goes back to pending if the change fails or the server
stops mid-way (after 5 minutes). If the identity is already in the
directory, approval is refused and the request can be marked resolved
instead, which checks that the identity has access now. **Deny** takes a
reason, which the requester sees. Approving needs a placementd that
supports directory management; with an older one the tab is read-only.

With `placementd` in `HTTP_API_IDENTITY_MAP`, an approved person who is
still signed in gets their account without signing in again, as any newly
onboarded identity does.

Requests are kept in this server's database (`placement_access_requests`);
the placementd records only who has access. Approved, denied and
withdrawn requests are deleted once they have not changed for
`HTTP_API_PLACEMENT_REQUEST_RETENTION` (default `2160h`, 90 days), checked
hourly; pending ones are kept. Nothing is sent by email.

| Endpoint | Who |
| --- | --- |
| `GET`, `POST`, `DELETE /api/v1/placement/me/request` | The signed-in person, for their own identity. `POST` and `DELETE` require `X-Requested-With`. |
| `GET /api/v1/placement/admin/requests?status=pending\|approving\|approved\|denied\|withdrawn\|all` | Admins. |
| `GET /api/v1/placement/admin/requests/count` | Admins. |
| `POST /api/v1/placement/admin/requests/{id}/approve` | Admins. `{account, attach_to_existing, authorizations, projects, default_project, expires_at, display_name, comment}`; `?dry_run=1` checks only. |
| `POST /api/v1/placement/admin/requests/{id}/deny` | Admins. `{reason}`. |
| `POST /api/v1/placement/admin/requests/{id}/resolve` | Admins. `{comment}`. |

| Knob | Purpose |
| --- | --- |
| `HTTP_API_PLACEMENT_PREFILL_DOMAINS` | Comma-separated identity domains (the part after the last `@`, case-insensitive) whose requests get an account suggested. Empty, the default, suggests none. List only domains where the part before the `@` is the person's own login name. Read at startup. |
| `HTTP_API_PLACEMENT_REQUEST_RETENTION` | How long approved, denied and withdrawn requests are kept, as a duration with a unit (`2160h`). Default 90 days. Read at startup. |


## Finding the placementd

The server uses only this access point's placementd: the one named by `HTTP_API_PLACEMENTD_NAME`
(or HTCondor's `PLACEMENTD_HOST`) if set; else the one in
`PLACEMENTD_ADDRESS_FILE` (or `$(LOG)/.placementd_address`); else a
PlacementD ad in the collector whose `Machine` is this access point's
host — the schedd's `Machine`, the host in the schedd's `Name`, or
`FULL_HOSTNAME`. A placementd another access point advertises to the
same collector is never chosen, since it would issue tokens for that
access point. Finding none disables the group and logs why once at
startup; `GET /api/v1/placement/status` reports the latest reason. It
looks again, by the same rule, when a connection fails (a restarted
placementd has a new address) and when the feature is next asked for,
so a placementd started or upgraded later is picked up without
restarting this server.

## API endpoints

**Administration** (admin-gated)

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
bearer token for anyone in the map file.

**Placement onboarding** (any signed-in session; see
[Placement onboarding](#placement-onboarding))
- `GET /api/v1/placement/me` — the session's placement identity, the
  projects and authorizations it may request, and whether the schedd has
  the account or a project disabled
- `POST /api/v1/placement/me/token` — `{project, authorizations[],
  user_code?}`; needs an `X-Requested-With` header. Returns the token, or
  with `user_code` hands it to that device request instead.
- `GET /api/v1/placement/me/device/{user_code}`,
  `POST /api/v1/placement/me/device/{user_code}/deny` — look up or cancel
  a device request. Both spend the device verification page's budget of
  20 code attempts a minute per session and per client address; past it
  they answer 429.
- `POST /api/v1/placement/me/project` -- `{project}`; selects the project
  of a session signed in through the `placementd` identity mapping
- `GET /api/v1/placement/me` and `POST /api/v1/placement/me/token` also
  accept a bearer access token holding the `placement` scope
- `POST /auth/device_authorization`, `GET /auth/code`,
  `POST /auth/cancel_device` — placement-webapp's device flow, for
  `placement-client`


## Trying it in demo mode


When the HTCondor on `PATH` includes a `condor_placementd` (in the
`SBIN` directory beside `condor_master`, or anywhere on `PATH`),
`htcondor-api -demo` adds `PLACEMENTD` to the mini HTCondor's `DAEMON_LIST` so the
placement features can be tried locally: the placement token page, the
device flow, and the admin Directory and access requests. Without one
it logs `no condor_placementd found; placement features are off in demo
mode` and nothing else changes. (Released HTCondor packages put
`condor_placementd` in the `condor-test` package, not `condor`.)

With a placementd, demo mode also:

- writes a map file that maps the IDP users `admin` and `user` to the
  accounts `admin` and `user` with `READ,WRITE` and the project `Demo`,
  and an authorizations file defining `READ` and `WRITE`;
- sets `SEC_USE_TOKENS_DATABASE` and `SEC_ACCEPT_CAPABILITY_TOKENS`, so
  the pool accepts the tokens the placementd issues;
- maps sign-ins with `HTTP_API_IDENTITY_MAP = username, placementd`,
  against a passwd file of its own that lists only `admin` and `user`.
  Those two sign in exactly as they do without a placementd; anyone
  else is looked up in the placementd;
- provisions a third IDP user, `newbie` (password printed as
  `NewbiePassword:`), whom nothing maps. Signing in as `newbie` gives a
  placement-only session with the access request form. Approve the
  request as `admin` on the Requests tab of `/admin/placement`, and
  `newbie`'s session becomes a full one;
- prints the placement URLs alongside the credentials.

The token page and device flow work with any placementd. The Directory,
and approving access requests, need a placementd that speaks API
version 2; with an older one the admin page lists users instead of the
Directory, and requests can be filed but not approved there.

The same flag works for the MCP binary:

```bash
./htcondor-mcp -demo
```
