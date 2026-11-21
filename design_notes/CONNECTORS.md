# Connectors: credentials this server obtains on a user's behalf

## Status

Design only. Nothing here is built. The one piece that already exists is
the `use_oauth_services` submit keyword, which reached the job ad in #988
and without which none of this has anywhere to land.

Written after tracing HTCondor's three credential-bootstrap mechanisms to
their source, because from the outside they look like one mechanism and
they are not.

## The problem

A job asks for a credential with `use_oauth_services`. Something has to
put that credential in the credd before the job runs, or the job is held
with "Job credentials are not available".

`condor_submit` does that something. This server does not, so a job
submitted through the REST API or MCP runs without the credential its
submit file asked for — which was #981 for the attribute, and is this
document for the credential itself.

The second driver is a research group that wants Google Earth Engine, and
the third is a Google Drive file picker on the submit page. All three are
the same question: how does a credential belonging to a third party, for
one user, get here without passing through an agent's context?

## Three mechanisms, not one

The bootstrap differs by *who holds the OAuth2 client registration*. This
is the organizing fact; everything else follows from it.

| kind | OAuth2 client is | we hold | we do |
|---|---|---|---|
| `credd` | the OAuth credmon | nothing | redirect to the credd's URL |
| `vault` | HashiCorp Vault | a `client_nonce`, transiently | initiate, redirect, poll |
| `oauth2` | **us** | client secret + per-user refresh tokens | the whole auth-code flow |

`credd`: the credd writes a key file and returns `<web_prefix>/key/<key>`
(`credd.cpp:811`). Visiting it logs the browser in as that user with no
further authentication (`OAuthCredmonWebserver.py:145-161`), and the key
file holds the provider's client secret. It is a bearer capability. We
obtain it and redirect; we never store it.

`vault`: `htgettoken` POSTs to `auth/oidc-<issuer>/auth_url` with a
`client_nonce` and `redirect_uri` pointing at *Vault's own* callback, then
polls `/poll` (`htgettoken.py:1058-1067`, `:1136-1145`). Vault holds the
IdP registration and does the code exchange. We would be a Vault auth
client, not an OAuth2 client: no client secret, no callback route. The
flow yields a 28-day Vault token which goes to the credd, and the Vault
credmon exchanges it for access tokens from then on.

`oauth2`: the full client role. Only this kind touches the database, and
only this kind can produce a credential that outlives a browser session,
which is the whole reason it exists.

**The generic part is the entry point, not the storage.** An interface
over all three is worth having for the URL, the identity binding and the
status reporting. An interface over their *backends* would be an
abstraction over three unrelated things.

```go
type Connector interface {
    Name() string
    Kind() Kind
    // Begin returns where to send the browser. Called with the identity
    // of an authenticated browser session, never a name from the request.
    Begin(ctx context.Context, user string) (redirect string, err error)
    Status(ctx context.Context, user string) (Status, error)
}
```

## The entry point carries no authority

```
GET  /api/v1/connect                     list connectors + this user's status
GET  /api/v1/connect/{ns}:{name}          302 to wherever the flow starts
GET  /api/v1/connect/{ns}:{name}/callback oauth2 kind only
```

`/api/v1/connect/builtin:gdrive` is **fixed, per-connector, and safe to
print** —
in a tool result, in a log, in documentation. That is the point of it.

It is safe because it carries no authority of its own: without an
authenticated browser session it yields a login redirect, not a
credential. Authority lives in the session; the URL is a handle naming
which provider to connect. An agent that fetches it gets a login page.

Three rules keep that true, and each is a test rather than a comment:

- **The connector id is in the path; the user never is.** The identity comes
  from the session. The moment `?user=` is honoured this becomes
  privilege escalation.
- **The 302 target comes from the connector, never from a request
  parameter.** This endpoint is shaped exactly like an open redirect and
  must not be one.
- **Session authentication only.** Not a bearer token, not an API key.
  A browser is the only thing that can complete any of these flows, so
  anything else asking is not doing what this endpoint is for.

A colon is legal in a path segment (RFC 3986 `pchar`), and Go's
`ServeMux` routes `/api/v1/connect/builtin:gdrive` and `.../token`
correctly with the id as a path value — checked, not assumed.

One hazard that follows, and it will be hit by whoever builds a link in
the frontend: a **bare id is a valid URL with a scheme**. `url.Parse(
"builtin:gdrive")` returns scheme `builtin`, opaque `gdrive`, path empty.
So a connector id must never be used as a relative reference on its own;
it is always a path segment under `/api/v1/connect/`.

This replaces URL-mode MCP elicitation as the mechanism. Elicitation
(`ElicitParams{Mode:"url"}`, supported by go-sdk v1.8.0) stays available
as a *convenience* — a client that declares the capability can open the
link without the user copying it — but the security property must not
depend on it. Under stateless HTTP an older client's capabilities are
unknowable rather than absent (see `elicitSupportFromCapabilities`), and
a design whose safety rests on capability negotiation fails open on
exactly the clients it cannot interrogate.

## Namespaces, not reserved names

An operator configuring a connector should not have to know a provider's
endpoints, its scope strings, or which of its quirks will bite. Something
has to ship that knowledge.

The tempting shape is a flat name space with a few magic names in it —
`gdrive` means the built-in Google Drive definition, anything else is
yours. Do not do that. It spends a name that is not ours to spend: a site
with its own `gdrive` has to be told to call it something else, and the
day we want to change what the built-in `gdrive` means, every submit file
and every stored credential naming it changes meaning with it.

A connector id is therefore **`<namespace>:<name>`**, and the namespace
says who defines it:

| namespace | defined by | can the operator add to it |
|---|---|---|
| `builtin:` | this server, shipped | no |
| `site:` | the operator | yes, freely |

`builtin:gdrive`, `builtin:box`, `builtin:onedrive` — the three HTCondor
already ships transfer plugins for, so a credential obtained under one of
them has somewhere to be used the day it lands. `site:cryoem` is the
operator's, and nothing we ship will ever collide with it.

A `builtin:` definition carries endpoints, scopes and quirks; the
operator supplies only what is theirs, the client registration and who
may use it. A `site:` definition supplies everything. Nothing in between,
because a half-known provider is one whose quirks are undocumented *and*
unconfigurable.

A `builtin:` definition fixes its default scopes at the narrowest that
works. For `builtin:gdrive` that is `drive.file`; see "Scope width is
blast radius" for why that is not merely a compliance choice.

Namespaces are also how this stays future-proof in the direction we
cannot see. A third namespace — a provider catalogue fetched from
somewhere, a vendor's definitions — slots in without renaming anything
that already exists. A flat space with magic names has to break something
to grow.

## Configuration

Mirrors site apps, which is the existing shape for "a group brings
something, the operator decides who gets it":

```
HTTP_API_CONNECTORS = builtin:gdrive, site:cryoem

HTTP_API_CONNECTOR_BUILTIN_GDRIVE_CLIENT_ID          = 1234-abc.apps.googleusercontent.com
HTTP_API_CONNECTOR_BUILTIN_GDRIVE_CLIENT_SECRET_FILE = /etc/condor/connectors/gdrive.secret
HTTP_API_CONNECTOR_BUILTIN_GDRIVE_GROUPS             = smith_lab
HTTP_API_CONNECTOR_BUILTIN_GDRIVE_TRANSFER           = spool

HTTP_API_CONNECTOR_SITE_CRYOEM_KIND                  = oauth2
HTTP_API_CONNECTOR_SITE_CRYOEM_AUTHORIZATION_URL     = https://...
HTTP_API_CONNECTOR_SITE_CRYOEM_TOKEN_URL             = https://...
HTTP_API_CONNECTOR_SITE_CRYOEM_SCOPES                = read
```

The id is `<ns>:<name>` everywhere a person or an API sees it, and
`<NS>_<NAME>` in a config macro, because HTCondor config names cannot
carry a colon. One substitution, stated once, rather than two spellings
that drift.

A `builtin:` connector needs no `_KIND`: the definition knows. A `site:`
one must say.

The secret is a **file path in config, bytes on disk** — config values are
public, so the path goes in config and the secret does not. Same rule as
`HTTP_API_KEK_FILE`.

`_GROUPS` gates who may connect, exactly as
`HTTP_API_SITE_APP_<ID>_GROUPS` gates who may see an app.

A site app *names* a connector it needs; the operator decides what that
name means. Site apps are static files served from this origin and the
docs promise their authors "register no OAuth2 client" — that promise
stays true. They register one with Google, not with us.

`_TRANSFER` is `spool` or `direct`; see "Two transfer paths".

## Storage

`oauth2` kind only. Modelled on `upstream_refresh_tokens` (migration
0011), which already holds a third-party refresh token under the same
threat model, so one KEK covers every long-lived secret rather than each
growing its own scheme.

```sql
CREATE TABLE connector_credentials (
    subject           TEXT NOT NULL,   -- our user
    provider          TEXT NOT NULL,   -- "gdrive"
    provider_subject  TEXT NOT NULL DEFAULT '',
    refresh_token     BLOB NOT NULL,
    refresh_token_dek BLOB,            -- NULL when stored in the clear
    granted_scopes    TEXT NOT NULL DEFAULT '',
    obtained_at       TIMESTAMP NOT NULL,
    last_refreshed_at TIMESTAMP,
    last_used_at      TIMESTAMP,
    PRIMARY KEY (subject, provider)
);
```

`granted_scopes` is what the provider actually granted, which is not
always what was asked for — the same reason 0011 records it.

`last_used_at` is what makes a connector tell a user their Drive
connection needs renewing *before* a job holds, rather than after. The
credd sweeps by last use and cannot report; this can.

## Maintenance

A timer refreshes credentials near expiry, rate-limited by
`last_refreshed_at` the way the upstream checker rate-limits itself: a
server refreshing on a timer must not turn its user list into steady load
on somebody else's identity provider.

A refresh that fails with an unambiguous revocation marks the row dead
and surfaces it in `Status`. A refresh that fails transiently retries.
Telling those apart matters: a revoked grant needs the user, and
retrying it forever is how a provider starts rate-limiting the whole
server.

**Credentials reach the credd at submit time, not on a timer.** Pushing
on every refresh would write credentials for every user whose connector
exists, including those with nothing in the queue. Submit-time push
matches what `condor_submit` does, and the starter's own
`SEC_CREDENTIAL_REFRESH` timer (default 300s,
`jic_shadow.cpp:3516-3525`) carries later updates into running jobs.

Store with `NeedRefresh` set explicitly. The credd otherwise decides
`.top` vs `.use` from `CredSorter::Sort` (`store_cred.cpp:510-521`),
which depends on access-point configuration this server cannot see — so
the same store silently changes meaning the day an admin adds a
`<SERVICE>_CLIENT_ID`. We are supplying a usable token, we know it, and
we should say so rather than let config decide.

### The credd is a directory we share with the sysadmin

A credential in the credd is a file: `<service>_<handle>.use` under the
user's cred dir. The admin's credmons write there too, and nothing
arbitrates. If this server writes `gdrive.use` for a user whose
administrator has also configured a `gdrive` OAuth2 credmon, the two are
the same path — we clobber their token, or their credmon refreshes ours
using *their* client registration, which is a different application
entirely.

So everything this server stores goes under a **handle of its own**:

```
HTTP_API_CONNECTOR_HANDLE = webapi      # default
```

`builtin:gdrive` then stores service `gdrive`, handle `webapi`, giving
`gdrive_webapi.use`, which a job names as `gdrive*webapi` and a transfer
plugin addresses as `webapi+gdrive2://...`. The handle is configurable
because two API servers in front of one access point would otherwise
collide with each other, having both avoided colliding with the admin.

This uses HTCondor's own mechanism rather than inventing one: the handle
exists precisely to say "the same service, provisioned differently", and
`contrib/gdrive2_plugin` already reads `<handle>+gdrive2://`.

**Write no `.meta`.** `OAuthCredmon.check_access_token` skips any token
with no metadata file (`OAuthCredmon.py:154-158`), so a `.use` we wrote
is correctly ignored by an admin's OAuth2 credmon rather than fought
over. Writing one would hand our credential to a credmon configured for
somebody else's OAuth2 client. The namespace keeps the files apart; the
absent `.meta` keeps the *credmon* away even if a name ever lines up.

Worth knowing while in there: an invalid-JSON `.meta` passes that guard
and then `should_renew` dereferences an unbound `token_metadata`
(`OAuthCredmon.py:52-63` — `except ValueError` leaves it unassigned and
line 63 reads it). Not ours to trip, but it is how a corrupt metadata
file takes out a token's renewal with an `UnboundLocalError` rather than
a diagnosis. Worth an upstream patch alongside the plugin.

## Two transfer paths

`_TRANSFER = spool` (**default**)

The server fetches the bytes with the stored credential and spools them
as job input; output comes back to the AP normally and the server uploads
on request. Works with stock execute nodes. **No third-party token ever
reaches an execute node.**

`_TRANSFER = direct`

The credential goes to the credd, the job declares
`use_oauth_services = gdrive`, and the transfer plugin on the execute
node fetches from the provider. Avoids moving bytes twice, which matters
for large inputs.

Default `spool` because it needs nothing deployed anywhere and keeps
tokens off machines we do not control. `direct` is an opt-in for sites
whose inputs are big enough to care.

The asymmetry is allowed and probably right: inputs `direct`, outputs
`spool`. Results are usually smaller, they are coming back to the AP
anyway, and the user is returning to the web UI to look at them.

## The Picker needs a token in the browser

Google's Picker runs client-side, so `builtin:gdrive` has to hand the
user's *own browser* an access token:

```
GET /api/v1/connect/{ns}:{name}/token   -> { access_token, expires_in }
```

This is the one place a third-party credential leaves this server, and it
needs the sharpest rule in the document:

**Session authentication only, same origin, never a bearer token, never
an API key, never reachable from MCP.** A browser is the only caller with
a legitimate use for it. Anything else asking for a user's Google token
is the thing this whole design exists to prevent.

One consent, one custodian. The alternative — the SPA running its own
PKCE flow for the Picker while the server holds a separate grant for jobs
— means two consent screens for one user intention, two grants to revoke,
and two sets of scopes to keep aligned.

## Scope width is blast radius

In `direct` mode the token sits in `$_CONDOR_CREDS` on an execute node,
which on the OSPool is a machine we do not control.

A leaked `drive.readonly` token exposes the user's entire Drive. A leaked
`drive.file` token exposes the handful of files they picked for that job.

That argument stands on its own, before any compliance question. It
happens to agree with the compliance answer — `drive.file` is not a
restricted scope and avoids Google's annual CASA assessment — but we
would want the narrow scope even if CASA did not exist.

`drive.file` grants access **to the OAuth2 client**, per file, durably.
The Picker is the grant mechanism: the user picking a file is what
authorizes us for it. So the same client's token, refreshed later onto an
execute node, can still read it. **This is the load-bearing assumption of
`direct` mode and it is unverified** — see "Still open".

## Testing: a mock Google, built from the documentation

None of this can be developed against a real Google client. Registering
one needs an operator, a consent screen and a Drive account, and the
useful failure modes — an expired token mid-transfer, a revoked grant, a
429 under a many-proc cluster, a file the user never picked — are exactly
the ones that are hard to produce on demand against the real thing.

So there is a **mock provider**: the OAuth2 authorization and token
endpoints, the Drive files API, and enough of the Picker's contract to
drive the submit page. It is the same approach
`contrib/gdrive2_plugin/test_gdrive2_plugin.py` already takes for the
transfer half — a stand-in Drive on localhost, 22 tests, no account.

Two rules, because a mock is a place where a wrong belief becomes a
passing test:

- **Every response is transcribed from Google's published documentation
  or its published examples, and the mock records which document and
  when it was read.** A mock built from what we assume the API does will
  agree with code built from the same assumption, and the tests will be
  green and wrong. That has happened here before: the wire format had
  code, tests and documentation agreeing with each other and all three
  wrong.
- **The mock is not the oracle for anything the real provider can be
  asked about cheaply.** It covers flow, error handling and our own
  plumbing. Whether a `drive.file` grant outlives the session that made
  it is a question about Google, and a mock that answers it is answering
  with our own assumption — see "Still open".

Scope: the authorization-code flow with PKCE, refresh and its failures
(expired, revoked, scope withheld), `files.get` with `alt=media`,
`files.list` narrowed as `drive.file` narrows it, multipart create and
update, 401/403/404/429 with Google's documented error bodies, and
`Retry-After`.

## What bites

**The stock gdrive plugin cannot work under `drive.file`.** It resolves
`gdrive://Folder/Sub/file.csv` by *listing*: `get_object_id` queries
`/files?q=name = '...' and '<parent>' in parents`
(`gdrive_plugin.py:235-250`), and `drive.file` withholds listing. Worse,
`upload_file` calls `get_parent_folders_ids(..., create_if_missing=True)`
(`:368-385`), so under `drive.file` it will not find the user's existing
folder and will **create a shadow one it owns**. That is a silent wrong
answer, not an error. `direct` mode needs the ID-addressed plugin, which
is why that patch is tracked as its own piece of work.

**The plugin is deployed everywhere already.** Measured: all 14,552 CHTC
slots across 260 machines advertise `gdrive`, as do all 246 PATh Facility
slots, so a job opting into the OSPool keeps the capability. But what is
deployed is the *stock* path-walking version. A fix is an upstream change
that has to propagate to every execute node — which is why `spool` is the
default and `direct` waits.

**Per-user isolation is the bug class to fear.** A stored token must only
ever be usable for a request by the user who granted it. This repository
has been bitten by that shape before (owner-scope injection; the pool
query path needing an identity allowlist at five call sites). It wants a
test that names the property, not a comment asserting it.

**Multi-AP: which credd?** `spool` mode does not care. `direct` mode must
push to the credd of the AP the job was routed to, which is
`credentialContext`'s existing problem and should reuse its answer rather
than grow a second one.

## Still open

- **Does a `drive.file` grant survive the session that created it?** The
  whole of `direct` mode rests on yes. If it turns out to be
  session-scoped, `direct` collapses into `spool` and the plugin patch is
  wasted. Verify before building `direct`.
- **Folder picking under `drive.file`** — whether picking a folder
  usefully grants its contents, which decides whether "pick a directory
  of inputs" is offerable.
- **Can a job-supplied plugin claim a method name** already advertised by
  a stock plugin, or must a prototype use a distinct scheme? Decides
  whether `direct` can be tried before the upstream patch lands.
- **Vault kind is unbuilt and unneeded so far.** It is in the table above
  because the entry point must not be shaped in a way that excludes it,
  not because anything has asked for it. Build it when an access point
  turns out to need it.
- **Does a `site:` connector get to name a `builtin:` definition as its
  base?** "Like `builtin:gdrive` but our own client and scopes" will be
  asked for. Allowing it means a `site:` id whose behaviour changes when
  we change a `builtin:`, which is the coupling namespaces were meant to
  avoid. Refusing it means copying a definition to vary one field. Not
  decided; do not let the first implementation decide it by accident.
