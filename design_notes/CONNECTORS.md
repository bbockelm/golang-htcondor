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

### A `site:` connector is never based on a `builtin:` one

Decided, not open. "Like `builtin:gdrive` but with our own scopes" will
be asked for, and the answer is no.

Inheritance would make every field of every `builtin:` definition a
compatibility promise. Today `builtin:` is ours and closed, so when
Google moves an endpoint or we find a scope was too wide, we change it
in a release. The moment a `site:` id can be based on one, that same
change silently alters a connector the operator believes is theirs —
which is exactly the coupling the namespaces exist to remove, reintroduced
through the back door.

It also ruins the thing the namespace is for. `builtin:` or `site:` is
supposed to answer "who defines this" in one word. With inheritance the
answer becomes "both, depending which field you are asking about", and
the admin page's read-only/editable split needs a third state for fields
that are ours but overridden.

And it moves the answer to "why did this connector change behaviour?"
out of the operator's configuration and database and into our release
notes, where they will not look.

**The variation people actually want is already there.** A `builtin:`
connector requires the operator to supply the client registration — that
is the normal case, not a deviation — and exposes groups, transfer mode
and scopes. Those fields are the variation surface. Narrowing scopes
below the definition's default is ordinary; widening them is the
operator's call to make, and the page should say what it costs, because
on `builtin:gdrive` widening past `drive.file` is what buys an annual
security assessment and a token on an execute node that can read the
whole of someone's Drive.

Anything beyond those fields — different endpoints, a different provider
wearing a familiar name — means it was never that provider. Write it out
as a `site:` connector and have the definition say what it actually is.

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

Plus one knob that is not per-connector:

```
HTTP_API_CONNECTOR_PREFIX = webapi
```

the service-name prefix everything this server stores in the credd goes
under; see "The credd is a directory we share with the sysadmin".

Configuration is only one of the two ways to declare a connector — the
admin page is the other, and configuration wins where both do. See
"Configuring one".

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

Two tables: what a connector *is*, and what a user has *granted*. They
have different lifetimes and different blast radii, and keeping them
apart is what lets a connector be revoked without being deleted.

Both follow `upstream_refresh_tokens` (migration 0011), which already
holds a third-party secret under the same threat model, so one KEK covers
every long-lived secret rather than each growing its own scheme.

```sql
-- A connector declared HERE rather than in the configuration. A
-- connector the configuration declares has no row: configuration wins,
-- and a row that merely loses is a row an operator can edit to no
-- effect.
CREATE TABLE connectors (
    id                 TEXT NOT NULL,   -- "site:cryoem", "builtin:gdrive"
    kind               TEXT NOT NULL,   -- credd | vault | oauth2
    client_id          TEXT NOT NULL DEFAULT '',
    client_secret      BLOB,            -- sealed; never leaves the server
    client_secret_dek  BLOB,            -- wrapped data key, NULL if unsealed
    secret_updated_at  TIMESTAMP,       -- shown; the secret itself is not
    authorization_url  TEXT NOT NULL DEFAULT '',   -- site: only
    token_url          TEXT NOT NULL DEFAULT '',   -- site: only
    scopes             TEXT NOT NULL DEFAULT '',
    groups             TEXT NOT NULL DEFAULT '',
    transfer           TEXT NOT NULL DEFAULT 'spool',
    enabled            BOOLEAN NOT NULL DEFAULT 1,
    created_at         TIMESTAMP NOT NULL,
    updated_at         TIMESTAMP NOT NULL,
    PRIMARY KEY (id)
);

-- What one user granted for one connector. oauth2 kind only: credd and
-- vault connectors leave their credential in the credd and keep nothing
-- here.
CREATE TABLE connector_credentials (
    subject           TEXT NOT NULL,   -- our user
    connector         TEXT NOT NULL,   -- "builtin:gdrive"
    provider_subject  TEXT NOT NULL DEFAULT '',
    refresh_token     BLOB NOT NULL,
    refresh_token_dek BLOB,
    granted_scopes    TEXT NOT NULL DEFAULT '',
    obtained_at       TIMESTAMP NOT NULL,
    last_refreshed_at TIMESTAMP,
    last_used_at      TIMESTAMP,
    PRIMARY KEY (subject, connector)
);
```

`connector` is the id, namespace and all, so a `site:gdrive` grant and a
`builtin:gdrive` grant are different rows for the same user. They are
different applications with different client registrations, and merging
them would hand one's token to the other.

`granted_scopes` is what the provider actually granted, which is not
always what was asked for — the same reason 0011 records it.

`last_used_at` is what lets a connector tell a user their Drive
connection needs renewing *before* a job holds, rather than after, and
what answers the operator's question of whether anyone uses this at all.
The credd sweeps by last use and cannot report; this can.

Deleting a `connectors` row deletes its credentials. They are unreachable
otherwise: no page lists a credential whose connector is gone, so nobody
could revoke it.

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
administrator has also configured a `gdrive` OAuth2 credmon, that is the
same path — we clobber their token, or their credmon refreshes ours using
*their* client registration, a different application entirely.

So everything this server stores goes under a **service name of its own**:

```
HTTP_API_CONNECTOR_PREFIX = webapi      # default
```

`builtin:gdrive` stores the service `webapi_gdrive`, giving
`webapi_gdrive.use`, which a job names as `use_oauth_services =
webapi_gdrive`. The prefix is configurable because two API servers in
front of one access point would otherwise collide with each other, having
both successfully avoided the administrator.

**Not a handle**, which was the first design and is worse on three counts:

- A handle buys no protection a service name does not. The credmon's
  guards key on `token_name`, the whole filename stem
  (`OAuthCredmon.py:142-158`), so `gdrive_webapi` and `webapi_gdrive` are
  equally distinct from `gdrive`.
- `CredSorter::Sort` keys on the **service alone**. Under a handle the
  service is still `gdrive`, so an administrator with `GDRIVE_CLIENT_ID`
  set flips the credd's default from `.use` to `.top`
  (`store_cred.cpp:510-521`) and `NeedRefresh` becomes load-bearing
  rather than belt-and-braces. A service name the administrator will
  never configure sorts as `UnknownType`, whose default is already what
  we want.
- A handle cannot be asked for directly. It exists only as a side effect
  of scanning `<service>_oauth_(permissions|resource|options)_<handle>`
  keys, so the submit file needs a second, vestigial command whose only
  purpose is to create the handle. `use_oauth_services = webapi_gdrive`
  is one command and one name.

`_` is legal in a service name (`okay_for_oauth_filename`,
`store_cred.cpp:280-297`).

Worth knowing: `<service>_<handle>` is a **lossy** encoding. Service
`webapi_gdrive` with no handle and service `webapi` with handle `gdrive`
produce the same `webapi_gdrive.use`. The file is the real namespace
whichever scheme is chosen, which is the last argument for putting the
distinguishing prefix in the part we control outright.

**Write no `.meta`.** `OAuthCredmon.check_access_token` skips any token
with no metadata file (`OAuthCredmon.py:154-158`), so a `.use` we wrote
is ignored by an administrator's OAuth2 credmon rather than fought over.
Writing one would offer our credential to a credmon configured for
somebody else's OAuth2 client. The service name keeps the files apart;
the absent `.meta` keeps the credmon away even if a name ever lines up.

Worth an upstream patch while in there: an invalid-JSON `.meta` passes
that guard and then `should_renew` dereferences an unbound
`token_metadata` (`OAuthCredmon.py:52-63` — `except ValueError` leaves it
unassigned and line 63 reads it), so a corrupt metadata file takes out a
token's renewal with an `UnboundLocalError` rather than a diagnosis.

### The plugin has to be told which credential

`contrib/gdrive2_plugin` derives its credential from its method:
`gdrive2://` reads `gdrive.use`. A service name of our own breaks that,
and the stock `<handle>+method://` syntax cannot express the fix — it
always composes `<provider>_<handle>`, and reaching `webapi_gdrive` that
way would need the provider to be `webapi`, which is not a transfer
method.

So v2 reads `<cred>+gdrive2://` as the credential name **verbatim**:

```
webapi_gdrive+gdrive2://<fileId>/data.csv
```

This deliberately differs from the stock plugin, where the same syntax
means `<provider>_<handle>`. It is safe because the two never see the
same URL: the methods differ, so no URL is ambiguous between them. It
would not be safe if v2 ever claimed the `gdrive` method, which is one
more reason it does not.

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

## Configuring one: config file or database

A connector may be declared two ways, and the rule is the one site apps
already use, because an operator who has learned it once should not have
to learn a second:

- **The HTCondor configuration** declares it. Read-only here. Changing it
  means changing the configuration and running `condor_reconfig`.
- **This server's database** holds it. Editable from the admin page, in
  force as soon as it is saved.

**Configuration wins.** If both declare the same id, the configuration is
what runs. The page must say so against the shadowed row rather than
hiding it: a stored connector that silently does nothing is an operator
editing a form that has no effect, and finding out from a user.

### Where the configured half actually lives

Three places, with three lifetimes. Saying which is which is the
difference between an edit that takes and one that silently does not.

- **The configuration file** is authoritative for anything it declares,
  and it is **public**: values are readable with `condor_config_val`,
  which is the whole reason `_CLIENT_SECRET_FILE` names a path and the
  bytes live on disk under their own permissions.
- **In the process**, nothing is snapshotted into a struct of its own.
  Following `siteapps.ConfigPolicy`, a connector's config source holds
  the `*config.Config` and reads `HTTP_API_CONNECTOR_<NS>_<NAME>_*` on
  each lookup, so there is one copy of the answer and no second one to
  go stale. A reconfigure replaces the whole source rather than mutating
  it.
- **The database** holds what the admin page stored, and is in force the
  moment it is written. No reconfigure, no restart.

### A reconfigure has to re-read all of it, not diff it

`cmd/htcondor-api/reconfig.go` keeps a table of every parameter the
daemon has an answer for: those with an `apply` are installed live,
those without are **reported as needing a restart, naming the
parameter**. The comment there is the rule worth honouring —

> until a parameter is listed here a change to it either does nothing or
> is not noticed at all. The second case is the one that costs an
> operator an afternoon.

Connectors cannot be handled by diffing a parameter, for the same reason
site apps cannot: a connector's definition is spread over a parameter per
connector per setting, and **adding a connector adds names nothing was
watching**. A diff of the names that existed before cannot see a name
that did not.

So, exactly as `SetSiteAppPolicy` is called: a
`SetConnectorConfig(*config.Config)` taking the whole configuration,
called on every reconfigure whether or not anything appeared to change.
It is also how an operator makes an edit take effect at the moment they
ran `condor_reconfig`, rather than at the end of some reload interval.

The secret *file* is re-read then too. Its path is in the configuration
but its contents are not, so a rotated secret with an unchanged path is
invisible to any diff — the same shape as the skills directory and the
project-leads file, both of which are re-read unconditionally for this
reason.

### Where

`/admin/connectors`, in `ADMIN_NAV`.

A naming hazard worth heading off: the admin pane already has **OAuth2
Clients**, which are clients of *our* identity provider — applications
connecting **to** this server. Connectors are accounts this server
connects **to**. Opposite directions, adjacent words, one letter of
difference in a hurried reading. The page should say which it is in a
sentence, not rely on the title.

### The API

Mirrors `handlers_site_apps` / `siteapps_config.go`, including the
`origin` / `stored_here` / `editable` triple that page already renders:

```
GET    /api/v1/admin/connectors                      list, with provenance
POST   /api/v1/admin/connectors                      create a stored one
GET    /api/v1/admin/connectors/{ns}:{name}/config   settings rows
PUT    /api/v1/admin/connectors/{ns}:{name}/config   editable rows only
DELETE /api/v1/admin/connectors/{ns}:{name}          remove a stored one
GET    /api/v1/admin/connectors/{ns}:{name}/users    who connected, last use
POST   /api/v1/admin/connectors/{ns}:{name}/revoke   drop stored credentials
POST   /api/v1/admin/connectors/{ns}:{name}/test     check it is usable
```

A settings row is `{key, setting, value, effective, effective_from,
editable}` as site apps renders it, so `HTTP_API_CONNECTOR_BUILTIN_GDRIVE_
GROUPS` appears under its real name and an operator can find it in a
configuration file afterwards.

### The secret is write-only

The one thing site apps does not have, and the part to get right first.

- **Never rendered.** Not in `GET`, not masked, not by length. A row for
  the secret carries `secret_set` and `secret_updated_at` and no value.
- **Omission means unchanged.** A `PUT` without the field leaves it
  alone; an explicit null clears it. A form that round-trips an empty
  string into "no secret" is how a working connector breaks on an
  unrelated edit.
- **Configuration-declared secrets are a path, not bytes.** The page
  shows `_CLIENT_SECRET_FILE` as the path it is. Configuration values are
  public; that is the whole reason the bytes are on disk.
- **Stored secrets are sealed** with the existing envelope, under the
  same KEK as `upstream_refresh_tokens`. One KEK covers every long-lived
  secret rather than each growing its own scheme.

### Two creation flows, which is the namespaces paying off

- **Enable a built-in.** Pick from the `builtin:` catalogue — a closed
  set we ship, so the list is finite and ours — and supply only what is
  the operator's: client id, secret, groups. Endpoints, scopes and quirks
  come with the definition.
- **Add a site connector.** `site:<name>`, and every field is the
  operator's: kind, authorization URL, token URL, scopes.

Four fields versus a dozen, decided entirely by which namespace the id is
in.

### What a row shows

Id, kind, origin, enabled, the groups permitted, whether a secret is set
and when it last changed, transfer mode, **how many users have connected
and when it was last used**.

That last pair is the question an operator actually has — is anyone using
this? — and it is the reason `last_used_at` is a column rather than a
nice-to-have. The credd sweeps by last use and cannot report; this can.

### Test, revoke, delete are three different things

**Test** answers "is this configured correctly" without a user's grant:
resolve the endpoints, confirm the token URL speaks OAuth2, confirm the
secret file is readable. A connector that is wrong should say so when it
is configured, not at some user's first attempt.

**Revoke** drops every stored credential for the connector, so users
re-consent. It is what to do when a client secret has leaked or rotated,
and it does **not** remove the connector.

Revoke stays available on a **read-only** row. The configuration owns the
connector's definition; the stored credentials are this server's own
state, and an operator who cannot revoke them here has to go and delete
database rows by hand. Read-only is about the definition, not about
everything on the page.

**Delete** removes a stored connector *and its credentials*. The
confirmation has to say how many credentials will be destroyed, because
the alternative is orphaned secrets that no page lists and nobody can
revoke. Deleting a connector whose definition came from configuration is
refused, not silently ignored.

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

## Answering the grant-durability question

Google's documentation does not state it. The [scope
guide](https://developers.google.com/workspace/drive/api/guides/api-specific-auth)
says `drive.file` covers files "you open with an app or that the user
shares with an app while using the Google Picker API" — the language of a
relationship between an app and a file, not of a session — and the
[Picker guide](https://developers.google.com/workspace/drive/picker/guides/overview-desktop)
describes the returned ids without saying how long they stay usable.
Secondary sources point the same way without settling it: that access is
"per user, per file", and that authorization ends "when the user
deauthorizes the app", which is the language of revocation rather than
expiry. Nobody documents a timer. That is evidence, not an answer.

So it gets tested, and the test has to be built so that passing it means
something.

**What must be proved:** a token minted from a *refresh token*, in a
*different process*, after the browser session that did the picking is
*gone*, can still read the picked file.

1. Register a development client (Web application, `drive.file`).
2. In a browser, run auth-code + PKCE with `access_type=offline`.
   Keep the refresh token.
3. Open the Picker, pick one file, record its id.
4. **Destroy the browser session.** Close it, clear cookies, ideally
   move to another machine. Doing this step in the same tab is how the
   test passes while proving nothing.
5. Discard the original access token and wait out its hour.
6. In a separate process, holding only the refresh token: mint a new
   access token and `GET /drive/v3/files/<id>?alt=media`.

200 means durable and `direct` mode is viable. 404 means session-scoped,
`direct` collapses into `spool`, and the ID-addressed plugin was wasted
effort. Note it is **404 and not 403**: under `drive.file` a file the app
was never granted does not exist as far as the app is concerned, which is
the distinction `gdrive2_plugin.describe_http_error` already explains to
whoever reads the hold reason.

**Two controls, or a failure is uninterpretable.** Without them a 404 at
step 6 cannot be told from a broken refresh:

- Read a file the app *created* rather than picked, with the same
  refreshed token. If that fails too, the refresh is the problem, not the
  grant.
- Read the picked file immediately at step 3 with the original access
  token, to establish that the grant ever existed.

**A trap in the setup itself.** An External OAuth client left in
*Testing* publishing status has been reported to expire refresh tokens
after seven days. A dev client will be in Testing. If refresh starts
failing about a week in, that is the consent screen's publishing status
and not a finding about `drive.file` — and it is exactly the sort of
thing that gets written down as a limitation of the design.

**Worth answering in the same sitting**, because standing the client up
is the expensive part and the rest is minutes:

- Does a *folder* pick grant its children? That is the second open
  question, and the same harness answers it.
- Does the grant survive refresh-token rotation?
- Does revoking and re-granting the app reset it?
- Is picking the same file twice idempotent?

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
  wasted. See "Answering the grant-durability question"; verify before
  building `direct`.
- **Folder picking under `drive.file`** — whether picking a folder
  usefully grants its contents, which decides whether "pick a directory
  of inputs" is offerable.
- **Can a job-supplied plugin claim a method name already advertised by
  a stock plugin?** Still unknown, and no longer blocking: the design
  chose a distinct method for its own reasons. The half that mattered is
  answered — `SetRequirements` excludes a method the job supplies itself
  from the generated `TARGET.HasFileTransferPluginMethods` clause
  (`submit_utils.cpp:6337`), so a job carrying `gdrive2` needs no execute
  node to advertise it and `direct` can be tried before anything is
  deployed. Worth confirming on a real pool before relying on it.
- **Vault kind is unbuilt and unneeded so far.** It is in the table above
  because the entry point must not be shaped in a way that excludes it,
  not because anything has asked for it. Build it when an access point
  turns out to need it.
