# Site apps

Serving a lab's own web interface from this access point, to the people
it belongs to. Part of the [HTTP API + MCP server](server.md)
documentation.

A research group wants a submission page of their own: drop some input
files, set two or three things, pick a pipeline, submit, watch it run.
Their pipelines are specific to their science and have no business in
an HTCondor release, and the general-purpose web interface is the wrong
shape for someone who did not come here to learn about batch systems.

A **site app** is that page: static files — HTML, CSS and JavaScript —
that the group builds and you serve, at `/site/<id>/`, to the groups
you name. Because it is served from this server, the visitor's existing
session is already there: the app calls `/api/v1/...` and is
authenticated. The group writes no login code and registers no OAuth2
client.

The feature is off until `HTTP_API_SITE_APPS_DIR` is set. An access
point that does not set it serves no `/site/` routes at all.

## Deploying one

A group gives you two files — a bundle and its checksum:

```bash
scp cryoem.zip cryoem.zip.sha256 ap.example.edu:/etc/condor/webapps/
```

You decide, once, who may see it:

```
# /etc/condor/config.d/51-site-apps.conf
HTTP_API_SITE_APP_CRYOEM_GROUPS = smith_lab
HTTP_API_SITE_APP_CRYOEM_HOME   = true
```

```bash
condor_reconfig -daemon htcondor-api
```

The app is then served at `/site/cryoem/`. A reconfigure re-reads every
site app's policy and rescans the directory, so it takes effect at
once; without one the next rescan picks it up within
`HTTP_API_SITE_APPS_RELOAD_INTERVAL`.

**A bundle no configuration names is not served**, and says so in the
log. Who may see an app is your decision, never the bundle's: a bundle
that names its own groups is refused outright. The app's author has no
idea which groups exist here, and their natural placeholder is
"everyone".

### Why configuration rather than a file beside the bundle

Every other group gate this server has —
`HTTP_API_WEBUI_ACCESS_GROUP`, `HTTP_API_WEBUI_ADMIN_GROUP`,
`HTTP_API_SUPERUSER_GROUP`, the MCP ones — is an `HTTP_API_*`
parameter. Keeping these with them means `condor_config_val -dump
HTTP_API` answers "who can see what here?" in one place, and your
configuration management deploys an access point without a second
mechanism to learn.

### The parameters

An app is `cryoem` if its bundle is `cryoem.zip`. Its parameters are
named after it, upper-cased:

| Parameter | Meaning |
| --- | --- |
| `HTTP_API_SITE_APP_<ID>_GROUPS` | Required. Comma-separated groups that may see the app. `*` means every authenticated user. Nothing is published without it, and an empty value publishes nothing rather than publishing to nobody. |
| `HTTP_API_SITE_APP_<ID>_HOME` | Members of an app-only group land here instead of the dashboard. See [App-only sessions](#app-only-sessions). |
| `HTTP_API_SITE_APP_<ID>_ENABLED` | `false` withdraws the app without deleting it. Absent means enabled. |
| `HTTP_API_SITE_APP_<ID>_NAME` | Override what the bundle calls itself. |
| `HTTP_API_SITE_APP_<ID>_DESCRIPTION` | As above, for the one-line description. |
| `HTTP_API_SITE_APP_<ID>_ICON` | As above, for the icon. |

Group names are compared case-insensitively, because a Unix group, a
file and an OIDC claim do not agree about case often enough to make an
exact match safe.

### The id is the file name

`cryoem.zip` is the app `cryoem`, served at `/site/cryoem/` and
configured by `HTTP_API_SITE_APP_CRYOEM_*`. The bundle carries no id of
its own.

Upgrading is replacing the file. Trying a new version alongside the
running one is copying it to `cryoem_next.zip` and giving
`HTTP_API_SITE_APP_CRYOEM_NEXT_GROUPS` your own account — a separate
app, at a separate URL, with its own policy, from the same artifact.
The app does not need rebuilding to be served under the second name.

A hyphen in an id becomes an underscore in the parameter name, since a
hyphen inside an HTCondor parameter name reads as subtraction wherever
the name is used in an expression. That makes `my-app` and `my_app` the
same parameter, so deploying both refuses **both** rather than guessing
which policy was meant for which; rename one.

### Checking what arrived

`cryoem.zip.sha256`, if present, is verified before the app is
published; a mismatch refuses it and logs loudly. Zip's own per-entry
checksums do not cover this case: an interrupted copy produces an
archive that opens cleanly and serves part of the app.

Every bundle is hashed whether or not a `.sha256` accompanies it, and
the hash is recorded (see [What has been served](#what-has-been-served)).
The sidecar is what turns "these are the bytes we found" into "these
are the bytes the author sent".

If the group's build is reproducible — `make bundle` in the starter
repository below produces identical bytes from identical source — you
can also rebuild from their tagged commit and compare, which answers
"is what is deployed what they shipped?" rather than only "did it
arrive intact?".

## Publishing from the web interface

Off by default. An administrator who can upload a bundle and name its
groups can run code in those users' browsers, with their session: a
site app is served same-origin and can do anything its visitor can. So
it is a grant of its own rather than something administering this
server implies.

```
HTTP_API_SITE_APPS_UPLOAD = true
```

With it set, **Site Apps** under the admin pages gains a form. The
bundle is written into `HTTP_API_SITE_APPS_DIR` as `<id>.zip` -- the
same place an scp would put it -- and who may see it is recorded in the
application database rather than in the configuration.

**The configuration still wins.** An id named by
`HTTP_API_SITE_APP_<ID>_GROUPS` cannot be uploaded over, withdrawn, or
re-scoped from the web: the upload is refused, naming the parameter to
edit. An app published by the configuration is read-only on that page
whatever this setting says. Without that rule, uploading would be a way
around the decision the configuration had already made.

Each listed app says which decision published it, so "why is this
visible?" is answerable from the page.

Leaving this off is a reasonable choice for an access point whose
configuration is managed centrally: the page still shows what is
published and what has been, and says where to put a bundle.

### Installing from a GitHub release

A bundle published as a release asset can be fetched by the access
point instead of attached by hand. On the publish form, choose **From a
GitHub release** and give the repository as `owner/name` -- or paste
its URL, which is what you have if the repository is open in another
tab.

The page reads the repository as you type it. It says whether GitHub
has it, lists the releases it has published to choose from, and names
the bundle it found in the one you chose, so the only release that can
be asked for is one that exists. Where a release attaches more than one
`.zip` -- the one case the access point refuses to guess at -- it asks
which. Where it attaches none, it says so rather than letting the
install start.

If the browser cannot reach GitHub, which a rate limit or a proxy will
do, the lists give way to boxes: type a tag, or leave it blank for the
latest. That is a browser's limitation and not the access point's, and
the install still goes through the server as it otherwise would.

What this does, in order: asks GitHub which release is meant, takes the
release's only `.zip` (or the asset you name, where there is more than
one), reads the `.sha256` published beside it, downloads the bundle,
and **refuses it unless the bytes hash to what that checksum says**.
Only then does it become the file the app is served from. The checksum
is written into the bundle directory too, so every later rescan
re-verifies it rather than taking this one download's word.

The repository must be public. Fetching a private one needs a GitHub
credential stored on the access point, which is a secret with its own
rotation and blast radius; download the asset yourself and attach it
instead.

Two things worth knowing about how this is built:

* **You give a repository, not a URL.** This is the one request the
  access point makes on a caller's behalf, and it runs inside your
  network, where a general "fetch this address" endpoint could reach a
  daemon's admin port or a cloud metadata service. The server builds
  the address from the pieces, and follows redirects only while they
  stay on GitHub's hosts.
* **The server downloads; your browser checks for updates.** GitHub
  allows a page to read release metadata cross-origin but not to read
  the asset, so the two halves cannot live in the same place.

The release that was installed is recorded against the app. The page
then shows where each app came from, and marks one whose repository has
since published a different release — a link, not a demand: a site that
pinned an older tag on purpose is told what is current and decides for
itself. That check is made by the browser that is looking at the page,
so the access point does not poll GitHub on a schedule.

Set `HTTP_API_SITE_APPS_GITHUB = false` to leave this out, on an access
point with no route to the internet. Attaching a file still works.

### Settings on the page

Opening an app's row shows its settings as the parameters above:
`HTTP_API_SITE_APP_<ID>_GROUPS` and its siblings, under the names
`condor_config_val` answers to, with what is set and what is merely in
force -- a `NAME` nobody set reads as the bundle's own label rather
than as a value to maintain.

For an app this page published, those settings can be changed there.
They are kept in the application database, and the change takes effect
on the rescan the write triggers: no `condor_reconfig`, no restart.
`ENABLED` is shown and not settable, because an app it disables leaves
the page with no way back; **Withdraw** is how to stop serving one.

For an app the configuration publishes, they are read-only and say so.
Nothing typed into this access point could take effect for such an id
-- the configuration is consulted first, and the server refuses the
change rather than recording one that would never apply.

## What has been served

The configuration says what you intend. It cannot tell you what was
running in October: a bundle replaced in place leaves nothing behind,
and a configuration file only ever describes now.

So each scan records what it published, in `site_app_incarnations` in
the application database. A row is one app, served from one artifact,
under one policy, over a period — `first_seen` to `last_seen`. A scan
that finds nothing changed extends the open row; a new bundle, or a
change to who may see it, opens another. An app that stops being served
is simply not mentioned again, and its row's `last_seen` is when it
stopped.

```sql
-- What was being served on 3 October, and to whom?
SELECT app_id, version, digest, app_groups
  FROM site_app_incarnations
 WHERE first_seen <= unixepoch('2026-10-03') AND last_seen >= unixepoch('2026-10-03');
```

`version` and `revision` are whatever the bundle's `app.yaml` claimed,
which is the author's word rather than a checked fact — `digest` is the
checked one. Recording is not a condition of serving: a database that
cannot be written is logged and the apps stay up.

## App-only sessions

Some users should not meet the general-purpose console at all:

```
HTTP_API_WEBUI_APP_ONLY_GROUP = smith_lab, jones_lab
```

Members land in their app instead of the dashboard, and the navigation
collapses to their apps. The bar across the top of every app (below)
offers them an **Expert mode** link, which opens the full console for
that browser session.

**This is presentation, not authorization.** The API is unchanged, every
console page is still reachable by typing its URL, and the expert link
is one click. It exists so that someone who came here to run a pipeline
is not handed a batch system console they did not ask for. Do not rely
on it to keep anyone out of anything; use
`HTTP_API_WEBUI_ACCESS_GROUP` and the ordinary authorization settings
for that.

A session counts as app-only only when *every* group it holds is named
here. Somebody who is also in a staff group keeps the console.

Users with more than one `home` app land on `/site/`, which lists the
apps they can open. That page is also the right thing to put in a lab
wiki: it resolves per-viewer, so the same link sends each person to
their own set.

## The bar

Every page of every app carries a bar across the top: the site's name,
the app you are in, the caller's other apps, and the way back to the
full console. It is drawn into a shadow root with `all:initial`, so the
app's stylesheet cannot reach it and its own styles cannot leak into
the app.

The way back is always there. An app-only session gets **Expert mode**,
which opens the console for that browser session; everybody else gets
**Full console**, a plain link to `/`. It is there even when there is
only one app and nothing to switch to: a user who can use the console
must always be offered it.

The bar sets `--htcondor-shell-height` on `<html>` and pushes the page
down by that much. An app with a fixed header of its own should clear
it:

```css
.my-header { top: var(--htcondor-shell-height, 0px); }
```

An app that cannot live under it declines:

```html
<meta name="htcondor-shell" content="none">
```

That costs the app the switcher and the way back, so `/site/` stays one
URL away and always lists what the caller can open.

## Writing one

Point the group at
[htcondor-site-app-template](https://github.com/bbockelm/htcondor-site-app-template).
It is a working submission app with a `Makefile`, a typed API client,
and CI that runs against a real access point. `make bundle` produces
the zip and its checksum.

Four things their build must respect, all covered in that repository's
`AGENTS.md`:

- **Static files only.** No server side runs here.
- **A relative base path.** The app is told where it is mounted at
  serve time, through an injected `<base href>` and
  `window.__HTCONDOR_APP__`. Nothing may hardcode `/site/<id>/`, which
  is what lets the same bundle be served under a second name.
- **No external scripts, fonts or images.** The server sends
  `Content-Security-Policy: default-src 'self'` and the browser will
  block them.
- **Nothing secret in the bundle.** It is static files served to every
  member of its groups; an API key committed to it is disclosed to all
  of them.

## What a site app can do

Everything the signed-in visitor can do, through the ordinary API —
there is no separate permission system. Submit with
`POST /api/v1/jobs`, attach dropped files with
`POST /api/v1/jobs/{id}/input/multipart`, watch the queue with
`GET /api/v1/jobs/watch`. See the [API surface](server-api.md).

That is also the limit worth understanding before you install one: a
site app runs with the full rights of whoever is looking at it, in code
that is not in this release and not reviewed here. For a group's own
staff that is usually an easy call. It should still be a knowing one.

## Settings

| Knob | Effect |
| --- | --- |
| `HTTP_API_SITE_APPS_DIR` | Directory holding `<id>.zip` bundles. Unset disables site apps entirely — no `/site/` routes are registered. Changing it needs a restart. |
| `HTTP_API_SITE_APPS_RELOAD_INTERVAL` | How often that directory is rescanned, as a Go duration (`30s`, `5m`). Default one minute. Changing it needs a restart. |
| `HTTP_API_SITE_APP_<ID>_*` | One app's policy; see [The parameters](#the-parameters). Re-read on every `condor_reconfig`, which also rescans the directory. |
| `HTTP_API_SITE_APPS_UPLOAD` | Whether administrators may publish a bundle from the web interface. Off by default; see [Publishing from the web interface](#publishing-from-the-web-interface). |
| `HTTP_API_SITE_APPS_GITHUB` | Whether a bundle may be fetched from a GitHub release rather than attached. On by default, and only consulted where `HTTP_API_SITE_APPS_UPLOAD` is already on; see [Installing from a GitHub release](#installing-from-a-github-release). |
| `HTTP_API_WEBUI_APP_ONLY_GROUP` | Comma-separated groups whose members land in their app rather than the dashboard. Reloaded on SIGHUP. |

An unpacked directory works in place of a zip, with the same layout, for
hand-editing during development. Zip is what to deploy.

## When an app does not appear

Every reason a bundle is not published is logged with the bundle's
name. Look there first — the server has already decided, and a 404 from
a browser looks the same whatever the reason.

| Log says | Means |
| --- | --- |
| `cryoem.zip is present but no configuration names who may see it` | Set `HTTP_API_SITE_APP_CRYOEM_GROUPS` and reconfigure. |
| `names groups, but no bundle ... has that id` | A policy with no bundle: a typo in the parameter name, or the zip was never copied across. |
| `share the configuration name` | Two bundles whose ids differ only by `-` versus `_`. Rename one; neither is published. |
| `bundle digest mismatch` | The file on disk is not the one that was built. Copy it again. |
| `app.yaml names groups, which a bundle cannot set` | The group put `groups` in their bundle. It belongs in your configuration. |
| `bundle has no web/index.html` | The bundle is laid out wrongly; `make bundle` in the starter repository gets this right. |

An app that loads but is not visible to the person asking is a group
mismatch: `GET /api/v1/auth/me` reports the groups the server resolved
for them, which is what `HTTP_API_SITE_APP_<ID>_GROUPS` is matched against.
