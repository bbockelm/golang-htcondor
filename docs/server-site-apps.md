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

You write one more, once, naming who may see it:

```yaml
# /etc/condor/webapps/cryoem.yaml
groups: [smith_lab]
home: true
```

The server notices within `HTTP_API_SITE_APPS_RELOAD_INTERVAL` and
serves it at `/site/cryoem/`. No restart and no signal.

**A bundle with no policy file beside it is not served**, and says so
in the log. Who may see an app is your decision, never the bundle's: a
bundle that names its own groups is refused outright. The app's author
has no idea which groups exist here, and their natural placeholder is
"everyone".

### The policy file

| Key | Meaning |
| --- | --- |
| `groups` | Required. Groups that may see the app, as a YAML list. `["*"]` means every authenticated user. There is no default, and an empty list is an error rather than "nobody". |
| `home` | Members of an app-only group land here instead of the dashboard. See [App-only sessions](#app-only-sessions). |
| `enabled` | `false` withdraws the app without deleting it. Absent means enabled. |
| `name` / `description` / `icon` | Override what the bundle calls itself, for a site that wants its own wording. |

Group names are compared case-insensitively, because a Unix group, a
file and an OIDC claim do not agree about case often enough to make an
exact match safe.

### The id is the file name

`cryoem.zip` is the app `cryoem`, served at `/site/cryoem/` and
configured by `cryoem.yaml`. The bundle carries no id of its own.

Upgrading is replacing the file. Trying a new version alongside the
running one is copying it to `cryoem-next.zip` and writing a
`cryoem-next.yaml` that names only yourself — a separate app, at a
separate URL, with its own policy, from the same artifact. The app does
not need rebuilding to be served under the second name.

### Checking what arrived

`cryoem.zip.sha256`, if present, is verified before the app is
published; a mismatch refuses it and logs loudly. Zip's own per-entry
checksums do not cover this case: an interrupted copy produces an
archive that opens cleanly and serves part of the app.

If the group's build is reproducible — `make bundle` in the starter
repository below produces identical bytes from identical source — you
can also rebuild from their tagged commit and compare, which answers
"is what is deployed what they shipped?" rather than only "did it
arrive intact?".

## App-only sessions

Some users should not meet the general-purpose console at all:

```
HTTP_API_WEBUI_APP_ONLY_GROUP = smith_lab, jones_lab
```

Members land in their app instead of the dashboard, and the navigation
collapses to their apps. A bar across the top of every app offers their
other apps and an **Expert mode** link that opens the full console for
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
| `HTTP_API_SITE_APPS_DIR` | Directory holding `<id>.zip` bundles and their `<id>.yaml` policy files. Unset disables site apps entirely — no `/site/` routes are registered. |
| `HTTP_API_SITE_APPS_RELOAD_INTERVAL` | How often that directory is rescanned, as a Go duration (`30s`, `5m`). Default one minute. |
| `HTTP_API_WEBUI_APP_ONLY_GROUP` | Comma-separated groups whose members land in their app rather than the dashboard. Reloaded on SIGHUP. |

An unpacked directory works in place of a zip, with the same layout, for
hand-editing during development. Zip is what to deploy.

## When an app does not appear

Every reason a bundle is not published is logged with the bundle's
name. Look there first — the server has already decided, and a 404 from
a browser looks the same whatever the reason.

| Log says | Means |
| --- | --- |
| `cryoem.zip is present but cryoem.yaml is missing; not published` | Write the policy file. |
| `its policy file names no groups` | `groups` is required; `["*"]` publishes to every authenticated user. |
| `bundle digest mismatch` | The file on disk is not the one that was built. Copy it again. |
| `app.yaml names groups, which a bundle cannot set` | The group put `groups` in their bundle. It belongs in your policy file. |
| `bundle has no web/index.html` | The bundle is laid out wrongly; `make bundle` in the starter repository gets this right. |

An app that loads but is not visible to the person asking is a group
mismatch: `GET /api/v1/auth/me` reports the groups the server resolved
for them, which is what the policy file is matched against.
