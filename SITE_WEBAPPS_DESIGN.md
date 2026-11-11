# Site Web Apps

Serving site-authored static web apps from the HTCondor API server, scoped to authorization groups.

## Motivation

A researcher wants a submission interface for her lab: drag and drop some input files, set two or three knobs, pick a pipeline, submit, watch it run. Her grad student will build it. The pipelines are specific to her science and have no business in an HTCondor release.

The same request arrives from any site with a domain-specific workflow and users who are expert in that domain and nowhere near expert in batch computing. The stock web UI is a general-purpose access point console: a dashboard, a queue, a pool view, an archive, a submit page that can express any job. For these users almost all of that is noise, and some of it is noise they can click on.

Two things are needed, and they are separable:

1. A way for a site to serve its own web app from the API server, visible only to the groups it names.
2. A way to make that app the whole of the web UI for users who should not be looking at the rest of it.

## Non-goals

**This is not a security boundary.** Users of a site app authenticate the same way as everyone else, hold the same session, and reach the same API. Nothing here reduces what their credential can do; a user who types `/jobs` after taking the expert-mode door gets the stock queue page and it works. The goal is that confusing surfaces are not *presented*, not that they are unreachable. Where the design does enforce something — group-gated serving of app content — that is called out explicitly and is enforced server-side on every byte.

**This is not an app runtime.** A site app is static files. It has no server side on the API host, no build step we run, no sandbox. It is HTML, CSS, JavaScript and assets, served from a bundle an operator dropped in place, calling the same HTTP API the stock UI calls.

**This does not prescribe how an app submits work.** Some apps will use the batch-submission templates (`HTTP_API_TEMPLATE_GLOBAL_PATH`); some will build submit files themselves; some are DAG-shaped and want a workflow, not a batch. The app contract is the HTTP API, not any one submission idiom. See [DAG submission](#dag-submission-is-mcp-only) for the one real gap this exposes.

## Why same-origin static files, and not a standalone app

The alternative design is a separate web app on its own host that proxies to the API as an OAuth2 client. That remains available and supported — `POST /mcp/oauth2/register` is RFC 7591 dynamic client registration, the device-code flow exists, and `HTTP_API_BASE_URL` configures CORS for a known second origin. For a team with its own deployment story it is the better answer.

It is the wrong default here because of what it costs the grad student. A separate origin means an OAuth2 client registration, a redirect URI, token storage, refresh handling, a backend to hold the client secret, and a deployment. Served same-origin from the API host, the app's first line of networking is:

```js
const me = await fetch('/api/v1/auth/me', { credentials: 'include' }).then(r => r.json());
```

The session cookie is already set, because the user logged into the API server to get here. Uploading the dropped files is `POST /api/v1/jobs/{id}/input/multipart` with a `FormData` — the same call [frontend/src/lib/api.ts:1277](webapi/frontend/src/lib/api.ts#L1277) makes. There is no authentication code in the app at all.

That is the whole argument. The deployment story is: `npm run build`, copy `out/` to the access point, done.

## Concepts

A **site app** is a zip bundle holding a manifest and a static web app, plus a policy file the operator writes beside it. Its id comes from the file name; its name and description come from the bundle; the groups that may see it, and whether it is a *home*, come from the policy file.

A **home** is where a user lands instead of the dashboard. It is a property of the app, not of the user, which means a user in two groups can have two homes. That is a supported state, not an edge case (see [Multiple homes](#multiple-homes)).

**App-only** is a property of a *group*: members of an app-only group get their home instead of the dashboard, and the stock UI's navigation collapses. They are not confined there — see [Expert mode](#expert-mode).

The **shell** is a thin bar the server overlays on every site app, carrying the app switcher and the expert-mode door. It is how a user gets out of an app without knowing any URLs.

## Bundle format

A site app is distributed as **one zip file**, dropped into `HTTP_API_SITE_APPS_DIR` beside a small YAML file the operator writes.

```
/etc/condor/webapps/
  cryoem.zip            the app, built by the lab
  cryoem.yaml           site policy, written by the operator
  cryoem.zip.sha256     optional integrity check
  seqqc.zip
  seqqc.yaml
```

The model is the WAR file: a single artifact that lands atomically. Copying a directory tree into a live server's content root is a sequence of non-atomic operations with a window in the middle where `index.html` is new and half the chunks it references are old, and no way to tell from the outside whether a half-finished `rsync` is the reason the app is broken. A rename over one file has no such window, and the thing that arrived is either the whole bundle or not there at all.

Inside the zip, the app lives under `web/` and the manifest sits at the root:

```
cryoem.zip
  app.yaml
  web/
    index.html
    assets/...
```

The nesting is load-bearing: the handler serves `fs.Sub(bundle, "web")`, so `app.yaml` is structurally unreachable over HTTP rather than excluded by a rule somebody can forget to apply to the next root-level file.

### The app id is the file name

`cryoem.zip` is the app `cryoem`, served at `/site/cryoem/`, configured by `cryoem.yaml`. The in-zip manifest carries no id at all.

Ids beginning with `_` are reserved for the server (`/site/_shell.js`, `/site/_switch`), so a bundle named `_shell.zip` is refused at load. Ids are otherwise restricted to the characters that are unambiguous in a URL path segment and a file name both.

Deriving the id from the file name instead of from the manifest removes an entire class of confusion. Upgrading is replacing `cryoem.zip`. Staging a candidate alongside production is copying it to `cryoem-next.zip`, which is a different app at a different URL with its own policy file, with no risk of the new bundle's manifest claiming the running app's id. Two bundles can never fight over one id, because the filesystem already settled it.

### Two manifests, with different authors

`app.yaml` inside the bundle is written by the app author and describes what the app *is*:

```yaml
# inside cryoem.zip
name: CryoEM Pipeline
description: Submit and track cryo-EM reconstruction runs
icon: microscope
```

`cryoem.yaml` beside the bundle is written by the operator and decides what the app is *allowed to be*:

```yaml
# /etc/condor/webapps/cryoem.yaml
groups: [smith_lab]
home: true
enabled: true
```

The sidecar wins key by key, so an operator who only needs to set `groups` writes only `groups` and inherits the author's name and description. But **`groups` is operator-only**: it is ignored if it appears inside the bundle, and it has no default.

That asymmetry is the most important rule in this document. The app author ships a demo manifest and has no idea which groups exist at a given site. If `groups` were inheritable from the bundle, an operator who drops a zip in and forgets the sidecar publishes whatever the author happened to write — and the author's natural placeholder is "everyone." Making it operator-only means the quiet failure is impossible by construction.

**A bundle with no sidecar is not served.** The loader registers nothing and logs `cryoem.zip present but cryoem.yaml missing; not published`. Fail-closed, and discoverable from the log rather than from a user mentioning that they can see the neuroscience lab's pipelines.

### Integrity

`cryoem.zip.sha256`, if present, is verified before the bundle is published; a mismatch refuses to publish and logs loudly rather than serving what arrived. Absent, the bundle loads unverified.

Zip's per-entry CRC32 already catches corruption, but only in an entry someone reads, and not at all for an archive truncated at a valid entry boundary — which is exactly what an interrupted `scp` produces. The whole-file digest is what makes "the bundle on disk is the bundle you built" checkable, and it doubles as the cheap change-detection key for reload.

Reload follows the `HTTP_API_MCP_SKILLS_DIR` precedent: rescan on an interval, notice `(mtime, size)` changes, re-verify the digest, and swap the opened bundle under an `atomic.Pointer` the way [webapi/httpserver/groupset.go](webapi/httpserver/groupset.go) swaps group lists. A request in flight finishes against the bundle it started with.

### Directories still work

A path that is a directory rather than a zip loads the same way, with `app.yaml` at its root and the app under `web/`. This is for hand-editing during development and for the one-page app that does not deserve a build step. Both forms land on `fs.FS`, so nothing downstream of the loader knows the difference.

Zip is what the documentation shows and what the starter app produces.

### Safety bounds

A bundle is site-supplied data read by a privileged daemon, so the loader bounds it: entry count, total uncompressed size, and per-entry size, all refused at load time rather than discovered at serve time. `zip.Reader.Open` already enforces `fs.ValidPath`, which rejects absolute paths and `..`, and `isSafeEmbeddedPath` in the SPA handler is the second layer — but the loader should reject a bundle containing an invalid name outright, rather than publishing an app with unreachable entries in it.

## Routing and the group gate

```
GET /site/                      switcher: the caller's apps, nothing else
GET /site/_shell.js             the overlay script
GET /site/{id}/...              the app, gated on {id}'s groups
```

`/site/` sorts above the SPA's `/` catch-all in [webapi/httpserver/routes.go:67](webapi/httpserver/routes.go#L67) without any ordering care: Go's `ServeMux` prefers the longer pattern.

**The gate runs on every request under `/site/{id}/`, not just the HTML.** The app's own JavaScript is likely to name pipelines, parameters and instrument models; a bundle served to a non-member leaks the thing the groups exist to scope. There is no public-assets carve-out.

| Caller | Response |
|---|---|
| No session | 302 to `/login?return_to=...` |
| Session, not in the app's groups | 404 |
| Session, in the app's groups | the file |
| Unknown app id | 404 |

404 rather than 403 for a non-member: the set of app ids is itself site information, and a 403 confirms existence. There is no usability cost, because nothing in a non-member's UI ever links there.

Every response under `/site/` carries `Cache-Control: private, no-store`. These are group-gated bytes and must not land in a shared cache in front of the access point.

`/api/v1/auth/me` grows a list containing only the caller's apps:

```json
{
  "authenticated": true,
  "username": "jsmith",
  "groups": ["smith_lab"],
  "app_only": true,
  "site_apps": [
    { "id": "cryoem", "name": "CryoEM Pipeline", "url": "/site/cryoem/", "home": true }
  ]
}
```

This is the single source of truth for the shell, the switcher, the stock UI's sidebar, and the app-only redirect. Nothing else computes app visibility.

## Serving the app

The SPA handler in [webapi/httpserver/webui/handler.go:17](webapi/httpserver/webui/handler.go#L17) already does everything a site app needs: exact file, `.html` suffix resolution, Next.js `[param]` -> `_` dynamic-route resolution, `index.html` fallback for client-side routing, and `isSafeEmbeddedPath` validation at the single `serveFile` chokepoint.

It takes no arguments today and reads the package's embedded `dist`. Split it:

```go
// NewSPAHandlerFS serves a static export from an arbitrary fs.FS.
func NewSPAHandlerFS(fsys fs.FS) http.Handler

// NewSPAHandler keeps serving the embedded frontend, via NewSPAHandlerFS.
func NewSPAHandler() http.Handler
```

`zip.Reader` implements `fs.FS`, so a bundle needs no adapter: the loader hands `fs.Sub(zipReader, "web")` to `NewSPAHandlerFS` behind `http.StripPrefix` and the group gate, and a directory bundle hands `fs.Sub(os.DirFS(dir), "web")` to the same call.

The path-safety logic is unchanged and now matters more. `embed.FS` could not reach anything outside the binary; a directory bundle can reach the real filesystem. `isSafeEmbeddedPath` already rejects `..`, absolute paths, `//` and anything `path.Clean` would alter, and `os.DirFS` refuses escaping paths independently. The comment in that file calling this defense in depth should be updated to say it is now load-bearing.

### Entries must be materialized

Zip entries are neither seekable nor cheap to re-read: each `Open` starts a fresh `flate` stream. `http.ServeFileFS` wants an `io.ReadSeeker` to answer range requests and to compute content length, and a zip entry is not one.

So the zip-backed handler reads an entry fully into memory and serves it from a `bytes.Reader`, behind a small size-bounded cache keyed on entry name. SPA bundles are a few megabytes of assets that every user fetches, so the cache hit rate is approximately one; the cap exists to bound a pathological bundle, not to manage pressure. Range requests, `ETag` and `If-None-Match` all work normally off the materialized bytes.

This is the one place where zip and directory bundles genuinely differ, and the only reason the handler needs to know which it has.

### The bundle does not know where it is mounted

A static build normally bakes its base path into every asset URL at build time, which would weld `cryoem.zip` to the id `cryoem` and make a rename — the staging trick described above — silently break every asset.

Instead the server tells the app where it lives, at serve time. When it injects into an HTML response it emits three things into `<head>`:

```html
<base href="/site/cryoem/">
<script>window.__HTCONDOR_APP__={"id":"cryoem","base":"/site/cryoem/","name":"CryoEM Pipeline"}</script>
<script src="/site/_shell.js" defer></script>
```

`<base href>` resolves every relative asset URL, so the bundle builds with a relative base (`base: './'` in Vite) and is genuinely portable: the same zip works dropped as `cryoem.zip` or `cryoem-next.zip`, with no rebuild.

`window.__HTCONDOR_APP__` is what the client-side router reads for its basename, and it is the value apps should use rather than inferring a prefix from `location.pathname`. Two caveats make this the documented path rather than a nicety: `<base href>` also reparents in-page fragment links and form actions, which surprises people; and an app doing `history.pushState` needs the prefix as a string regardless. Telling the app its base explicitly is cheaper than having every app rediscover these.

The inline `<script>` is permitted by the existing CSP (`script-src 'self' 'unsafe-inline'`, [webapi/httpserver/handler.go:2231](webapi/httpserver/handler.go#L2231)) — the same allowance the Next.js static export already relies on.

### The app contract

Everything a site app author must know:

- **Static build, no SSR.** Build with a relative base: Vite `base: './'`. Do not hardcode `/site/<id>/`.
- **Read `window.__HTCONDOR_APP__.base`** for client-side routing. Do not parse `location.pathname`.
- **Call the API with `credentials: 'include'`.** No tokens, no headers.
- **Read `/api/v1/auth/me` for identity.** Do not parse cookies.
- **On 401, go to `/login?return_to=<current path>`.**
- **CSP is `default-src 'self'`.** Same-origin scripts and inline styles are fine; a Google Fonts link or a CDN script is not. Vendor it.
- **Ship `app.yaml` with a name and description, and no `groups` key.** The site decides who sees the app.

### Useful endpoints for a submission app

| Need | Endpoint |
|---|---|
| Who am I | `GET /api/v1/auth/me` |
| Submit | `POST /api/v1/jobs` with `{"submit_file": "..."}` |
| Upload dropped files | `POST /api/v1/jobs/{id}/input/multipart` |
| Watch the queue | `GET /api/v1/jobs`, or `GET /api/v1/jobs/watch` (SSE) |
| Job detail, logs, output | `GET /api/v1/jobs/{id}`, `.../output` |
| Site pipelines, if used | `GET /api/v1/templates` |
| DAG structure | `GET /api/v1/jobs/{id}/dag` |

Operator-wide submit policy ([webapi/submitpolicy/submitpolicy.go](webapi/submitpolicy/submitpolicy.go)) applies to anything a site app submits, as it does to every other surface. An app does not need to know the site's `log =` rule.

## The shell overlay

A user in a site app needs a way back out, and a user with two apps needs a way across. Neither can depend on the app implementing it: the app is site code we do not review, and the one thing worse than a confusing console is a page with no exit.

**The server injects into the app's HTML responses.** Before serving a `text/html` response under `/site/{id}/`, insert the `<base>`, `window.__HTCONDOR_APP__` and `_shell.js` block described above, before `</head>`. Assets pass through untouched. If the shell tag is already present the server does not add a second one, so an app that wants to control placement can include it itself and opt out of that part.

The injection is therefore doing two jobs at once — telling the app where it is mounted, and giving the user a way out of it — and an app cannot opt out of the first. That is deliberate: a bundle that never learns its base path is broken, and that must not depend on site code remembering a tag.

`_shell.js` fetches `/api/v1/auth/me`, and renders nothing at all unless the user has more than one app or is eligible for expert mode. When it does render, it attaches a `<div>` to `document.body` and puts the bar in a **shadow root**. Shadow DOM is the whole reason this is tolerable: the app's CSS cannot reach into the bar and the bar's cannot leak out, so we are not negotiating specificity with a stranger's Tailwind build.

CSP compatibility is already in place. `script-src 'self'` admits `/site/_shell.js`; `style-src 'self' 'unsafe-inline'` admits a `<style>` inside the shadow root. The shell uses no inline `<script>` and no `eval`.

Layout is the honest weak point. A fixed bar can overlap an app's own fixed header. The shell sets `--htcondor-shell-height` on `:root` and applies `scroll-padding-top`; an app that cares reads the variable. An app that fights it can opt out with `<meta name="htcondor-shell" content="none">`, and in exchange must provide its own way back — the switcher at `/site/` is always a link away and always correct.

### Mechanics of injection

HTML cannot go through `http.ServeFileFS`, which serves the file's bytes with its own length and range handling. Read it, inject, and serve with `http.ServeContent` over a `bytes.Reader`, with an ETag computed from the injected bytes rather than the file. Cap the size of a file eligible for injection; an `index.html` is kilobytes, and anything large enough to be worth streaming is not an entry point.

For a zip bundle the entries are being materialized into memory anyway, so injection costs one string operation on an already-decompressed buffer, and the injected result is what the cache holds.

An HTML file with no `</head>` gets the block prepended to the body instead of being silently left alone. A hand-written `index.html` without a head is a plausible thing for a site to ship, and it needs its base path like any other.

### The alternative we are not taking

An iframe shell — a server-rendered nav page framing the app — needs no HTML rewriting, has perfect CSS isolation, and is already permitted by `frame-ancestors 'self'` and `X-Frame-Options: SAMEORIGIN`. It loses the URL bar: in-app navigation does not change the address, so deep links and bookmarks need `postMessage` plumbing the app would have to implement, and nested scrolling plus drag-and-drop across a frame boundary is unpleasant on exactly the file-drop interaction these apps are built around. Keep it in reserve for an app that cannot live with the overlay; do not make it the default.

## Multiple homes

Group memberships overlap, so a user can have more than one home. This falls out of the design rather than being designed for, and the handling is small:

- **Exactly one home** — the app-only redirect goes there.
- **More than one home** — the redirect goes to `/site/`, a server-rendered switcher listing the caller's apps and, if eligible, the expert-mode door. Plain, keyboard-navigable, no build step.
- **No home, but one or more apps** — no redirect; the apps appear in the stock sidebar as ordinary links.

The shell bar carries the switcher on every page of every app, so a user who lands in the wrong one is one click from the right one and never has to know a URL.

`/site/` is also the correct destination for a bookmark, a link in a lab wiki, or an email from the PI: it resolves to the right place for whoever opens it.

## Expert mode

Members of an app-only group get a redirect, not a cage.

```
HTTP_API_WEBUI_APP_ONLY_GROUP = smith_lab, jones_lab
```

A middleware in front of the SPA handler: if the session's groups are all within the app-only set, and the request is not already under `/site/`, `/login`, `/logout`, `/api/`, `/.well-known/` or a static asset, 302 to the user's home (or `/site/`). The stock SPA additionally reads `app_only` from `/api/v1/auth/me` and collapses its sidebar to the apps plus a way back, so a user who arrives by any other route does not meet a dashboard.

The shell bar's **Expert mode** link opens the door. It sets a session-scoped `site_expert` cookie — same attributes and lifetime as the session cookie, cleared on logout — and the middleware stops redirecting while it is set. The stock UI then renders normally, with a persistent "Back to CryoEM Pipeline" affordance in the sidebar so the return trip is as easy as the trip out.

Three properties worth stating, because they are the point:

- **It is a door, not a privilege.** No group governs it, nothing is audited, and the API has not changed. A user who types `/jobs` directly reaches the queue whether or not they ever clicked the link. Expert mode makes the full UI *presented* rather than *permitted*.
- **It expires with the session.** Nobody acquires a permanently cluttered console by having been curious once.
- **It is visible.** The user pressed something labeled "Expert mode" and can see how to get back. Compare with a hidden query parameter, which is the same mechanism with worse ergonomics and a folklore problem.

## The starter app

A site app is easy to serve and not obvious to write. The author is typically a graduate student who knows the science, has built a web page before, and has never seen an HTCondor submit file. What they need is not documentation but a repository that already works, which they can change until it is theirs.

`htcondor-site-app-template` is a **GitHub template repository** — "Use this template" rather than "Fork", so the lab's repo starts with its own history and does not carry a fork relationship it will never use.

Cloned and run, it is a working submission app: drop files, set two knobs, pick a pipeline, submit, watch the jobs finish. It is not a skeleton with `TODO` comments. The first thing the student does is delete the parts they do not want, which is a much better first task than assembling the parts they do.

### Layout

```
app.yaml                 name, description, icon. No groups.
Makefile
AGENTS.md
README.md
web/
  index.html
  vite.config.ts         base: './'
  src/
    main.tsx
    app.tsx              the demo flow, meant to be replaced
    lib/api.ts           typed client for the endpoints below
    lib/htcondor.ts      window.__HTCONDOR_APP__, login redirect on 401
e2e/
  submit.spec.ts
  fixtures/login.ts
.github/workflows/ci.yml
```

**Vite and React, not Next.js.** The stock UI is Next and this is a deliberate divergence. Next's static export is a trap for someone who has not used it before: the natural thing to write is a server component, and the failure is a build error about a feature that works fine in every tutorial. Vite has one base-path setting, no server-side anything to misuse, and a dev server that proxies to the API in four lines. The template should be boring.

`src/lib/api.ts` is the highest-leverage file in the repository. It is a small typed client — submit, upload, list, watch, cancel — modeled on [webapi/frontend/src/lib/api.ts](webapi/frontend/src/lib/api.ts) and covering the endpoints in the table above. Without it the first thing a newcomer does is invent an endpoint that does not exist, and the first thing they learn is a 404.

### Makefile

```make
APP ?= $(notdir $(CURDIR))

dev:      ## Vite dev server, proxying /api to a local htcondor-api
build:    ## production build into web/dist
bundle:   ## build + package dist/$(APP).zip and dist/$(APP).zip.sha256
test:     ## unit tests
e2e:      ## playwright against a demo htcondor-api container
lint:
check: lint test build   ## what CI runs, runnable locally
clean:
```

`make bundle` is the deliverable:

```make
bundle: build
	rm -rf dist/stage && mkdir -p dist/stage/web
	cp app.yaml dist/stage/
	cp -R web/dist/. dist/stage/web/
	find dist/stage -exec touch -t 198001010000 {} +
	cd dist/stage && zip -qrX ../$(APP).zip .
	cd dist && shasum -a 256 $(APP).zip > $(APP).zip.sha256
```

The `touch` and `-X` are there to make the bundle **reproducible**: no timestamps, no extra attributes, so the same source produces the same bytes and the same digest. That turns the checksum from a corruption check into an identity — a site can tell whether the zip on the access point is the one that came out of a given commit, and a rebuild that changes nothing produces no diff to review.

Deployment is then two files and a restart-free reload:

```
scp dist/cryoem.zip dist/cryoem.zip.sha256 ap.example.edu:/etc/condor/webapps/
```

The operator writes `cryoem.yaml` once, the first time.

### CI

The workflow mirrors the two-suite split already proven in [.github/workflows/playwright.yml](.github/workflows/playwright.yml), because that file has already paid for discovering what is flaky:

1. **Lint, unit test, build, bundle.** Fast, no services. Uploads the bundle as a build artifact, so every green commit has a downloadable zip.
2. **End-to-end**, only if the first passed. Start the published API container in demo mode:

   ```yaml
   docker run -d --name api -p 8443:8443 ghcr.io/bbockelm/golang-htcondor:<tag> --demo
   ```

   Demo mode runs a personal HTCondor and the built-in IdP, seeds an `admin` and a `user` account, and prints the generated password. CI scrapes it from the container logs — the same trick [.github/workflows/playwright.yml](.github/workflows/playwright.yml) uses, including its failure message when the line never appears. Then drop the freshly built bundle into the container's apps directory, log in through the real OAuth flow with the `login.ts` fixture, and drive the app.

Running the real server rather than mocking it is the point. A lab app's most likely bug is a wrong assumption about the API — a field that is a string and not a number, a 202 where a 200 was expected, a job that is `held` because spool upload has not finished. Fixtures freeze those assumptions instead of testing them.

The template ships perhaps three e2e tests: the page renders, a submit reaches the queue, the job list updates. Enough to demonstrate the shape, few enough that nobody deletes the suite in frustration.

**Demo mode needs a deterministic credential for CI.** Scraping the password out of a log line works and is what we do today, but it is the kind of thing that breaks on an unrelated logging change and strands every downstream lab repo at once. A `--demo-password` flag, or honoring an environment variable, would make the template's CI a published contract rather than an impression of one. Small, and worth doing before the template is advertised.

### AGENTS.md

Lab apps will be written with an AI assistant, whether or not we plan for it. A good `AGENTS.md` in the template is the cheapest leverage available on quality, because it is read before the first line of code and applies to every change after.

It should carry:

- **The API contract.** The endpoint table, the `credentials: 'include'` rule, and an instruction to check `/openapi.json` on the running demo server rather than guessing. Agents invent plausible REST routes; this is the single most valuable paragraph in the file.
- **The platform constraints.** CSP forbids external scripts and fonts — vendor them. Build with a relative base. Read `window.__HTCONDOR_APP__.base` for routing. Never hardcode `/site/<id>/`.
- **The audience.** The users are domain experts and not computing experts. Prefer one obvious control over three flexible ones. Never surface a raw submit file, a ClassAd expression or a HoldReasonCode without translating it. An error must say what to do next.
- **The loop.** `make check` before claiming anything works; `make e2e` for anything touching submission. Do not add a dependency without saying why in the commit message.
- **What not to do.** No credentials, API keys or tokens in the bundle — it is static files served to the browser, and anything in it is public to every group member. No telemetry to third parties. Do not re-implement authentication; the session cookie is already there.

The same file is useful to a human on their first day, which is a reasonable test of whether it says anything worth saying.

## Configuration

| Macro | Meaning |
|---|---|
| `HTTP_API_SITE_APPS_DIR` | Directory holding `<id>.zip` bundles and their `<id>.yaml` policy files. Unset disables the feature entirely — no `/site/` routes are registered. |
| `HTTP_API_SITE_APPS_RELOAD_INTERVAL` | Rescan interval, mirroring `HTTP_API_MCP_SKILLS_RELOAD_INTERVAL`. A bundle whose `(mtime, size)` changed is re-verified and swapped in; dropping a new zip therefore needs no restart and no signal. |
| `HTTP_API_WEBUI_APP_ONLY_GROUP` | Comma-separated groups whose members land in their home and get a collapsed sidebar. |

Group resolution uses the existing machinery unchanged: `HTTP_API_GROUP_SOURCE` (token, system, or file), parsed by [webapi/httpserver/groupsource.go](webapi/httpserver/groupsource.go), held in the atomic `groupSet` of [webapi/httpserver/groupset.go](webapi/httpserver/groupset.go), reloadable on SIGHUP.

## Trust model

**A site app runs with the full rights of the user viewing it.** Same origin, same session cookie, same API. That is the feature — it is why the app needs no authentication code — and it is also the cost: a compromised dependency in a site app's `node_modules` can do anything the user can do, in code that is not in our release and not in our review.

This should be stated plainly in the admin documentation, because an operator installing a site app is extending their trust boundary to whoever wrote it, at the same level as the stock UI. For a lab's own grad student that is usually an easy call; it should still be a knowing one. The escape hatch, when it stops being easy, is the standalone OAuth2 client on a separate origin, where the app holds a scoped token instead of the user's session.

Three narrower notes:

- The group gate is real authorization and is enforced server-side on every request. Nothing about the non-adversarial user assumption applies to it.
- The app-only redirect is presentation. It must never be described in documentation as a restriction, or someone will eventually rely on it as one.
- **The bundle is a supply chain.** A zip is easier to hand around than a directory, which is the point and also the risk: a bundle can be emailed, and the person who drops it on the access point may not be the person who built it. The `.sha256` sidecar proves the file arrived intact, not that it came from anyone in particular. Reproducible bundles narrow the gap — an operator can rebuild from the lab's tagged commit and compare digests — but the honest statement is that installing a bundle is trusting its author, and the server does not check that trust. Signing is the real answer and is deferred, not dismissed.

Nothing in the bundle is secret. It is static files served to every member of its groups, so an API key or a password compiled into it is disclosed to the whole group. This belongs in the author documentation and in `AGENTS.md`, because it is exactly the mistake a hurried build pipeline makes.

## Gaps in the existing code

**DAG submission is MCP-only.** `submit_dag` is a tool in [webapi/mcpserver/handlers_dag.go:108](webapi/mcpserver/handlers_dag.go#L108); the REST API has only `GET /api/v1/jobs/{id}/dag` for reading a submitted workflow's structure. A DAG-shaped site app — and the pipeline apps this design exists to serve are a likely source of them — has no REST route to submit one. Its options today are to replicate `condor_submit_dag`'s scheduler-universe submit file and POST it to `/api/v1/jobs`, or to go through MCP. Neither is reasonable to ask of a site app author. `webapi/dagman.SubmitFile` already builds the submit file and is already driven by the MCP handler; a `POST /api/v1/dags` wrapping the same call is small. **This should land before or with the first DAG-shaped site app**, and arguably on its own merits regardless.

**Global submit templates have no group scoping.** `templates.All()` ([webapi/templates/templates.go:439](webapi/templates/templates.go#L439)) makes built-in and global entries visible to every caller; the private/shared distinction applies only to user-saved templates. A lab that puts its pipelines in `HTTP_API_TEMPLATE_GLOBAL_PATH` publishes them to every user's submit picker. An optional `groups:` key on global template entries is the matching fix. This is not a prerequisite — an app need not use templates at all — but a site that does use them will hit it immediately.

**CORS allows exactly one origin.** `HTTP_API_BASE_URL` configures the single origin echoed back with credentials ([webapi/httpserver/routes.go:47](webapi/httpserver/routes.go#L47)). This does not affect site apps, which are same-origin, but it does constrain the standalone-app fallback to one browser-side client unless the app proxies server-side. Worth knowing before recommending that path to a second group.

**`apps` is already taken.** `/api/v1/apps` is long-lived servers running inside a job — code-server and its eventual siblings ([webapi/httpserver/handlers_apps.go](webapi/httpserver/handlers_apps.go)). That file's own header records choosing "apps" over "sessions" because `interactive` had already spent that word twice. `/site/` keeps this design clear of a third collision, and "site app" is the term to use in documentation and code.

## Implementation outline

Roughly in dependency order; the phases are separately shippable and separately useful.

**Phase 1 — serve and gate.** New `webapi/siteapps` package: the two manifest types and their merge, the bundle loader (zip and directory) with safety bounds, digest verification, reserved-id rejection and interval reload, and per-caller visibility. Split `webui.NewSPAHandlerFS` out of `NewSPAHandler` and add the materializing cache for zip entries. Register `/site/{id}/` behind the group gate with `Cache-Control: private, no-store`. Inject `<base>` and `window.__HTCONDOR_APP__` into HTML. Add `site_apps` and `app_only` to `AuthMeResponse`. At this point an operator can drop a bundle and a policy file and serve a group-scoped app reachable by URL.

**Phase 2 — navigation.** The `/site/` switcher. Stock sidebar renders the caller's apps. At this point users can find their app.

**Phase 3 — app-only and expert mode.** `HTTP_API_WEBUI_APP_ONLY_GROUP`, the redirect middleware, the `site_expert` cookie, the collapsed sidebar and the "back to app" affordance.

**Phase 4 — the shell.** `_shell.js`, the `htcondor-shell` opt-out meta, the shadow-root bar. The injection path itself already exists from phase 1, which carries the base-path block; this adds the script tag to it. Last because phases 2 and 3 already leave every user with a way out; the shell makes it one click instead of two.

**Phase 5 — the template.** `htcondor-site-app-template` as a public template repository, with the working demo app, the Makefile, the two-suite CI and `AGENTS.md`. It can be built against phase 1 alone — the shell and app-only mode are site configuration, not app concerns — but should not be advertised until `--demo-password` (or its equivalent) exists, so the labs that clone it inherit CI that will not break on an unrelated logging change.

A note on sequencing: phases 1 and 5 are the only ones a site genuinely needs. Everything between them is about users who have more than one app or who should not be seeing the dashboard, and a first deployment has neither problem.

Testing worth calling out specifically, since the quiet failure here is serving science to the wrong group: assert that a non-member gets 404 for a **nested asset** path, not merely for the app root. A test that only checks `/site/cryoem/` passes against a gate wired up on the HTML alone.

## Open questions

- Should an app be able to declare required credentials (`HTTP_API_REQUIRED_CREDENTIALS` is per-deployment today), so a pipeline needing an OAuth2 credential can prompt rather than fail at submission?
- Is a per-app submit policy wanted — the `submitpolicy` Defaults/Overrides hooks scoped to jobs submitted from a given app — or is site-wide policy plus the app's own submit file enough? Site-wide is enough to start, and per-app wants a trustworthy way to attribute a submission to an app, which the session alone does not provide.
- Should `/site/` be the landing page for *everyone* at a site that configures apps, with the dashboard one click away, rather than only for app-only groups? That is a larger change to the stock UI's shape and should wait for a site that wants it.
- **Signed bundles.** The server already holds signing keys (`HTTP_API_SIGNING_KEY`, and the pool key used by superuser mode). A detached signature beside the zip, verified against an operator-configured set of authorized publishers, would turn "trusting the author" from a social arrangement into a checkable one — and would matter most in the case this design makes easy, where a bundle travels between institutions. Deferred because the first deployments are a PI handing a file to their own sysadmin, where it buys little.
- Should the template's bundle carry provenance — the source repository, commit and build time, written into `app.yaml` by `make bundle` and surfaced on an admin page? Cheap to add, and it answers "what is actually running" without a digest comparison. Probably yes; left out of the first pass to keep the manifest small.
- Is one app per zip the right granularity, or will a lab want several related apps sharing a build? One per zip, until somebody asks: the file-name-is-the-id rule is most of what makes this design simple to reason about, and a multi-app bundle gives it up.
