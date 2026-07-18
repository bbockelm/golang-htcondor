# Web API Module Split & JWT Consolidation

Status: **Implemented** (Phases 1 & 2) · Multi-module refactor of `golang-htcondor`

## Motivation

`golang-htcondor` mixed two very different things in one Go module:

1. **The core HTCondor library / daemon framework** — the protocol client, collector,
   schedd, master, credd, file transfer, `classadlog`, `qmgmt`, `daemon` lifecycle,
   `sharedport`, `startd`, `param`/`config`, `authz`, `sessioncache`, `ratelimit`,
   `logging`, `metricsd`. This is what the other daemon repos import.

2. **The web application** — the OAuth2 issuer (`ory/fosite`), web UI (`frontend`,
   Next.js embed), embedded docs (`condordocs`), `mcpserver`, chat, API keys, the batch
   submit `templates` library, the `matchanalyzer`, and the JupyterLab tunnel.

Because it was a single module, **every consumer of the core library inherited the web
layer's transitive dependency tree** — ~1041 lines of `go.sum`, dominated by `ory/fosite`
(→ `ory/x`, `gorm`, `gobuffalo/pop`, `spf13/viper`, the OTel stack, `prometheus`,
`go-jose`, `cristalhq/jwt`) plus `glebarez/sqlite`, `modernc/sqlite`, and `goose`.

The seam was already clean at the import level — no core package imported the web/OAuth
stack; all dependency arrows pointed *from* the web layer *into* core — so this was a
module-boundary change, not an untangling of reverse edges.

## Result: multi-module monorepo

The core keeps its module path at the repo root (downstream repos need no import changes);
the web layer and the credential monitor become nested modules. A committed `go.work` ties
them together for local dev; each nested module also carries `replace ... => ../` so it
builds standalone (matching the existing `examples/*` convention).

```
golang-htcondor/                     # repo root
├── go.work                          # use ( . ./webapi ./localcredmon )
├── go.mod                           # github.com/bbockelm/golang-htcondor          (CORE, lean)
├── collector.go, schedd.go, …       # core client/protocol API (path unchanged)
├── daemon/ classadlog/ qmgmt/ …     # core subpkgs (incl. ratelimit, sessioncache, metricsd)
│
├── webapi/
│   ├── go.mod                       # …/golang-htcondor/webapi                     (WEB, heavy)
│   ├── httpserver/  mcpserver/  condordocs/  frontend/
│   ├── templates/  matchanalyzer/  jupytertunnel/
│   ├── examples/schedd_address_update/
│   └── cmd/{htcondor-api,htcondor-mcp,htcondor-jupyter-helper}/
│
└── localcredmon/
    ├── go.mod                       # …/golang-htcondor/localcredmon               (lean daemon)
    ├── localcredmon.go
    └── cmd/htcondor-localcredmon/
```

### Dependency footprint (go.sum lines)

| Module | Before | After |
|---|---:|---:|
| core (root) | 1041 | **107** |
| webapi | — | ~1022 |
| localcredmon | — | ~26 |

Core now carries **zero** fosite/OAuth/OTel/gorm/viper/prometheus dependencies.

### What moved to `webapi/`

Everything that only the web layer imports: `httpserver` (+ `chat`, `appdb`, `apikey`,
`webui`, `jupyterhelperbin`, `seal`), `mcpserver`, `condordocs`, `frontend`,
`jupytertunnel`, `templates`, `matchanalyzer`, the three web `cmd/`s, and the
web-dependent `examples/schedd_address_update`.

`templates` and `matchanalyzer` are web-specific (only httpserver/mcpserver use them), so
they moved too. The only obstacle was `submit_template_test.go`, a root-package test that
walked the built-in templates through the core submit parser. It was split:

- The two pure submit-parser tests stay in core as `submit_inline_queue_test.go`.
- The templates round-trip test moved to `webapi/templates/builtin_submit_test.go` as an
  external (`templates_test`) test that imports both the core `htcondor` package (for
  `ParseSubmitFile`) and the `templates` library.

### What stayed in core

`ratelimit` (used by root `security.go`), `sessioncache` (used by `daemon/`), `metricsd`,
and the whole protocol/daemon surface.

### localcredmon is its own module

It is a credential-monitor daemon, not part of the web app, and after the JWT change it
needs only `golang-jwt` (plus the core library) — so it is a third, lean module rather
than living under `webapi/`.

## JWT consolidation (Phase 1)

Before: three JWT code paths — `golang-jwt/jwt/v5` (parse/verify in httpserver, mcpserver,
token_fetch), `lestrrat-go/jwx/v2` (localcredmon signing), and fosite's bundled
`ory/fosite/token/jwt`.

**Standardized on `golang-jwt/jwt/v5`.** `localcredmon`'s RS256/ES256 signing was rewritten
from jwx to golang-jwt (`jwt.NewWithClaims(method, MapClaims{…}).SignedString(key)`), and
`cmd/htcondor-localcredmon`'s `loadPrivateKey` now returns a `jwt.SigningMethod`. jwx and its
7 transitive modules (`decred/.../secp256k1`, `goccy/go-json`, `segmentio/asm`, four
`lestrrat-go/*`) dropped out. golang-jwt has **zero** third-party dependencies, which is why
it wins for the lean core/daemon side; fosite's own bundled jwt remains, confined to webapi.

A new `localcredmon/token_sign_test.go` exercises both RS256 and ECDSA sign→verify
round-trips (the daemon previously had no unit tests).

## Build system

- **`go.work`** lists the three app modules (core, webapi, localcredmon). It deliberately
  excludes `examples/*` (standalone modules with `replace => ../..`) and `reference/*`
  (vendored copies of `cedar`/`swamp` that would otherwise shadow the real dependencies).
- **Makefile**: `MODULE_PATTERNS := ./... ./webapi/... ./localcredmon/...` drives
  `build`/`test`/`test-integration`/`test-race`. Embed/asset paths repointed under
  `webapi/` (`FRONTEND_DIR`, `WEBUI_DIST`, `CONDOR_DOCS_DST`, `JUPYTER_HELPER_EMBED_DIR`);
  the api/jupyter-helper builds target `./webapi/cmd/...`. `examples` builds with
  `GOWORK=off`.
  - `tidy`: tidies the three app modules (GOWORK=off, per-module).
  - `tidy-all`: **new** — `find`s every `go.mod` in the repo (app modules, examples, any
    future test clients) except `reference/`, `node_modules/`, and build caches, and runs
    `go mod tidy` in each with GOWORK=off.
- **CI/Docker** updated for the moved paths and multi-module patterns: `.github/workflows/
  ci.yml` (vet/test/build span all three; examples build with `GOWORK=off`),
  `docker-test.yml`, `release-binaries.yml` (frontend + artifact + build paths), and
  `Dockerfile.release`. These could not be executed locally — **run a CI dry-run / test tag
  before relying on the release pipeline.**

## Notes & caveats

- **fosite pinned to v0.47.0.** Recreating `webapi/go.mod` initially re-resolved fosite to
  v0.49.0, whose `CoreStorage` interface added `CreateRefreshTokenSession` (runtime panic in
  the oauth tests) and which is incompatible with the older `ristretto` the code builds
  against. `webapi/go.mod` was seeded from the original root module's exact version set so
  the web dependency graph is byte-for-byte the pre-refactor one. This refactor performs **no**
  functional dependency upgrades.
- **Pre-existing test failure, not a regression:** `httpserver.TestGetDefaultDBPath`'s
  "empty config" subtest depends on the core `config` package's `$(TILDE)`/`LOCAL_DIR`
  param-default resolution and only passes where HTCondor is installed (i.e. in CI, not on
  a bare macOS dev box). The tested code and test are unchanged by this refactor.

## Not done (future)

- Absorbing the per-daemon repos (`collector`, `ap`, `ep`, `ccb`) as additional nested
  modules under `daemons/`. `cedar` stays an external tagged dependency (its own release
  chain) unless/until that chain is deliberately retired.
