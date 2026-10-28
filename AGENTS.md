# AGENTS.md

Notes for automated agents working in this repo. Keep it short; add only non-obvious things that have bitten us.

## This is a multi-module repo

`go.mod` files live in several places, not just the root:

- **App modules** (`APP_MODULE_DIRS` in the Makefile): `.`, `webapi`, `localcredmon`.
- **`examples/*`** and other test clients each have their own module too.

The sub-modules `replace github.com/bbockelm/golang-htcondor => ../`, so they build against the **local** root. That means:

> **After changing any dependency (e.g. bumping `github.com/bbockelm/cedar`), a root-only edit is not enough.** Every module that replaces the root must be re-tidied to the same version, or the `webapi` jupyter-helper build and the CI **Tidy check** fail.

Do **not** hand-loop `go mod tidy`. Use the Makefile:

```sh
make tidy-all     # go mod tidy in EVERY module (app + examples + test clients)
make tidy-check   # exactly what CI runs; fails if any go.mod/go.sum is not tidy
make tidy         # app modules only (., webapi, localcredmon)
```

Always run `make tidy-all` after a dependency bump and commit the resulting `go.mod`/`go.sum` changes across all modules.

## Build / lint / test use `GOWORK=off`

CI (and the Makefile targets) run with `GOWORK=off` so each module resolves its own `go.mod`. A local `go.work` may point at sibling checkouts (e.g. a local `../golang-cedar` on a feature branch) — handy for cross-repo work, but it can make the IDE and a bare `go build` disagree with CI. When verifying a change the way CI will see it, prefix with `GOWORK=off`.

## Lint

`make lint` runs `golangci-lint` per module with `GOWORK=off`. The root package (`.`) is large: linting it locally can take many minutes cold, while CI's `Lint (.)` job finishes in ~20s with a warm cache. Prefer letting CI lint the root package rather than blocking on a slow local run; lint the smaller sub-packages/modules locally for fast feedback.

## We are a dbrpc client against mirrors we do not control

`webapi` reads the htcondordb mirror over `dbrpc`. The mirror is upgraded on
its operators' schedule, so this code meets servers both older and newer than
itself. The rules live in the `classad` repo's `AGENTS.md`; three matter here.

**Ask, do not probe.** `Client.Supports(Feature)` answers from what the server
advertised in the CEDAR handshake, so a supported feature dispatches with no
fallback path. The `Err*Unsupported` sentinels are for a server that advertises
nothing — reach for one only then, and say so in a comment.

**`SupportUnknown` is not `SupportNo`.** Every feature predates advertisement.
Treating silence as refusal degrades every mirror older than the advertisement.

**Put the fallback where the accumulator is.** The streaming helpers here take
the caller's `yield`, and the caller is what accumulates — `dec.row`,
`batch.AddAd`, `append(members, ...)`. A retry inside the helper re-runs that
closure and double-counts. `utilizationFromMirror` has the right shape: the
retry wraps the function that owns the decoder, not the query.

## Projected reads return at least their closure

A projected read may return more attributes than it asked for, and callers must
tolerate that. What it will not return is less than the transitive closure of
the projection: `RequestMemory` is commonly an expression over `MemoryUsage`,
and `MemoryUsage` over `ResidentSetSize`, so a projection that drops the
siblings evaluates to undefined and the page shows a dash — or worse, a number
derived from a partial ad.

So when a read path parses rows and evaluates attributes (`utilization.FromAd`,
`runtimeest`, `evaluateUsageAttrs`), it needs the closure. Where a response has
a projection contract to keep, fetch the closure and trim before writing, as
`withHistoryOrderAttr`/`dropHistoryOrderAttr` already does.

A test for any of this needs ads whose attributes are expressions. Against a
corpus of literals both the closure and its absence pass.
