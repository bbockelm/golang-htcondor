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
