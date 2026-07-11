# Security remediation tracking

Source: parallel security audit (auth/authz, frontend, injection, tool labeling),
2026-05-09. The unified findings list is in conversation history.

## User-overrides on the audit

- **#1 (`userHeader` trust):** keep functional for demo/test. Off by default;
  to enable in production, operator must pass an explicit trusted-proxy CIDR
  list. To enable for demo/test, an explicit `--trust-user-header-unsafe` (or
  equivalent) flag with a loud startup warning.
- **#2 (anonymous OAuth2 registration → `condor:/ADMINISTRATOR`):** AUDIT
  WAS WRONG. The server intersects requested `condor:/*` scopes with a
  user-side calculation (groups). This is unlike scitokens, where scopes
  override remote authz. Action: add a code comment noting this distinction
  for future readers; no code change.
- **#9 (MCP tools missing `Owner ==` wrapper):** apply `scopeToOwner` for
  *non-admin* users only. Admins skip the wrapper.
- **#21 (`/metrics` unauthenticated):** record in findings doc; defer fix
  until API-token functionality lands.

## Plan

Phase A — quick wins (≤ 20 lines each):

- [x] Set up tracking doc
- [x] Verify the scope-intersection claim in code; add explanatory comment
- [x] Security headers middleware (CSP / nosniff / frame-options / referrer-policy)
- [x] `isSafeLocalRedirect` in `redirectToLogin`
- [x] `Content-Disposition: attachment` + `nosniff` on /files/
- [x] `confirm: true` on `run_in_job`
- [x] POST-only on `/logout`

Phase B — structural:

- [x] Trusted-proxy CIDR gating for `userHeader` + demo opt-in flag
- [x] Verify JWT signature before caching `Username`
- [x] Apply scope-to-owner wrapper to MCP `toolGetJob`, `toolAnalyzeJobMatch`,
       `toolRemoveJobs`, `toolQueryHistory` (admins exempt)
- [x] Session cookie `SameSite=Strict`

Phase C — additional HIGH items:

- [x] Reject `..` / `\x00` / leading `/` in tar upload entry names
- [x] WebSocket `CheckOrigin` validation
- [x] `tools/list` filtering by caller scope
- [x] `handleJobOutputShare` ownership check
- [x] `tools/list` description leak — addressed by scope filtering

Phase D — MEDIUM:

- [x] GPU/CUDA submit-string validation
- [x] Move read-only history + credd-list tools to `readOnlyTools` allowlist
- [x] CORS `Allow-Origin` pinned to configured base URL

## Deferred (need separate work)

- `/metrics` auth (#21): needs API-token feature. Captured in
  SECURITY_FINDINGS.md.
- Per-scope consent checkboxes (#3): UI work; planned but not in this batch.
- Templates "shared by other user" labelling (#18): SPA UX change.

## Notes

- Run `go test ./...` and `go test -tags embed_condor_docs ./...` after
  every batch to catch regressions.
- The `userHeader` change must NOT break
  `httpserver/session_integration_test.go` or other tests that rely on
  it; gate via the new opt-in flag.

## Final state (2026-05-09)

- All planned items from Phases A–D done.
- `go test ./...` (no tags): all green.
- `go test -tags "embed_condor_docs embed_jupyter_helper" ./...`: all green.
- `golangci-lint run ./...`: 3 pre-existing issues unrelated to this
  work (`templates/templates.go` const-comment, `templates_test.go`
  ifElseChain, `schedd_peek.go` unused const). The pre-existing
  `handlers_multipart_test.go` revive issue was fixed in passing
  per the user's request.
- Two test cases needed updating to reflect the new policy:
  - `TestLogoutEndpoint` now expects 405 on GET (was 200)
  - `TestSessionCookie` now expects `SameSite=Strict` (was Lax)
  Both updates point at the audit doc.

## Touched files (for change-set review)

Production code:
- `httpserver/handler.go` — security headers, WebSocket Origin check,
  trusted-proxy CIDR for userHeader, response-status capture for
  lazy JWT validation, CORS Origin allowlist.
- `httpserver/auth.go` — `Validated` flag, `MarkValidated` /
  `ValidatedUsername`, request-token context plumbing.
- `httpserver/server.go` — userHeader trusted-source gate; cached
  username read replaced with `ValidatedUsername`.
- `httpserver/handlers.go` — `Content-Disposition: attachment` +
  `application/octet-stream` on `/files/`; POST-only `/logout`.
- `httpserver/handlers_share.go` — owner verification before share
  token sign.
- `httpserver/handlers_jupyter.go`,
  `httpserver/handlers_ssh.go` — switched WebSocket upgraders to
  per-Handler factories with origin check.
- `httpserver/handlers_jupyter.go`,
  `httpserver/handlers_interactive.go` — GPU submit-string
  whitelist.
- `httpserver/mcp_handlers.go` — userHeader trusted-source gate at
  three call sites, scope filter via `mcpserver.IsReadOnlyTool`,
  `WithGrantedScopes` plumbing into MCP dispatch, comment fix on
  `extractUsernameFromToken`, and the new explanatory comment on
  `mapCondorScopesToAuthz`.
- `httpserver/oauth2_sso.go` — `isSafeLocalRedirect` re-validation
  on callback, comment on condor:/* scope grant.
- `httpserver/routes.go` — CORS Allow-Origin pinned.
- `httpserver/session.go` — `SameSite=Strict`.
- `httpserver/submit_string_validate.go` (new) — GPU whitelist.
- `httpserver/tarvalidate.go` (new) — tar entry name validation.
- `mcpserver/server.go` — `Config.AdminUsers`.
- `mcpserver/handlers.go` — scope-to-owner applied to four tools,
  `tools/list` filtering, `IsReadOnlyTool` export.
- `mcpserver/handlers_docs.go` — (no security changes; condordocs
  tooling from earlier batch).
- `mcpserver/owner_scope.go` (new) — scope-to-owner helper +
  classadStringLit + isAdmin.
- `mcpserver/tarvalidate.go` (new) — tar entry name validation.
- `frontend/src/components/Sidebar.tsx` — `<a href="/logout">`
  replaced with POST button via `api.auth.logout()`.

Tests updated:
- `httpserver/handlers_test.go` — GET /logout now 405.
- `httpserver/session_test.go` — SameSite=Strict.
- `httpserver/handlers_multipart_test.go` — pre-existing revive fix
  (unused-parameter).

Docs:
- `SECURITY_REMEDIATION.md` (this file).
- `SECURITY_FINDINGS.md` (deferred items).
