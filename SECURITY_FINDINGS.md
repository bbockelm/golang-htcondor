# Security findings — open items

This is the carry-forward list from the 2026-05-09 security audit.
Items addressed in the same change are tracked in
`SECURITY_REMEDIATION.md`; this doc captures the items that need
follow-up work.

## Deferred — needs prerequisite work

### `/metrics` exposed unauthenticated — RESOLVED

**Audit ref:** Auth M5.
**Where:** [`httpserver/handlers.go`](httpserver/handlers.go), the
`handleMetrics` auth gate.

`/metrics` now requires a server-minted API key carrying the
`metrics` scope. Admins mint keys via `/admin/api-keys` (the new
admin page); Prometheus presents the key as a Bearer token. The
gate checks three things in order:

1. `HTTP_API_METRICS_PUBLIC=true` — operator opt-out for sites where
   the endpoint is already isolated by network ACLs. Default false.
2. The request must authenticate via API key (NOT a session cookie
   or JWT — Prometheus has no cookie jar and a regular user token
   has no business hitting `/metrics`).
3. The key must carry the `metrics` scope.

The API-key feature also addresses the "what about the other
findings about labels?":
- [x] Add a `metrics` scope and an admin-mintable token capability.
- [x] Gate `/metrics` on either an opt-in public flag OR a valid
      `metrics`-scoped API key.
- [ ] Audit the labels we emit; consider hashing or dropping the
  `user` dimension entirely if the scraper doesn't need
  per-user breakdowns. *Still open — the gate prevents
  unauthenticated leak, but a scraper with a valid key still sees
  the labels.*


## Recently closed (2026-05-09 follow-up batch)

### Per-scope consent checkboxes — DONE

The OAuth2 consent page now renders each requested scope as a
checked checkbox (`openid` is rendered as a fixed/required item
because OIDC mandates it). The POST handler intersects the
form-supplied accepted set with both the originally-requested set
and the group-policy filter (`getScopesForGroups`). For the device
flow, `OAuth2Storage.ApproveDeviceCodeSessionWithScopes` lets the
verify-page write the user's narrowed `granted_scopes` back to the
device-code row so the subsequent token exchange honors the
narrowing.

Code: `httpserver/mcp_handlers.go` (`renderConsentPage`,
`handleOAuth2Consent` POST branch, `handleOAuth2DeviceVerify`
approve branch, `narrowDeviceApprovalScopes`),
`httpserver/oauth2_storage.go` (`ApproveDeviceCodeSessionWithScopes`).

### Shared-template author labelling — DONE

The submit-page template picker now flags "shared by others" rows
with an amber pill carrying the owner's username, and the
selected-template detail card shows an amber warning banner when
the author isn't the current user, prompting the user to review
the template body and default input files before submitting.

Code: `frontend/src/app/submit/page.tsx`.

## Notes on items addressed elsewhere

The following audit findings were addressed in code; see
`SECURITY_REMEDIATION.md` and the individual commit messages for
detail. Listed here so this doc is complete:

- Auth C1 (userHeader trust): trusted-proxy CIDR gating with a
  loud demo opt-in (`UserHeaderTrustAnyUnsafe`).
- Auth C2 (anonymous registration → admin scope): explanatory
  comment added in `mapCondorScopesToAuthz` and
  `getScopesForGroups`. Audit was wrong on the framing —
  `condor:/*` scopes narrow rather than expand schedd authz, and
  `mapCondorScopesToAuthz` already drops ADMINISTRATOR / CONFIG /
  DAEMON / NEGOTIATOR.
- Auth H3 (JWT signature trust): tokens now have a `Validated`
  flag set by a 2xx-response middleware (lazy validation).
  Identity reads use `ValidatedUsername` which returns "" until
  the schedd handshake has accepted the token at least once.
- Auth H4 (`extractUsernameFromToken` confused logic): comment
  updated to reflect actual behavior.
- Frontend C1 (XSS via /files/): `Content-Disposition: attachment`
  + `nosniff` + global CSP.
- Frontend C2 (open redirect): `isSafeLocalRedirect` applied in
  `redirectToLogin` and re-validated at the OAuth2 callback.
- Frontend H1-H4: WebSocket Origin check, POST-only logout, CSP +
  X-Frame-Options + nosniff + Referrer-Policy middleware, CORS
  Allow-Origin pinned to httpBaseURL.
- Tool H1 (`run_in_job` no confirm): `confirm: true` set.
- Tool H2 (MCP tools missing owner scope): `scopeToOwner`
  applied to `toolGetJob`, `toolAnalyzeJobMatch`, `toolRemoveJobs`,
  `toolQueryHistory` (admins exempt via `Config.AdminUsers`).
- Tool H3 (`tools/list` unfiltered): scope-gated filter wired
  from the HTTP transport.
- Injection H2 (tar entry traversal): `validateTarEntryName`
  rejects `..`, NUL, leading `/`, and backslash on both upload
  paths.
- Injection M1 (GPU submit-string injection):
  `validateGPUSubmitFields` whitelist applied in both
  `InteractiveCreateTerminalRequest.validate` and
  `JupyterCreateRequest.validate`.
- Auth H1 (handleJobOutputShare ownership): owner verification
  via schedd query before signing the share token.
- Auth H2 (session SameSite): switched to `SameSite=Strict`.
- Tool MEDIUM-1 (read-only history/credd tools required write):
  added to `readOnlyMCPTools` and consumed via
  `mcpserver.IsReadOnlyTool` from both the in-package list filter
  and the httpserver scope gate.
