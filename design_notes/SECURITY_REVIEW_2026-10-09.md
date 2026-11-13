# Security review findings — 2026-10-09

Target: `origin/main` @ `28266da` (2026-10-09). Root module (CEDAR client library) plus
`webapi/` (htcondor-api, MCP, SSH gateway). Cedar pinned at `v0.7.1`; the relevant cedar code
is unchanged in v0.7.2 / v0.7.3.

Line numbers refer to that tree. `hs/` abbreviates `webapi/httpserver/`.

Each finding: **Where** (file:line, function) · **What** (the missing/incorrect check) · **Attack**
(concrete, with who the attacker is and the deployment precondition) · **Fix** · **Test** (what
regression test to add). Confidence: CONFIRMED = traced input → sink and the guard is absent;
RE-VERIFIED = additionally re-traced by the review lead; PLAUSIBLE = not fully traced, remaining
check stated.

Severity: CRITICAL = cross-user data/write or daemon-privilege escalation with no precondition;
HIGH = same but needs a realistic config or a second bug; MEDIUM = DoS, metadata leak, clear
hardening gap; LOW = defense in depth / latent.

Suggested order: C1, C2 → H1, H2, H9 → H5, H6, H7 together (shared root: empty identity reaches a
daemon-credential path) → H3, H4, H8 → H10, H11 with C1's cedar change → MEDIUM sprint (M7 needs a
policy decision first) → LOW.

---

## Scorecard against the five historical bug classes

| Class | Status | Findings |
|---|---|---|
| 1. CEDAR session cache reused across users | No live recurrence (latent: L1) | L1 |
| 2. REST route authz ≠ MCP tool authz | **Recurred** | C2, H4, H7, M2, M7, M8, M9 |
| 3. Missing sanitization of files written | No recurrence on user paths | H2 (daemon's own DB), L9, L10 |
| 4. Unbounded memory | **Recurred** | H8, H9, M11, M12, M13, M15, M16 |
| 5. User queries falling back to the daemon credential | **Recurred, new form** | C1, H10, H11, L4, L19 |
| 6. ClassAd constraint injection | Held | L16 (no data boundary crossed) |

---

## CRITICAL

### C1. Delegated-token CEDAR connections fall through to the daemon's `tokens.d` — RE-VERIFIED

- [ ] fixed

**Where**
- `security.go:425-447` `GetSecurityConfig`: sets `secConfig.TokenDir = SEC_TOKEN_SYSTEM_DIRECTORY`
  whenever `runningAsDaemon()` (`security.go:283`: euid 0 **or** `CONDOR_INHERIT` set — always true
  under condor_master). The only two writes to `TokenDir` in the tree are here (`:436`, `:443`).
- `security.go:121-167` `NewClientSecurityConfig`: the `token != ""` branch calls
  `loadClientSecurityDefaults` → `GetSecurityConfig`, then filters `AuthMethods` (drops FS, fronts
  TOKEN) and sets `secConfig.Token = token`. It never clears `TokenDir` / `TokenFile`.
- `security.go:529` `sc.Credentials = daemonCredentialCache` and `:274`
  `security.SetDefaultCredentialReader(daemonCredentialCache)` — the root-elevating reader, so the
  privilege-dropped daemon can read `/etc/condor/tokens.d`.
- cedar `security/token_auth.go:351-390` `loadTokenForAuthentication`: tries `config.Token`; if
  `isTokenCompatibleString` is false (`iss` ≠ server TrustDomain or `kid` ∉ server IssuerKeys) **or**
  `validateTokenExpiration` fails, it "continue[s] to files": `TokenFile`, then
  `scanTokenDirectory(config.TokenDir)`, sending the first compatible token found.
  `findCompatibleTokenInFile` (`:486-500`) reads through `a.config.readCredential` = the privileged
  reader, by design.
- cedar `token_auth.go:1509-1546` `hasCompatibleToken`: TOKEN stays in the offered method list as
  long as *any* directory token matches.
- `hs/auth.go:306-333` `parseJWTClaims` / `TokenCache.Add`: accepts any 3-part JWT with `sub` and a
  future `exp`; no `iss`/`kid` check, no signature check (by design). Expired tokens are rejected
  here, so from webapi only the iss/kid route is live; the expiry route hits library callers and
  long-lived contexts (H11).
- Both REST (`hs/server.go:1370` `createAuthenticatedContext` →
  `ConfigureSecurityForTokenWithCacheAndFallback`, `hs/auth.go:92-125`) and MCP
  (`hs/mcp_handlers.go:160`) build the caller config through `NewClientSecurityConfig`.
- `hs/mcp_actor.go:146-160` `actorForSession`: identity = whatever `schedd.Ping` reports for the
  connection, so the daemon identity is then recorded as the request's actor.

**What**: the caller's credential is attached but cedar treats it as the *first candidate*. When it
is incompatible with the peer's advertised trust domain / issuer keys (or expired), cedar silently
offers the daemon's own pool token (`condor@<trust>`, in `QUEUE_SUPER_USERS` by default,
`config/param_defaults.go:456`). The credential-origin gate (PR #542, `credential_origin.go`) cannot
see this; the substitution happens inside cedar after the gate decided a user credential was present.

**Attack** (unauthenticated):
1. Build `H.P.S` with header `{"alg":"HS256","kid":"nope"}`, payload
   `{"sub":"x","iss":"not-this-pool","exp":<future>}`, garbage signature. (Or use a real IDTOKEN
   from a *different* pool — flocking users have these.)
2. `GET /api/v1/ping -H "Authorization: Bearer <tok>"` → response reports `user: condor@<trust>`.
3. `GET /api/v1/jobs?owned_by_me=false` → every user's ads (schedd drops MyJobs for superusers);
   `DELETE`/`PATCH`/hold/release act on any job; submit runs as superuser.
4. `POST /api/v1/collector/advertise` with `{"command":"UPDATE_STARTD_AD","ad":{...}}` (or MCP
   `advertise_to_collector`) authenticates with the daemon's `ADVERTISE_*` token → attacker slot gets
   other users' jobs matched to it.
5. credd read/delete of other users' credentials where `CRED_SUPER_USERS` includes `condor`.

Second trigger with no attacker: an API server whose `TRUST_DOMAIN` differs from the schedd's turns
every legitimate user into the superuser with no error logged.

**Precondition**: a daemon IDTOKEN compatible with the target daemon in `/etc/condor/tokens.d`
(standard whenever the AP authenticates to its CM with IDTOKENS; the local schedd accepts any
pool-key-signed token) and the daemon running under condor_master or as root.

**Fix**
1. In `NewClientSecurityConfig`'s `token != ""` branch and in
   `ConfigureSecurityForTokenWithCacheAndFallback`: set `secConfig.TokenDir = ""` and
   `secConfig.TokenFile = ""`. The caller made the identity decision; nothing may be substituted.
2. cedar: add a `SecurityConfig` flag (e.g. `TokenOnly`) so that an explicit `Token` that is
   incompatible or expired means TOKEN is *not offered* (`hasCompatibleToken` false,
   `loadTokenForAuthentication` error) rather than "look elsewhere".
3. `TokenCache.Add`: reject bearers whose `iss` ≠ the configured trust domain (they can never
   authenticate here anyway).

**Test**
- Unit: `NewClientSecurityConfig(ctx, tok, …)` with `runningAsDaemon` forced true and a populated
  `SEC_TOKEN_SYSTEM_DIRECTORY` → assert `TokenDir == ""` and `TokenFile == ""`.
- Cedar: client config with iss-mismatched `Token` and a compatible token in `TokenDir` → auth must
  FAIL.
- Integration: wrong-issuer bearer to `/api/v1/ping` → 401; to `/api/v1/jobs?owned_by_me=false` →
  no other owners' ads (assert both directions).

### C2. `/api/v1/jobs/watch` and `/api/v1/dashboard/activity/stream` serve every user's ads with no identity and no owner scope — RE-VERIFIED

- [ ] fixed

**Where**
- `hs/handlers_watch.go:203-266` `handleJobsWatch`, local `job_queue.log` branch: after
  `requireAuthentication`, opens `h.jobMirror.Collection().Watch(ctx, cursor)`, filters only by the
  caller's own `constraint` (`vm.Parse` → `collections.WatchFilter`), `streamCollectionEvents` emits
  the whole ad. No `GetAuthenticatedUserFromContext` check, no `resolveOwnerScope`/`scopeToOwner`,
  no schedd contact (the data is the daemon's own read of `job_queue.log`).
- `hs/handlers_jobswatch_mirror.go:38-48` `streamJobsWatchFromMirror` and
  `hs/handlers_dashboard_stream.go:80-82,108-127` `handleDashboardActivityStream` /
  `activityStreamScope`: returns `owner` unchanged for non-admins; for an unidentified caller
  `owner == ""`, which `webapi/jobwatch/activity.go:125-131` `publishActivityLocked`
  (`if s.owner != "" && s.owner != ev.Owner { continue }`) treats as pool-wide.
- `hs/server.go:1437-1452` `createAuthenticatedContext`: for a bearer the schedd does not
  recognise, `actorForSession` returns `""` and the function returns `ctx, nil` —
  `hs/unverified_sub_test.go:TestForgedTokenResolvesToNobody` documents `/whoami` answering 200
  with `user:""`.
- `webapi/cmd/htcondor-api/main.go:834-866` `resolveJobQueueLog`: the tailer is auto-enabled
  whenever `JOB_QUEUE_LOG` is readable (co-hosted deployment) unless `HTTP_API_JOB_QUEUE_LOG=none`.

**Attack** (unauthenticated): `curl -N -H "Authorization: Bearer hdr.{sub,exp}.junk"
https://ap/api/v1/jobs/watch` → SSE stream of every job ad (Owner, Cmd, Args, Environment, Iwd,
RemoteHost, hold reasons) and every subsequent change. `/api/v1/dashboard/activity/stream` → the
pool-wide transition feed. Any authenticated non-admin gets the same, cross-user. MCP
`query_jobs`/`watch_jobs` over the same data are owner-scoped.

**Precondition**: readable `job_queue.log` (local branch) or an htcondordb mirror (mirror branch).
Also hits legitimate bearers while the global actor-resolve limiter (5/s) is saturated.

**Fix**
- Both handlers: refuse an empty identity (401). Unless `resolveOwnerScope` says unconfined, AND
  `Owner == ownerFromActor(actor)` into the match (wrap via `scopeToOwner` before `vm.Parse`).
- `activityStreamScope("")` must return a sentinel that matches nothing (or refuse before
  `SubscribeActivity`); make `SubscribeActivity` refuse `owner == ""` unless an explicit `all bool`
  is passed.
- Generally: have `requireAuthentication` return 401 when a bearer yields no identity, so every
  schedd-less data path inherits the refusal.

**Test**: forged-JWT `GET /api/v1/jobs/watch` with a two-owner `job_queue.log` fixture → 401, zero
events; user A session → only A's ads (assert B absent AND A present);
`activityStreamScope("", "", false)` must not equal the admin "all" value. Same for the activity
stream.

---

## HIGH

### H1. Job HTTP proxies forward the session cookie / bearer into the job sandbox — CONFIRMED

- [ ] fixed

**Where**: `hs/handlers_jobproxy.go:223-276` `handleJobProxy` `Director` (rewrites only `req.URL`
and `req.Host`); `webapi/jupytertunnel/registry.go:625-666` `Registry.Proxy` `Director` (same
shape). Nothing deletes `Cookie` or `Authorization`; no test asserts stripping. Jupyter runs with
`--ServerApp.token='' --ServerApp.password=''` (`hs/handlers_jupyter.go:1399-1400`), code-server
with `--auth none` (`webapi/vscode/launch.go:284`): the tunnel is the auth boundary.

**Attack**: anything running in the user's job (chosen container image, pip package, notebook or
VS Code extension, or on a shared-UID glidein a neighbouring job that binds the socket first) logs
`Cookie: htcondor_session=<id>` or the bearer and replays it to the AP: submit/remove jobs,
read/store credentials, mint API keys. Under superuser mode (`superuserActionContext` requires a
session cookie, `hs/superuser_context.go:206-240`; proxy runs impersonated,
`handlers_jobproxy.go:140-147`), an operator proxying into user B's job hands B an *armed*
superuser session. `SameSite=Strict` does not help: the replay is a direct request.

**Fix**: one shared director helper used by both proxies that deletes `Cookie` (at minimum
`htcondor_session`; simplest is the whole header), `Authorization`, `Proxy-Authorization`, and the
`Forwarded` / `X-Forwarded-*` identity headers.

**Test**: using the fake upstream in `hs/handlers_jobproxy_test.go`, send
`Cookie: htcondor_session=secret; other=x` and `Authorization: Bearer t`; assert the upstream
request carries neither. Same for `Registry.Proxy` over a yamux pair.

### H2. Application DB created world-readable; holds raw session IDs (and keys/refresh tokens without a KEK) — CONFIRMED (empirically)

- [ ] fixed

**Where**: `hs/appdb/appdb.go:47-57` `Open` probes writability then `sql.Open("sqlite", path)`
with no mode handling; no `Chmod`/`0600` anywhere in `httpserver/` or `cmd/htcondor-api/`.
condor_master sets `umask(022)` (`daemon_core_main.cpp:3507`) and children inherit it; verified
with the same driver: `sql.Open` + `CREATE TABLE` under umask 022 → mode 0644 (and `-wal`/`-shm`).
Default path `$(LOCAL_DIR)/lib/condor/htcondor-api.db` (`main.go:560-581` `loadDBPath`) in a 0755
`condor:condor` directory. `hs/session.go:99-140` `SessionStore.Create` stores `session_id` raw —
it is the cookie value (`hs/oauth2_sso.go:447-454`). Without `HTTP_API_KEK_FILE` (supported
back-compat mode, `main.go:505-545`): `oauth2_rsa_keys.private_key_pem`,
`oauth2_hmac_secrets.secret`, `idp_rsa_keys.private_key_pem`
(`hs/oauth2_storage.go:497`, no-sealer branch) and `upstream_refresh_tokens.refresh_token`
(`hs/upstream_refresh.go:127-130`) are plaintext. Contrast
`sessioncache/sqlite/store.go:70-108` `ensureFileMode(path, 0o600)`, which fixed this exact hazard
for the CEDAR session DB.

**Attack**: any local shell account on the AP:
`sqlite3 /var/lib/condor/htcondor-api.db "select session_id,username from http_sessions where expires_at > datetime('now')"`,
set the cookie, become the victim (server mints `sub=<victim>` IDTOKENs). Without a KEK: forge
OAuth2/OIDC tokens for any subject, act as the user at the upstream IdP.

**Fix**: in `appdb.Open`, `os.OpenFile(path, O_CREATE|O_RDWR, 0o600)` + `os.Chmod(path, 0o600)`
before `sql.Open` (lift `ensureFileMode` from `sessioncache/sqlite` into a shared helper); refuse to
start if the parent directory or an existing DB has world bits; store `sha256(session_id)` instead
of the raw id. Ops mitigation now: `chmod 0600` the DB and sidecars; set `HTTP_API_KEK_FILE`;
rotate OAuth2/IdP signing keys if the file was ever world-readable on a multi-user host.

**Test**: open a fresh app DB under `syscall.Umask(022)` and assert `Perm() == 0600`; pre-create a
0644 file and assert it is tightened; assert the `-wal` sidecar mode after the first write (mirror
`sessioncache/sqlite/store_test.go:TestOpenRestrictsFileMode`).

### H3. Token exchange launders any access token into a revocation-proof, indefinitely renewable chain — CONFIRMED

- [ ] fixed

**Where**: `hs/oauth2_token_exchange.go:36-150` `handleTokenExchange`: `:96`
`DefaultOpenIDConnectSession(subject)` (fresh session, `AuthTime = now`), `:108`
`fosite.NewAccessRequest(session)` (fresh `request_id`), `CreateAccessTokenSession` with no link
to the subject grant; `reauthorizeRefreshGrant` (lifetime cap, group-policy re-eval, oracles) runs
only for `grant_type=refresh_token`. `resolveSubjectToken` accepts any token `IntrospectAccessToken`
likes — including one already issued by exchange. `hs/mcp_handlers.go:1266-1395`
`handleOAuth2Register`: unauthenticated, `:1304 regReq.GrantTypes = rawReq.GrantTypes` unvalidated.

**Attack** (any valid token holder — a user about to be de-provisioned, or a thief of a leaked
token): `POST /mcp/oauth2/register {"redirect_uris":["https://x/"],"grant_types":["urn:ietf:params:oauth:grant-type:token-exchange"]}`
→ client id/secret; `POST /mcp/oauth2/token` (Basic) with
`grant_type=urn:ietf:params:oauth:grant-type:token-exchange&subject_token=<tok>&subject_token_type=urn:ietf:params:oauth:token-type:access_token`
→ new token, same subject and scopes (incl. `mcp:admin`/`mcp:superuser`), fresh lifetime; repeat
with the new token forever. Group removal, `condor_qusers -disable`, the 30-day grant cap and the
admin "revoke this grant" button never touch the chain.

**Fix**: (a) refuse to exchange a token that was itself issued by exchange (`Session.Actor != ""`
or stored grant type); (b) inherit the subject grant's `request_id` and `AuthTime` so
`RevokeGrant`, refresh-reuse revocation and the lifetime cap propagate, and run the same
`reauthorizeRefreshGrant` checks before minting; (c) allow-list DCR `grant_types` to
`{authorization_code, refresh_token}` and `response_types == ["code"]` so the actor client is
operator-provisioned only.

**Test**: exchange → admin-revoke original grant → exchanged token must introspect inactive;
exchange of an exchanged token → `invalid_grant`; DCR with `grant_types:[token-exchange]` → 400; a
subject past `maxGrantLifetime` cannot be exchanged.

### H4. SDK MCP transport serves the full tool catalogue to a grant with nil scopes; nil and empty grants share a cache slot — CONFIRMED (by test)

- [ ] fixed

**Where**: `webapi/mcpserver/handlers.go:66-78` `WithGrantedScopes` (`if scopes == nil { return ctx }`)
and `:94-116` `scopesAllowTool` (`if scopes == nil { return true }`) — nil means "no scope model,
show everything", intended for forwarded pool IDTOKENs (`hs/mcp_sdk_route.go:59-69`
`sdkTokenInfoFor(nil)`). `mcpserver/sdk_scopes.go:42-62` `scopeKey` = `strings.Join(c, " ")`, so
`scopeKey(nil) == scopeKey([]string{}) == ""`. `mcpserver/sdk_transport.go:39-55` `sdkServerFor`.
`hs/oauth2_sso.go:119` `getScopesForGroups` starts from `var grantedScopes []string` and appends
nothing when groups deny every requested scope → stored as JSON `null` → nil
(`hs/oauth2_storage.go:428-432`). `handleCallTool` performs no scope check of its own. The builtin
transport is unaffected (`isMethodAllowedByScopes` refuses a token with neither `mcp:read` nor
`mcp:write`). Verified with a throwaway test: `scopesAllowTool(nil,"submit_job")=true`,
`scopesAllowTool([]string{},"submit_job")=false`.

**Attack** (`HTTP_API_MCP_TRANSPORT = sdk`; user denied MCP by `HTTP_API_MCP_ACCESS_GROUP`):
register a client via DCR, run auth-code requesting only `mcp:read mcp:write` (no `openid`),
approve; groups deny both → token with nil scopes; `POST /mcp` → `tools/list` returns everything,
`tools/call` runs (schedd writes fail: minted IDTOKEN authz is READ; but full read surface over own
jobs, share-URL minting, and with nil scopes `scopedTransport()==false` so `MCP_ADMIN_USERS` grants
the cross-user read tier). Cache collision: an empty non-nil grant (device flow stores `[]`; admin
`SetGrantScopes` to nothing; `scopesAllowedByScheddACL` returns non-nil empty) shares the `""` slot
with the forwarded-token full catalogue — whoever builds it first decides what the other gets.

**Fix**: typed sentinel (`WithGrantedScopes` stores `{scopes []string, scoped bool}`; the SDK
verifier passes `scoped=true` for every fosite token, always non-nil); key the server cache on
flag + sorted scopes; `mcpAuthContext` refuses an OAuth2 token with no `mcp:*` scope (one check for
both transports); `handleCallTool` re-checks `scopesAllowTool`.

**Test**: SDK transport with fosite tokens `GrantedScope=nil` and `[]string{}` → `tools/list` empty
and `tools/call submit_job`/`query_jobs` refused; a forwarded IDTOKEN caller after an empty-grant
caller still sees the full catalogue.

### H5. Job-transport cache keyed on an empty owner; a forged bearer reuses an IDTOKEN user's cached SSH transport — RE-VERIFIED

- [ ] fixed

**Where**: `hs/handlers_jobproxy.go:197-203` `handleJobProxy`
(`owner := GetAuthenticatedUserFromContext(ctx); if owner == "" { owner = username }` — also
empty; `key := jobssh.Key{Owner: owner, Cluster, Proc}`); `hs/handlers_jobwarm.go:92-96`
`handleJobWarm`; `hs/handlers_apps.go` `probeApp`; `webapi/jobssh/cache.go:244-330`
`DialJob`/`acquire` fast path returns a cached `*ssh.Client` on `conn != nil` with no credential
re-check. `hs/mcp_actor.go:137-170` `actorForSession`: when `h.mcpActors.allowResolve()` (process-
global limiter, 5/s, burst 10) is exhausted it returns `""` **without caching the miss**; also `""`
for 30 s after a schedd blip. `hs/server.go:1443-1456`: identity set only `if username != ""`.
`refuseRemoteAccessByUniverse` returns `known=false` on a failed query, so the attacker's unusable
credential does not stop the request. (`markValidatedOnSuccess` is dead — L3 — so `actorForSession`
is the only identity source for IDTOKEN bearers.)

**Attack** (unauthenticated): (1) stream >5 distinct forged JWTs/s at any authenticated route →
every new bearer, including valid ones, resolves to `""`. (2) Victim using an IDTOKEN (VS Code
extension, CLI) opens `/api/v1/jobs/42.0/proxy/unix/vscode.sock/` or POSTs `/warm`; transport
dialled with the victim's valid credential, cached under `{"",42,0}` for 10 idle min. (3) Attacker
GETs the same proxy path with the forged JWT → identity `""` → same key → cache hit → code-server /
terminal in the victim's sandbox as the victim. Session-cookie and OAuth2-opaque victims are
unaffected (identity always set).

**Fix**: 401 on empty owner in `handleJobProxy`, `handleJobWarm`, `probeApp`, and in
`jobssh.Cache.acquire`/`DialJob` (`Key.Owner == ""` → error); key the cache on a digest of the
credential (`sessionTagFor`) rather than the claimed owner; make the actor limiter per-source.

**Test**: open a transport with a stub dialer under `Key{Owner:""}`; request `/proxy/...` with a
second context whose identity is empty → 401 and no `DialJob`; unit test `Cache.DialJob` with empty
Owner returns an error.

### H6. Mirror serves whole-queue / history reads to any identity the schedd merely *authenticates* — CONFIRMED

- [ ] fixed

**Where**: `hs/handlers.go:300-318` `handleListJobs` → `jobsFromMirror(... actor, ownedByMe)`;
`hs/handlers_dbroute.go:79-95,161-172` (only gate before a mirror read is `owner != ""`);
`hs/mcp_actor.go:154` → `ping.go:154-170` (identity resolved with `DC_NOP`, registered at `ALLOW`
in `src/condor_daemon_core.V6/daemon_core_main.cpp:4347`); `webapi/dbmirror/dbmirror.go:1014-1035`
(mirror read with the daemon's own READ token). For a bearer caller `resolveOwnerScope` leaves
`ownedByMe=false`, so the read is unscoped. The same DC_NOP identity feeds MCP
`mcpserver/db_routing.go`.

**Attack**: holder of a scope-limited pool IDTOKEN (compromised EP/pilot token minted with
`-authz ADVERTISE_STARTD,ADVERTISE_MASTER`, or any identity outside `ALLOW_READ`):
`GET /api/v1/jobs?owned_by_me=false&limit=*&projection=*` or `/api/v1/jobs/archive` → every user's
ads from the mirror. The schedd would have refused `QUERY_JOB_ADS` for that token.

**Fix**: resolve identity with `DC_NOP_READ` (READ-level) for callers whose data will be served by
the mirror, or require one successful READ-level schedd op before routing; never serve an unscoped
mirror read to a non-admin (see M7).

**Test**: integration with an IDTOKEN limited to `ADVERTISE_STARTD`: schedd query fails AND
`/api/v1/jobs?owned_by_me=false` with a mirror configured returns no rows.

### H7. `/api/v1/metrics/{table}` returns every user's resource samples to an unidentified or bearer caller — CONFIRMED

- [ ] fixed

**Where**: `hs/handlers_metrics.go:87-160` `handleMetricsQuery`: `:141 constraint, err =
s.bulkOwnerScope(ctx, r, constraint)`; `hs/handlers.go:1081-1091` `bulkOwnerScope`:
`if !hasSession || s.isWebUIAdmin(r) { return raw, nil }` — no identity check. Mirror dialled as
`condor@<trust>` (`webapi/dbmirror/dbmirror.go:716-738,1014-1040`, `hs/dbmirror_token.go`). Unlike
`jobsFromMirror`/`historyFromMirror` there is no `owner == ""` gate.

**Attack** (unauthenticated, forged JWT; precondition: mirror + job_metrics sampler):
`GET /api/v1/metrics/job_metrics?group_by=Owner,RunInstanceID&agg=max:MemoryUsage,count:*` → per-job
resource archive for every user and the full user list.

**Fix**: gate every mirror read on `GetAuthenticatedUserFromContext(ctx) != ""`; for every non-admin
caller (regardless of session type) AND `Owner == ownerFromActor(actor)` via `scopeToOwner`.

**Test**: forged token → 401; validated bearer `alice` with a two-owner fixture → rows contain
only `Owner == alice`.

### H8. Unauthenticated bearers create permanent TokenCache entries — CONFIRMED

- [ ] fixed

**Where**: `hs/auth.go:333-407` `TokenCache.Add` (called from `hs/server.go:1260,1278`
`createAuthenticatedContext` for every unknown bearer): per entry a `security.NewSessionCache()`,
a `context.WithCancel`, a `time.AfterFunc`, keyed by the full token string, removed only when the
attacker-chosen `exp` fires; no size cap or LRU (`len(tc.entries)` only read by `Size()`).

**Attack** (unauthenticated): loop `curl -H "Authorization: Bearer $(unsigned_jwt sub=x exp=+100y
nonce=$i)" https://ap/api/v1/jobs`; each request adds an entry that never leaves (KBs each). A few
million → OOM-kill.

**Fix**: do not insert unvalidated tokens (insert on `MarkValidated`/`AddValidated` only; keep a
short-TTL negative cache), or bound the cache (LRU with max entries and ~10 min residency until
validated).

**Test**: present 10k distinct unsigned JWTs with `exp=+10y`; `tokenCache.Size()` ≤ cap and
unvalidated entries gone after the short TTL.

### H9. JSON bodies on job-mutating routes are unbounded and decoded before any credential check — CONFIRMED

- [ ] fixed

**Where**: `json.NewDecoder(r.Body).Decode` with no `http.MaxBytesReader` at `hs/handlers.go:464`
(`handleSubmitJob`), `:1003` (`handleEditJob`), `:1150/:1233/:1316` (bulk hold/edit/release/
remove), `:2332` (`parseJobActionRequest`), `:3581` (`handleCollectorAdvertise`);
`hs/handlers_credd.go:60,205`; `hs/handlers_interactive.go:271`; `hs/handlers_jupyter.go:652`;
`hs/handlers_share.go:247`; `hs/handlers_watch_share.go:127`. `ServeHTTP` installs no global
limit and `routes.go` has no body-limit middleware. The bearer path does no schedd round trip
before `Decode` (`hs/server.go:1200-1280`). Only `ReadTimeout=30s` bounds it.

**Attack** (unauthenticated): `POST /api/v1/jobs` with a fake bearer and a 20 GB
`{"submit":"AAAA…"}` from a few connections → RSS exhaustion.

**Fix**: `r.Body = http.MaxBytesReader(w, r.Body, 1<<20)` once in `Handler.ServeHTTP`; raise per
route where the existing larger limits already live (multipart 100 MiB, tar 1 GiB, templates 8 MiB,
MCP 16 MiB).

**Test**: POST 2 MiB JSON to `/api/v1/jobs` with an unsigned bearer → 413 and the mock schedd is
never called.

### H10. Daemon's SSL client certificate is offered on delegated-token connections — CONFIRMED mechanism, config-dependent impact

- [ ] fixed

**Where**: `security.go:407-423` `GetSecurityConfig` fills `CertFile`/`KeyFile` from
`AUTH_SSL_CLIENT_CERTFILE`/`KEYFILE` whenever SSL is in the client list; `security.go:158-163`
keeps SSL on the token path ("SSL stays … unlike FS it is not a silent same-host shortcut"); cedar
`security/auth.go:1680-1690` negotiates in the **server's** preference order; cedar
`ssl_auth.go:164-171` presents `CertFile` when set.

**What**: FS was removed because the server picks the method and FS identifies the process. SSL
with a configured client cert is the same. A CM with `SEC_DEFAULT_AUTHENTICATION_METHODS = SSL,
IDTOKENS` selects SSL, cedar presents the AP host cert (readable via `daemonCredentialCache`), and
`CERTIFICATE_MAPFILE` maps it to the AP's daemon identity (`ALLOW_DAEMON`/`ALLOW_ADVERTISE_*`); the
forwarded user token is never used. Most visible on `POST /api/v1/collector/advertise`.

**Fix**: when a delegated token is present, clear `CertFile`/`KeyFile` (SSL stays only as an
anonymous client for server-cert verification), or drop SSL from the offered list whenever a client
cert would be presented.

**Test**: `NewClientSecurityConfig(ctx, token, …)` with `AUTH_SSL_CLIENT_CERTFILE` configured →
empty `CertFile`; integration against a collector with `SSL, IDTOKENS` order →
`/api/v1/collector/ping` reports the token subject, not the host DN mapping.

### H11. Short-lived minted credentials copied into long-lived contexts expire and then take the C1 fallback — CONFIRMED mechanism

- [ ] fixed

**Where**: cookie-session IDTOKENs `exp = now+1m` (`hs/server.go:1120-1122`), user-header tokens
likewise (`:1174`), MCP/gateway 5 min (`hs/mcp_handlers.go:2795`). Copies held past the request:
`hs/jobwatch_poll.go:166-176` `keyFor` (`cfg := secCfg; pollCtx = WithSecurityConfig(pollCtx,
&cfg)`, "the group outlives the request"); `webapi/interactive/manager_internal.go:531`
(`sess.secConfig` reused for expiry/removal); SSH-gateway / VS Code channels. Cedar
`token_auth.go:340-346` validates `exp` client-side and treats an expired explicit token exactly
like an incompatible one.

**What**: every poll tick / removal after expiry runs as `condor@pool`. For a watch whose scoping
relies on `MyJobs` rather than an explicit `Owner` clause, the escalated poll returns other users'
ads.

**Fix**: C1 (then an expired credential fails closed). Independently, re-mint per tick rather than
copying the request's config into anything that outlives it.

**Test**: `jobwatch` unit test with a token whose `exp` is 1 s in the past → the poll errors rather
than succeeds.

---

## MEDIUM

### M1. SSO login CSRF / forced login: OAuth2 `state` not bound to the browser — CONFIRMED

- [ ] fixed

**Where**: `hs/handler.go:2885-2935` `redirectToLogin` (`:2924 StoreWithURL(state, nil,
originalURL)` — state → URL only); `hs/oauth2_sso.go:296` `GetWithURL(state)`, `:447-454` session
creation + `setSessionCookie` with no comparison to any pre-existing cookie;
`hs/oauth2_state.go` (in-memory map keyed by state); same pattern in `handleOAuth2DeviceVerify` GET
(`hs/mcp_handlers.go:1823-1845`).

**Attack** (unauthenticated; victim clicks a link within ~10 min): attacker visits `/login`,
captures the IdP redirect (state S), authenticates at the IdP as *attacker*, stops the final
redirect and copies `code=C`; sends victim `https://ap/oauth2/callback?state=S&code=C`. Victim now
holds an `htcondor_session` for the attacker's account; everything they do next (uploads,
`store_service_credential`, submits, chat) lands in the attacker's account.

**Fix**: on `redirectToLogin`/authorize-SSO set a short-lived `SameSite=Lax` cookie with a random
nonce (or HMAC of state), store the nonce with the state entry; at the callback require the cookie
to match, else 400 and delete the entry.

**Test**: callback with a valid state but missing/mismatched login cookie → 400 and no
`Set-Cookie: htcondor_session`.

### M2. Bulk hold/release and single-job PATCH skip the owner scope; bulk edit lets the caller disable protected-attr checks — CONFIRMED

- [ ] fixed

**Where**: `hs/handlers.go:1430-1530` `handleBulkJobAction` (`:1444 parseBulkActionRequest` …
`:1505 actionFunc(ctx, constraint, reason)` with no `bulkOwnerScope`; only the superuser-armed
branch owner-splits); `hs/handlers.go:982-1079` `handleEditJob` (`:1031 EditJob(ctx, cluster,
proc, …)` with no `jobOwnerScope`); `hs/handlers.go:1263-1266` `handleBulkEditJobs` honours
`options.allow_protected_attrs`/`force` from the body (disables the client-side guard in
`schedd_edit.go:63-80`, whose map is case-sensitive anyway). Compare `handleBulkDeleteJobs:1167`,
`handleBulkEditJobs:1283`, `handleSingleJobAction:2414`, `handleDeleteJob:803`, which all scope.
`hs/handlers_bulk_scope_test.go` tests the helpers in isolation only.

**Precondition**: the caller's identity is a queue superuser at the schedd (`QUEUE_SUPER_USERS`, or
a service-account IDTOKEN whose subject is the AP account). Then a non-admin browser session
(confined everywhere else) can `POST /api/v1/jobs/hold {"constraint":"true"}` and hold the whole
queue, or `PATCH /api/v1/jobs/<other>.0` any attribute.

**Fix**: call `bulkOwnerScope` in `handleBulkJobAction` before planning; in `handleEditJob` use
`EditJobs(ctx, jobOwnerScope(...), …)` or verify ownership via a scoped query first; drop caller
control of `AllowProtectedAttrs`/`Force` for non-admin sessions (parity with MCP `edit_job`, which
hard-codes `AllowProtectedAttrs:false`).

**Test**: non-admin session, two-owner fixture: bulk hold with `constraint=true` touches only own
jobs; `PATCH /jobs/<other>` → 404/403.

### M3. `HTTP_API_SUBMIT_FILE_OVERRIDES` is defeated by `+Attr` / `MY.Attr` — CONFIRMED (empirically)

- [ ] fixed

**Where**: `webapi/submitpolicy/submitpolicy.go:68-83` `Policy.Apply` splices overrides as submit
*commands* before `queue`; `submit.go` applies `+Name`/`MY.Name` custom attributes
(`customAttrName`, ~`:1568`) *after* the standard commands. Verified with a scratch program:
`+AccountingGroup = "evil"` and `+ConcurrencyLimits = "none"` survive the override; a plain
`accounting_group = evil` is correctly overridden. Assignments after `queue` and backslash
continuations are not bypasses.

**Attack**: any submitter opts out of the operator's mandatory accounting group / concurrency limit
/ log location via REST, chat or templates.

**Fix**: in `Policy.Apply` (or `Schedd.SubmitRemote`) also assert each override as `+Attr`, or
reject/strip user custom attrs whose ClassAd name collides with an override's attribute
(case-insensitive).

**Test**: `submitpolicy` + `ParseSubmitFile().Submit()` round trip with `+AccountingGroup` yields
the override value.

### M4. Unparseable constraint silently becomes `true` on the QUERY_JOB_ADS path — CONFIRMED

- [ ] fixed

**Where**: `schedd.go:462-475` `createJobQueryAd`: `if err != nil { constraintExpr, _ =
classad.ParseExpr("true") }`; `schedd_edit.go:171` `EditJobs` → `s.Query(ctx, constraint, …)`;
`hs/handlers.go:1212-1309` `handleBulkEditJobs`. Actions (`schedd_actions.go:168-171`) and
history (`history_query.go:160`) reject a bad constraint; only the query path widens it. Session
callers are protected because `scopeToOwner` parses first; bearer callers' constraints pass raw.

**Attack**: bearer user `PATCH /api/v1/jobs {"constraint":"JobStatus = 1",
"attributes":{"Requirements":"false"}}` (typo) → every job the schedd lets them edit is edited.

**Fix**: return the parse error from `createJobQueryAd`/`queryWithAuth`
(`QueryWithOptions`/`QueryStreamWithOptions` fail like the other paths).

**Test**: `EditJobs(ctx, "JobStatus = 1", …)` returns an error, edits nothing.

### M5. Share URLs redeem with a freshly minted authz-unlimited IDTOKEN — CONFIRMED

- [ ] fixed

**Where**: `hs/handlers_share.go:264-300` `redeemContext`:
`security.GenerateJWT(dir, base, username, s.trustDomain, now.Unix(), now.Add(2*time.Minute).Unix(), nil)`
(no authz limit, `AddValidated`); minters `mcpserver/handlers_uploadurl.go:30-110`,
`mcpserver/handlers_downloadurl.go:30-110` require only that the caller can QUERY the job (READ).

**Attack** (same subject only): a READ-limited credential with `mcp:write` calls
`create_input_upload_url(job_id)` for a job held for spooling, `curl -T`s the tar → job released
and runs (WRITE); `create_output_download_url` → full sandbox tar.

**Fix**: carry the minter's authz in the signed payload (`Authz []string`) and mint the redeem
token with it, or refuse minting unless the caller's credential has WRITE.

**Test**: mint with a READ-limited token, redeem → 403; mint with WRITE → 200.

### M6. Global CSRF check skipped for *any* `Authorization` header, including browser-attached Basic — CONFIRMED

- [ ] fixed

**Where**: `hs/handlers_ssh_consent.go:695-697` `hasBearerCredential` = `r.Header.Get("Authorization") != ""`;
`hs/handler.go:2049-2060` `ServeHTTP` skips `requireSameOrigin` when true;
`hs/server.go:1087-1099` `extractBearerToken` accepts only `Bearer `.

**Attack**: deployment with a Basic-auth reverse proxy that sets `HTTP_API_USER_HEADER`. Attacker
page auto-submits a form POST to `/api/v1/jobs/hold` (or submit, `/jobs/{id}/input/share`); the
browser attaches cached `Authorization: Basic …`, the proxy forwards it and sets the user header,
the same-origin check never runs, the action executes as the victim.

**Fix**: exempt only when `extractBearerToken(r)` succeeds.

**Test**: POST with `Authorization: Basic x`, `Origin: https://evil`, and a trusted user header →
403.

### M7. REST job reads unscoped for bearer callers while MCP scopes the same bearer — CONFIRMED (policy decision needed)

- [ ] decided / fixed

**Where**: `hs/handlers.go:1081-1090` `bulkOwnerScope` (`if !hasSession || isWebUIAdmin { return
raw }`), `hs/handlers_admin.go:55-63` `resolveOwnerScope`; used by `handleGetJob`,
`handleJobWatch` (single job), `handleJobMatchAnalysis` (incl. `?source=archive`),
`handleListJobs`, `historyOwnerScope`. Compare `mcpserver/owner_scope.go:40-94` `scopeToOwner`
for every non-admin caller.

**What**: scoping is decided by cookie presence, not identity. A non-admin with their own IDTOKEN /
device-flow token reads any job's full ad (`GET /jobs/{id}`, `?owned_by_me=false&limit=*`,
`/archive`, `/epochs`, `/transfers`, `/{id}/watch`, `/{id}/match-analysis`) because schedd reads are
unfiltered. Comments call this deliberate ("schedd ACLs are the backstop"); the premise is false for
reads, and `SECURITY_FINDINGS.md` does not record it as accepted. With a mirror (H6) it is also
unscoped *and* not ACL-checked.

**Fix**: scope every non-admin caller (session or bearer) as `mcpserver.scopeToOwner` does; decide
admin by identity (`adminUsers`/group oracle), not by cookie.

**Test**: `TestRESTBearerReadIsOwnerScoped`: bearer for user B, `GET /api/v1/jobs/{A's job}` → 404;
mirror and schedd paths both.

### M8. `requireCondorScope` gates API keys only; READ-only OAuth2 grants can execute code in the user's own job — CONFIRMED

- [ ] fixed

**Where**: `hs/apikey_scope_gate.go:51-61` (`if err != nil || !apikey.LooksLikeKey(raw) {
next.ServeHTTP }`); OAuth2 scopes attached via `withAPIKeyScopes` (`hs/server.go:1332-1345`) but
consulted only in `hs/handlers_sshcert.go:174`; `hs/handlers_jobproxy.go` (GET + WebSocket);
`hs/handlers_jupyter.go:1523-1551` `handleJupyterProxy` (no schedd call).

**Attack**: holder of a `condor:/READ`-only OAuth2 token of user U (leaked read-only integration
token): WebSocket GET to `/api/v1/jupyter/instances/{id}/proxy/api/kernels/…/channels` → arbitrary
code as U on the EP; or GET U's cached code-server proxy (a READ-only API key minted by an admin
shares `Creator` with the admin's own session transport).

**Fix**: apply `requireCondorScope` to any context carrying scopes (`scopedCredential(ctx)` after
`createAuthenticatedContext`); require `condor:/WRITE` for the Jupyter/job proxy, warm and
tunnel-adjacent routes regardless of HTTP method.

**Test**: extend `hs/routes_condor_scope_test.go` with an OAuth2 bearer granted only
`condor:/READ`: `GET /api/v1/jupyter/instances/{id}/proxy/x` and `GET /api/v1/jobs/1.0/proxy/80/`
→ 403.

### M9. A `metrics`-only API key authenticates as its creator on identity-only routes — CONFIRMED

- [ ] fixed

**Where**: `hs/apikey_auth.go:150-153` `authenticateAPIKey` always
`WithAuthenticatedUser(ctx, row.Creator)` regardless of scopes; `/api/v1/templates` (`routes.go`,
not behind `requireCondorScope`; `hs/handlers_templates.go:93-213` acts on `username`); also
`/whoami`, `/version`, `/ssh/ca`.

**Attack**: holder of a Prometheus key: `GET/POST/DELETE /api/v1/templates[/id]` → read, overwrite,
delete the minting admin's private and shared templates (incl. `InputFiles`).

**Fix**: attach identity for API keys only when a scope grants it (e.g. `condor:/*`), or add a
default "API keys need an explicit scope here" gate to every non-`/metrics` route.

**Test**: `["metrics"]` key → `POST /api/v1/templates` 403; `GET` does not list the creator's
private templates.

### M10. Built-in IdP login limiter keyed on `ip:port`; goroutine per key — CONFIRMED (only with `HTTP_API_ENABLE_IDP`)

- [ ] fixed

**Where**: `hs/idp_handlers.go:134-139` (`ip := r.RemoteAddr`, no `SplitHostPort`, no
`clientIP`); `hs/login_rate_limiter.go:30-49` (`rate.NewLimiter` + `go func(){ time.Sleep(1h);
delete }` per key). The SSH-consent limiter (`hs/handlers_ssh_consent.go:534`) does it right.

**Attack**: new TCP connection per guess → unlimited bcrypt brute force of `POST /idp/login`;
~1M connections/h → 1M sleeping goroutines.

**Fix**: key on `clientIP(r, h.trustedProxies)` plus a per-username limiter; periodic sweep with a
map-size cap instead of goroutine-per-key.

**Test**: 6 failed logins over 6 source ports from one IP → 6th is 429; `runtime.NumGoroutine()`
does not grow per request.

### M11. Dynamic client registration and `/device/authorize` grow tables with no cap, TTL or rate limit; DCR body unbounded — CONFIRMED

- [ ] fixed

**Where**: `hs/mcp_handlers.go:1265-1395` `handleOAuth2Register` (unauthenticated; `:1290
json.NewDecoder(r.Body).Decode(&rawReq)` with no `MaxBytesReader` — every other OAuth2 POST sets
1 MiB; bcrypt DefaultCost per call; `clientID := fmt.Sprintf("client_%d", time.Now().UnixNano())`
predictable; `grant_types`/`response_types` stored verbatim); `hs/mcp_handlers.go:1637-1700`
`handleOAuth2DeviceAuthorize` → `hs/device_code_handler.go:104` (needs only a known `client_id`,
row per call); `hs/oauth2_retention.go:45-73` sweeps only `oauth2_access_tokens`/
`oauth2_refresh_tokens` — `oauth2_clients`, `oauth2_device_codes`, `oauth2_authorize_codes`,
`oauth2_pkce` accumulate forever.

**Attack** (unauthenticated): multi-GB `redirect_uris` array → OOM; 14 req/s saturates a core on
bcrypt; loops fill the AP's DB and slow every `GetClient`/verify lookup.

**Fix**: `MaxBytesReader(64<<10)` on register; allow-list `grant_types ⊆ {authorization_code,
refresh_token}` and `response_types == ["code"]`; per-IP rate limit on both endpoints (reuse the
login limiter keyed by `clientIP`); config gate to disable DCR; TTL for clients that never obtained
a token; extend retention to device/authorize/pkce tables (`expires_at < cutoff`).

**Test**: 10 MB body → 413; `grant_types:[token-exchange]` → 400; 1000 calls from one IP → 429;
retention pass deletes expired device-code rows.

### M12. CIMD resolver cache is insert-only and reachable unauthenticated; CIMD on by default — CONFIRMED

- [ ] fixed

**Where**: `hs/oauth2_cimd.go:256-282` `resolve` (`:276 r.cache[clientID] = …` never evicted,
only overwritten; TTL only controls re-fetch); `:142-146` `hostAllowed` returns true when the
allowlist is empty; reached from unauthenticated `/mcp/oauth2/authorize?client_id=https://…` and
`/device/authorize` via `OAuth2Storage.GetClient`; default on (`main.go:3050-3054`).

**Attack** (unauthenticated): `client_id=https://<i>.attacker.example/m` for i=1..N → N outbound
HTTPS fetches from the AP (SSRF-guarded: private IPs denied, 5 s, 64 KiB) and N permanent map
entries; slow attacker hosts tie up handler goroutines.

**Fix**: bounded LRU (~1k) with expiry sweep; per-IP limit on cache-miss fetches; document
`HTTP_API_MCP_CIMD_ALLOWED_HOSTS` as the production setting (or default CIMD off when the allowlist
is empty).

**Test**: 10 000 distinct unresolvable client_ids → `len(resolver.cache)` ≤ bound.

### M13. OAuth2 state store has no entry cap; populated by unauthenticated GETs — CONFIRMED

- [ ] fixed

**Where**: `hs/oauth2_state.go:53-75,116-140` (`s.entries[state] = …` no size check; sweep only
`> 10 min`, every 5 min); writers `hs/handler.go:2924` (any unauthenticated UI hit that triggers
SSO), `hs/mcp_handlers.go:648,1838`, `hs/oauth2_sso.go:506`. Each entry holds the original URL (up
to the 1 MiB header limit) / a fosite `AuthorizeRequest`.

**Attack**: 2000 req/s × 900 s × 8 KB ≈ 14 GB in-process before the first sweep.

**Fix**: cap entries (evict oldest beyond ~10k), cap `originalURL` at 2 KiB, or move pre-login
state into a signed cookie.

**Test**: store 20k states → `len(entries)` ≤ cap, oldest evicted.

### M14. SSH gateway: one unauthenticated IP can hold all 256 connection slots for 6 minutes at a time — CONFIRMED

- [ ] fixed

**Where**: `webapi/sshgateway/listener.go:141-144,211-230` `Serve` (global slot taken at accept,
before the banner), `:299-303` `serveConn` (`HandshakeTimeout` 6 min); `webapi/sshgateway/auth.go:130`
`MaxPerSource=4` counts only logins *in flight*; `banlist.go:479-525` — `Fail` is only called from
the auth callback and `cert.go`, so an idle socket is never charged.

**Attack**: open 256 TCP connections, send nothing; every real `ssh user@ap` is refused for 6 min;
reconnect when they drop.

**Fix**: per-source pre-auth socket cap (≤4 per /32 and /24, like sshd `MaxStartups`); a short
banner/kex deadline (10–30 s) separate from the device-flow wait (extend once auth is in progress);
`Bans.Fail` on handshake timeout.

**Test**: 300 idle sockets from one IP; a second IP still completes a handshake; idle sockets closed
within the short deadline and the source charged.

### M15. MCP `get_job_output` / `get_job_stdout` / `get_job_stderr` buffer the whole sandbox in memory — CONFIRMED

- [ ] fixed

**Where**: `webapi/mcpserver/handlers.go:2083-2088` (stdout/stderr helper: `var sandboxBuf
bytes.Buffer; ReceiveJobSandbox(ctx, constraint, &sandboxBuf)`), `:2592-2597` (`get_job_output`),
`:2968` (`extractSandboxFile` → `io.ReadAll(tr)`). The 100 KiB `maxFileSize` truncation applies
only in `get_job_output`'s per-file reader. REST equivalents (`streamFileFromTar`,
`fetchSandboxFileBytes` with `CopyN(maxBytes+1)`) are bounded.

**Attack**: authenticated user with a 20 GB-output job calls `get_job_stdout` from a few MCP
sessions → OOM.

**Fix**: stream the tar through `io.Pipe`, skip non-matching entries, `CopyN(maxFileSize+1)` the
match, abort the transfer once found (as `fetchSandboxFileBytes` does).

**Test**: fake schedd emitting a 1 GiB tar entry → tool returns truncated, peak heap < 10 MiB.

### M16. Per-stream schedd polling with no per-user SSE cap — CONFIRMED (when no warm mirror feed)

- [ ] fixed

**Where**: `hs/handlers_jobwatch.go:107-150` (`pollSrc = s.jobPolls.Subscribe(ctx, constraint)`),
`hs/jobwatch_poll.go:120-220` (ticker per group, `QueryWithOptions(Limit:1)` every 2 s for up to
`jobWatchMaxAge=30 min`), `hs/handler.go:1887` (`newJobPollHub(2*time.Second, …)`); `sseSetup`
clears the write deadline; `streamOpened` is only a counter; `SCHEDD_QUERY_PER_USER_RATE_LIMIT`
defaults to 0.

**Attack**: one user opens 2000 SSE streams on 2000 distinct job ids → 1000 queue walks/s on the
single-threaded schedd.

**Fix**: cap concurrent SSE streams per identity (~16) and globally; coalesce one credential's poll
groups into one `ClusterId in (...)` query per tick; a default per-user schedd rate limit.

**Test**: 50 watches as one user → 17th is 429; fake schedd sees ≤1 query per tick for that user.

### M17. `/readyz` (unauthenticated) discloses the mirror daemon name/address and raw error text — CONFIRMED

- [ ] fixed

**Where**: `hs/routes.go` (`/readyz` ungated), `hs/handlers.go:2190-2245` `handleReadyz` →
`mirrorHealth`, `hs/ping_health.go:142-147,195-202,272-273,314` (`Name`, `Address`, `PinnedName`,
`PinnedAddress`, `LastError`, `DialError`, `TokenError`). `hs/handlers_dbmirror.go:51-54` gates
`/api/v1/dbmirror/status` on `requireAdmin` precisely to hide this.

**Attack**: `curl /readyz` → internal mirror address, auth-method lists and the trust domain (the one
fact needed to craft the C1 bearer).

**Fix**: status booleans only on `/readyz`; the rest behind `requireAdmin` or a `metrics`-scoped key.

**Test**: unauthenticated `GET /readyz` contains none of `address`, `pinned_address`, `last_error`.

---

## LOW

### L1. Cedar stores client sessions with an empty tag but looks them up by `SecurityTag` — CONFIRMED (structural; latent cross-grant reuse)

- [ ] fixed (together, in cedar AND webapi)

cedar `security/auth.go:1530` `NewSessionEntry(…, "")`, `:1541` `cache.MapCommand("", serverAddr,
cmd, …)` vs `:544` `LookupByCommand(a.config.SecurityTag, …)`; key is `{tag,addr,<cmd>}` or
`{addr,<cmd>}` (`session_cache.go:214-256`) and contains no identity, auth level or policy. Also
`inherited_session.go:563`, `mint_inheritable.go:72` map with `""`.

Consequences: (a) tagged callers (MCP OAuth2 and SSH gateway tag by *username*,
`hs/sshgateway.go:67-93` `withCondorCredential`; API keys and superuser tag by digest) never
resume — full handshake per request, schedd load; the webapi comments saying "the tag isolates
sessions" hold by accident. (b) Untagged + global-cache callers share `{addr,<cmd>}` with the
daemon's own sessions (ping `hs/handler.go:3281/3294`, dbmirror `dbmirror.go:1022`); no user path
lands there today (bearer/cookie/share use per-token caches; others set tags). (c) **Latent**: if
the cedar store is fixed to use the tag without changing the username tags, a READ-limited MCP grant
resumes a session negotiated by a READ+WRITE grant of the same user (the schedd's authz bounding set
is the negotiating token's); `isMethodAllowedByScopes` checks only `mcp:*`, and the SDK transport
never calls it.

Fix: cedar stores with `a.config.SecurityTag` and derives a mandatory tag (SHA-256 of the token)
when a token credential has none; root module refuses `Token != "" && SecurityTag == "" &&
SessionCache == nil`; webapi tags by credential digest (`sessionTagFor`) or `username|authz`, never
bare username; apply `isMethodAllowedByScopes` (extended to `condor:/*`) on the SDK route.
Test: two configs with different tokens, same addr/cmd, nil cache → second does not resume the
first; a tagged config resumes its *own* session.

### L2. MCP single-job hold/release/remove and edit_job apply no owner clause or privilege tier — CONFIRMED

- [ ] fixed

`webapi/mcpserver/handlers.go:1607-1640` `performJobAction`, `:1709-1760` `toolEditJob` send
`ClusterId==X && ProcId==Y` as-is; `owner_scope.go` says tierMutate covers these but only
`remove_jobs`/`upload_job_input` consult it. "Not found vs refused" leaks; a queue-superuser
operator driving an LLM is one prompt injection from `remove_job` on anyone's job. Also
`handlers.go:1311-1316` `query_jobs` skips owner scoping when `ownerFromActor` yields `""` (actor
like `@domain`). Fix: `scopeToOwner(ctx, idClause, tierMutate)`; treat `owner==""` without
`AllUsers` as "authentication required". Test: non-superuser actor `hold_job` on another user's id
→ "not found" before any schedd action; `mcp:superuser` still succeeds.

### L3. `markValidatedOnSuccess` is dead code — and must stay dead — CONFIRMED

- [ ] deleted

`hs/handler.go:2028,2169-2186` reads `requestTokenFromContext(r.Context())`, but the token is only
placed on the derived context in `hs/server.go:1227` (`withRequestToken`), never written back to
`*r` — so `MarkValidated` never fires for JWT bearers and `ValidatedUsername` is always `""`
(identity comes solely from `actorForSession`; this is the safe outcome). If wired up as designed,
any 2xx from an identity-free endpoint (`/api/v1/ssh/ca`, `/version`, `/chat/info`, `/templates`,
`/metrics/{table}` returning `{enabled:false}`) would promote a forged JWT's `sub`; chained with
`/api/v1/ssh/certificate` that is account takeover. Delete `markValidatedOnSuccess` /
`withRequestToken` and the "Auth H3" lazy-validation description in `SECURITY_FINDINGS.md`; fix the
comment at `hs/handlers_dbroute.go:45` that cites `MarkValidated` as a trust source. Validate only
from a negotiated CEDAR identity. Test: `ValidatedUsername(forged)` stays `""` after 200s from
`/whoami`, `/version`, `/templates` through full `ServeHTTP`.

### L4. Unmarked credential-origin policy is `Allow` in production; several daemon paths unmarked — CONFIRMED

- [ ] fixed

No caller of `SetUnmarkedOriginPolicy` (`credential_origin.go:139-142`) in htcondor-api
(htcondor-mcp marks its root ctx daemon, `main.go:128,292`). Unmarked: `hs/handlers_interactive.go:558-585`
`removeJobOnDisconnect` (see L19), `hs/handler.go:3270` `performPeriodicPing`, `:2383,2391`
`jobMirror.Run`/`superuserPolicy.Run`, `:1311,1346` credd/placementd discovery,
`hs/handlers_jupyter.go:82-87`. All legitimate daemon work. Fix: mark each
`WithDaemonCredential(ctx, "<reason>")`, run `UnmarkedWarn`, then `UnmarkedDeny`. Test: run the
httpserver unit suite with `UnmarkedDeny` set in `TestMain`. Note (out of scope, plausible):
`/api/v1/placement/*` passes a user-marked ctx with no SecurityConfig to `placementd.go:240`
`GetSecurityConfigOrDefault` — should already be refused at runtime; verify.

### L5. Privilege drop keeps root's supplementary groups; continues as root when the condor account cannot be resolved — CONFIRMED

- [ ] fixed

`droppriv/init_linux.go:14-26` (`Setegid`/`Seteuid` only, no `Setgroups`);
`webapi/cmd/htcondor-api/main.go:1559-1566` ("cannot resolve condor user identity … continuing as
root"). Fix: `syscall.Setgroups([]int{gid})` before `Setegid`; make an unresolvable drop target
fatal (as `Manager.Start` is for uid 0).

### L6. Starter/CCB legs dial an EP-chosen address with the daemon credential and fall back to a full handshake — CONFIRMED

- [ ] fixed

`schedd_ssh.go:187` `starterSecurityConfig` (`WithoutSecurityConfig` → daemon credential),
`:244-256` `dialStarter` (addr = `StarterIpAddr` from the schedd reply, controlled by the
EP/starter, incl. `ccbid` broker contacts); cedar `client/client.go:248-269` (resumption failure →
fresh full auth). No bearer is disclosed (TOKEN auth sends `header.payload` + AKEP2 transcript), but
the daemon identity is exercised against an attacker host. Fix: set `SessionID =
claim.SecSessionID()` (cedar explicit-session path, `auth.go:521-534`) so a failed resumption is an
error; restrict the CCB broker leg to brokers from the collector's `CCB_ADDRESS`. Test: fake starter
rejecting resumption → no `DC_AUTHENTICATE` full handshake.

### L7. Transport cache ignores superuser impersonation; `ownerFromActor` collapses realms — CONFIRMED / PLAUSIBLE

- [ ] fixed

`hs/handlers_jobproxy.go:195-204`: `impersonate` does not change `GetAuthenticatedUserFromContext`,
so the key is `{operator, cluster, proc}` armed or not (the comment claiming "that is the job's
owner" is wrong); a transport opened while armed is reused after disarm with no schedd check or
`auditSuperuserAction` line. Fix: include the impersonation marker in `jobssh.Key` or evict on
disarm. `hs/sshgateway.go:368-382` `sshGatewayIdentity` / `hs/handlers_sshcert.go:148`:
identity = `actor[:lastIndex("@")]`, so `alice@a.org` and `alice@b.org` both become `alice` (same
minted `sub`, same cache key) — collision depends on the IdP. Fix: refuse/disambiguate a realm that
differs from the configured domain; key the cache on the full actor.

### L8. With a user token the client still offers SSL and ANONYMOUS at `Authentication=OPTIONAL` — CONFIRMED

- [ ] fixed

`security.go:158-165` (filter removes only TOKEN/FS), `:593-595` (ANONYMOUS appended for
CLIENT/READ), `:557-568` (defaults OPTIONAL — same as `condor_secman.cpp`), `hs/auth.go:116-118`
(`Authentication` forced REQUIRED only when empty — never is); cedar `auth.go:1734-1736`
(OPTIONAL+OPTIONAL → no authentication). Against a READ-open schedd (`SEC_READ_AUTHENTICATION=OPTIONAL`,
the recommended config) a plain `QUERY_JOB_ADS` completes unauthenticated after the token is
filtered out. Impact today is what anonymous would get anyway (L3 is dead); still set
`Authentication = REQUIRED` and `AuthMethods = [TOKEN]` (SSL only by explicit opt-in) on the token
path and drop `AuthNone`. Test: config with `SEC_CLIENT_AUTHENTICATION=OPTIONAL` + token → REQUIRED
and no `AuthNone`/`AuthSSL`.

### L9. Raw-tar upload routes skip `validateTarEntryName`; directory entries skip the allow-set — CONFIRMED (schedd guards it)

- [ ] fixed

`hs/handlers.go:1548` `handleJobInput` (raw tar body) and `hs/handlers_share.go:510-599`
`handleSharedInput` hand the tar straight to `SpoolJobFilesFromTar`; `validateTarEntryName` is
applied only in `writeMultipartTar` (`handlers.go:1702`) and `toolUploadJobInput`
(`mcpserver/handlers.go:2468`). In `schedd_transfer.go:802-885` `sendJobFilesFromTar`, `TypeDir`
entries are forwarded as `CommandMkdir` with only `TrimSuffix("/")`. Schedd `LegalPathInSandbox`
(`file_transfer.cpp:2610`, before the Mkdir branch at `:3172`) rejects traversal, so no host impact.
Fix: validate names (file and dir) inside `sendJobFilesFromTar` (reject the upload on a bad name) so
all four routes agree. Test: raw tar with `../x/` dir entry and `foo/../bar` file via
`POST /jobs/{id}/input` and via a share URL → 400 before any schedd traffic.

### L10. Library-only: `sandbox.ExtractOutputSandbox` lets ad-chosen paths escape `Iwd` — CONFIRMED, no caller in tree

- [ ] fixed

`sandbox/sandbox.go:378-421` `outputDestination`/`stdioDestination`, `:430-457`
`getDestinationPath`, `:460-486` `extractFile`: `escapesIwd` is applied only to the raw tar entry
name; a remap `Dest` of `../../x`, a relative `Out`/`Err` of `../x`, and absolute remap targets go
through unchecked; `droppriv/operations.go:49-76` `withUser` runs `fn()` as the current process
user when `!m.enabled`. No caller in `webapi/` or the root binaries (every API retrieval uses
`ReceiveJobSandbox` into a writer). Fix before any consumer (golang-ap shadow) appears: resolve
every destination with `filepath.Rel(iwd, dest)` and reject `..` unless the write identity is the
ad's owner under an enabled privsep manager. Test: ad with `TransferOutputRemaps="a=../../escape"`
and `Out="../o"` → nothing written outside `Iwd`.

### L11. Built-in IdP internal RP client has a hard-coded secret; a seeded client stores its secret unhashed — CONFIRMED

- [ ] fixed

`hs/handler.go:3508-3530` (`clientID := "internal-client"; clientSecret := "internal-secret"`);
`:3755-3800` `initializeIDPClient` (`Secret: []byte(secret)` raw while fosite compares with bcrypt
→ "htcondor-server" is dead). `/idp/authorize` auto-approves and PKCE is not required for
confidential clients, so any leaked IdP auth code is redeemable by anyone at `/idp/token`. Fix: mint
with `crypto/rand` on first start and persist sealed (or `masterSubkey("idp-internal-client")`);
bcrypt in `initializeIDPClient` or delete that client. Test: `/idp/token` with
`internal-client:internal-secret` → `invalid_client`.

### L12. Device flow: `slow_down` never enforced; legacy verify looks up the user code pre-auth with no rate limit; `device/authorize` ignores client `grant_types` — CONFIRMED

- [ ] fixed

`hs/device_code_handler.go:27` (`ErrSlowDown` never returned), `:146` (`UpdateDeviceCodePolling`
written, never read); `hs/mcp_handlers.go:1960` (`GetDeviceCodeSessionByUserCode` before
`deviceApprovalIdentity`), `:1645-1660` (no `client.GetGrantTypes()` check).
`design_notes/DEVICE_CODE_FLOW.md:190` documents `slow_down` as implemented. User codes are 40
bits / 10 min, so brute force is impractical; the pre-auth lookup is a valid/invalid oracle. The
SPA path (`hs/handlers_ssh_consent.go`) has proper limits. Fix: enforce `interval` from
`last_polled_at`; move the lookup after `deviceApprovalIdentity` and gate with `sshConsentAllow`;
require `device_code` in the client's `grant_types`. Test: two polls <5 s apart → `slow_down`;
21 bad codes/min from one IP → 429.

### L13. SSO logs the full userinfo claim set at Info; signing-key path logged; both reach the admin log ring — CONFIRMED

- [ ] fixed

`hs/oauth2_sso.go:247` (`"claims", claims` — email, name, groups on every login);
"Minted JWT for session user" logs `signing_key_path`; Info lines land in the admin ring buffer
(`hs/handler.go:1271`) and so in `/api/v1/admin/logs`. Fix: log the subject only at Info, full
claims at Debug.

### L14. A shared user template under a built-in id shadows the built-in for every user fetching by id — CONFIRMED

- [ ] fixed

`webapi/templates/templates.go:491-509` `Library.Get` consults the user store before
global/builtin; `:769-779` `sqlUserTemplateStore.Get` (`WHERE id=? AND (owner=? OR
visibility='shared') LIMIT 1`, no ORDER BY / owner preference); `validateTemplate:371` does not
reserve built-in ids. Cross-owner overwrite/delete is not possible (PK `(owner,id)`, delete checks
owner). Fix: `ORDER BY owner=? DESC`, check global/builtin before other owners' shared rows, reject
saving an id that collides with a global/builtin template. Test: save shared `hello-world` as
`mallory`; `Get("hello-world","alice")` returns the builtin.

### L15. Owner clause built from the *qualified* actor on mirror/dashboard paths; share handlers split at the first `@` — CONFIRMED (fails in the safe direction)

- [ ] fixed

`hs/handlers_webui.go:273-307,420-432`, `hs/handlers_issues.go:113,170`,
`hs/handlers_dashboard_stream.go:80-85`, `hs/handlers_jobswatch_mirror.go:39-43`,
`hs/dashboard_mirror.go:49-51` compare `Owner == "<actor>"` where a bearer's actor from `Ping` is
`alice@domain` and ads hold bare `alice` → bearer users see empty dashboards/issues/streams.
`hs/handlers_watch_share.go:69` and the output/input share handlers use `SplitN(…, "@", 2)[0]`
while `ownerFromActor` uses the last `@` (SSSD-style `foo@bar@domain` users get a fail-closed
404). Fix: route all through `ownerFromActor`. Tests must assert both directions ("others absent"
AND "own present").

### L16. New string-built expressions from user input — CONFIRMED (bounded)

- [ ] fixed

`hs/pool_summary.go:369-372` `constraint = fmt.Sprintf("(%s) && (%s)", constraint, userExpr)` —
unbalanced parens widen the `SlotType =!= "Dynamic"` filter (collector read; same caller can read
dynamic slots via `/collector/ads`, so no boundary crossed), exactly the pattern `classadBalanced`
exists to end. `webapi/mcpserver/handlers_build.go:418-424,585` `build_container.destination`
(only `Contains("://")` checked) and `handlers_dag.go:282-320` `batch_name`/`append` are spliced
into generated submit files without newline filtering (job runs as the caller; equals
`submit_job`'s power; tool arguments no longer mean what they say; `interactive/manager_internal.go:831-836`
already guards its GPU fields for this reason). `interactive_session_start.requirements` is
parse-validated then raw-spliced (`combineRequirements`) — safe given `ParseExpr`'s whole-input
rule, but the one remaining raw splice of LLM text. Fix: `classadBalanced` in pool_summary; reject
`\n`/`\r`/`"` in `destination` and `batch_name`.

### L17. Opaque OAuth2 bearers are "Validated" by the AS, not the schedd, yet the mirror route treats that as schedd acceptance — CONFIRMED

- [ ] fixed

`hs/auth.go:436-492` `AddValidated`; `hs/server.go:1322,1441-1452` (skips `actorForSession`);
`hs/handlers_dbroute.go:42-52,79-90`. A user the schedd's READ ACL would refuse (or for whom
minting fails) still reads the queue from the mirror, unscoped as a bearer. Fix: run
`actorForSession` once (cached 5 min) for `AddValidated` entries before mirror routing (and H6's
READ-level resolution). Test: opaque token for a user excluded by `ALLOW_READ` → `/api/v1/jobs`
with mirror enabled → 401.

### L18. API-key IDTOKEN `sub` not UID_DOMAIN-qualified; user-header mode tags the session from the header while the credential comes from the cookie — CONFIRMED

- [ ] fixed

`hs/apikey_condor.go:48` mints `generateMCPAccessJWT(row.Creator, …)` with a bare creator while
every other mint qualifies (`hs/mcp_handlers.go:2821`) — verify the schedd maps a bare `sub` as
intended. `hs/server.go:1245-1259`: with `userHeader` set and no Bearer, `extractOrGenerateToken`
prefers the session cookie (token `sub` = cookie user) but `sessionTag = r.Header.Get(userHeader)`
with the global cache; a cookie-user session is stored under the header user's tag. Fix: derive the
tag from the identity the minted token carries. Test: cookie=alice + trusted header=bob →
`SecurityTag` derived from alice.

### L19. Interactive-terminal disconnect removes the job with the daemon credential and no owner clause — CONFIRMED

- [ ] fixed

`hs/handlers_interactive.go:558-585` `removeJobOnDisconnect`: `context.Background()` (unmarked →
`GetSecurityConfigOrDefault` falls through to the daemon; `WithToken` only stores a value no CEDAR
path reads) and constraint `ClusterId == %d && ProcId == %d` with no `Owner ==`. No exploit today
(the job id came from a schedd-authorized shell). Compare `interactive.Manager.removeJob`, which
adds `Owner == %q`. Fix: keep the caller's `SecurityConfig` (as `interactive.session.secConfig`
does) and add the owner clause. Test: fake schedd recording the constraint and credential origin.

### L20. `/api/v1/whoami` reports `authenticated:true` with an empty `user` for an unverified bearer — CONFIRMED

- [ ] fixed

`hs/handlers.go:3077-3105`. Fix: `Authenticated = username != ""`.

### L21. SSH gateway: per-source cap and lockout key on the TCP peer; forwarding reaches any host:port — CONFIRMED (design)

- [ ] documented / fixed

`webapi/sshgateway/auth.go:77-83,123-149` (`MaxPerSource` 4), `banlist.go:559-577`: no PROXY
protocol (address not spoofable — good) but behind a TCP LB/NAT the whole site is one source (4
in-flight logins; one user's abandoned logins lock everyone out 15 min → 24 h); `TrustedNetworks`
exempts the LB but also disables its lockout. `webapi/sshgateway/session.go:668-709,726-787`,
`webapi/jobssh/cache.go:230-247`: `direct-tcpip` dialled verbatim through the job's sshd (parity
with `condor_ssh_to_job -L`; the starter's sshd template sets no `PermitOpen`), while the HTTP proxy
restricts itself to loopback/scratch. Fix: document that the gateway must terminate TCP itself (or
add PROXY-protocol support gated on a trusted-upstream list); optionally restrict `direct-tcpip` to
loopback and `direct-streamlocal` to the scratch dir.

### L22. GECOS identity mapping: fails closed on ambiguity, but GECOS is user-writable on some hosts — PLAUSIBLE

- [ ] documented

`idmap/idmap.go:356-400` `Resolve`, `:473-520` `resolveByGecos`, `:540-552` `probeByName`:
duplicate GECOS → `ErrAmbiguous` (no fall-through to `username`); hits re-verified against live
GECOS. Where `chfn` allows full-name changes (RHEL default; Debian `CHFN_RESTRICT=rwh` blocks; SSSD
users cannot), a local user can make another subject ambiguous (login DoS) or capture a login-name
subject whose own account lacks a matching GECOS. Fix: document `CHFN_RESTRICT`; prefer the
`username` strategy first where subjects are login names; alert on `ShadowedUsernames`. Test:
passwd fixture with bob's GECOS == "alice" and no other GECOS "alice"; `Resolve("alice")` must not
return "bob".

### L23. Token-exchange subjects carry the external issuer's `groups` even with `HTTP_API_GROUP_SOURCE=system` — PLAUSIBLE

- [ ] checked

`hs/oauth2_token_exchange_ext.go:206` returns `claims.Groups`; `hs/oauth2_token_exchange.go:98`
`session.Groups = subjectGroups`; the SSO path instead runs `localIdentity.resolveWithHint`
(`hs/oauth2_sso.go:374`), which ignores token groups when sourcing from the system
(`hs/identity_local.go:470-476`). Remaining check: whether the exchange handler passes the identity
through `localIdentity.resolve` before setting `session.Groups`; if not, `mcp:admin`/`mcp:superuser`
entitlement (`getScopesForGroups`) for exchanged tokens is decided by the external IdP's claim.

### L24. Documentation divergences — CONFIRMED

- [ ] fixed

`hs/README.md:537-541,667-680,905-909` show `HTTP_API_USER_HEADER` without
`HTTP_API_USER_HEADER_TRUSTED_PROXIES` (the documented config refuses to start and the error
suggests `HTTP_API_USER_HEADER_TRUST_ANY=1`); `README.md:540` calls `HTTP_API_SIGNING_KEY` "demo
mode only" although it is the production minting key. `DEVICE_CODE_FLOW.md:190` documents
`slow_down` (unimplemented). `OAUTH2_IMPLEMENTATION.md:74,123` lists rate limiting and PKCE as
future work (PKCE *is* enforced for public clients; rate limiting exists only for SSH consent and,
brokenly, IdP login). `hs/mcp_handlers.go:1463` comment "publishes with the server's own collector
client, not the caller's credential" is stale. `SECURITY_FINDINGS.md` "Auth H3" describes L3's
non-running mechanism. `HTTP_API_METRICS_PUBLIC=true` is not warned at startup.

---

## Also noticed, not findings on their own

- `mcpActors.allowResolve()` is one process-global 5 req/s limiter (`hs/mcp_actor.go:62-70`): a
  flood of unknown bearers starves identity resolution for every IDTOKEN caller (owner-scoped tools
  refuse; feeds H5). Make it per-source.
- Session-cookie mode mints a new JWT and creates a `TokenCache` entry + `AfterFunc` per request
  (1-min TTL) — churn under load.
- `hasBearerCredential` exempting any `Authorization` header would become a cookie-less CSRF bypass
  if user-facing Basic auth is ever added (M6 covers today's case).
- `fetchUserInfo` decodes the upstream userinfo body with no size cap (operator URL; trusted).
- `handleOAuth2Authorize` with a trusted `userHeader` skips `mapAssertedIdentity` while
  `deviceApprovalIdentity` applies it.
- `handleAdminCondorConfig` redaction is name-based (`PASSWORD|SECRET|PRIVATE_?KEY|API_?KEY|TOKEN|BEARER|CLIENT_?SECRET`);
  a future knob named `*_KEK`/`*_SALT` would be dumped to admins.
- `droppriv.withRoot` silently runs `fn()` unprivileged when `captureThreadCredentials` fails —
  fine for reads; a future write-as-root helper would write as condor unnoticed.
- `ReadTimeout=30s` applies to the whole body and no handler calls `SetReadDeadline`: 1 GiB tar /
  100 MiB multipart uploads over a slow link fail at 30 s (functional).
- Templates: no per-user count cap (8 MiB body each); chat has no per-user rate/concurrency gate
  (operator LLM-cost burn); `jupytertunnel` has no per-owner instance cap (each is a job in the
  user's own queue).
- `ratelimit.Limiter.userLimiters` keyed by the unverified JWT `sub`, never evicted (only when a
  per-user limit is configured).
- Demo mode caches a 24 h READ/WRITE/DAEMON/ADMINISTRATOR token untagged in the global session
  cache (`main.go:2332,2415`).
- Chat `AutoApprove` is client-controlled, so the `confirm:true` gate on destructive chat tools is a
  UI affordance for the user's own authority — state that in docs.

---

## Checked and found sound (do not "fix" these)

- Identity: `TokenCache.Add` never sets `Validated` (`TestTokenCacheDoesNotValidateOnAdd`); JWT
  bearer identity comes only from `actorForSession` (schedd Ping) or `AddValidated` after
  introspection / API-key / share-token verification; no mint path takes `sub` from an unverified
  claim; minted scopes narrowed to READ/WRITE (`mapCondorScopesToAuthz` drops
  ADMINISTRATOR/CONFIG/DAEMON/NEGOTIATOR); the opaque-token fix (`hs/server.go:1310-1360`) is intact;
  `NewClientSecurityConfig` with an explicit token does not inherit the ctx's config/cache/tag.
- Daemon fallback gate: `ServeHTTP` and `sshgateway.channelContext` mark requests user;
  `WithDaemonCredential` detaches the caller credential; `checkDaemonFallbackAllowed` refuses
  `OriginUser`; `GetSecurityConfigOrDefault` returns a copy; FS stripped unconditionally on the token
  path and again in `ConfigureSecurityForTokenWithCacheAndFallback(…, false)`; no production
  `allowFSFallback=true` caller; `withCondorCredential` errors without signing key / trust domain.
- Owner scoping: `scopeToOwner`/`classadBalanced` (parse + reserialize; `ParseExpr` rejects
  `true) || (true`, `x == 1 ) foo`, `a; b`, multi-line) at every LLM/REST constraint sink combined
  with an owner clause — `handleListJobs`, `historyOwnerScope`, `bulkOwnerScope`, `jobsFromMirror`,
  `planSuperuserBulkAction`, all chat mutating tools, `query_history_db`/`as_of`/`aggregate_jobs`;
  watch constraints are compiled and evaluated in-process over `Owner == <actor>` rows only; job
  ids via `Atoi`/`%d`; projections/group_by are names, metrics `group_by`/`agg` regex-validated;
  edit names/values are separate QMGMT wire strings; `Submit`/`SubmitRemote` set effective owner
  from the negotiated identity; mirror cursors can only move position, constraint re-sent and
  re-scoped per page; `/api/v1/jobs` and `/archive` refuse unidentified callers before mirror
  routing; single delete/hold/release/sandbox/log/match-analysis/dag/job-watch use `jobOwnerScope`;
  superuser impersonation derives the target from the job, caps fan-out (25 owners / 10k jobs),
  audits every action, errors rather than falls back.
- Paths into jobs: `GET_JOB_CONNECT_INFO` ownership enforced by schedd `UserCheck2`
  (`schedd.cpp:19058-19077`) with the caller's IDTOKEN on gateway/WS/proxy/exec/peek legs; START_SSHD
  leg pins Auth/Enc/Integrity REQUIRED, AES, host key `FixedHostKey` from the reply; cert auth
  compares CA by `bytes.Equal` before `CheckCert`, exactly one principal, `CriticalOptions` passed
  through, no bare public keys, no password auth, identity never from `conn.User()`; device-flow
  identity from fosite introspection; per-channel 5-min tokens with `SecurityTag = account`;
  `jobssh` socket names `[A-Za-z0-9._-]`, address from `<name>.path` with length checks,
  `MaxSessionsPerTransport` accounted on every path; interactive manager keyed `(owner,name)`, every
  lookup `Owner == %q`, `ValidateCallerSubmitLines`, GPU strings newline-checked, admins NOT exempt
  for exec; MCP exec/tail pre-check `Owner == classadStringLit(owner)` + running/universe; Jupyter
  tunnel token 72-byte HMAC, instance-bound, single-use with durable nonce roll, sealed under the KEK,
  token file 0600 and unlinked; WebSocket origin check, 64 KiB terminal read limit, signal
  allow-list; gateway lockout tables bounded, bans never evicted, IPv6 /64 and /48.
- Filesystem: no user-facing surface writes a user-named file to the AP's disk; `validateTarEntryName`
  rejects empty/NUL/`\`/leading `/`/non-canonical/`..`; non-`TypeReg` entries never reach the schedd;
  share-URL upload redemption owner-rescoped, state-gated, size-capped; submit text cannot touch the
  host (`include`, `include command`, `$ENV()`, `queue from file`, `matching` refused under
  `NoLocalAccess`, set by every webapi caller); DAG / build_container / Jupyter / interactive stage
  via `fstest.MapFS` → `SpoolJobFilesFromFS`; nothing exec'd on the AP; `/files/{name}` rejects
  separators and reads from the schedd tar stream; all `*AsRoot` paths are operator config;
  `withRoot` thread-scoped (`LockOSThread` + raw `setresuid`); privileges dropped before log / DB /
  listeners; KEK, SSH, API-key loaders refuse world bits; `Growing` spool buffer limit enforced with
  non-caller-chosen temp names; `handleAdminLogs` is an in-memory ring; `localcredmon` writes `.use`
  via `CreateTemp` 0600 + rename.
- OAuth2/OIDC: PKCE for public clients; CIMD clients forced public, fetch https-only, no
  userinfo/fragment, no redirects, resolved-IP deny list, 64 KiB cap, 5 s timeouts, `doc.client_id
  == URL`; `redirect_uri` exact match (loopback port variance only, identical at authorize and
  token); consent CSRF HMAC bound to `(username, state|user_code)` with a master-derived subkey,
  constant-time; `narrowConsentScopes` only drops; `getScopesForGroups` is the ceiling,
  privileged scopes default-deny; `scopesAllowedByScheddACL` on consent and device approval;
  `AuthorizedScopes` recorded and admin edits bounded; refresh: `reauthorizeRefreshGrant` (absolute
  cap, group re-eval + narrowing, user-record / schedd-ACL / upstream oracles), rotation with reuse
  detection and chain revocation; tokens opaque fosite HMAC; `client_credentials` needs a configured
  service subject; revocation client-bound; token exchange otherwise confidential-only, scope
  intersection, RS256/ES256 with iss/aud/exp/nbf after signature; device codes 256-bit single-use
  10 min, approval needs authenticated identity + CSRF, `UPDATE … WHERE status='pending'`; IdP bcrypt,
  pending accounts refused, off by default; SSO code exchanged server-side, identity from userinfo,
  `oauth2Requirements` fails closed, idmap refuses ambiguity, identity cookie HMAC + subject-bound +
  expiry in payload, `return_to` validated at store and callback; sessions 256-bit,
  Secure/HttpOnly/SameSite=Strict/Path=/, fresh per login, server-side delete on logout and superuser
  disarm, `/logout` POST-only; global Origin check on non-safe methods without Bearer; `userHeader`
  trusted only from proxy CIDRs by `RemoteAddr`, never XFF; share URLs HKDF of the pool key read as
  root, kind/cluster/proc/owner/exp bound, kind confusion rejected, ownership re-checked at mint and
  enforced by the schedd at redeem, TTLs clamped; SSH certs: principal = schedd-validated account,
  one principal, ≤24 h, random serial, RSA ≥3072, `condor:/WRITE` required, extensions limited, CA
  sealed and never regenerated when the KEK cannot open it; API keys admin-session-only, creator-bound,
  128-bit secret as SHA-256, constant-time, scope allowlist, expiry enforced; master-key envelope:
  unopenable master is an error, only `rand.Read` fallbacks are the two ephemeral form-token keys when
  there are no signing keys (warned), seal AES-256-GCM random nonces per-row DEK, KEK file never
  auto-created.
- Admin/infra: `requireAdmin` 503/401/403, bearers never qualify; admin scope editor narrows only;
  admin POSTs same-origin; superuser group re-checked per action; group sources cannot mix
  token+local, degraded-and-empty system lookups refuse login, header identities go through
  `mapAssertedIdentity`; `handleCollectorAdvertise` authenticates as the caller with no discarded auth
  error; credd client uses the ctx credential, `user=` enforced daemon-side, payloads validated;
  placement admin-gated with 403 (never 200-empty), no MCP/chat path; mirror token READ-only, 10 min,
  daemon subject, never returned; `/metrics` API key + `metrics` scope, no identity labels;
  `/healthz` returns only status; chat LLM key file 0600/0400 via `OpenMaybeAsRoot`, sent only as
  `x-api-key`, 8 tool hops, 32 KiB tool results, destructive tools owner-scoped; `toolstats` records
  no arguments; access log uses `r.URL.Path` only (share `?t=` never logged); cedar `🔐 CLIENT:`
  lines redact session ids and never print token bytes; no `Authorization`/cookie logging; startup
  refuses user-header without trusted proxies, invalid durations/booleans fatal, TLS min 1.2.
- Resource bounds present: `/mcp` 16 MiB (after `mcpAuthContext`, before `ReadAll`), OAuth2
  token/consent/device 1 MiB, admin 64 KiB/1 MiB, templates 8 MiB, chat 1 MiB, SSH consent/cert,
  multipart 100 MiB, tar 1 GiB spooled to disk (fan-out ≤1000 procs, concurrency 10), tars forwarded
  raw (no decompression on the AP); listings stream with `limit` (default 50) / `scan_limit` (10000)
  and `LimitResults` pushed to the schedd; MCP `clampToolLimit`; DAG sandbox reads 64/8/96 MiB and
  50000 entries, structure cache 16×1 h, archive query 20000/200000; peek 64 KiB default, 4 MiB
  REST / 256 KiB MCP hard, `/log` `CopyN(max+1)`, `/files/` via `io.Pipe`; interactive MaxPerOwner 4,
  lease 8 h, exec ≤30 min, output 64 KiB; `jobssh` 10 sessions/transport, 10 min idle; gateway 32
  channels/connection, ban tables 4096 via `makeRoom`, max ban 24 h; watches TTL ≤7 d, dedup, one
  schedd query per owner per pass, `MaxMatched` 25, ≤1000 share URLs per mint; `mcpActorCache` sweep;
  state store sweeper (no cap — M13); jwt-assertion tables cleaned on insert; session tables expire;
  token retention daily; metrics labels fixed templates; `http.Server` Read/Write 30 s, Idle 120 s,
  HTTP/2 off; MCP request deadline 15 min with 30 s write window; CIMD 5 s; schedd rate-limit wait
  1 s; sandbox fetches 30/60 s; all 11 per-request goroutine sites exit on ctx/channel close.

## Not reached

`collector_watch.go` per-user caps; dbmirror ingest memory; exact per-entry size of a cedar
`SessionCache`; `issues_collect.go` / `diagnostics.go` resource bounds; SSH gateway `Session.Serve`
beyond the channel cap; the SPA frontend; whether the Go config parser honours subsystem-prefixed
knobs (`HTTP_API.SEC_TOKEN_SYSTEM_DIRECTORY`, the only candidate C1 stopgap). Nothing was run
against a live access point; empirical checks were unit-level (SQLite mode under umask 022, `+Attr`
override ordering, `scopeKey(nil)`, `ParseExpr` on unbalanced input, `go build ./...` in both
modules).
