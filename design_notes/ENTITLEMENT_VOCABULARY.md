# Entitlement vocabulary

Status: **draft, for iteration.** Nothing here is implemented except
`pool:read`. Open questions are marked **[OPEN]** and are the parts most
worth arguing about.

## The problem

The server has two independent vocabularies for "may act beyond your own
jobs", and they are inverted relative to each other.

| Name | Where | What it actually grants |
| --- | --- | --- |
| `HTTP_API_WEBUI_ADMIN_GROUP` | session | cross-user **read and mutate**, plus the admin UI |
| `mcp:admin` | scope | cross-user **read** only |
| `mcp:superuser` | scope | cross-user **mutate** only; *not* a superset of `mcp:admin` |
| `HTTP_API_SUPERUSER_GROUP` | session | the right to **arm impersonation**, which grants neither tier by itself |
| `HTTP_API_MCP_ADMIN_GROUP` | config | who may be *granted* `mcp:admin` |
| `HTTP_API_MCP_SUPERUSER_GROUP` | config | who may be *granted* `mcp:superuser` |
| `MCP_ADMIN_USERS` | config | cross-user read, but only for a credential carrying no scopes |
| `IsQueueSuperUser` | schedd | HTCondor's own `QUEUE_SUPER_USERS` |

So "admin" means both tiers in one place and read-only in another.
"Superuser" means three different things, only the last of which is the
established HTCondor meaning.

This is not only ugly. It is how the API-key gap hid: an operator
reasonably concluded that an admin-minted key inherits admin powers,
because in the Web UI vocabulary "admin" means exactly that. Nothing
in the names says the two vocabularies disagree.

## Every scope

The whole vocabulary, so a change to part of it can be judged against
the rest. "Carried by" is which credential kinds can hold it.

| Scope | Carried by | Grants | Proposal |
| --- | --- | --- | --- |
| `openid` | OAuth2 | Authentication. | unchanged |
| `profile` | OAuth2 | Nothing; accepted for OIDC compatibility, no claim is read. | unchanged |
| `email` | OAuth2 | Nothing; accepted for OIDC compatibility, no claim is read. | unchanged |
| `offline_access` | OAuth2 | A refresh token. Requested from the upstream provider by default unless `HTTP_API_UPSTREAM_REFRESH` is `off`. | unchanged |
| `mcp:read` | OAuth2 | Read through `/mcp`. | **[OPEN]**, below |
| `mcp:write` | OAuth2 | Submit and manage through `/mcp`. | **[OPEN]**, below |
| `mcp:admin` | OAuth2 | Read **every** user's records, on REST and MCP alike. | → `pool:read` |
| `mcp:superuser` | OAuth2 | Act on **every** user's records. | → `pool:write` |
| `condor:/READ` | OAuth2, API key | HTCondor READ, carried into the minted IDTOKEN as an authorization limit. | unchanged |
| `condor:/WRITE` | OAuth2, API key | HTCondor WRITE, same mechanism. Not a superset of READ. | unchanged |
| `condor:/ADVERTISE_STARTD`, `_SCHEDD`, `_MASTER` | OAuth2 | Nothing. Deprecated, kept only so existing grants can refresh; dropped from a grant at its next authorization. | unchanged |
| `condor:/ADMINISTRATOR`, `/CONFIG`, `/DAEMON`, `/NEGOTIATOR` | — | Nothing. **[OPEN]**, below | |
| `metrics` | API key | `/metrics` (Prometheus exposition). | unchanged |
| `placement` | OAuth2 | The placement API. Held only by the seeded placement client, never advertised. | unchanged |
| `pool:read` | API key, OAuth2 | Read every user's records. New; see *Already using one of these names*. | **[OPEN]** name |
| `pool:write` | API key, OAuth2 | Act on every user's records. New. | **[OPEN]** name |

Three things that table makes visible and prose did not:

**[OPEN]** `mcp:read` / `mcp:write` keep their surface name, and should.
Unlike `mcp:admin` they really are scoped to a surface: they gate `/mcp`
and nothing else. The rename is for scopes whose name claims a surface
while their meaning is global, which is only the admin pair. Worth
confirming, because "rename everything with a prefix" is the tempting
over-correction.

**[OPEN]** `condor:/ADMINISTRATOR`, `/CONFIG`, `/DAEMON` and
`/NEGOTIATOR` have user-facing descriptions in `getScopeDescription` but
are granted nothing: `mapCondorScopesToAuthz` maps only READ and WRITE,
and registration refuses the rest. They are dead vocabulary that still
describes itself as live. Either delete the descriptions or say in them
that the scope is not granted — the current state is a description that
reads like a capability.

**[OPEN]** `condor:/WRITE` does not imply `condor:/READ`, and
`mcp:superuser` does not imply `mcp:admin`. Two separate instances of
the same surprise, and whatever is decided for `pool:write` should
probably be decided for `condor:/WRITE` at the same time or deliberately
not.

## The proposal

Name entitlements after the two axes that actually exist — **reach**
(whose records) and **action** (what you may do to them) — and remove
"admin" and "superuser" from the entitlement vocabulary entirely.

Reserve **administrator** for managing *this service* (OAuth2 clients,
API keys, tokens, branding). Reserve **superuser** for HTCondor's
meaning and nothing else.

### Scopes

| Today | Proposed | Grants |
| --- | --- | --- |
| `mcp:admin` | `pool:read` | read every user's records |
| `mcp:superuser` | `pool:write` | act on every user's records |

Dropping the surface name from the scope is the point. The scope names a
power, not a door; honouring it on both REST and MCP is then obviously
correct rather than the leak it currently looks like.

**[OPEN]** `pool:write` vs `pool:mutate`. `write` pairs with `read` and
matches `condor:/WRITE`; `mutate` matches the internal `jobScopeMutate`
and avoids implying the HTCondor WRITE authorization level. Weak
preference for `write`.

**[OPEN]** Whether `pool:write` should imply `pool:read`. Making write
imply read is the conventional reading, but it silently widens every
existing `mcp:superuser` grant on upgrade.

### Configuration

Two knobs per entitlement, and they mean the same thing: **who may
request it**. Never who holds it.

| Entitlement | Groups | Users |
| --- | --- | --- |
| `pool:read` | `HTTP_API_POOL_READ_GROUPS` | `HTTP_API_POOL_READ_USERS` |
| `pool:write` | `HTTP_API_POOL_WRITE_GROUPS` | `HTTP_API_POOL_WRITE_USERS` |
| `mcp:read` | `HTTP_API_MCP_READ_GROUPS` | `HTTP_API_MCP_READ_USERS` |
| `mcp:write` | `HTTP_API_MCP_WRITE_GROUPS` | `HTTP_API_MCP_WRITE_USERS` |
| reach `/mcp` at all | `HTTP_API_MCP_ACCESS_GROUPS` | `HTTP_API_MCP_ACCESS_USERS` |
| reach the web UI at all | `HTTP_API_WEBUI_ACCESS_GROUPS` | `HTTP_API_WEBUI_ACCESS_USERS` |
| administer this service | `HTTP_API_SERVICE_ADMIN_GROUPS` | `HTTP_API_SERVICE_ADMIN_USERS` |
| act as another user | `HTTP_API_IMPERSONATION_GROUPS` | `HTTP_API_IMPERSONATION_USERS` |
| lead a project | `HTTP_API_PROJECT_LEADS_GROUPS` | `HTTP_API_PROJECT_LEADS_USERS` |

Three rules, and they are the point of the table:

1. **Every `*_GROUPS` has a matching `*_USERS`.** Naming one person
   should not require inventing a group for them, and a deployment with
   no group source at all should still be able to say who may do what.
2. **Both are plural, and both are lists.** The existing names are
   singular (`HTTP_API_WEBUI_ADMIN_GROUP`) while already accepting a
   list, which reads as a single group and is not one.
3. **Membership confers the ability to REQUEST a scope, never the
   scope.** A credential gets a power only by being granted it, at
   consent or at mint, and only if its holder was entitled to ask. This
   is the whole correction below.

#### Entitlement is not a grant

`MCP_ADMIN_USERS` **is not carried forward.** It does not gate a
request; it hands the read tier directly to any caller on the list whose
credential states no scopes. That is a permission appearing on a
credential that never asked for it and whose holder never consented to
it, which is exactly what the scope vocabulary exists to prevent.

`HTTP_API_POOL_READ_USERS` replaces it in name only. The semantics are
different: being listed means a request for `pool:read` *may be
granted*, and a credential that never requests it never carries it.

**This is a behaviour change, and the only one in this document that
silently removes a power.** A deployment relying on `MCP_ADMIN_USERS`
today has unscoped stdio callers reading every user's jobs; after this
they read their own until something requests `pool:read` for them. That
is the correct end state and it will look like a regression to whoever
hits it, so it needs a release note and a startup warning naming the
replacement, not a silent swap.

### Internal names

`jobScopeRead` / `jobScopeMutate` already name the axes correctly and
need no change. `seesAllJobs` is the one function every owner-scoping
decision passes through; renaming it is cosmetic and low priority.

## Already using one of these names

API-key service keys ship `pool:read` as a mintable entitlement
(`scopePoolRead` in `apikey_entitlements.go`). It is the only live use
of the proposed vocabulary, and it is deliberately referenced through
one constant so settling on a different name is a single edit.

It carries no compatibility burden *yet*: no grant outside this server
has ever been issued with it. That stops being true at the first release
that ships it, so the naming question above is worth closing before
then. **[OPEN]** by the same token: if `pool:read` is the wrong name,
say so now rather than after it has been minted into keys in the field.

## The MCP scope challenge, and what `scopes_supported` is for

Found while reviewing this: the server has two defects against the
**2025-11-25** MCP authorization spec. We implement **2025-06-18**,
which says nothing about either, so neither is a violation today — but
both will become one, and one of them is already the cause of real
over-permissioning.

### We never send `scope`, so clients ask for everything

`addWWWAuthenticateHeader` emits `realm`, `error`, `error_description`
and `resource_metadata`. It does not emit `scope`.

The 2025-11-25 spec's Scope Selection Strategy is explicit about what a
client does then:

1. Use the `scope` parameter from the `WWW-Authenticate` challenge.
2. **If `scope` is absent, request every scope in `scopes_supported`.**

Our `scopes_supported` is `oauth2AdvertisedScopes`, which includes
`mcp:admin` and `mcp:superuser`. So every compliant client — claude.ai's
included — asks for cross-user admin powers on every authorization, and
the only thing standing between that request and a grant is the consent
page and the group policy.

That is the same objection as `MCP_ADMIN_USERS`, arriving by a different
road: a permission being requested because nothing said not to.

The spec also states what the field is meant to hold: `scopes_supported`
"is intended to represent the **minimal set of scopes necessary for
basic functionality**", with anything further obtained through step-up.
Ours is the maximal set.

The comment on `oauth2AdvertisedScopes` explains why the admin scopes
were added to it: unadvertised, nothing ever requested them, so the
two-tier privilege model was dead in practice. That reasoning was right
under 2025-06-18, which offered no other way to reach them. 2025-11-25
offers the step-up challenge, which is the mechanism that was missing.

**Proposal.** Advertise the minimal set — `openid`, `profile`, `email`,
`offline_access`, `mcp:read`, `condor:/READ` — and name the rest in the
challenge when a request actually needs them. Keep every scope
*requestable*, because `cimdClientScopes` recomputes a CIMD client's
allowed set from the advertised list on every request, so dropping one
from `scopes_supported` must not drop it from what may be asked for.
Those are two different lists today only by accident.

**[OPEN]** Whether to do this before or after the rename. It is
independent of the vocabulary, and arguably more urgent.

### We return 403 without saying what was missing

`seesAllJobsByPolicy` narrows a request silently: a caller without the
entitlement gets their own records and no indication that a wider view
exists or what would buy it. The spec's runtime insufficient-scope
response is `403` plus
`error="insufficient_scope"`, `scope="<what this request needs>"` and
`resource_metadata`, and a client **SHOULD** respond with a step-up
authorization.

Silent narrowing is what produced the original report that started this
work. For REST the right answer is still to narrow — a dashboard that
403s because it cannot see everyone is worse than one that shows you
your own jobs — but **on `/mcp` the challenge is the correct response**,
because an MCP client can act on it and a browser cannot.

**[OPEN]** Which surfaces challenge and which narrow. My view: `/mcp`
challenges, REST narrows and keeps saying so in the response body
(`owned_by_me`), and `/api/v1/*` called with a bearer that *could* step
up is a third case worth thinking about rather than guessing at.

### Clients must treat the challenge as authoritative

Worth recording because it is the part that makes the above safe:
clients **MUST** treat challenged scopes as authoritative for the
current request, and **MUST NOT** assume any set relationship between
them and `scopes_supported` — subset, superset or disjoint are all
allowed. So a minimal `scopes_supported` plus an accurate challenge is a
supported configuration, not a trick.

## Compatibility

Config knobs and granted scopes are public API, so nothing is deleted:

- Old config names stay accepted as aliases, with a startup line naming
  the replacement. This follows the existing precedent for
  `MCP_ADMIN_USERS`, which already logs when its meaning has narrowed.
- Stored `granted_scopes` rows carrying `mcp:admin` / `mcp:superuser`
  keep resolving to the corresponding power. A grant must not lose its
  power because the server was upgraded, and a refresh must not silently
  narrow it.
- The old scope strings stay advertised in OAuth2 metadata, so existing
  clients requesting them keep working. Note the trap recorded in
  `oauth2AdvertisedScopes`: a client asks for every scope the server
  advertises, so *removing* one from that list is what breaks clients,
  and *adding* an unapproved one is what breaks providers. Both
  directions of that list are load-bearing.
- Aliasing is pinned with a test per alias, not left to inspection.

## What this does not change

Owner scoping itself, the schedd's ACLs, impersonation's audit trail,
and the project-leads path all keep their current behavior. This is a
renaming and a split, not a change to who can see what — except for the
`HTTP_API_WEBUI_ADMIN_GROUP` split above, which is a real change and is
flagged as such.

## Sequencing

1. Introduce the new names as aliases; both spellings work. No behavior
   change, so it can land on its own.
2. Move internal call sites and documentation to the new names.
3. Decide and execute the `WEBUI_ADMIN` split, which is the only step
   with a behavior change and deserves its own release note.
