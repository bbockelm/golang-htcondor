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
| `pool:read` | API key | Read every user's records. New; see *Already using one of these names*. | **[OPEN]** name |

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

| Today | Proposed | Means |
| --- | --- | --- |
| `HTTP_API_MCP_ADMIN_GROUP` | `HTTP_API_POOL_READ_GROUP` | who may be granted `pool:read` |
| `HTTP_API_MCP_SUPERUSER_GROUP` | `HTTP_API_POOL_WRITE_GROUP` | who may be granted `pool:write` |
| `HTTP_API_SUPERUSER_GROUP` | `HTTP_API_IMPERSONATION_GROUP` | who may act as another user |
| `HTTP_API_WEBUI_ADMIN_GROUP` | `HTTP_API_SERVICE_ADMIN_GROUP` | who may administer this service |
| `MCP_ADMIN_USERS` | `HTTP_API_POOL_READ_USERS` | unscoped-caller fallback for `pool:read` |

**[OPEN]** The `HTTP_API_WEBUI_ADMIN_GROUP` split is the highest-value
and highest-risk item, and the only one here that can break a running
deployment. Today it grants *both* cross-user tiers *and* service
administration, because nobody ever decided it should — the powers were
merged by being spelled the same. Splitting it means an existing
deployment's single group has to become two settings, and the compatible
reading (one name keeps granting all three) preserves exactly the
conflation we are trying to remove.

1. **Alias, keep conflated.** `HTTP_API_WEBUI_ADMIN_GROUP` continues to
   grant all three. New deployments use the new names. Zero breakage,
   but the old name stays a trap forever.
2. **Alias, warn, migrate.** The old name keeps granting all three *and*
   logs at startup naming the three settings that replace it. After a
   deprecation window it grants only service administration.

Leaning 2. **[OPEN]** — needs your call.

**[OPEN]** `MCP_ADMIN_USERS` is the only knob without the `HTTP_API_`
prefix. Renaming it fixes that inconsistency but is a second breaking
change layered on the first. It may be better left alone.

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
