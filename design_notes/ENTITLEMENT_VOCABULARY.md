# Entitlement vocabulary

Status: **draft, for iteration.** Open questions are marked **[OPEN]**
and are the parts most worth arguing about.

The document mixes work that has landed with work that has not, so the
line between them is drawn here rather than left to be inferred:

| Landed | Proposed |
| --- | --- |
| `anyuser:read` and `anyuser:write` exist, mintable on an API key and grantable through OAuth2 | every rename below |
| Both are advertised, consent-unchecked, and gated on the groups their older spellings answer to | the `*_GROUPS` / `*_USERS` scheme |
| Entitlements are granted at mint and re-verified on use (service keys) | splitting `HTTP_API_WEBUI_ADMIN_GROUP` |
| `MCP_ADMIN_USERS` keeps its behaviour | deprecating it in earnest |
| | both MCP scope-challenge fixes |

Nothing landed changes a power anyone holds today: the two new scopes
answer to the same groups as `mcp:admin` and `mcp:superuser`, so they
add a name, not a privilege.

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
| `mcp:admin` | OAuth2 | Read **every** user's jobs on this access point, on REST and MCP alike. | → `anyuser:read` |
| `mcp:superuser` | OAuth2 | Act on **every** user's jobs on this access point. | → `anyuser:write` |
| `condor:/READ` | OAuth2, API key | HTCondor READ, carried into the minted IDTOKEN as an authorization limit. | unchanged |
| `condor:/WRITE` | OAuth2, API key | HTCondor WRITE, same mechanism. Not a superset of READ. | unchanged |
| `condor:/ADVERTISE_STARTD`, `_SCHEDD`, `_MASTER` | OAuth2 | Nothing. Deprecated, kept only so existing grants can refresh; dropped from a grant at its next authorization. | unchanged |
| `condor:/ADMINISTRATOR`, `/CONFIG`, `/DAEMON`, `/NEGOTIATOR` | — | Nothing. **[OPEN]**, below | |
| `metrics` | API key | `/metrics` (Prometheus exposition). | unchanged |
| `placement` | OAuth2 | The placement API. Held only by the seeded placement client, never advertised. | unchanged |
| `anyuser:read` | API key, OAuth2 | Read every user's jobs on this access point. See *Already using one of these names*. | **[OPEN]** name |
| `anyuser:write` | API key, OAuth2 | Act on every user's jobs on this access point. | **[OPEN]** name |

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
the same surprise, and whatever is decided for `anyuser:write` should
probably be decided for `condor:/WRITE` at the same time or deliberately
not.

## The proposal

Name entitlements after the two axes that actually exist — **reach**
(whose records) and **action** (what you may do to them) — and remove
"admin" and "superuser" from the entitlement vocabulary entirely.

The reach these scopes grant is **one access point**: every user's jobs
on the schedd this server fronts, or in multi-AP mode on the AP a
request was routed to and no other. Not the pool. They confer nothing
over machines, the collector, the negotiator or another AP's queue, and
`pool:` would have claimed all four — besides colliding with
`HTTP_API_POOL_QUERY_*`, which governs the genuinely pool-scoped thing
(which collector attributes a caller may read). Hence `ap:`.

Reserve **administrator** for managing *this service* (OAuth2 clients,
API keys, tokens, branding). Reserve **superuser** for HTCondor's
meaning and nothing else.

### Scopes

| Today | Proposed | Grants |
| --- | --- | --- |
| `mcp:admin` | `anyuser:read` | read every user's jobs on this access point |
| `mcp:superuser` | `anyuser:write` | act on every user's jobs on this access point |

Dropping the surface name from the scope is the point. The scope names a
power, not a door; honouring it on both REST and MCP is then obviously
correct rather than the leak it currently looks like.

**[OPEN]** `anyuser:write` vs `pool:mutate`. `write` pairs with `read` and
matches `condor:/WRITE`; `mutate` matches the internal `jobScopeMutate`
and avoids implying the HTCondor WRITE authorization level. Weak
preference for `write`.

**[OPEN]** Whether `anyuser:write` should imply `anyuser:read`. Making write
imply read is the conventional reading, but it silently widens every
existing `mcp:superuser` grant on upgrade.

### Configuration

Two knobs per entitlement, and they mean the same thing: **who may
request it**. Never who holds it.

| Entitlement | Groups | Users |
| --- | --- | --- |
| `anyuser:read` | `HTTP_API_ANYUSER_READ_GROUPS` | `HTTP_API_ANYUSER_READ_USERS` |
| `anyuser:write` | `HTTP_API_ANYUSER_WRITE_GROUPS` | `HTTP_API_ANYUSER_WRITE_USERS` |
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

The rule above is what `MCP_ADMIN_USERS` breaks. It does not gate a
request; it hands the read tier directly to any caller on the list whose
credential states no scopes. That is a permission appearing on a
credential that never asked for it and whose holder never consented to
it, which is the thing the scope vocabulary exists to prevent.

**It stays, deprecated, with its current behaviour intact.** Removing it
would log out working stdio integrations on upgrade, and the people
running them did nothing wrong. What does not happen is carrying its
semantics forward: `HTTP_API_ANYUSER_READ_USERS` is not its replacement in
meaning, only in subject matter.

| | `MCP_ADMIN_USERS` (deprecated) | `HTTP_API_ANYUSER_READ_USERS` |
| --- | --- | --- |
| Effect of being listed | **holds** the read tier | **may request** `anyuser:read` |
| Applies to | a credential stating no scopes | any credential |
| Needs a request | no | yes |
| Needs consent | no | yes, where consent applies |

So the two can coexist without contradiction, and a deployment moves at
its own pace: list people under the new knob, have their tooling request
the scope, then drop the old one.

**[OPEN]** What the deprecation actually does. Options: (a) a startup
line naming the replacement, behaviour unchanged — lowest friction, and
the old knob stays indefinitely; (b) the same plus a removal release
named in the message. The existing startup warnings for this knob are
already the precedent for (a).

**[OPEN]** Whether a credential that *could* request `anyuser:read` but did
not should be told so. Saying nothing is what produced the report this
work started from; saying something on every request is noise. The MCP
scope challenge below is the mechanism that answers this properly for
`/mcp`, and nothing answers it for REST.

#### How a `*_USERS` list is actually checked

Every authorization decision today runs through `groupSet.allows(groups)`
— a set of configured group names against the groups a caller carries.
A user list answers a different question, about identity rather than
membership, so it needs a second check beside that one rather than a
value stuffed into the same set.

The shape that fits what already exists:

```
type principalSet struct {
    groups *groupSet   // HTTP_API_X_GROUPS
    users  []string    // HTTP_API_X_USERS
}

func (p *principalSet) allows(actor string, groups []string) bool
```

`allows` is true when the group set allows the groups **or** the actor
matches a user entry. Three details that are not free choices:

- **Identity comparison is `authz.SameUser`,** which already handles the
  `@` and the domain fold. A bare `alice` does not match
  `alice@uid.domain`; this is the trap that bit `MCP_ADMIN_USERS`, and
  it should be documented at the knob rather than discovered.
- **`configured()` means either half is non-empty.** The existing
  "unset means nobody" rule for a cross-user privilege has to keep
  holding, and a deployment that names only users must not read as
  unconfigured.
- **The group half still needs a group source.** With
  `HTTP_API_GROUP_SOURCE = token` and no groups in the token, the users
  half is the only half that works — which is a large part of why it
  should exist at all.

**[OPEN]** Whether a user list also applies where a *session* is the
caller. The group half is checked against `session.Groups`; the user
half would be checked against `session.Username`, which is well defined
but means a knob that reads as "service configuration" also grants
browser powers. I think yes, for consistency, but it is worth saying
out loud.

### Internal names

`jobScopeRead` / `jobScopeMutate` already name the axes correctly and
need no change. `seesAllJobs` is the one function every owner-scoping
decision passes through; renaming it is cosmetic and low priority.

## Already using one of these names

`anyuser:read` and `anyuser:write` are live: mintable on an API key
(`validScopes`), grantable through OAuth2 (`getScopesForGroups`),
advertised (`oauth2AdvertisedScopes`), and privileged on the consent
page (`privilegedScopes`). Each is referenced through one constant
(`scopeAnyUserRead`, `scopeAnyUserWrite` in `apikey_entitlements.go`), so
settling on different names is two edits.

Advertising them was the step with teeth. `getScopesForGroups` ends in
a default branch that grants an unrecognized scope unconditionally, so
a scope advertised without a case of its own is handed to every client
that asks. They therefore answer to `HTTP_API_MCP_ADMIN_GROUP` and
`HTTP_API_MCP_SUPERUSER_GROUP` — the groups their older spellings
already answer to — until those settings are renamed.
`TestAdvertisedPrivilegedScopesAreNotGrantedByDefault` is what keeps
that true.

It carries no compatibility burden *yet*: no grant outside this server
has ever been issued with it. That stops being true at the first release
that ships it, so the naming question above is worth closing before
then. **[OPEN]** by the same token: if `anyuser:read` is the wrong name,
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

Config knobs and granted scopes are public API, so nothing is deleted.
Old config names stay accepted as aliases with a startup line naming the
replacement; stored `granted_scopes` rows carrying `mcp:admin` or
`mcp:superuser` keep resolving to the corresponding power, because a
grant must not lose its power to an upgrade and a refresh must not
silently narrow it; the old scope strings stay advertised so existing
clients requesting them keep working. Each alias is pinned with a test,
not left to inspection.

Note the trap recorded on `oauth2AdvertisedScopes`: a client asks for
every scope the server advertises, so *removing* one from that list is
what breaks clients, and *adding* an unapproved one is what breaks
providers. Both directions are load-bearing.

### What an existing deployment sees on upgrade

Walked through, surface by surface. The short answer is that nothing in
the shipped work changes behaviour for a credential that exists today,
with one deliberate exception.

| Thing that exists today | On upgrade |
| --- | --- |
| An API key minted before this | Untouched. It carries no `anyuser:*` scope — none existed — so the entitlement path is skipped entirely and costs it not even a lookup. |
| An OAuth2 grant carrying `mcp:admin` / `mcp:superuser` | Still honoured, on REST and MCP alike. The `anyuser:*` scopes were added beside them, not in place of them. |
| A refresh of such a grant | Unchanged. Re-authorization re-runs the group policy it always did. |
| A CIMD client | Unchanged. Its requestable set is recomputed from the advertised list, which did not change. |
| `MCP_ADMIN_USERS` | Unchanged, deprecated. See above. |
| A browser session | Unchanged. |
| An upstream SSO login | **Changes:** the next authorization also asks for `offline_access`. A provider that refuses it has that refusal absorbed and the sign-in retried without it, so a login that worked keeps working. This is the one deliberate exception. |

### The rollback, which is where it nearly went wrong

Migration 0030 adds two columns, and SQLite before 3.35 cannot drop a
column, so the down migration rebuilds the table. A rebuild that
forgets a column loses it silently — and the loss here is the bad kind:
a service key demoted to an ordinary key goes on authenticating, then
loses its entitlement an hour later for a reason nothing connects back
to the rollback.

So the down migration sets the dropped values aside and the up
migration restores them. Down-then-up is a round trip, pinned by
`TestServiceKeySurvivesDownAndUp`, which also asserts the keys
themselves survive the downgrade — a rollback that logs everybody's
automation out is worse than whatever it is rolling back.

On the older code a key carrying `anyuser:read` is simply a key with a
scope nothing reads: scopes are validated at mint, not at use, so it
keeps working as an ordinary key. Forward compatibility is the weaker
direction, as usual: a *new* admin UI posting `service: true` to an
*old* server gets a 400, because the create handler rejects unknown
fields. That is an upgrade-order constraint, not a data hazard.

## What this does not change

Owner scoping itself, the schedd's ACLs, impersonation's audit trail,
and the project-leads path all keep their current behavior. This is a
renaming and a split, not a change to who can see what — except for the
`HTTP_API_WEBUI_ADMIN_GROUP` split above, which is a real change and is
flagged as such.

## Sequencing

Ordered so that each step is separately revertible and only one of them
can change what anybody can do.

1. **Done.** `anyuser:read` / `anyuser:write` exist beside `mcp:admin` /
   `mcp:superuser`, on the same group policy. No power moved.
2. **Settle the names.** Cheapest now: two constants, no grant in the
   field carries them outside this server. After the first release it is
   a compatibility exercise instead.
3. **Introduce `principalSet` and the `*_GROUPS` / `*_USERS` pairs** as
   aliases of the current settings, both spellings accepted, old names
   logging their replacement. Still no behaviour change — a `*_USERS`
   list that nobody is on grants nobody anything.
4. **Move internal call sites and documentation** to the new names.
5. **Deprecate `MCP_ADMIN_USERS` in earnest**: keep the behaviour, name
   the replacement at startup, and give the removal a release.
6. **Split `HTTP_API_WEBUI_ADMIN_GROUP`.** The only step that changes a
   power. Its own release note.

The two MCP scope-challenge fixes are independent of all six and can
land whenever; the `scopes_supported` trim is the one worth doing soon,
since it is live over-requesting rather than a naming problem.

## What this is not

Worth stating, because each has come up and each would be a different
project:

- **Not per-tool or per-route scopes.** The axes are reach and action,
  not endpoint. A scope per tool is a much larger vocabulary and a much
  worse consent page.
- **Not a replacement for the schedd's ACLs.** Every scope here narrows
  what this server will do on a caller's behalf. HTCondor still decides
  what it will accept, and a `anyuser:write` grant is worth nothing against
  a schedd that refuses the identity.
- **Not an audit mechanism.** Impersonation already writes its own audit
  trail; nothing here changes what is recorded.
