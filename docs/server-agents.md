# Agents: MCP, site skills and the chat assistant

What an LLM agent may do through this access point, and the
site-specific text it is given. Part of the
[HTTP API + MCP server](server.md) documentation.

## Enabling MCP

`HTTP_API_ENABLE_MCP = true` serves the MCP surface at `/mcp/*` and the
`/mcp/oauth2/*` spelling of the OAuth2 endpoints, and advertises the
`mcp:read` / `mcp:write` scopes. It is also required by the chat
assistant. OAuth2 itself is served whenever the web UI **or** MCP is
enabled — see
[When OAuth2 is served](server-auth.md#when-oauth2-is-served).

The standalone `htcondor-mcp` binary speaks the same protocol over
stdio. The tool catalogue is in
[mcpserver/README.md](../webapi/mcpserver/README.md).

Who may drive the access point through MCP is
`HTTP_API_MCP_ACCESS_GROUP`, narrowed by `HTTP_API_MCP_READ_GROUP` and
`HTTP_API_MCP_WRITE_GROUP`; see
[Authorization groups](server-auth.md#authorization-groups).

## What to hand a user

One address: `https://<your-api-host>/mcp`. That is what goes in a
client's configuration, and it is the only thing a user needs.

A trailing slash is fine: `/mcp/` redirects to `/mcp`, keeping the
method, so a client configured that way works too.

It looks like a link, so people follow it in a browser. A browser gets a
setup page: the address to copy, and the steps for Claude Code, Claude's
custom connectors, VS Code, Cursor and Codex. `/mcp/setup` serves the
same page at a URL of its own, for putting in a message or a wiki.

Only a request that asks for HTML gets the page. An MCP client's own
`GET` of `/mcp` — the server-to-client stream of the streamable HTTP
transport — and anything sending `Accept: */*`, `curl` included, get the
protocol's responses as before.

The page names this server and the address to connect to, and says
nothing about who may connect or which tools are on offer. There is no
setting for it.

## MCP is not a sandbox

Enabling MCP hands an agent the access point with the privileges of
whoever authenticated to it. Those privileges are the ones HTCondor
already grants that person, unchanged — so everything an agent can do
here, that user could already do from a shell on this machine. What
changes is the speed, the volume, and the absence of the pause a person
takes before doing something unwise.

This is worth stating plainly to whoever turns MCP on, because "the
agent acts as the user" undersells it:

- **Submitting a job is running code.** A DAG's PRE and POST scripts are
  supplied as file contents and run on the access point as the
  submitting user. An agent that can submit a DAG can therefore read
  that user's home directory — `.git-credentials`, SSH private keys,
  cloud tokens — write what it finds into a file, and read the file back
  as ordinary job output. `exec_in_job`, the interactive session tools
  and `condor_ssh_to_job` reach a shell by shorter routes.
- **A job reaches whatever that user's jobs reach.** Where the site
  mounts shared or staging storage into jobs, an agent's job gets that
  mount with that user's rights on it, deletion included.
- **Nothing here reviews the size of a request.** Agents ask for what
  they estimate they need, and will request several hundred CPU hours
  without raising it as a decision. What bounds that is the pool's own
  policy, not this server.
- **Pool queries describe other people.** Slot and submitter ads carry
  the names, projects and running jobs of everyone else in the pool.
  That is what `condor_status` tells any user, but an agent can pull all
  of it remotely in one call — see [Pool queries and other users'
  identities](#pool-queries-and-other-users-identities).

None of this is a flaw in the protocol, and none of it is fixed by the
agent being well behaved or by the client prompting before each tool
call. A user who wants the thing done will approve the prompt, and the
request that led there may not have been the user's own. The controls
that hold are the ones enforced on this side:

- `HTTP_API_MCP_READ_ONLY` serves the whole MCP surface read-only, for
  every caller — see [A read-only access point](#a-read-only-access-point)
  below. This is the control to reach for when the answer to "should our
  users have agents" is yes and the answer to "should those agents be
  able to act" is no.
- `HTTP_API_MCP_ACCESS_GROUP`, narrowed by `HTTP_API_MCP_READ_GROUP` and
  `HTTP_API_MCP_WRITE_GROUP`, decides who may drive the access point and
  whether they may change anything or only look. A read-only grant is a
  real reduction and is worth being the default for most people. It is
  the caller's authorization rather than the server's policy, so it does
  not reach a caller with no scopes at all; `HTTP_API_MCP_READ_ONLY`
  does.
- `HTTP_API_MCP_DISABLED_TOOLS` withdraws tools the site does not want
  offered at all — see [Disabling tools](#disabling-tools) below. It
  raises the cost of a shell but does not remove it: withdrawing
  `exec_in_job` and `interactive_session_*` still leaves `submit_dag`,
  and withdrawing that still leaves plain `submit_job`, which can name
  the local or scheduler universe and so run on the access point. Code
  execution is what a job *is*; it is not a tool that can be switched
  off while job submission remains.
- HTCondor's own policy on the access point and the pool, which is where
  a limit of this kind has to be expressed. `SUBMIT_REQUIREMENT_NAMES`
  on the schedd can refuse universes or resource requests a site does
  not want; the pool's policy governs what jobs may mount and whether
  `condor_ssh_to_job` is permitted. These bind an agent exactly as they
  bind a person, which is the reason to put a site's limits there rather
  than hoping the agent respects them.

## A read-only access point

A site can offer MCP and offer nothing through it that changes anything:

```
HTTP_API_MCP_READ_ONLY = true
```

Every tool that submits, holds, releases, removes, edits, uploads,
advertises, stores a credential or starts a session is left out of
`tools/list` and refused if called anyway. What remains is the whole
reading surface — the queue, the history, the archive, the pool, job
output, the documentation and skills tools, and the watches, which
record nothing outside this server's own bookkeeping.

This is the server's decision and not the caller's, which is the reason
it exists alongside `HTTP_API_MCP_WRITE_GROUP`. A write group is checked
when a scope is granted, so it binds OAuth2 callers and nobody else: a
forwarded HTCondor IDTOKEN carries no scopes by design — HTCondor gates
it instead — and a token granted `mcp:write` before the policy changed
keeps carrying it until it is refreshed. `HTTP_API_MCP_READ_ONLY` is
enforced in the tool server itself, which every transport and every kind
of caller passes through, so none of those are exceptions to it.

While it is on, `mcp:write` is neither advertised nor granted, so a
consent page does not offer a user a write authorization this server
would then refuse to honour. A token that already holds `mcp:write` is
not revoked; it simply buys nothing here.

Applied on SIGHUP (or `condor_reconfig`), including for sessions already
connected. REST clients, the web console and `condor_submit` are
untouched: this governs the MCP tool surface, not the access point.

## Disabling tools

Some tools cannot work at some sites for reasons this server cannot see.
Where policy forbids `condor_ssh_to_job`, for example, the tools built on
it will fail however the pool is configured. Offering them anyway costs
an agent a turn to discover that, and the error it gets back describes a
permission problem rather than a decision somebody made.

`HTTP_API_MCP_DISABLED_TOOLS` names the tools this access point does not
offer:

```
# One tool, a family, or both. Commas or whitespace, either is fine.
HTTP_API_MCP_DISABLED_TOOLS = exec_in_job interactive_session_*
```

Patterns are shell-style globs matched against the tool name. A disabled
tool is left out of `tools/list` and refused if called anyway — a client
may be holding a catalogue from before the setting changed. The refusal
names this parameter, so whoever reads the agent's transcript knows where
the decision lives, and tells the agent not to retry.

Applied on SIGHUP (or `condor_reconfig`), including for sessions already
connected: a tool withdrawn because policy changed stops working without
waiting for agents to reconnect. Clearing the setting restores the tools.

A pattern that is not a valid glob is logged as an error and ignored,
leaving the tools it was meant to disable still offered — check the log
after setting one.


## Pool queries and other users' identities

`query_pool` and the REST endpoints under `/api/v1/collector/ads/`
answer what `condor_status` answers, which includes attributes
describing other people's work. A busy slot ad names the user running on
it (`RemoteOwner`, `RemoteUser`), often their project (`RemoteProject`),
the access point they submitted from, the job's id and start time, and
how it is behaving — memory, CPU and GPU usage. A submitter ad is
nothing but identity: one ad per user with jobs in the pool.

Any caller authorized for MCP or the HTTP API can read these, and can
choose the attributes returned: the projection is free-form, `*` returns
every attribute a slot ad carries, and a constraint can test attributes
whether or not they are returned. The same is true of a person running
`condor_status`. The difference an agent makes is bulk and reach — every
slot in the pool, in one call, from anywhere the API is reachable, into
a context the site does not control.

Whether that matters is a site decision and depends on what the pool's
ads carry; a site that puts personal data in custom machine attributes
is exposing more than the attributes listed above.

`HTTP_API_POOL_QUERY_IDENTITY` is the control:

```
# open (default) | restricted | admin
HTTP_API_POOL_QUERY_IDENTITY = restricted
```

- **`open`** is the default and today's behaviour: every authorized
  caller reads what `condor_status` would show them. Upgrading changes
  nothing until this is set.
- **`restricted`** confines callers *without* the cross-user read
  privilege to attributes that describe machines rather than the people
  on them. Administrators are unaffected.
- **`admin`** requires that privilege for any pool query at all.

The privilege is the same one that decides whether a caller may read
other users' jobs — `HTTP_API_WEBUI_ADMIN_GROUP`, the `mcp:admin` scope,
or `MCP_ADMIN_USERS`; see [Authorization
groups](server-auth.md#authorization-groups). Someone who may already
read everyone's jobs is not restricted here.

Under `restricted`:

- The attribute list is an **allowlist**, not a list of attributes to
  strip. A denylist cannot be made complete, because a site advertises
  whatever it likes from `STARTD_ATTRS`, and naming the attributes that
  carry personal data would mean knowing every site's custom ones. An
  attribute nobody listed is withheld, which is the safe direction to be
  wrong in.
- `HTTP_API_POOL_QUERY_EXTRA_ATTRS` adds a site's own known-safe
  attributes to it:

  ```
  HTTP_API_POOL_QUERY_EXTRA_ATTRS = GLIDEIN_Site, GLIDEIN_ResourceName
  ```

- **Submitter ads are refused outright.** Every submitter ad names one
  user — that is all a submitter ad is — so there is no redacted form of
  one that still answers anything.
- Constraints are checked, not only output. A constraint is an oracle
  for an attribute it never returns: `RemoteOwner == "someone@example.edu"`
  answers "is that person running anywhere" from the result count alone.
- A projection naming a withheld attribute is **refused**, not quietly
  shortened. An attribute silently dropped comes back absent, which
  reads as "this slot has no owner" rather than "you may not see it",
  and an agent will report the first as fact.

Applied wherever a caller chooses what to read: the `query_pool` tool,
`/api/v1/collector/ads/`, the `/api/v1/collector/watch` stream, and
`/api/v1/collector/pool-summary`. Restricting the MCP tool alone would
be no restriction, because the REST endpoints answer the same question
with the same credentials. This server's own aggregate reads — drain
estimates, utilization, match analysis — are unaffected; they count
rather than publish.

On the web UI's pool page, a session that may not see slot owners is
told so: the Owner column reads "not shown" rather than going blank,
which would look like an idle machine.

A value this server does not understand **fails closed** to `admin`, and
logs. Restricting pool queries by accident is noticed and corrected in
minutes; quietly publishing identities is not noticed at all.


## Masking credentials in tool results

Several tools hand a caller bytes a job produced, and a job's output is
whatever the job wrote. A job that runs `cat $_CONDOR_CREDS/<service>.use`,
or whose framework logs the configuration it just loaded, puts that
credential in its stdout, and `get_job_stdout` then returns it. So do
`get_job_output`, `tail_job_output` and `exec_in_job`. The caller is
usually a model, so the credential lands in a context window, and from
there in a transcript and a provider's logs.

The server masks credential-shaped text in every tool result before
returning it:

```
# On by default. Set false to return job output exactly as written.
HTTP_API_MCP_REDACT_SECRETS = true
```

A masked value is replaced with `[REDACTED:<rule>]` and the result says
so, both in the text an agent reads and as a `redaction` object in the
structured payload. Nothing else in the result is altered.

**This is not a security boundary**, and it is not one of the controls
in [MCP is not a sandbox](#mcp-is-not-a-sandbox). A job runs arbitrary
code as the submitting user, so anything that can print a credential can
also encode it past any pattern — reverse it, base64 it, print it a
character at a time. An agent that wants a credential will get one.

What this stops is the accident: a stack trace, a debug log, a `curl
-v`, a framework announcing its configuration at startup. It is the same
bargain a CI system's log masking makes, and worth the same amount.

### What is recognised

Formats are matched by structure, prefix or field name. There is no
entropy heuristic: job output is full of checksums, UUIDs, accession
numbers and base64 payloads, and a filter that ate those would be one
you turned off.

Where part of a credential is not secret, that part is kept:

- **JWTs** — SciTokens, WLCG tokens, HTCondor IDTOKENs, OIDC id tokens —
  keep their header and claims and lose only the signature. The issuer,
  subject, scopes and expiry are usually the answer to whatever the
  output is being read for, and a token cannot be replayed without its
  signature. A JOSE token with more segments is encrypted and goes whole.
- **X.509 proxies and other PEM blocks** keep their certificates and lose
  the private key. The certificate chain is public and is the diagnosable
  half; a block whose `-----END-----` line is missing, because the output
  was cut off mid-key, is masked to the end of the text.
- **URLs** keep everything but the credential: a password in the userinfo,
  or the signing parameter of a presigned S3, GCS, Azure or Pelican URL.
  Which object a transfer failed on is the reason anyone is reading it.

The rest is masked whole: a field whose name says its value is a
credential (`access_token`, `refresh_token`, `client_secret`,
`AWS_SECRET_ACCESS_KEY`, `password`, and the other spellings of those),
an `Authorization` header's credential, a base64-wrapped Kerberos
credential cache or keytab, and the published issuer prefixes — GitHub,
GitLab, Slack, AWS, Google, OpenAI, Anthropic, Hugging Face, Docker Hub,
npm, PyPI, Stripe, SendGrid, Atlassian, DigitalOcean, age.

Two things are deliberately left alone. `create_output_download_url`,
`create_input_upload_url` and `create_watch_url` return URLs this server
has just minted for the caller; masking those would hand back a link that
cannot be redeemed. And a credential the job transformed before printing
it is not recognised, by construction.

### Turning off a rule

A site whose output trips one rule can turn off that rule rather than the
whole mechanism:

```
# Globs over rule ids, commas or whitespace.
HTTP_API_MCP_REDACT_DISABLED_RULES = kerberos-credential github-*
```

The rule id is the one that appears in the marker, so a result that
masked something it should not have names the rule to disable. A pattern
matching no rule is logged as an error — check the log after setting one,
since otherwise a typo leaves the rule in force and looks like it did not
work.

Both settings are applied on SIGHUP (or `condor_reconfig`), including for
sessions already connected.


## Site skills

A site can publish its own documentation to agents: how work is actually
done here, which generic HTCondor knowledge does not cover. Point the
server at a directory -- typically a checkout of the documentation
repository -- and every Markdown file in it becomes a skill.

```
HTTP_API_MCP_SKILLS_DIR = /etc/condor/skills
```

```
git clone https://git.example.edu/ap/skills /etc/condor/skills
```

The server re-reads that directory every five minutes, so keeping the
library current is a matter of keeping the checkout current -- a cron
`git pull`, a git-sync sidecar, a config-management run. Nothing has to
signal the daemon afterwards.

**What is loaded.** Every `*.md` file underneath the directory, at any
depth. Hidden directories and hidden files are skipped, so a git checkout
works directly -- `.git` alone holds thousands of files, none of them
documentation. Symbolic links are not followed: a link is the one way a
file outside the configured directory could be served from inside it.
Files larger than 1 MiB are skipped, as is anything past 2000 skills,
which indicates the server has been pointed at the wrong directory.

**Front matter.** An optional YAML header supplies the catalogue entry:

```markdown
---
name: Submitting GPU jobs
description: How to request a GPU on this access point.
---

Use `request_gpus = 1` and the local GPU partition...
```

`summary` is accepted as an alias for `description`. A file with no front
matter still loads: its name falls back to the first Markdown heading and
then the filename, and its description to the first paragraph. A file
named `SKILL.md` takes its parent directory's name, so a skill laid out as
a directory reads as `gpu-jobs` rather than `gpu-jobs/SKILL`.

**How agents see them.** Both as tools and as resources, because a client
that lists resources up front can show the catalogue without calling
anything, while an agent that has decided it needs guidance looks for a
tool:

| Surface | What |
| --- | --- |
| `skills_list` | The catalogue, with an optional `query` filter. |
| `skills_get` | One skill in full, by id or name. |
| `skill://index.json` | The catalogue as a resource. |
| `skill://<id>` | One skill as a Markdown resource. |

When any skill is published, the MCP `initialize` response gains a **Site
skills** section that names each one with its description and tells the
agent to consult the relevant skill *before* using other tools. The
catalogue is inlined rather than merely pointed at, because an agent reads
the instructions before deciding anything -- a bare "call `skills_list`"
is advice it has no reason to take until it has already guessed.

**Order and length.** The `initialize` text is the access point's name,
then `MCP_INSTRUCTIONS`, then the Site skills section, then under 2 KB of
built-in guidance on submitting and monitoring jobs. Site text comes first
because some clients pass only the beginning to the model (Claude Code
keeps about the first 2 KB), so keep `MCP_INSTRUCTIONS` and skill
descriptions short. The longer built-in guidance is served by the
`doc_guide` tool, one topic at a time.

**Reloading.** Two paths, and the difference between them matters if you
are automating around it.

*The poll.* Every `HTTP_API_MCP_SKILLS_RELOAD_INTERVAL` (default `5m`) the
server checks the directory and re-reads it if anything changed. The check
is stat-only -- one `stat` per Markdown file, comparing path, size and
modification time against what is loaded -- so the normal outcome, nothing
changed, costs almost nothing and a short interval is affordable. It also
does not touch the published library or the `initialize` text when nothing
changed, which matters because rebuilding that text invalidates the cached
per-scope MCP servers.

Set the interval to `0` to turn the poll off and drive reloads yourself.

*`condor_reconfig` / SIGHUP.* Re-reads unconditionally, without consulting
the stat check, and takes effect at once. It is the right tool when you
have just changed the directory and want to know now, and the only one
that catches the case the poll cannot see: a file rewritten with the same
size and modification time.

A reload that fails -- the directory momentarily missing, an automount that
has not returned -- keeps the previously loaded set rather than leaving
agents with nothing, on either path. Clearing the setting does unpublish
them. Agents already connected keep the instructions they were given: MCP
delivers those once, at initialize, so a reload reaches sessions that
connect after it.


## Chat assistant

The web UI's chat assistant is enabled by `HTTP_API_LLM_API_KEY_FILE`;
the model, endpoint and authentication scheme come from the other
`HTTP_API_LLM_*` knobs in [Configuration](server-config.md). It needs
`HTTP_API_ENABLE_MCP`.

- `POST /api/v1/chat` — AI-SDK v6 UI-message stream. The body's `scope`
  (`mine` or `everyone`) is the page's Mine/Everyone view; the server
  grants `everyone` only to a caller the page's own endpoint would show
  other users' jobs, and the assistant's tools act on other users' jobs
  only for an administrator with the right to change them.
- `GET /api/v1/chat/info` — feature probe
- `GET /api/v1/chat/scope?page=<page>&scope=<mine|everyone>` — which jobs
  the assistant would see for this caller on that page

The assistant is given the same two pieces of site-specific text an MCP
agent is: the operator's own rules from
`HTTP_API_LLM_OPERATOR_INSTRUCTIONS_FILE`, and the catalogue of the site
skills published by `HTTP_API_MCP_SKILLS_DIR`, which it reads with a
`get_site_skill` tool. One library serves both surfaces, so a skill added
to the checkout reaches web users and agents together, and both describe
it the same way. Both are read on every turn, so a `condor_reconfig` --
or the skills reload poll -- lands on sessions already open.
