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
