package httpserver

// mcpSetupHTML is the setup page, kept apart from the handler because it
// is prose and markup rather than code.
//
// Self-contained on purpose: no stylesheet, font or script is fetched.
// The page is what a person sees when nothing else about this server has
// worked for them yet, and the Content-Security-Policy this server sends
// allows inline styles and scripts but no third-party origin.
//
// The instructions are per harness rather than one generic JSON blob
// because the harnesses disagree on all of it -- the key is mcpServers or
// servers, the transport field is type or absent, the file is in
// ~/.cursor or ~/.codex or ~/.copilot -- and a reader cannot tell from a
// generic example which of those their client wants.
const mcpSetupHTML = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Connect an AI assistant{{if .SiteName}} &middot; {{.SiteName}}{{end}}</title>
<style>
:root {
  --bg: #f6f7f9;
  --card: #ffffff;
  --ink: #1d2126;
  --muted: #5b6471;
  --rule: #e2e5ea;
  --accent: #2d5fa6;
  --code-bg: #f2f4f7;
}
@media (prefers-color-scheme: dark) {
  :root {
    --bg: #15181c;
    --card: #1d2127;
    --ink: #e8eaed;
    --muted: #a3acb9;
    --rule: #2e343d;
    --accent: #7fa8e3;
    --code-bg: #14171b;
  }
}
* { box-sizing: border-box; }
body {
  margin: 0;
  padding: 32px 16px 64px;
  background: var(--bg);
  color: var(--ink);
  font: 16px/1.6 -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif;
}
main { max-width: 760px; margin: 0 auto; }
h1 { font-size: 26px; line-height: 1.25; margin: 0 0 4px; }
.site { color: var(--muted); font-size: 14px; margin: 0 0 24px; }
h2 {
  font-size: 17px;
  margin: 32px 0 8px;
  padding-top: 20px;
  border-top: 1px solid var(--rule);
}
h2:first-of-type { border-top: 0; padding-top: 0; }
p { margin: 0 0 12px; }
.lead { font-size: 17px; }
.muted { color: var(--muted); font-size: 14px; }
ol, ul { margin: 0 0 12px; padding-left: 22px; }
li { margin-bottom: 4px; }
a { color: var(--accent); }
code {
  font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace;
  font-size: 0.9em;
  background: var(--code-bg);
  padding: 1px 5px;
  border-radius: 4px;
}
.url {
  display: flex;
  gap: 8px;
  align-items: center;
  flex-wrap: wrap;
  background: var(--card);
  border: 1px solid var(--rule);
  border-radius: 8px;
  padding: 14px 16px;
  margin: 0 0 20px;
}
.url pre { flex: 1 1 320px; }
.snip { position: relative; margin: 0 0 12px; }
pre {
  font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace;
  font-size: 13px;
  line-height: 1.55;
  background: var(--code-bg);
  border: 1px solid var(--rule);
  border-radius: 8px;
  padding: 12px 14px;
  margin: 0;
  overflow-x: auto;
  white-space: pre;
}
.url pre { border: 0; background: transparent; padding: 0; font-size: 14px; }
button.copy {
  font: inherit;
  font-size: 13px;
  color: var(--muted);
  background: var(--card);
  border: 1px solid var(--rule);
  border-radius: 6px;
  padding: 4px 10px;
  cursor: pointer;
}
button.copy:hover { color: var(--ink); border-color: var(--accent); }
.snip button.copy { position: absolute; top: 8px; right: 8px; }
footer {
  margin-top: 40px;
  padding-top: 16px;
  border-top: 1px solid var(--rule);
  color: var(--muted);
  font-size: 14px;
}
</style>
</head>
<body>
<main>

<h1>This address is for an AI assistant, not a browser</h1>
<p class="site">{{if .SiteName}}{{.SiteName}} &middot; {{end}}HTCondor access point</p>

<p class="lead">You have reached a Model Context Protocol (MCP) endpoint. Give this address
to an AI assistant and it gains tools for this access point &mdash; it can look at your jobs,
submit new ones, read logs and output, and help work out why something is held or idle.
Opening it in a browser does nothing by itself, which is why you are reading this instead
of an error message.</p>

<div class="url">
<pre>{{.ServerURL}}</pre>
<button class="copy" type="button">Copy</button>
</div>

<p>Setting it up takes one command or one dialog, below. You sign in with your usual
account for this access point, in a browser window your assistant opens for you &mdash; there
is no API key or token to paste anywhere. Your assistant then acts as you, and can do
exactly what you can do and nothing more.</p>

<h2>Claude Code</h2>
<div class="snip">
<pre>claude mcp add --transport http htcondor {{.ServerURL}}</pre>
<button class="copy" type="button">Copy</button>
</div>
<p>Then run <code>/mcp</code> inside Claude Code and follow the sign-in. To share the setup
with a team, add <code>--scope project</code>, which writes it to <code>.mcp.json</code> in
the current project.</p>

<h2>Claude (claude.ai and the desktop app)</h2>
<ol>
<li>Go to <strong>Customize &gt; Connectors</strong>. On a Team or Enterprise plan an Owner
does this once for everyone, under <strong>Organization settings &gt; Connectors</strong>.</li>
<li>Select <strong>Add</strong>, then <strong>Add custom connector</strong>.</li>
<li>Give it a name and paste the address above, then <strong>Continue</strong>.</li>
<li>Leave the authentication settings as Claude detects them, and select <strong>Add</strong>.</li>
<li>Select <strong>Connect</strong> and sign in.</li>
</ol>
<p class="muted">Claude connects from Anthropic&rsquo;s servers rather than from your
computer, so this works only if this access point is reachable from the internet.</p>

<h2>VS Code (GitHub Copilot)</h2>
<p>Run <strong>MCP: Add Server</strong> from the Command Palette, choose
<strong>HTTP</strong>, paste the address, and give the server an ID. Or write it into
<code>~/.copilot/mcp-config.json</code> yourself:</p>
<div class="snip">
<pre>{
  "mcpServers": {
    "htcondor": {
      "type": "http",
      "url": "{{.ServerURL}}"
    }
  }
}</pre>
<button class="copy" type="button">Copy</button>
</div>
<p class="muted">An older VS Code puts the same entry under a <code>servers</code> key in
<code>.vscode/mcp.json</code> instead.</p>

<h2>Cursor</h2>
<p>Add it to <code>~/.cursor/mcp.json</code>, or to <code>.cursor/mcp.json</code> for one
project:</p>
<div class="snip">
<pre>{
  "mcpServers": {
    "htcondor": {
      "url": "{{.ServerURL}}"
    }
  }
}</pre>
<button class="copy" type="button">Copy</button>
</div>
<p>Cursor handles the sign-in itself the first time it connects.</p>

<h2>Codex CLI</h2>
<div class="snip">
<pre>codex mcp add htcondor --url {{.ServerURL}}
codex mcp login htcondor</pre>
<button class="copy" type="button">Copy</button>
</div>

<h2>Anything else</h2>
<p>Any client that speaks MCP over streamable HTTP can connect. Most of them want some
spelling of this:</p>
<div class="snip">
<pre>{
  "mcpServers": {
    "htcondor": {
      "type": "http",
      "url": "{{.ServerURL}}"
    }
  }
}</pre>
<button class="copy" type="button">Copy</button>
</div>
<p class="muted">Clients differ on the details: Windsurf calls the address
<code>serverUrl</code>, and some want the transport written
<code>streamable-http</code>. The name <code>htcondor</code> is only what the server is
called on your own machine, so use whatever you like &mdash; something naming this access
point helps if you connect to more than one.</p>

<h2>Checking it worked</h2>
<p>Ask your assistant what HTCondor tools it has. If it can list them, it is connected. It
also has a tool called <code>doc_guide</code> that explains the rest to it, so
&ldquo;read your doc_guide and then show me my jobs&rdquo; is a good first thing to ask
for.</p>

<footer>
{{if .WebUI}}<p>The web interface for this access point is at
<a href="/">{{if .SiteName}}{{.SiteName}}{{else}}the home page{{end}}</a>.</p>{{end}}
<p>Trouble connecting is worth reporting to whoever runs this access point &mdash; the sign-in
and the tools on offer are both things a site configures.</p>
</footer>

</main>
<script>
document.querySelectorAll("button.copy").forEach(function (button) {
  button.addEventListener("click", function () {
    var text = button.parentElement.querySelector("pre").textContent;
    navigator.clipboard.writeText(text).then(function () {
      button.textContent = "Copied";
      setTimeout(function () { button.textContent = "Copy"; }, 1500);
    }, function () {
      button.textContent = "Press Ctrl-C";
    });
  });
});
</script>
</body>
</html>
`
