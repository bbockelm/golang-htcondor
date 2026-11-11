# SSH gateway: `ssh` into a job without an account on the access point

Give users an interactive terminal in an HTCondor job by pointing the stock
OpenSSH client at the API server. Nobody gets a login on the access point; the
gateway authenticates with the same OAuth2 identity the web UI and MCP use, then
proxies the SSH session into the job over `condor_ssh_to_job`.

Status: design only. Nothing below is implemented yet except the pieces called
out as already on `main`.

## Why a gateway rather than a login

The complaint this answers is that interactive work on the AP — editors, file
watchers, builds — has no owner, no cgroup and no eviction policy. Moving it
into a job fixes all three. But `ssh ap` + `condor_ssh_to_job` requires an
account on the AP, which is the thing we are trying not to hand out.

A gateway also removes the host-key problem. Today a user who runs
`condor_ssh_to_job` gets a fresh per-session host key for every job. The gateway
presents **one stable host key** and pins the per-job key internally from
`START_SSHD`, so `known_hosts` behaves the way users expect it to.

## What is already on `main`

Merged as of `2e519e2`:

- **`webapi/jobssh`** (PR #520) — one `condor_ssh_to_job` transport per
  `(owner, cluster, proc)`, idle-reaped, CCB-traversing, with the three lifetime
  rules already encoded. `Cache.DialJob(ctx, key, network, addr)` returns a
  `net.Conn` inside the sandbox that holds the transport open until it is
  Closed. `ScratchDir` memoizes the sandbox's scratch path.
- **`Schedd.OpenJobShell`** (`schedd_ssh.go`) — `GET_JOB_CONNECT_INFO` +
  `START_SSHD` + crypto/ssh handshake, returning a live `*ssh.Client`.
- **direct-tcpip and Unix-socket forwarding through a job** (PR #521), proven
  end to end in `TestSSHToJobIntegration`.
- **RFC 8628 device flow** — `/mcp/oauth2/device/authorize`
  (`webapi/httpserver/mcp_handlers.go:1551`), `device_code_handler.go`, the
  approval page, scope filtering, refresh, and the reauth/revoke machinery.
  The authorize handler does only `GetClient()`, so a **public client works**.
- **Identity mapping** — `HTTP_API_IDENTITY_MAP` (gecos/username), resolving an
  OIDC subject to the local account HTCondor knows.
- **The key envelope** — `webapi/httpserver/masterkey.go`: pool signing keys as
  KEKs, wrapping a per-deployment master, purposes derived by distinct HKDF
  label (`identityCookieInfo` is the existing consumer).
- **`webapi/interactive`** — submit-file builder, per-owner session limits,
  lease/watchdog, heartbeat, `.shutdown` sentinel. `Manager.Create` submits and
  returns; it does **not** wait for the job to start.

So the gateway is mostly wiring. The new code is the SSH server itself, the
keyboard-interactive bridge to the device flow, and key management.

## Decisions

### Authenticate with `keyboard-interactive`, not a password

RFC 4256 lets the server send free-text **instruction** plus prompts, and
OpenSSH prints the instruction verbatim. That is the whole trick:

```
$ ssh ap2001.chtc.wisc.edu -p 2222
To continue, open

    https://ap2001-api.chtc.wisc.edu/mcp/oauth2/device

and enter this code:   WDJB-MJHT

Press Enter once you have approved.
```

`x/crypto/ssh`'s `ServerConfig.KeyboardInteractiveCallback` supports multiple
challenge rounds, so "still pending, press Enter again" is expressible. Set only
that callback and it is the only method advertised.

**Verified against OpenSSH 10.3p1**, driving the real client in
`webapi/sshgateway`'s tests rather than reasoning about it:

- **It does not need a TTY.** An earlier draft of this document said it did, and
  that was wrong. A challenge with no questions reads no input, so `ssh -T`,
  plain `ssh`, and `ssh -tt` all print the instruction and authenticate.
- **`scp` authenticates too.** It prints the code on stderr and the user can
  approve it. (The transfer then needs an `sftp` subsystem, which is a separate
  problem — see below.)
- **A client offering a public key still reaches the prompt.** The server
  advertises keyboard-interactive alone, so the key is refused and the client
  moves on; a user with a loaded agent needs no configuration. The earlier worry
  about burning `MaxAuthTries` did not materialise.
- **Only `BatchMode=yes` is refused** — the client declines to attempt the
  method at all. That is the one real gap, and it is the client's policy, so the
  tests assert the capabilities rather than pinning somebody else's refusal.

### Use the literal device flow

Register the gateway as a public OAuth2 client and drive the real endpoints over
loopback HTTP. The alternative — a bespoke "open this URL" challenge store —
would reimplement consent, scope filtering, refresh, revocation and the reauth
oracles in a second place that can disagree with the first.

**Show the one-click `verification_uri_complete`, with the code printed beside
it so the user can check it against the approval page.**

An earlier draft of this document said the opposite — print only the code and
make the user transcribe it — on the usual device-flow phishing grounds. That
was wrong, for three reasons:

- The device-authorize endpoint authenticates no client, so an attacker starts
  their own flow and builds the same URL. Whether we print it changes nothing
  about what they can send.
- RFC 8628 §3.3.1 offers the complete URI for delivery **on the same device, out
  of band**. Printing it on the terminal the user just typed `ssh` into is that
  case; the §5.4 warning is about a code arriving over a channel an attacker
  controls.
- The check that actually catches a phished victim already exists: the consent
  page renders the code with *"Verify this code matches the one shown on your
  device"* (`mcp_handlers.go`, `renderConsentPage`). Somebody who followed a
  link they were **sent** sees a code matching nothing they have.

Transcription cost every legitimate user a step and stopped nothing.

No new scope is needed: `GET_JOB_CONNECT_INFO` is registered at **WRITE** in the
schedd, so `condor:/WRITE` already covers shell access. This matters because
narrowing the advertised scope list later is retroactive for CIMD clients and
kills live grants.

`offline_access` is required — a terminal session outlives an access token, and
the IDTOKEN minted for the schedd leg has to be re-minted mid-session.

### The SSH username is a target selector, not an identity

`ssh bob@gateway` asserts nothing. The OAuth identity, mapped through
`HTTP_API_IDENTITY_MAP` to a local account, is the only identity. Use the
username field for routing instead:

- `ssh 12345.0@gateway` / `ssh 12345@gateway` — that job (proc defaults to 0).
- **anything else** — the interactive session of that name, **created if the
  caller has none**. Implemented in `sshGatewaySession`, sharing the MCP
  server's `interactive.Manager` rather than building a second: the per-owner
  limits, leases and watchdog windows are per-manager state, and two managers
  would each enforce half a limit.

**Every username produces a session name; none is refused.** Session names are
`^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$`, and applying that to a username directly
refused real logins — `_appstore` is a genuine macOS account, an eppn like
`bob@wisc.edu` is a real username, and names with spaces exist. "That is not a
valid session name" is not something the person can act on when they did not
pick the name and often did not type it. `sessionNameFor` derives one instead:
characters outside the pattern become dashes, leading separators drop, truncate
to the limit. A usable name survives untouched, which is the case that matters.
A username with nothing usable in it falls back to a short digest of the
original — deterministic, so the same laptop reaches the same session, and
distinct, so two unrelated logins do not collide.

The truncation length is asserted against `interactive.ValidateSessionName`
rather than assumed: a name only `sshgateway` considered usable would fail
later, at submit, with a worse message.

Implemented as `ParseTarget` in `webapi/sshgateway/target.go`. Session names are
validated with `interactive.ValidateSessionName`, the same check the API itself
uses, so a session created through MCP is reachable here by the name it was
given.

Two consequences worth stating rather than discovering:

- **A bare `ssh gateway` sends the client machine's local username**, so it
  lands in the session-name case and gives that user a session named after their
  laptop login. Predictable rather than clever — but it does mean two machines
  with different local logins reach two different sessions.
- **Whitespace is not trimmed.** Turning `" 5"` into job 5 reaches a different
  job than the text names, which is the same hazard the digit check guards
  against for `+5`. Padded input becomes a session name like any other. An
  earlier draft trimmed, which quietly defeated that guard.

### One gateway package, two callers

`vscode-htcondor-remote/docs/DESIGN.md` item 5 specifies a *local* SSH gateway on
the laptop whose inner transport is a raw-SSH relay. That is the same
channel-proxying code as this one, differing only in how the inner client is
obtained. Write it once, parameterized by an inner-client factory, or it will be
written twice and the second copy will lack whatever the first one learned.

## The gateway itself

After authentication the gateway must **not** exec a local shell. It serves the
channels itself against a `*ssh.Client` reaching into the job:

| Client channel / request | Gateway action |
|---|---|
| `session` + `pty-req` + `shell` | inner `NewSession`, `RequestPty`, `Shell`, splice |
| `session` + `exec` | inner `exec` — see the word-splitting hazard below |
| `subsystem` | refused, with the `eval sftp` reason written to the channel |
| `window-change` | forward; also the width source for the progress display |
| `signal` | forward |
| `exit-status` / `exit-signal` | propagate back, so `$?` is real |
| `direct-tcpip` | `cache.DialJob(ctx, key, "tcp", addr)` |
| `direct-streamlocal@openssh.com` | `cache.DialJob(ctx, key, "unix", path)` |

### Required change to `webapi/jobssh`

`jobssh.Conn` is currently `{DialContext, Run, Wait, Close}` — it can open TCP
and Unix connections inside the sandbox, but it cannot open a **session**. The
gateway needs pty + shell + exec, so:

1. Add a session opener to the `Conn` interface. Keep `*ssh.Session` out of the
   interface if it can be avoided, so the cache stays testable without a pool —
   a narrow `JobSession` interface (`RequestPty`, `WindowChange`, `Shell`,
   `Start`, `Signal`, `Wait`, stdio pipes, `Close`) is enough, with the real
   implementation a thin wrapper over `*ssh.Session`.
2. Add `Cache.Session(ctx, key)` returning that session plus a release, built
   the same way `DialJob` builds `trackedConn`: **acquire a reference on open,
   release it on Close**.

Rule (2) is load-bearing. An interactive shell can sit silent for an hour; the
reaper's idle clock alone would close the transport under the user. A held
session has to count as a live connection exactly as a tracked conn does. The
symmetric rule from `DialJob` applies too: a *session* that fails to open must
not evict the transport — only `watch()` can tell a dead transport from a busy
sandbox.

### Fold the WebSocket bridge onto the cache — for capacity, not for convergence

An earlier draft of this document justified the migration as collapsing "two
independent paths into a job". **That was wrong.** `handlers_ssh.go` calls
`schedd.OpenJobShell`, and so does `jobssh.ScheddDialer` through its
`openJobShell` seam; both reach the wire through `dialStarter`. There is one
implementation, used with caching and without. The bug-convergence story
belongs to `dialStarter` itself, which unified `schedd_peek.go` and
`schedd_ssh.go` — that work is already done, and citing it here transplanted
the lesson onto a seam it does not apply to.

What the migration actually buys is transport reuse, shared fate on transport
loss, and one place where the session budget below is enforced. Those are worth
having, but they are a deliberate change with a real trade-off, not a cleanup.

The `.shutdown` sentinel hazard is real — on a shared transport "this session
ended" stops meaning "the last session ended" — but it is being fixed on its
own in **#527**, so the migration does not have to carry it.

### The session budget is 10, and sharing a transport shares it

`condor_ssh_to_job_sshd_config_template.in` sets no `MaxSessions`, so OpenSSH's
default of **10** applies, and that budget is **per connection**. Before the
cache, every client had its own connection and therefore its own 10. Behind it,
every terminal and every exec on one job draws from a single 10. `jobssh`
enforces this explicitly in #526 (`MaxSessionsPerTransport`,
`ErrTooManySessions`) rather than letting it surface as an opaque channel
failure.

Consequences for the gateway:

- **Port forwards are exempt.** `MaxSessions` counts shell, login and subsystem
  channels; `direct-tcpip` and `direct-streamlocal` are neither. So the reverse
  proxy and every forwarded port cost nothing against the budget. This is why
  the browser path is unaffected.
- **A gateway multiplexing shells does draw on it.** Ten concurrent terminals on
  one job is a generous ceiling for a human and a thin one for a tool that
  opens an exec per operation. When it is hit, the gateway must say so in
  words — "you have 10 sessions open on job 12345.0" — because the SSH-level
  symptom is an unexplained channel-open failure.
- **We cannot raise it.** The sshd config is generated by the starter, so 10 is
  fixed unless HTCondor makes it configurable. Worth adding to the upstream
  report alongside the `sftp` and `eval` items.
- If the ceiling ever binds, the escape hatch is a second transport for the same
  job rather than a bigger number — the key becomes `(owner, cluster, proc, n)`.
  Not now.

## Key management

Two persistent keys: the **gateway host key** and the **SSH CA key**.
Implemented in `webapi/sshkeys`, with migration `0014_ssh_gateway_keys.sql`.

**Which envelope.** webapi has two, and the earlier draft of this document
picked the wrong one. `masterkey.go`/`crypt` (pool signing keys wrap a master,
HKDF label per purpose) protects the identity cookie. `appdb/seal`
(`HTTP_API_KEK_FILE` -> per-DB KEK -> per-row DEK) protects every long-lived
*private key* in this database: the OAuth2 issuer key, the IDP key, fosite's
GlobalSecret. The SSH keys are private keys of exactly that kind, so they use
`seal` — otherwise a deployment with a KEK file but no `SEC_PASSWORD_DIRECTORY`
would have its OAuth2 issuer key protected and its SSH host key homeless, and a
deployment with the reverse would get the reverse. One matrix instead of two.

It also matches the deployment this feature is for: an API server in a pod has
a mounted KEK secret far more reliably than it has HTCondor pool signing keys.

One difference from every other sealed column: `private_key_dek` is **NOT
NULL**. The other tables carry a nullable `_dek` so a pre-KEK deployment keeps
working against plaintext rows; there is no plaintext era here to stay
compatible with, and a private key is not a thing to leave lying in a database
by default. For the same reason the table must **not** be added to
`sealableRows` in `seal_setup.go` — the backfill walker looks for plaintext rows
to seal and by construction there are none.

### Precedence

1. **`HTTP_API_SSH_HOST_KEY_FILE` / `HTTP_API_SSH_CA_KEY_FILE`** — a path to an
   OpenSSH private key, read through `droppriv.OpenMaybeAsRoot`. This is the
   documented Kubernetes path: a projected secret volume. Deliberately **no**
   plain `HTTP_API_SSH_HOST_KEY` env var — `/proc/PID/environ` and crash dumps
   both leak the environment, and a secret volume does not. Permission posture
   copied from `seal.LoadMasterKEKFromFile`: world-accessible refused, group
   bits tolerated because kubelet's `fsGroup` turns a 0400 mount into 0440.
   A passphrase-protected key is refused with an error that says how to strip
   it, since `ssh.ParsePrivateKey`'s own message suggests no fix.
2. **Sealed row in `ssh_gateway_keys`**, minted on first use when a sealer is
   configured.

A configured file always wins, and never mints a row.

### Failure semantics

These are the decisions that matter, and two of them run against instinct.

- **Minting on first use is fine.** If a sealer is available and no key is
  stored or configured, generate ed25519, seal it, store it. No operator action
  required for the common case.
- **The mint reads its own row back.** Two processes sharing a database must
  converge on one key, so the insert is `ON CONFLICT DO NOTHING` and the result
  is re-read rather than returned directly; the loser of the race serves the
  winner's key. Returning the locally generated signer gives two replicas two
  host keys, and no single-process test ever sees it.
- **A stored key that cannot be opened is a startup error.** Never mint a
  replacement. A new host key is indistinguishable from MITM to every client
  holding the old one, and the recovery users will learn is "delete the
  known_hosts line" — which is a permanent loss of the protection the key
  exists to provide. The likely cause is a misconfigured
  `SEC_PASSWORD_DIRECTORY`, which is recoverable; the trust is not. This is the
  same rule `openOrCreateMaster` already applies to the master itself.
  It is more emphatic still for the CA: reminting it invalidates every
  outstanding certificate at once.
- **No key file and no sealer means the gateway is disabled**, not backed by an
  ephemeral in-memory key. An ephemeral host key changes on every restart and
  differs between replicas. `Resolve` returns `ErrNoKeyStore` so the caller can
  disable the feature deliberately rather than crash or improvise.
- **A file configured while a DB row exists** is a config change with full
  client-visible blast radius, and otherwise completely silent. The file wins,
  but log both fingerprints at startup and say which is in use. Do not mint a DB
  row at all when a file is configured — a shadow key nobody is using is a
  surprise waiting for the day the file mount breaks.
- **More than one replica** must present the same host key. This is the
  strongest argument for the secret-file path; the DB-minted key is correct for
  a single process and a foot-gun behind a load balancer. Worth a startup
  warning if there is any way to detect the situation.

## Progress while the job is queued

`Manager.Create` submits and returns, so the gateway owns the wait loop. Waiting
20 minutes at a prompt is worse than SSHing to the AP, so the wait has to be
legible.

**Resolution happens after `Accept`, which is the opposite of the obvious
order.** Until the channel exists there is nowhere to write, so a job that takes
three minutes to start would be three minutes of silence. Accepting first buys a
place to draw; the cost is that a failure past that point cannot use
`nch.Reject` and goes to the channel's stderr with an exit status instead. Only
what is knowable instantly — a username that parses as nothing — stays in front
of `Accept`.

Two consequences, both handled:

- **The client's early requests have nowhere to go yet.** It sends `pty-req`,
  `env`, `shell` and waits for each reply, and none can be answered before the
  job exists. `requestPump` holds them and replays them in order once it does.
  It stops holding when the *session arrives*, not when a `shell` turns up — an
  earlier version waited for `shell` and hung any client that sent `pty-req` and
  then waited for its reply, which is what a client does.
- **A failure must still answer them.** `refuseHeld` replies "no" to everything
  outstanding, or the client learns nothing until the channel closes and reports
  a dropped connection rather than the sentence just written to its stderr.

**You cannot animate during `keyboard-interactive`.** Every `Challenge` round
trip needs a client answer, so the auth phase gets static text only. The
animation belongs after authentication, on the session channel, where the
gateway owns the byte stream. The `pty-req` tells you which case you are in:

- **With a pty** — a spinner redrawn with `\r\x1b[K`, never a newline per frame.
  Verified against a real client:

  ```
  ⠋  Session "work" (job 5.0) is idle, waiting for a slot   0:00
  ⠙  Session "work" (job 5.0) is idle, waiting for a slot   0:00
  ```

  Erase-to-end rather than padding with spaces, so a shorter status cannot leave
  the tail of a longer one behind on a narrow terminal. `stop()` clears the line
  so the job's first output starts clean.
- **Without a pty** — each distinct status once, on its own line. A pipe has no
  cursor to move and escape sequences in it corrupt whatever is reading.

`ResolveFunc` takes a `report func(string)`: the resolver knows why it is
waiting, the gateway knows how to show it.

**Ctrl-C does not remove the job**, which is the opposite of what an earlier
draft said. Somebody who gives up waiting almost always still wants the session
they asked for; reconnecting picks it up once it starts, and the lease and
watchdog reclaim it if they never come back. Removing it would make Ctrl-C
destroy several minutes of queue position. The message says so, so the user
knows to reconnect rather than assuming it died.

**Ctrl-C** cancels the wait — but only on a session with a terminal. Reading the
channel consumes bytes meant for the job's stdin, which is harmless for someone
typing at a shell that does not exist yet and is data loss for
`echo hi | ssh gateway cat`. Without a terminal nothing is read at all: the SSH
window fills, the client blocks, and the bytes are intact when the real stdin
copier starts. `TestStdinSentDuringTheWaitSurvives` pins that.

## Certificate path

After a first browser login, hand the user a short-lived SSH certificate so
`publickey` auth works.

The reason is narrower than the earlier draft claimed, now that the client
matrix has been measured. Keyboard-interactive is not the blocker for `scp` or
for a missing terminal — both work. What certificates actually buy is
**`BatchMode=yes`**, which the client refuses outright, and **not making a human
approve every single connection**: every `ssh` invocation is its own device
authorization, and an editor or a loop opening connections would ask for
approval each time. That second reason is the one users will feel.

- `GET /api/v1/ssh/ca` — the CA public key, its fingerprint, and a ready
  `@cert-authority * …` line for `known_hosts`. The wildcard is deliberate: a
  gateway may be reached by several names, and narrowing it would silently stop
  working the first time somebody uses an alias.
- `POST /api/v1/ssh/certificate` — body carries the caller's **public** key;
  returns a certificate to save as `<key>-cert.pub`, which `ssh` finds beside
  the private key on its own.

Three properties, all tested:

- **The principal is the resolved account and the request cannot choose it.**
  There is deliberately no principal field on the request type, so adding one
  later has to break a test. `createAuthenticatedContext` resolves the name
  through the token cache or by asking the schedd and leaves it empty when it
  cannot; empty is refused rather than treated as anonymous. This is an
  identity-only endpoint — nothing downstream re-checks who asked — which is
  exactly the category the trust model says is not self-protecting.
- **12 hours, never more than 24.** Not conservatism for its own sake: there is
  no revocation, so the lifetime is the only control.
- **The username is never checked against the principal**, because here it names
  the job. Requiring a match would mean a certificate per job.

**The trap that nearly shipped.** `ssh.CertChecker.CheckCert` verifies a
certificate's signature against the key embedded *in the certificate* and never
asks whose key that is. Only `CertChecker.Authenticate` consults
`IsUserAuthority` — and it also insists the principal match `conn.User()`, which
is unusable here. Calling `CheckCert` alone therefore accepts **any self-signed
certificate**. It passed every test that did not present a foreign CA, and read
as working code. The authority is now compared explicitly before `CheckCert`
runs, and `TestCertificateFromAnotherCAIsRefused` is the test that caught it.

Agent forwarding: **undecided, deliberately**. The gateway is an
`x/crypto/ssh` server, so it only handles channel types it implements — nothing
is broken by inaction today. But do not start enforcing certificate extensions
without deciding, or omitting `permit-agent-forwarding` becomes an accidental
denial rather than a choice.

## What will bite

- **`sftp` does not work through `condor_ssh_to_job`.** The forced command in
  `condor_ssh_to_job_shell_setup` ends in `eval ${SSH_ORIGINAL_COMMAND}`, so the
  subsystem request becomes `eval sftp`. `scp`/`sftp` into the job will fail
  confusingly unless the gateway terminates the subsystem itself and bridges
  over exec. Being reported upstream.
- **That `eval` is unquoted**, so anything sent as a command is word-split on
  IFS — newlines included — and rejoined with spaces before `eval` re-parses it.
  A multi-line script arrives as one line and dies on its first indented block.
  Send a single line (base64 the payload) or write a file first. Interactive
  shells are unaffected. Also being reported upstream.
- **A containerized session job must keep a long-lived main process alive.**
  `condor_nsenter` needs a live target pid, found by `findChildProc` heuristics.
- **`sun_path` is ~104 bytes** and both ends of a Unix forward are bound by it.
  An HTCondor scratch directory can fill most of it. The failure is `open
  failed` and names nothing — check the length yourself.
- **Preemption.** A session dying mid-edit is unacceptable. Needs a
  non-preemptible interactive partition or a serious `MaxJobRetirementTime`.
- **Idle reaping.** An open terminal with a shell prompt sends nothing;
  traffic-based idle detection reaps the session someone stepped away from and
  keeps the one whose tab is closed. The `interactive` lease plus its
  `periodic_remove` ceiling is the backstop.
- **Debugging forwards:** `administratively prohibited` means forwarding is
  disabled; `connect failed` means forwarding works and nothing is listening.
  Different findings.

## Milestones

1. `jobssh` session extension + `Cache.Session` — **in review as #526**, with
   the `.shutdown` fix split out into **#527**. Unblocks both this and the VS
   Code desktop path.
2. ~~Host key / CA key loading and sealing~~ — **done**, branch
   `ssh-gateway-keys`: `webapi/sshkeys` + migration 0014. Not yet wired into
   `Handler`, deliberately: with no gateway to consume it, startup wiring would
   mint keys into databases that never use them. Milestone 3 adds the config
   knobs and the call.
3. SSH server + keyboard-interactive bridged to the device flow, session channel
   only, attach-to-existing-job form. **DONE** on branch `ssh-gateway`, four
   commits off `main`:
   - `webapi/sshgateway` — `HTTPFlow`/`Wait` (device flow), `Authenticator`
     (keyboard-interactive), `Server` (channel proxy), `Listener`, `ParseTarget`.
   - `webapi/sshkeys` + migration `0014_ssh_gateway_keys.sql` — host and CA keys.
   - `webapi/httpserver/sshgateway.go` — the wiring, plus `withCondorCredential`
     extracted from `mcpAuthContext` so the gateway shares the credential path
     rather than copying it.

   Config: `HTTP_API_SSH_GATEWAY_ADDRESS` (enables it),
   `HTTP_API_SSH_GATEWAY_ISSUER`, `HTTP_API_SSH_HOST_KEY_FILE`,
   `HTTP_API_SSH_CA_KEY_FILE`.

   **Exercised against a real pool**, in `sshgateway_integration_test.go`:
   a real ssh client, a real device grant, a real schedd checking ownership,
   an sshd in a real job. Only the browser approval is stood in for.

   That test found the issuer bug — `shouldUpdateIssuer` only replaces an empty
   or `:0` issuer, so an unconfigured deployment keeps the hardcoded
   `http://localhost:8080` default and the gateway posts to a server that is not
   there. `probeSSHGatewayIssuer` now checks once after startup and logs what to
   set.

4. ~~Create-a-session-on-demand through `interactive.Manager`~~ — **done**, and
   covered end to end against a real pool. Remaining in this milestone: move
   resolution after `Accept` so the queue wait it introduces can be shown, then
   the progress display and Ctrl-C cancellation.

   Sized by `HTTP_API_SSH_GATEWAY_SESSION_{CPUS,MEMORY_MB,DISK_MB}`, each
   defaulting to the interactive default when unset or unparseable. A bad value
   warns rather than stopping startup: these size a session somebody may not
   create for weeks, and refusing to boot the whole API over a typo in one of
   them is out of proportion.
5. ~~`direct-tcpip` / `direct-streamlocal` channels~~ — **done**. Neither is a
   session, so neither draws on the sshd's 10-session budget. The socket form
   is the one that matters: a TCP port on 127.0.0.1 in a sandbox is open to
   every local user on the execute node unless the job has its own network
   namespace, which no pool can be assumed to configure.
6. Certificate path — **backend done**. `webapi/sshgateway/cert.go` verifies,
   `handlers_sshcert.go` issues, and a real `ssh -o BatchMode=yes -i key` logs
   in and runs with no browser. Remaining: the `/info` page rendering the CA
   line and a one-line enrollment command, which is the part that wants a human
   to look at it.
