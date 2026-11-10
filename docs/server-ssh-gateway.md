# SSH gateway

An SSH port on the API server that authenticates with the OAuth2 device
flow and drops the caller into an HTCondor job — so users get an
interactive terminal without an account on the access point. Part of the
[HTTP API + MCP server](server.md) documentation.

## Turning it on

```
HTTP_API_SSH_GATEWAY_ADDRESS = :2222
HTTP_API_SSH_HOST_KEY_FILE = /etc/condor/htcondor-api/ssh_host_key
```

A user connects with a stock `ssh` and sees:

```
$ ssh 12345.0@ap.example.edu -p 2222
Approve at https://ap.example.edu/mcp/oauth2/device/verify?user_code=WDJB-MJHT (code WDJB-MJHT), then press Enter:
```

Approve in the browser, press Enter, and the session opens. Clients that
render the longer RFC 4256 instruction show the URL and code on their own
lines above that prompt; OpenSSH on Linux shows only the prompt, which is why
everything needed to act is repeated there.

No client configuration, no key to distribute: the prompt is an ordinary
RFC 4256 keyboard-interactive challenge, which every SSH client already
renders. Approving in the browser lets the session continue by itself.

## What the username selects

The username carries no identity — the OAuth2 grant does — so it names the
target instead:

| `ssh <this>@gateway` | reaches |
| --- | --- |
| `12345.0`, or `12345` | that job, proc 0 if omitted |
| `+work` | your interactive session called `work`, **started if you have none** |
| anything else, including a bare `ssh gateway` | your **default** session |

The `+` is required to name a session, and a bare `ssh gateway` reaches the
same `default` session from every machine you own. That is the point: the
username is whatever your local machine calls you, and your laptop login has
nothing to do with your HTCondor session — reading it as one would give you a
different session from a laptop, a login node and a container.

`+` is used because a POSIX username cannot contain it, so no local login can
be mistaken for an explicit request. A word like `session-` would need an
escape hatch for the account actually called `session-manager`; this needs
none.

It also reaches a session whose name looks like a job id, which is otherwise
unreachable because job ids are tried first: `ssh +12345.0@gateway`.

While a newly created session waits in the queue, the terminal shows what it is
waiting for and how long it has been waiting. Ctrl-C stops waiting; it does
**not** remove the job, so reconnecting picks the session up once it starts.

## The approval screen

Where the web UI is built into the binary, the approval link opens a screen
for the workspace the `ssh` command asked for rather than a generic "allow
this device" page. The `ssh` client sends the workspace name along with the
device authorization, and the verification endpoint redirects to
`/ssh/approve`.

If you already have a workspace by that name, the screen says what it is
doing — queued, running, or held and why — and offers the sign-in alone.
If you do not, it shows the same resource form as the **Interactive** page
(CPUs, memory, disk, GPUs, extra submit lines), opened on what
`HTTP_API_SSH_GATEWAY_SESSION_*` would have submitted. One button creates the
workspace **and** approves the sign-in. Nothing is submitted if you refuse,
and nothing is approved if the submission fails.

The browser submits the job, as you, before the approval is recorded, so the
gateway finds the workspace waiting and attaches to it. Creating on demand
from the gateway remains the fallback for a deployment with no web UI and for
an approval that created nothing; it cannot produce a second job, because the
first one to submit a given name wins and the other attaches to it.

The code is shown large at the top of the screen. It is the check that
catches a login somebody else started: a code that matches nothing in your
terminal is not yours to approve.

A deployment without the web UI keeps the server-rendered consent page, and so
does every device code that is not an SSH login.

## Host key and CA key

Both are long-lived and both are dangerous to lose: replacing a host key trips
`StrictHostKeyChecking` for every user at once, and replacing the CA key
invalidates every certificate it signed. They come from, in order:

1. `HTTP_API_SSH_HOST_KEY_FILE` / `HTTP_API_SSH_CA_KEY_FILE` — a path to an
   OpenSSH private key you staged (`ssh-keygen -t ed25519 -N '' -f <path>`).
   World-readable is refused; group-readable is fine, because a kubelet
   `fsGroup` mount turns 0400 into 0440. Passphrase-protected keys are refused
   with an error saying how to strip it.
2. Otherwise the daemon generates one and keeps it **sealed in the application
   database**, which requires `HTTP_API_KEK_FILE`.

There is deliberately no setting carrying the key bytes themselves:
`/proc/<pid>/environ` and crash dumps both leak the environment, and HTCondor
configuration is public to anyone who can run `condor_config_val`.

A stored key that cannot be decrypted is a **startup error**, never silently
replaced — the usual cause is a swapped `HTTP_API_KEK_FILE`, which is
recoverable, while a new host key is indistinguishable from an attack. Enabling
the gateway with neither a key file nor a KEK is also a startup error rather
than a port that quietly is not there.

**Running more than one replica?** Use the key file. A database-minted key
belongs to one database, so replicas would present different host keys.

## Knobs

| Knob | Purpose |
| --- | --- |
| `HTTP_API_SSH_GATEWAY_ADDRESS` | Where to listen, e.g. `:2222`. Empty disables the gateway. |
| `HTTP_API_SSH_GATEWAY_ISSUER` | OAuth2 issuer the device flow runs against. Defaults to the server's own issuer; set it when this process cannot reach its own public URL. |
| `HTTP_API_SSH_HOST_KEY_FILE` | Host key clients pin. Generated and sealed in the DB when unset. |
| `HTTP_API_SSH_CA_KEY_FILE` | CA key for signing user certificates. Same treatment; without it certificates are unavailable and the device flow still works. |
| `HTTP_API_SSH_GATEWAY_HOST` | The name(s) users actually `ssh` to, e.g. `ap.example.edu`, comma-separated. It is what the web UI prints as the `ssh` command, **and** what the host certificate and published `known_hosts` line are narrowed to — so list every name and alias in use. It cannot be derived, because the listen address is usually not what anybody types: a container listening on `:2222` sits behind a service publishing 22 on another address. Unset means no command is printed, and host verification falls back to a `*` pattern. |
| `HTTP_API_SSH_GATEWAY_LOCKOUT_THRESHOLD` | Failed logins one host may accumulate within the window before it is locked out. Default 10. |
| `HTTP_API_SSH_GATEWAY_LOCKOUT_NET_THRESHOLD` | The same budget for the surrounding network, shared by every host in it. Defaults to four times the host threshold. |
| `HTTP_API_SSH_GATEWAY_LOCKOUT_WINDOW` | How long failures are remembered. Needs a unit: `10m`. |
| `HTTP_API_SSH_GATEWAY_LOCKOUT_TIME` | How long the first lockout lasts; each subsequent one doubles. Default `15m`. |
| `HTTP_API_SSH_GATEWAY_LOCKOUT_MAX_TIME` | Where the doubling stops. Default `24h`. |
| `HTTP_API_SSH_GATEWAY_LOCKOUT_TRUSTED` | Addresses and CIDR blocks never counted and never locked out, separated by commas or spaces. A typo here is a startup error. |
| `HTTP_API_SSH_GATEWAY_LOCKOUT_DISABLE` | `true` turns the lockout off. |
| `HTTP_API_SSH_GATEWAY_SESSION_CPUS` | CPUs a session created on demand requests. Default 1. |
| `HTTP_API_SSH_GATEWAY_SESSION_MEMORY_MB` | Memory for the same. Default 1024. |
| `HTTP_API_SSH_GATEWAY_SESSION_DISK_MB` | Disk for the same. Default 8192 — a VS Code Remote server does not fit in less. |

The gateway needs OAuth2, which is served whenever the web UI or MCP is
enabled (see [When OAuth2 is served](server-auth.md#when-oauth2-is-served)), since the device
flow is how it authenticates. Shell access needs no new scope: the schedd
registers `GET_JOB_CONNECT_INFO` at `WRITE`, so `condor:/WRITE` covers it.

If logins fail with *"could not start the login flow"*, the gateway cannot reach
its own device endpoint. It checks once shortly after startup and logs the URL
it tried — the usual cause is an unset `HTTP_API_OAUTH2_ISSUER`, which leaves
the default `http://localhost:8080` pointing at nothing.

## Locking out what keeps knocking

A public SSH port attracts traffic from people who are not users, so
the gateway counts failed logins per source and refuses new connections
from one that fails too often -- fail2ban's idea, without the log
scraping. It is on by default.

Counting happens at two granularities, because one is not enough. Per
host alone is free to evade over IPv6, where one allocation holds more
addresses than anyone could enumerate; per network alone would let a
single bad machine on a campus lock out the campus. So a host has its
own budget and the network around it has a larger shared one, and
tripping either is enough. A host is a `/32` on IPv4 and a `/64` on
IPv6, since one machine there routinely has several addresses; a
network is a `/24` and a `/48`. Once a host is locked out its further
failures stop counting anywhere, so it cannot spend its neighbours'
budget on their behalf.

Not every failure weighs the same:

| What happened | Weight |
| --- | --- |
| A login that began and was not finished -- the code expired, the browser said no | 1 |
| A certificate this deployment's CA did not sign, or one that did not verify | 1 |
| A **self-signed** certificate | 5 |
| Added when a failed login asked for a name a scanner works through -- `root`, `admin`, `ubuntu` | 3 |
| Authentication by a method this gateway never advertised -- password, GSSAPI | locked out at once |
| A refusal that is the gateway's own doing -- at its concurrency cap, issuer unreachable | 0 |
| `none` and `publickey` failures | 0 |

The last two rows are the ones that matter in practice. `none` is how
every SSH client asks what the server offers, and a client with a full
agent offers every key it holds before its certificate -- counting
either would lock out the people this is meant to protect. And an
issuer outage must not be mistaken for an attack, or a degraded gateway
locks out everybody who tried to reach it during the outage.

Asking for password authentication, on the other hand, is unambiguous:
this gateway never offers it, so no real client asks. That is the
strongest signal there is, and it is what most scanners trip on.

The username is a weaker one and is only ever added to a login that
*already failed*. `ssh root@gateway` is not by itself evidence of
anything here: an unprefixed username means "my default session", so
that is exactly what a real person gets from a container, and a real
person finishes the login. An explicit `+root` is somebody naming a
session and is never counted.

A lockout lasts `15m`, and doubles each time the same source comes back
for another, up to a day. Knocking while locked out does not extend it.

**Two caveats worth knowing.** The list lives in memory, so a restart
clears it and each replica keeps its own -- a restarted gateway starts
counting again rather than staying protected. And it counts whatever
address the connection arrives from, which behind a load balancer that
does not preserve the client address is the balancer: on Kubernetes
that means `externalTrafficPolicy: Local` on the gateway's Service, or
one bad client locks out everyone.

Put the office and the monitoring host in
`HTTP_API_SSH_GATEWAY_LOCKOUT_TRUSTED` so testing the gateway cannot
lock you out of it.

## Behind a load balancer

The gateway has to see each client's own address. It terminates the TCP
connection itself and does not accept the PROXY protocol, so nothing
upstream can tell it who the client is: pass the connection through at
layer 4 with the source address intact (`externalTrafficPolicy: Local`
on a Kubernetes Service, or no SNAT on the path). Behind anything that
rewrites the source -- a TCP proxy, SNAT, a NAT gateway -- every client
arrives from the same address, and everything counted per source is
counted for the whole site at once:

- At most four logins may be waiting at the approval prompt from one
  address. The fifth person to connect is refused until one of those
  finishes or its device code expires.
- The failure budget is shared. One user's abandoned logins lock
  everyone out, for `15m` the first time and up to a day.

Listing the balancer in `HTTP_API_SSH_GATEWAY_LOCKOUT_TRUSTED` stops the
lockouts by turning them off for every client behind it, and leaves the
four-login limit in place.

## Certificates, for scripts and for not approving every connection

`BatchMode=yes` refuses keyboard-interactive outright, so a script cannot use
the device flow at all — and nobody wants a browser prompt per connection
either. A certificate is obtained once and then works until it expires.

The gateway signs them with a CA key resolved exactly like the host key:
`HTTP_API_SSH_CA_KEY_FILE`, else generated and sealed in the database. Without
either, certificates are simply unavailable and the device flow still works —
losing convenience, not access.

That response also carries `gateway_host` and `gateway_port` when
`HTTP_API_SSH_GATEWAY_HOST` names one, so a client can find the gateway without
being told where it is. Both are omitted when it is unset: the listen address is
not the answer, since a container on `:2222` usually sits behind a service
publishing 22 somewhere else, and a guess would send clients to a closed port.
The port is reported only when the operator wrote one — `ap.example.edu:2222` —
and a client should read its absence as the SSH default rather than as an
instruction.

The common deployment is worth spelling out. A container binds
`HTTP_API_SSH_GATEWAY_ADDRESS = :2222` and a service publishes it as
`ap.example.edu` on port 22. Set `HTTP_API_SSH_GATEWAY_HOST = ap.example.edu`
and nothing else: the port is not 2222 as far as any client is concerned, and
the listen address is never consulted for what is advertised. Write
`ap.example.edu:8022` only if that is the port users really type.

Leaving it unset is logged as a warning at startup, because what it costs is
otherwise silent: no address is advertised, so every client has to be told by
hand; the host certificate is issued for every name rather than this one; and
the web UI prints no `ssh` command for a session.

```bash
# The CA, so your client trusts the gateway's host key.
curl -H "Authorization: Bearer $TOKEN" https://ap.example.edu/api/v1/ssh/ca

# A certificate for a key you already have.
curl -X POST -H "Authorization: Bearer $TOKEN" \
     -d "{\"public_key\": \"$(cat ~/.ssh/id_ed25519.pub)\"}" \
     https://ap.example.edu/api/v1/ssh/certificate
```

Save the `certificate` field as `~/.ssh/id_ed25519-cert.pub`, beside the private
key; `ssh` finds it on its own. Add the `known_hosts_line` to `~/.ssh/known_hosts`
and the gateway's host key verifies without pinning it by hand: the gateway
presents a host certificate signed by the same CA, so trusting the CA is enough.

Set `HTTP_API_SSH_GATEWAY_HOST` to the name users reach the gateway by, and both
the certificate's principals and the published `known_hosts_line` narrow to it.
That is worth doing: a line reading `@cert-authority * <ca>` tells the client to
trust this CA for **any** host, so naming yours confines what a stolen CA key
could vouch for. Several names are comma-separated, and a port is tolerated and
ignored — list every name and alias in use, because one left out stops verifying.

Left unset, the certificate lists no principals and the line uses `*`. A server
that does not know the names it is reached by cannot do better: it binds `:2222`
behind whatever the operator put in front of it, and a certificate naming the
wrong name fails closed for everyone.

Each configured name appears in the line twice, as `name` and `[name]:*`, because
OpenSSH looks a host up as `[name]:port` for any port but 22 — and this gateway
defaults to 2222.

The bare host key is still offered alongside it, so a client that pinned the key
before certificates existed keeps connecting and notices nothing. A client that
holds the CA line negotiates the certificate instead; OpenSSH prefers whichever
algorithm it already knows something about for that host.

Certificates last 12 hours by default and never more than 24. That is not
conservatism for its own sake: **there is no revocation**. No CRL, no OCSP, no
list to add a stolen key to. The lifetime is the only control, which is the
reason not to make it generous.

Three properties worth knowing, because they differ from how OpenSSH
certificates usually work:

- **The principal is the account, and the request cannot choose it.** The name
  signed is the one the access point resolved for the caller.
- **The username is not checked against the principal.** On this gateway the
  username names the job to reach, so requiring a match would mean a
  certificate per job.
- **Bare public keys are never accepted**, only certificates. A key on its own
  carries no identity and no expiry, so accepting one would mean this server
  keeping a list of whose key is whose — and a list that never forgets a
  compromised key.

## Limits worth knowing

- **`scp` and `sftp` work**, and so does anything else that asks for a
  subsystem: the gateway forwards the request to the job, whose sshd serves its
  own `Subsystem` directive. This was documented as impossible, on the belief
  that the forced command in `condor_ssh_to_job_shell_setup` turns a subsystem
  request into `eval sftp`. It does not — a probe against a real job gets a
  genuine `SSH_FXP_VERSION` reply from a real `sftp-server`.
- **The device flow needs somewhere to prompt.** `BatchMode=yes` declines
  keyboard-interactive outright, and a client with no terminal has nowhere to
  show the code; both want a certificate instead. A remote terminal is not
  required — `ssh -T` is fine, as long as the *local* end can prompt.
- **Ten sessions per job.** The sshd HTCondor starts uses OpenSSH's default
  `MaxSessions`, and every terminal for one job shares it. Port and socket
  forwards do not count against it.
- Each `ssh` is its own device authorization, so each asks for approval.
- **Port forwards reach whatever the job can.** `ssh -L` and socket
  forwards are dialled from inside the job, as `condor_ssh_to_job -L`
  does, to any host and port or socket path the job could reach itself.
  They carry the user's own authority over their own job, not the
  server's.
