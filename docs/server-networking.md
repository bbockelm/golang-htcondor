# Reaching jobs behind CCB

What it takes for this server to open a connection *into* a running job
when the execute nodes are firewalled. Part of the
[HTTP API + MCP server](server.md) documentation.

Anything that reaches *into* a running job — a shell, `tail_job_output`,
`exec_in_job`, an interactive session — connects to the starter on the execute
node. When that node is firewalled, its address carries a Condor Connection
Broker contact and the connection has to go through the broker.

## When you are already on their network

Before any of that: if this server sits on the same private network as the
execute nodes — a pod beside the pool is the usual case — it can open a TCP
connection to them directly, and the broker is only in the way.

HTCondor's convention for saying so is `PRIVATE_NETWORK_NAME`. A daemon
publishes its own as `PrivNet` in the address it advertises, and a client whose
name matches dials the daemon directly instead of through its broker:

```
PRIVATE_NETWORK_NAME = pool-internal
```

Set it to the same value the execute nodes use. When it matches, this server
uses the daemon's `PrivAddr` if the address carries one, and otherwise dials the
advertised address with the broker contact dropped — the same two cases C++
HTCondor implements.

Nothing has to listen inbound, so `HTTP_API_SHARED_PORT` and everything under it
becomes unnecessary, and the dial no longer depends on the broker's version.

A direct dial that fails falls back to the broker rather than failing the
request, since a private network can be partly reachable. That failure is
remembered for `HTTP_API_CCB_LEARNED_TTL` so the timeout is not paid on every
dial, and is per network — one unreachable node steers the rest to the broker
until the TTL expires. A success clears it.

The parameter defaults to `$(FULL_HOSTNAME)`, matching C++. That is harmless:
it only matches a remote `PrivNet` when the daemon really is on this host.

CCB offers two ways through, and on a host that is itself firewalled neither is
automatic:

- **Connection reversal** (the default). The broker tells the starter to dial
  *us*. That needs this server to be reachable from the execute node — which an
  API server in a container, behind NAT, or in a Kubernetes pod is not. The
  failure is silent: the starter connects to an address nothing routes to and
  the request times out without naming CCB.
- **Streaming**, where the broker relays both directions itself. No inbound path
  needed, but it requires a broker running HTCondor 25.13 or newer, and *which*
  broker a given dial uses is decided by the execute node, not by this server.

Setting `HTTP_API_SHARED_PORT` gives this server the inbound path, using the
same mechanism the access point already uses for `condor_ssh_to_job`: one port,
multiplexed. Each dial registers an unguessable id and advertises
`<host:port?sock=ID>` as its reverse-connect address, so any number of
concurrent sessions share the one port. No `condor_shared_port` daemon is
involved — the routing happens inside this process.

```
# The port execute nodes will connect back to.
HTTP_API_SHARED_PORT = 9618

# Only when that is not what they should dial -- a Kubernetes Service, a
# published container port, a NAT.
HTTP_API_SHARED_PORT_ADDRESS = htcondor-api.example.org:9618
```

With it set, connection reversal through that port is tried first, because it
works with every broker version. If the execute node turns out not to be able
to reach it after all, the server falls back to streaming (unless
`HTTP_API_CCB_STREAMING = false`), and remembers the answer per broker for
`HTTP_API_CCB_LEARNED_TTL` so later requests do not pay the timeout again. A
broker too old to relay is likewise remembered and not asked again.

Open the port in the host firewall, and check the log line at startup — it
prints the address being advertised, which is the thing that is wrong when this
does not work:

```
HTCondor shared port open for CCB connection reversal listen=9618 advertised=htcondor-api.example.org:9618
```
