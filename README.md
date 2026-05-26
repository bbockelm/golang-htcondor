# golang-htcondor

A Go client library for HTCondor — collector queries, schedd
submission and management, file transfer, sandbox handling, and pool
metrics — plus two long-running servers built on top of it.

## What's in this repo

- **Go library** (`github.com/bbockelm/golang-htcondor`) — idiomatic
  Go bindings mirroring the HTCondor Python bindings. Submit jobs,
  query the schedd/collector, transfer files, build sandboxes,
  collect pool metrics. See [docs/library.md](docs/library.md).
- **`htcondor-api`** — RESTful HTTP API server with a bundled SPA,
  OAuth2/OIDC support, API-key auth, an embedded IDP, admin UI, and
  an LLM-powered chat assistant. Runs standalone, under
  `condor_master`, or in Docker. See [docs/server.md](docs/server.md).
- **`htcondor-mcp`** — [Model Context Protocol](https://modelcontextprotocol.io/)
  server that exposes the same engine to LLM agents (Claude Code,
  etc.) over stdio. See [docs/server.md](docs/server.md).

## Install

As a Go module:

```bash
go get github.com/bbockelm/golang-htcondor
```

As a server (pre-built container, multi-arch amd64/arm64):

```bash
docker run -p 8080:8080 ghcr.io/bbockelm/golang-htcondor:latest
```

Or build from source:

```bash
git clone https://github.com/bbockelm/golang-htcondor
cd golang-htcondor
make build
```

## Quickstart

**Library** — query a collector:

```go
collector := htcondor.NewCollector("collector.example.com:9618")
ads, _, err := collector.QueryAdsWithOptions(ctx, "ScheddAd", "",
    &htcondor.QueryOptions{Limit: 50})
```

More: [docs/library.md](docs/library.md).

**HTTP server** — start a demo (no HTCondor required):

```bash
./htcondor-api -demo
```

The SPA, admin UI, and chat assistant are served at
`https://localhost:8080`. The first-time `admin` credentials are
printed to stdout.

More: [docs/server.md](docs/server.md).

## Documentation

- [docs/library.md](docs/library.md) — using the Go library
- [docs/server.md](docs/server.md) — running the HTTP API + MCP server
- [httpserver/README.md](httpserver/README.md) — full HTTP API reference
- [mcpserver/README.md](mcpserver/README.md) — MCP tool catalog
- [SECURITY_CONFIG.md](SECURITY_CONFIG.md) — operator security guide
- [design_notes/](design_notes/) — design rationale for major features

## Contributing

Patches welcome — see [CONTRIBUTING.md](CONTRIBUTING.md) for the
local-development setup, pre-commit hooks, and CI expectations.

### Building and testing locally

```bash
go build ./...
go test ./...
golangci-lint run
```

Integration tests need HTCondor installed; they run automatically in
Docker via:

```bash
make docker-test-integration
```

The Docker dev environment (Rocky Linux 9, HTCondor pre-installed)
works on Linux and Apple Silicon Macs. Open this repo in
**GitHub Codespaces** for an instant cloud-based environment with
HTCondor pre-installed.

## License

Apache License 2.0. See [LICENSE](LICENSE).
