# golang-htcondor

A Go client library for HTCondor that provides functionality similar to the HTCondor Python bindings.

## Overview

This library provides a Go interface to HTCondor services, allowing you to:
- Query the collector for daemon advertisements
- Advertise to the collector
- Locate HTCondor daemons
- Query the schedd for job information
- Submit and manage jobs
- Transfer files using HTCondor's file transfer protocol
- Rate limiting for query protection (configurable via HTCondor config)
- **Query optimization with defaults, limits, and pagination** (see [QUERY_OPTIMIZATION.md](design_notes/QUERY_OPTIMIZATION.md))

## Dependencies

This project uses:
- [github.com/bbockelm/cedar](https://github.com/bbockelm/cedar) - Cedar protocol bindings
- [github.com/PelicanPlatform/classad](https://github.com/PelicanPlatform/classad) - ClassAd language implementation

**Note:** Dependencies are currently under development. See [DEPENDENCIES.md](DEPENDENCIES.md) for setup instructions.

## Installation

```bash
go get github.com/bbockelm/golang-htcondor
```

## Usage

### Collector

```go
import (
    "context"
    "log"
    "time"

    "github.com/bbockelm/golang-htcondor"
)

// Create a collector instance
collector := htcondor.NewCollector("collector.example.com:9618")

// Create a context with timeout
ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
defer cancel()

// Query for schedd ads
ads, err := collector.QueryAds(ctx, "ScheddAd", "")
if err != nil {
    log.Fatal(err)
}

// Ping collector for health check and authentication info
pingResult, err := collector.Ping(ctx)
if err != nil {
    log.Fatal(err)
}
fmt.Printf("Collector ping: auth=%s, user=%s, encryption=%v\n",
    pingResult.AuthMethod, pingResult.User, pingResult.Encryption)

// Locate a daemon
location, err := collector.LocateDaemon(ctx, "Schedd", "schedd_name")
if err != nil {
    log.Fatal(err)
}
```

### Schedd

```go
import (
    "context"
    "fmt"
    "log"
    "time"

    "github.com/bbockelm/golang-htcondor"
)

// Create a schedd instance
schedd := htcondor.NewSchedd("schedd_name", "schedd.example.com:9618")

// Create a context with timeout
ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
defer cancel()

// Ping schedd for health check and authentication info
pingResult, err := schedd.Ping(ctx)
if err != nil {
    log.Fatal(err)
}
fmt.Printf("Schedd ping: auth=%s, user=%s\n", pingResult.AuthMethod, pingResult.User)

// Submit a job using submit file content
submitFile := `
universe = vanilla
executable = /bin/sleep
arguments = 10
output = test.out
error = test.err
log = test.log
queue
`

clusterID, err := schedd.Submit(ctx, submitFile)
if err != nil {
    log.Fatal(err)
}
fmt.Printf("Submitted job cluster %s\n", clusterID)

// Query jobs with new QueryWithOptions API (recommended)
opts := &htcondor.QueryOptions{
    Limit: 50,  // limit to 50 results
    Projection: []string{"ClusterId", "ProcId", "JobStatus"},
}
jobs, pageInfo, err := schedd.QueryWithOptions(ctx, "Owner == \"user\"", opts)
if err != nil {
    log.Fatal(err)
}
fmt.Printf("Found %d jobs\n", pageInfo.TotalReturned)

// Query jobs with old API (still supported, no limits applied)
jobs, err := schedd.Query(ctx, "Owner == \"user\"", []string{"ClusterId", "ProcId", "JobStatus"})
if err != nil {
    log.Fatal(err)
}
```

See [QUERY_OPTIMIZATION.md](design_notes/QUERY_OPTIMIZATION.md) for more details on query limits, default projections, and pagination.

The `Submit` method supports all HTCondor submit file features:
- Simple `queue` statements
- Multiple procs: `queue 5`
- Queue with variables: `queue name from (Alice Bob Charlie)`
- Full submit file syntax with macros and expressions

### HTTP API Server

The library includes an HTTP API server for RESTful access to HTCondor:

```bash
# Start the API server with demo mode (includes mini HTCondor)
cd cmd/htcondor-api
go build
./htcondor-api --demo

# Or use with existing HTCondor (auto-discovers schedd)
./htcondor-api

# Specify collector and let it discover the schedd
./htcondor-api -collector collector.example.com:9618

# Specify a specific schedd
./htcondor-api -schedd myschedd -collector collector.example.com:9618

# Or specify schedd address directly
./htcondor-api -schedd-addr "<192.168.1.100:9618?addrs=192.168.1.100-9618>"
```

**CLI Options:**
- `-listen` - Address to listen on (default: `:8080`)
- `-collector` - Collector host:port (overrides `COLLECTOR_HOST` from config)
- `-schedd` - Schedd name (overrides `SCHEDD_NAME` from config)
- `-schedd-addr` - Schedd address (if specified, schedd name is ignored)
- `-demo` - Run in demo mode with mini HTCondor
- `-user-header` - HTTP header to read username from (demo mode only)

The server works out-of-the-box with minimal configuration:
- **Auto-discovery**: If schedd is not specified, it searches for a local schedd address file or queries the collector
- **Fallback logging**: If configured log paths are inaccessible, falls back to stdout
- **Minimal config**: Can start with an empty HTCondor config or no directories configured
- **TILDE handling**: If `TILDE` is empty, `LOCAL_DIR` defaults to `/usr`

**API Endpoints:**
- `POST /api/v1/jobs` - Submit jobs
- `GET /api/v1/jobs` - List jobs (with constraint and projection)
- `GET /api/v1/jobs/{id}` - Get job details
- `PUT /api/v1/jobs/{id}/input` - Upload input files (tarball)
- `GET /api/v1/jobs/{id}/output` - Download output files (tarball)
- `GET /api/v1/ping` - Ping both collector and schedd for health check
- `GET /api/v1/schedd/ping` - Ping schedd only
- `GET /api/v1/collector/ping` - Ping collector only
- `GET /metrics` - Prometheus metrics endpoint
- `GET /openapi.json` - OpenAPI 3.0 specification

**Example Usage:**
```bash
# Submit a job
curl -X POST http://localhost:8080/api/v1/jobs \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"submit_file": "executable=/bin/echo\narguments=Hello\nqueue"}'

# List jobs
curl http://localhost:8080/api/v1/jobs?constraint=Owner==\"user\" \
  -H "Authorization: Bearer $TOKEN"

# Get job details
curl http://localhost:8080/api/v1/jobs/1.0 \
  -H "Authorization: Bearer $TOKEN"

# Ping daemons for health check
curl http://localhost:8080/api/v1/ping

# Get Prometheus metrics
curl http://localhost:8080/metrics
```

**Container Images:**

Pre-built container images are available from GitHub Container Registry:

```bash
# Pull the latest stable release
docker pull ghcr.io/bbockelm/golang-htcondor:latest

# Pull a specific version
docker pull ghcr.io/bbockelm/golang-htcondor:v1.0.0

# Pull the development version (built from main branch)
docker pull ghcr.io/bbockelm/golang-htcondor:devel

# Run the container
docker run -p 8080:8080 ghcr.io/bbockelm/golang-htcondor:latest

# Run with demo mode
docker run -p 8080:8080 ghcr.io/bbockelm/golang-htcondor:latest -demo
```

The container images are multi-architecture (amd64/arm64) and include only the `htcondor-api` binary with minimal dependencies (~15MB total).

See [httpserver/README.md](httpserver/README.md) for full documentation and [HTTP_API_TODO.md](HTTP_API_TODO.md) for implementation status.

### Metrics Collection (metricsd)

The library includes a metrics collection module inspired by `condor_gangliad` for exporting metrics to Prometheus:

```go
import (
    "github.com/bbockelm/golang-htcondor/metricsd"
)

// Create metrics registry
registry := metricsd.NewRegistry()

// Register collectors
poolCollector := metricsd.NewPoolCollector(collector)
registry.Register(poolCollector)

// Export to Prometheus format
exporter := metricsd.NewPrometheusExporter(registry)
metricsText, err := exporter.Export(ctx)
```

**Built-in Metrics:**
- Pool-wide statistics (machines, CPUs, memory, jobs)
- Process-level metrics (memory, goroutines)
- Machine state distribution
- Resource utilization

The HTTP API server automatically exposes metrics at `/metrics` when a collector is configured. See [metricsd/README.md](metricsd/README.md) for details.

## Rate Limiting

The library includes built-in rate limiting for schedd and collector queries to protect daemons from being overwhelmed. Rate limits are configured via HTCondor configuration parameters:

```
# Schedd query rate limits
SCHEDD_QUERY_RATE_LIMIT = 10              # 10 queries/sec globally
SCHEDD_QUERY_PER_USER_RATE_LIMIT = 5     # 5 queries/sec per user

# Collector query rate limits
COLLECTOR_QUERY_RATE_LIMIT = 20           # 20 queries/sec globally
COLLECTOR_QUERY_PER_USER_RATE_LIMIT = 10 # 10 queries/sec per user
```

Features:
- **Global rate limits**: Protect overall system capacity
- **Per-user rate limits**: Prevent individual users from monopolizing resources
- **Automatic user detection**: Extracts username from authentication or uses "unauthenticated"
- **Token bucket algorithm**: Allows short bursts while maintaining average rate
- **Zero-config**: Defaults to unlimited if not configured

See [RATE_LIMITING.md](design_notes/RATE_LIMITING.md) for complete documentation.

## Development

### Building

```bash
go build ./...
```

### Testing

```bash
# Run unit tests
go test ./...

# Run with race detector
go test -race ./...

# Run integration tests (requires HTCondor installed)
go test -tags=integration -v ./httpserver/

# Or use make
make test
make test-integration
```

The integration test verifies the complete HTTP API workflow:
1. Starts a mini HTCondor instance
2. Launches the HTTP API server
3. Submits a job via HTTP
4. Uploads input files as tarball
5. Polls job status until completion
6. Downloads output tarball
7. Verifies results

See [httpserver/INTEGRATION_TEST.md](httpserver/INTEGRATION_TEST.md) for details.

## API Reference

This library aims to provide an API similar to the [HTCondor Python bindings](https://htcondor.readthedocs.io/en/latest/apis/python-bindings/):
- [Collector API](https://htcondor.readthedocs.io/en/latest/apis/python-bindings/api/version2/htcondor2/collector.html)
- [Schedd API](https://htcondor.readthedocs.io/en/latest/apis/python-bindings/api/version2/htcondor2/schedd.html)

## Status

This project is under active development.

### Current Status
- ✅ Project structure and API design complete
- ✅ Collector interface defined
- ✅ Schedd interface defined
- ✅ Collector QueryAds implementation complete
- ✅ Cedar protocol integration for queries
- ✅ ClassAd integration
- ✅ HTCondor configuration file parser
- ✅ Submit file parser with full queue statement support
- ✅ Job ad generation from submit files
- ✅ QMGMT (Queue Management) protocol implementation
- ✅ Job submission via Schedd.Submit() with submit file strings
- ✅ Remote job submission with file spooling (Schedd.SubmitRemote)
- ✅ HTTP API server with RESTful job management
- ⏳ Collector Advertise method (pending)
- ⏳ Collector LocateDaemon method (pending)
- ⏳ Schedd Query implementation (pending)
- ⏳ Schedd Act/Edit methods (pending)
- 🚧 File transfer protocol (proof-of-concept complete, see below)
- 🚧 HTTP API token authentication integration (partial, see HTTP_API_TODO.md)

### File Transfer Protocol

The library includes support for HTCondor's file transfer protocol (requires cedar v0.0.2+):

- ✅ Protocol design and documentation ([FILE_TRANSFER_DESIGN.md](FILE_TRANSFER_DESIGN.md))
- ✅ Core types and interfaces ([file_transfer.go](file_transfer.go))
- ✅ Client upload/download implementation with streaming file I/O
- ✅ Efficient file streaming (Stream.PutFile/GetFile)
- ✅ Secure transfer key handling (Stream.PutSecret/GetSecret)
- ✅ Unit tests for metadata serialization
- ⏳ Higher-level command API (manually sends command codes as workaround)
- ⏳ Server-side handlers (awaiting command registration API)

See the [file transfer demo](examples/file_transfer_demo/) for a working example that demonstrates the complete protocol flow.

### Working Examples

The library includes several fully working examples:
- `QueryAds` - Query HTCondor collectors for daemon advertisements
- `Submit` - Submit jobs to HTCondor using submit file syntax
- File transfer protocol demonstration

See:
- `query_demo.go` - Original low-level example using cedar directly
- `query_demo_lib.go` - Example using the golang-htcondor library
- `examples/basic/main.go` - Simple example with real queries
- `examples/submit_demo/` - Job submission demonstration
- `examples/file_transfer_demo/` - File transfer protocol demonstration

Try it:
```bash
# Query the OSG collector for machine ads
go run query_demo.go cm-1.ospool.osg-htc.org 9618

# Or use the library-based demo
go run query_demo_lib.go cm-1.ospool.osg-htc.org 9618

# Or run the basic example
cd examples/basic && go run main.go

# Try the submit demo (requires HTCondor schedd)
cd examples/submit_demo && go run main.go

# Try the file transfer demo (requires HTCondor schedd)
cd examples/file_transfer_demo && go build
./file_transfer_demo localhost 9618 /tmp/testfile.txt
```

See [DEPENDENCIES.md](DEPENDENCIES.md) for information about required dependencies.

## Development

### Docker Development Environment

The project includes a complete Docker environment with HTCondor for testing on any platform, including Mac with Apple Silicon (arm64).

```bash
# Run tests inside Docker (builds image automatically)
make docker-test

# Run integration tests with HTCondor inside Docker
make docker-test-integration

# Start an interactive shell in Docker
make docker-shell

# Build Docker image manually
make docker-build
```

The Docker environment uses Rocky Linux 9 (RHEL-like) because HTCondor is available for arm64 on RHEL-based distributions. This allows development and testing on Mac laptops.

**GitHub Codespaces Support**: Open this repository in Codespaces for an instant cloud-based development environment with HTCondor pre-installed.

See [DOCKER.md](DOCKER.md) for complete Docker setup documentation.

### Local Setup Development Environment

```bash
# Clone the repository
git clone https://github.com/bbockelm/golang-htcondor.git
cd golang-htcondor

# Install pre-commit hooks (recommended)
pip install pre-commit
pre-commit install

# Install golangci-lint
brew install golangci-lint  # macOS
# or see https://golangci-lint.run/usage/install/ for other platforms

# Run tests
go test ./...

# Run linter
golangci-lint run
```

### CI/CD

This project uses GitHub Actions for continuous integration:

**Standard CI** ([`.github/workflows/ci.yml`](.github/workflows/ci.yml)):
- **Tests**: Run on Go 1.25
- **Linting**: golangci-lint with comprehensive checks
- **Build**: Verifies all packages and examples build successfully

**Docker CI** ([`.github/workflows/docker-test.yml`](.github/workflows/docker-test.yml)):
- **Multi-architecture testing**: Tests on both linux/amd64 and linux/arm64
- **Integration tests**: Runs with full HTCondor environment in Docker
- **Environment verification**: Validates Docker setup and tools

The Docker CI ensures the code works correctly in containerized environments including Codespaces.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines on contributing to this project.

## License

This project is licensed under the Apache License 2.0 - see the [LICENSE](LICENSE) file for details.
