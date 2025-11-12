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
import "github.com/bbockelm/golang-htcondor"

// Create a collector instance
collector := htcondor.NewCollector("collector.example.com", 9618)

// Query for schedd ads
ads, err := collector.QueryAds(ctx, "ScheddAd", "")
if err != nil {
    log.Fatal(err)
}

// Locate a daemon
location, err := collector.LocateDaemon(ctx, "Schedd", "schedd_name")
if err != nil {
    log.Fatal(err)
}
```

### Schedd

```go
// Create a schedd instance
schedd := htcondor.NewSchedd("schedd_name", "schedd.example.com", 9618)

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

// Query jobs
jobs, err := schedd.Query(ctx, "Owner == \"user\"", []string{"ClusterId", "ProcId", "JobStatus"})
if err != nil {
    log.Fatal(err)
}
```

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

# Or use with existing HTCondor
./htcondor-api
```

**API Endpoints:**
- `POST /api/v1/jobs` - Submit jobs
- `GET /api/v1/jobs` - List jobs (with constraint and projection)
- `GET /api/v1/jobs/{id}` - Get job details
- `PUT /api/v1/jobs/{id}/input` - Upload input files (tarball)
- `GET /api/v1/jobs/{id}/output` - Download output files (tarball)
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
```

See [httpserver/README.md](httpserver/README.md) for full documentation and [HTTP_API_TODO.md](HTTP_API_TODO.md) for implementation status.

## Development

### Building

```bash
go build ./...
```

### Testing

```bash
go test ./...
```

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

### Setup Development Environment

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
- **Tests**: Run on Go 1.21, 1.22, and 1.23
- **Linting**: golangci-lint with comprehensive checks
- **Build**: Verifies all packages and examples build successfully

See [`.github/workflows/ci.yml`](.github/workflows/ci.yml) for the full CI configuration.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines on contributing to this project.

## License

This project is licensed under the Apache License 2.0 - see the [LICENSE](LICENSE) file for details.
