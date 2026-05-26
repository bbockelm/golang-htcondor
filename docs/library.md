# Go library reference

The `github.com/bbockelm/golang-htcondor` module is a Go client for
HTCondor pools. The API roughly mirrors the
[HTCondor Python bindings](https://htcondor.readthedocs.io/en/latest/apis/python-bindings/) —
collector queries, schedd queries / submission / management, sandbox
handling, file transfer, and a metrics collector — exposed through
idiomatic Go types and `context.Context` cancellation.

This document covers using the library as a Go module. For the
HTTP / MCP server built on top of it, see [server.md](server.md).

## Install

```bash
go get github.com/bbockelm/golang-htcondor
```

## Collector

`*htcondor.Collector` talks to a collector daemon: query advertised
classads, advertise your own, locate other daemons, and ping for
health and authentication info.

```go
import (
    "context"
    "fmt"
    "log"
    "time"

    "github.com/bbockelm/golang-htcondor"
)

collector := htcondor.NewCollector("collector.example.com:9618")

ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
defer cancel()

// Query advertisements with pagination / projection.
ads, page, err := collector.QueryAdsWithOptions(ctx, "ScheddAd", "",
    &htcondor.QueryOptions{
        Limit:      50,
        Projection: []string{"Name", "Machine", "Cpus", "Memory"},
    })
if err != nil {
    log.Fatal(err)
}
fmt.Printf("matched %d schedds\n", page.TotalReturned)

// Health-check + authentication probe.
ping, err := collector.Ping(ctx)
if err != nil {
    log.Fatal(err)
}
fmt.Printf("auth=%s user=%s encrypted=%v\n",
    ping.AuthMethod, ping.User, ping.Encryption)

// Locate a specific daemon by type + name.
where, err := collector.LocateDaemon(ctx, "Schedd", "myschedd")
if err != nil {
    log.Fatal(err)
}
fmt.Printf("schedd at %s\n", where.Address)
```

For background on the limit/projection defaults and pagination
semantics, see
[design_notes/QUERY_OPTIMIZATION.md](../design_notes/QUERY_OPTIMIZATION.md).

## Schedd

`*htcondor.Schedd` submits, queries, and acts on jobs in a single
schedd. The submit-file string is parsed locally and converted to job
classads before being handed to QMGMT — so the same submit file you'd
hand to `condor_submit` works here too.

```go
schedd := htcondor.NewSchedd("myschedd", "schedd.example.com:9618")

ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
defer cancel()

// Submit a job. The submit-file syntax is the same as condor_submit's:
// macros, expressions, queue counts, queue from (...), etc.
submitFile := `
universe   = vanilla
executable = /bin/sleep
arguments  = 10
output     = test.out
error      = test.err
log        = test.log
queue
`
clusterID, err := schedd.Submit(ctx, submitFile)
if err != nil {
    log.Fatal(err)
}
fmt.Printf("submitted cluster %s\n", clusterID)

// Query jobs with options (recommended).
opts := &htcondor.QueryOptions{
    Limit:      50,
    Projection: []string{"ClusterId", "ProcId", "JobStatus"},
}
jobs, page, err := schedd.QueryWithOptions(ctx, `Owner == "alice"`, opts)
if err != nil {
    log.Fatal(err)
}
fmt.Printf("found %d jobs\n", page.TotalReturned)
```

The `Submit` method accepts every queue form HTCondor recognizes:
plain `queue`, count form `queue 5`, parameter form
`queue name from (Alice Bob)`, file-and-foreach forms, etc.

`QueryWithOptions` is the preferred entry point; `Query` (the older
form) stays for back-compatibility but applies no limits.

## Sandbox handling

The `sandbox` package creates and extracts job sandboxes at the
filesystem level — useful when you're proxying input/output through
your own service rather than letting HTCondor's transfer machinery
do it directly.

```go
import (
    "bytes"
    "context"

    "github.com/bbockelm/golang-htcondor/sandbox"
)

// Build an input tarball from the files referenced in a job ad.
jobAd := mustFetchJobAd(clusterID)
var inputTar bytes.Buffer
if err := sandbox.CreateInputSandboxTar(ctx, jobAd, &inputTar); err != nil {
    log.Fatal(err)
}

// Extract an output tarball into the right locations (applying
// transfer_output_remaps if present in the ad).
outputTar := mustFetchOutputTar(clusterID)
if err := sandbox.ExtractOutputSandbox(ctx, jobAd, outputTar); err != nil {
    log.Fatal(err)
}
```

Features:

- Input-sandbox creation from `transfer_input_files`.
- Output-sandbox extraction with `transfer_output_remaps` support.
- Wildcard / glob matching for output files.
- Directory structure preserved in tarballs.

Full reference: [sandbox/README.md](../sandbox/README.md) and
[design_notes/SANDBOX_API.md](../design_notes/SANDBOX_API.md).

## File transfer protocol

The library implements HTCondor's file transfer protocol (cedar
v0.0.2+). Client-side upload/download work end-to-end with streaming
I/O; secure transfer-key handling and metadata serialization are
unit-tested.

See the working example at
[examples/file_transfer_demo/](../examples/file_transfer_demo/).

## metricsd: pool/process metrics

The `metricsd` package collects HTCondor pool metrics (inspired by
`condor_gangliad`) and exports them in Prometheus format.

```go
import "github.com/bbockelm/golang-htcondor/metricsd"

registry := metricsd.NewRegistry()
registry.Register(metricsd.NewPoolCollector(collector))

exporter := metricsd.NewPrometheusExporter(registry)
text, err := exporter.Export(ctx)
```

Built-in collectors:

- Pool-wide totals (machines, CPUs, memory, jobs).
- Process-level metrics (Go runtime memory, goroutine count).
- Machine state distribution.
- Resource utilization.

The HTTP server bundled in this repo automatically exposes
`/metrics` when a collector is configured (see
[server.md](server.md)). The standalone library usage above is for
embedding the same collectors in a different binary.

Reference: [metricsd/README.md](../metricsd/README.md).

## Rate limiting

Schedd and collector queries are rate-limited to protect daemons
from accidental overload. Limits are read from HTCondor config at
construction time:

```
SCHEDD_QUERY_RATE_LIMIT          = 10   # global, queries/sec
SCHEDD_QUERY_PER_USER_RATE_LIMIT = 5    # per user, queries/sec

COLLECTOR_QUERY_RATE_LIMIT          = 20
COLLECTOR_QUERY_PER_USER_RATE_LIMIT = 10
```

Properties:

- **Global** limits cap aggregate load on the daemon.
- **Per-user** limits stop one caller from monopolizing the global
  quota. Username comes from the authenticated context; unauthenticated
  callers share a single bucket.
- **Token bucket** algorithm — short bursts permitted, average rate
  enforced.
- Defaults to unlimited when no config is set, so embedding the
  library in a tool that doesn't read HTCondor config still works.

Full reference: [design_notes/RATE_LIMITING.md](../design_notes/RATE_LIMITING.md).

## Examples

Runnable examples under [examples/](../examples/):

- `basic/` — minimal `QueryAds` demo against a real collector.
- `submit_demo/` — submit a job through a schedd.
- `queue_demo/` — exercise the various `queue` forms.
- `file_transfer_demo/` — end-to-end input + output transfer.
- `param_defaults_demo/` — read HTCondor config from Go.
- `metrics_demo/` — collect and expose Prometheus metrics.

Try one:

```bash
cd examples/basic && go run main.go
```

## API reference

The library aims to mirror the
[HTCondor Python bindings v2](https://htcondor.readthedocs.io/en/latest/apis/python-bindings/):

- [Collector API](https://htcondor.readthedocs.io/en/latest/apis/python-bindings/api/version2/htcondor2/collector.html)
- [Schedd API](https://htcondor.readthedocs.io/en/latest/apis/python-bindings/api/version2/htcondor2/schedd.html)
