# CI tool module

An isolated Go module whose only purpose is to pin the version of an
external binary that CI builds and runs.

It is separate from every other module in this repo on purpose. The
integration test in `webapi/httpserver` runs against a real `htcondordb`
daemon, which means CI has to get one — but `webapi` must not *depend* on
htcondordb: that would put htcondordb's whole tree into the module graph
of anything importing `webapi`, and would let minimum-version selection
drag `golang-htcondor` itself forward to whatever version htcondordb
happens to pin.

Keeping the requirement here gives the version a home Dependabot
understands (the `gomod` ecosystem scans every `go.mod` listed in
`.github/dependabot.yml`), so a new htcondordb release arrives as an
ordinary bump PR and the integration test starts exercising it — rather
than the pin quietly ageing in a shell script nothing watches.

Nothing imports this module. `go build` here produces the binary; the
test finds it via `$HTCONDORDB_BINARY` and skips when it is absent.
