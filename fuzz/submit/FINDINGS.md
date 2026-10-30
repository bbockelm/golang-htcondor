# Findings: Go submit parser vs C++ `SubmitHash`

Everything here was produced by the differential harness in this package
against `libcondor_utils 26.2.0`. Each entry is encoded in `differ.go`
(`knownDivergent`) or in a seed's `reason`, so the test suite fails if one
stops reproducing — a fix flips the case red and gets promoted to parity.

None of these are regressions introduced by the harness; they are the drift it
found on its first run.

## Behavior-changing

These change what the job does, not just what the ad looks like.

**`ShouldTransferFiles` default.** C++ defaults to `"IF_NEEDED"`, Go to
`"YES"`. On a pool where the submit and execute nodes share a filesystem, the
C++ default skips the transfer and the Go default forces it.

**`Requirements` is a different expression.** For the same file:

```
cpp: (TARGET.Arch == "<submit arch>") && (TARGET.OpSys == "<submit opsys>")
     && (TARGET.Disk >= DiskUsage) && (TARGET.Memory >= RequestMemory)
     && ((TARGET.FileSystemDomain == MY.FileSystemDomain) || (TARGET.HasFileTransfer))
go:  ((TARGET.Arch isnt undefined) && (TARGET.OpSys isnt undefined))
     && (TARGET.Memory >= RequestMemory) && (TARGET.Cpus >= RequestCpus)
```

Go does not pin Arch/OpSys to the submitting machine, drops the Disk and
filesystem-domain clauses, and adds a Cpus clause C++ does not have. A job
submitted through Go can match machines `condor_submit` would have excluded,
and vice versa.

**`RequestCpus` / `RequestMemory` synthesis.** When the submit file does not
set them, Go writes `RequestCpus = 1` and `RequestMemory = 128`; C++ writes
neither and lets the negotiator apply the pool's defaults. A pool whose default
request differs from 1/128 silently gets the wrong one.

**`Args` vs `Arguments`.** For empty arguments C++ emits `Arguments` (V2
syntax), Go emits `Args` (V1). The two attributes are parsed differently by the
starter — V1 splits on whitespace, V2 honors quoting — so the attribute *name*
is semantic, not cosmetic.

**`Cmd` is relative.** C++ resolves the executable against `Iwd` into an
absolute path; Go stores it as written. A job whose `executable` is relative
therefore records a path that only resolves from the submit directory. The
fuzzer found this one unprompted, within seconds, from a mutated seed
(`eXeCutABle=0queue`).

**`UserLog` is relative.** C++ resolves `log = j.log` against `Iwd` into an
absolute path; Go stores `"j.log"` as written. Whoever opens the log later
resolves it against their own working directory.

**`queue 2 in (a b)` produces the wrong number of jobs.** C++ makes 4 procs
(2 per item over 2 items); Go makes 2.

**`request_<resource>` is generic, and Go only knows three.** `request_foo = N`
becomes `RequestFoo` in C++ — that is how custom resources (GPUs, licenses,
site-defined slots) are requested. Go understands `cpus`, `memory` and `disk`
and silently drops everything else, so a job asking for a custom resource is
submitted without the request. Also found by the fuzzer, from
`request_A0 = queue`.

## Late materialization is not implemented, and its keywords are dropped

`max_materialize`, `max_idle` and `materialize_max_idle` make `condor_submit`
submit a **job factory**: it sends the cluster ad, a submit digest and the
itemdata rows, and the schedd materializes procs itself, keeping at most
`max_idle` of them idle at a time. None of this needs a schedd to check —
`want_factory_submit()` and `make_digest()` are `SubmitHash` methods.

Measured, for `max_materialize = 2 / queue 5`:

```
cpp: factory=true  max_materialize=2  + a digest for the schedd to expand
go:  5 fully materialized proc ads
```

All three spellings behave the same. `SubmitFile.SubmitLate` is named for the
feature but does not implement it: it builds the same per-proc ads `Submit`
does, with `ProcAds[0]` relabelled as the cluster ad.

Worse than the missing feature: **Go drops `JobMaterializeMaxIdle`.** Both
`max_idle` and `materialize_max_idle` set it in C++ and neither does in Go, so
even a schedd willing to materialize lazily would be told nothing and a
submission that asked to be throttled is silently submitted unthrottled. That
part is a small fix independent of implementing factories.

`max_materialize` is different and is **not** a divergence: it never becomes an
ad attribute on either side. `want_factory_submit` reads it and `condor_submit`
passes it to `set_Factory()` as a protocol argument, so there is nothing on the
ad to compare. The test asserts the oracle really does set an attribute before
checking Go for it, so a case like this cannot be mistaken for a Go bug again.

The digest keeps macro references unexpanded (`arguments=$(item)`), which is
what lets the schedd vary them per proc; a test asserts that, because a digest
with the values baked in would materialize every proc identically.

## Parse-acceptance divergence

Reported by `TestSeedParseAcceptance`, which logs rather than fails — these are
real, but failing on them would bury the semantic findings above.

- `queue name in (alice bob)` — C++ accepts a space-separated inline item list;
  Go's parser requires commas and rejects the file.
- `queue name from ( ... )` — C++ accepts an inline `from (...)` list; Go
  rejects the open paren.

## The oracle was under-reporting until it called config()

`condor_submit` calls `config()` before it builds a `SubmitHash`, and parts of
the submit code reach `param()` as a result. The shim did not, so those lookups
ran against an uninitialized config. Two consequences, both fixed:

- A submit file as short as `container_image = docker://busybox` + `queue`
  **segfaulted** inside `make_job_ad`, taking the whole fuzz process down. Real
  `condor_submit` parses the same file fine. This looked like a crash in
  `libcondor_utils` and was reported as one twice; it was the oracle's
  environment differing from the tool's.
- The oracle emitted **fewer** attributes than `condor_submit` does, so real
  divergences were invisible. Initializing config surfaced exactly one:
  `JobLeaseDuration`, which C++ sets to 2400 and Go omits (confirmed against
  `condor_submit -dry-run`, not just the oracle).

`CONDOR_CONFIG` is forced to an empty file so `param()` answers from built-in
defaults only — the oracle has to give the same answer on a laptop with a
populated `/etc/condor` as on a CI runner with none.

## Attributes C++ sets and Go does not

Mostly per-job bookkeeping the schedd would otherwise fill in
(`CommittedTime`, `Cumulative*`, `Num*`, `*SuspensionTime`, `RemoteSysCpu`,
`ExitStatus`, `ExitBySignal`, `CurrentHosts`, `LastSuspensionTime`,
`TotalSuspensions`), but several are not:

- `MyType = "Job"` and `TargetType = "Machine"` — absent from Go's ads.
- `MaxHosts` / `MinHosts` — C++ defaults both to 1.
- `JobPrio`, `JobNotification`, `LeaveJobInQueue` — C++ defaults them.
- `Environment` — C++ always emits it (empty when unspecified); Go omits it
  when the submit file is silent.

## Attributes Go sets and C++ does not

`TransferExecutable`, `EmailAttributes`, `JobRunCount`, and a `RequestDisk`
that C++ places on the cluster ad as a `MAX(...)` expression instead.

## Cosmetic

`Rank`: C++ emits the real `0.0`, Go the integer `0`. Same value, different
ClassAd type — listed because a type difference can still change an expression
that consumes it.
