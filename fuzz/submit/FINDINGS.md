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

`RequestGpuMemory`: Go turns `request_gpu_memory = 8GB` into
`RequestGpuMemory = 8192`. C++ lists `request_gpu_memory` and
`request_gpus_memory` as disallowed keywords (`f_error` in
`prunable_keywords`), warns that `gpus_minimum_memory` was probably meant, and
sets nothing.

## Fixed

**`request_<resource>` is generic, and Go only knew three.** `request_foo = N`
becomes `RequestFoo` in C++ — that is how custom resources (licenses,
site-defined slot types) are requested. Go understood `cpus`, `memory`, `disk`
and `gpus` and silently dropped everything else, so a job asking for a custom
resource was submitted without the request. Found by the fuzzer, from
`request_A0 = queue`. Go now runs the same generic pass: `Request` plus the tag
exactly as written, value stored as an expression. The `request`
`knownDivergentPrefix` entry that excused it is gone, so these attributes are
compared from here on.

## Cosmetic

`Rank`: C++ emits the real `0.0`, Go the integer `0`. Same value, different
ClassAd type — listed because a type difference can still change an expression
that consumes it.

# Findings from the generated corpus

Everything below came from `FuzzSubmitGenerated` and its fixed sweep, which
build submit files from HTCondor's own keyword table instead of mutating text.
Coverage went from 17 of 258 submit keywords to 253, and the comparison then
reached 167 attributes it had never seen.

Each one is recorded in `knownDivergentGenerated` in `differ.go`, so a fix
turns the sweep red and gets promoted the same way as everything above.

## Go writes the submit keyword's name as the attribute name

This is the largest class and the most misleading, because the ad looks
populated and nothing reads it. A job submitted through the Go parser carries
the setting under a name HTCondor does not use:

| submit command | HTCondor attribute | Go attribute |
|---|---|---|
| `vm_memory` | `JobVMMemory` | `VM_Memory` |
| `vm_type` | `JobVMType` | `VM_Type` |
| `vm_vcpus` | `JobVM_VCPUs` | `VM_VCPUs` |
| `vm_networking` | `JobVMNetworking` | `VM_Networking` |
| `vm_networking_type` | `JobVMNetworkingType` | `VM_NetworkingType` |
| `vm_checkpoint` | `JobVMCheckpoint` | `VM_Checkpoint` |
| `vm_macaddr` | `JobVM_MACADDR` | `VM_MACAddr` |
| `vm_disk` | `VMPARAM_vm_disk` | `VM_Disk` |
| `xen_kernel` | `VMPARAM_Xen_Kernel` | `Xen_Kernel` |
| `xen_root`, `xen_initrd`, `xen_kernel_params` | `VMPARAM_*` | keyword name |
| `cron_window` | `DeferralWindow` | `CronWindow` |
| `cron_prep_time` | `DeferralPrepTime` | `CronPrepTime` |
| `max_retries` | `JobMaxRetries` | `MaxRetries` |
| `retry_until` | folded into `OnExitRemove` | `RetryUntil` |
| `machine_count` | `MinHosts` / `MaxHosts` | `MachineCount` |
| `remote_initialdir` | `RemoteIwd` | `RemoteInitialDir` |
| `accounting_group_user` | `AcctGroupUser` | `AccountingGroupUser` |
| `checkpoint_exit_code` | `SuccessCheckpointExitCode` | `CheckpointExitCode` |
| `concurrency_limits_expr` | `ConcurrencyLimits` | `ConcurrencyLimitsExpr` |
| container/docker job | `WantContainer` + `WantDockerImage` | `WantDocker` |

A cron job submitted through Go therefore never defers, a parallel job asks
for one machine, a `max_retries` job never retries, and a VM job runs with
default memory and CPUs.

## Values that differ where both sides set the attribute

- **`AccountingGroup` loses the user.** C++ appends the submitting user
  (`Proj-1` becomes `Proj-1.<user>`); Go stores the group as written, so the
  accountant charges a different entity.
- **`OnExitRemove` is not rewritten.** With `max_retries` or `retry_until`
  set, C++ *replaces* `OnExitRemove` with the retry expression it builds. Go
  keeps the user's expression, and the job does not retry.
- **`KillSig` becomes a number.** C++ keeps the name (`"SIGTERM"`); Go
  converts it to `15`. Same for `remove_kill_sig`.
- **`JobLeaseDuration` floor.** C++ raises a short lease to its 20-second
  minimum; Go stores whatever was written.
- **Quote stripping.** `file_remaps`, `on_exit_hold_reason` and
  `periodic_hold_reason` are `f_strip_quotes` keywords: C++ removes the
  surrounding quotes, Go keeps them inside the stored string.
- **List canonicalization, in both directions.** `concurrency_limits` and
  `ec2_tag_names` are `f_as_list`, so C++ canonicalizes the separators and Go
  does not; `encrypt_input_files` and its three siblings are `f_as_string`, so
  C++ stores them verbatim and Go canonicalizes. The negotiator and the file
  transfer both match these literally.
- **A filename containing a space** survives in `TransferInput` on the C++
  side and is split away by Go, so the file is never transferred.
- **`mount_under_scratch`** stays a string in C++; Go coerces it to a boolean.
- **`want_graceful_removal = undefined`** stays undefined in C++; Go coerces
  it to `false`.
- **`stream_input` / `stream_output` / `stream_error`** produce opposite
  `TransferIn`/`TransferOut`/`TransferErr` booleans, so one side streams the
  stream and the other transfers it.
- **Iwd resolution, again.** The known `Cmd`/`UserLog` finding generalizes to
  every path-valued keyword the Go parser does implement:
  `azure_auth_file`, `gce_auth_file`, `gce_json_file`, `ec2_user_data_file`,
  `ec2_key_pair_file` and the access-key files. C++ resolves them against
  `Iwd`; Go stores them as written.
- **`Env` vs `Environment`.** The Args/Arguments naming split has a twin: for
  V1-shaped environments Go emits `Env`, C++ emits `Environment`.

## Keywords the Go parser ignores outside their universe

`docker_image` and `container_service_names` are set by Go whatever the
universe; C++ honours them only for a container or docker job.

## Keywords with no Go implementation at all

About 120 attributes are set by C++ and by nothing in Go. The full list is in
`knownDivergentGenerated`; the families are the EC2/GCE/Azure grid settings,
the tool-daemon (TDP) settings, the buffer settings, the Java settings, the
noop-job settings, the parallel-script settings, the submit-event notes, the
cron/deferral attributes, `kill_sig` and its siblings, `core_size`,
`stack_size`, `keep_claim_idle`, `max_job_retirement_time`,
`next_job_start_delay`, `allowed_execute_duration`, `allowed_job_duration`,
`manifest`, `output_destination`, `output_directory`, `scitokens_file`,
`project_name`, `primary_unix_group`, `jobset`, `dag_node_name` and the
DAGMan bookkeeping, `on_exit_hold`, `on_exit_remove`, `periodic_vacate` and
the `*_subcode` reasons.

## A crash in the oracle, not in either parser

`container_image = <anything>` segfaults the in-process oracle. It is not a
divergence and not reachable from `condor_submit`:
`process_container_input_files` iterates
`StringTokenIterator(param("CONTAINER_SHARED_FS"), ",")`, the shim loads no
config so `param()` returns null, and `StringTokenIterator::end()` calls
`strlen(nullptr)`. A real `condor_submit` always has that param's `/cvmfs`
default. The keyword is excluded from the generator's vocabulary with that
reason; the container universe is still generated, using `docker_image`.
