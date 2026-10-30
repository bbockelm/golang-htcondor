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

**`Cmd` and `UserLog` were relative.** FIXED. C++ resolved the executable and
the log into absolute paths and Go stored them as written, so a job whose
`executable` or `log` was relative recorded a path that only resolved from the
submit directory. The fuzzer found the `Cmd` half unprompted, within seconds,
from a mutated seed (`eXeCutABle=0queue`). `cmd`, `userlog` and `iwd` are
compared now; the rule they follow is written up in `submit.go` alongside
`fullPath`.

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

## Line assembly

**Whitespace before a line-continuation backslash.** `getline_implementation`
trims the physical line with `isspace()` *and then* looks for the trailing
backslash, so whitespace sitting before the backslash is kept, and the
continuation is joined on with nothing between — the next line's leading
whitespace having been trimmed in turn. For

```
+Note = "a   \
   b"
```

C++ produces `"a   b"`; Go trims the run to nothing and inserts one space,
producing `"a b"`. Files with exactly one space before the backslash agree by
coincidence, which is why this hid for so long.

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

## java universe replaces Cmd with the JVM

For `universe = java`, C++ puts the JVM from `param("JAVA")` in `Cmd` and passes
the submitted class through `Args`; Go leaves the resolved executable in `Cmd`,
so the job would try to run the class file itself rather than a JVM.

This is recorded in `knownDivergentInUniverse`, which excuses an attribute only
inside one universe, rather than in `knownDivergent`, which would have excused
`Cmd` everywhere and undone the path comparison that found it. The universe is
read from the **C++** ad, so a Go bug that drops `JobUniverse` cannot also hand
itself an excuse.

It surfaced only once two changes were both in: comparing `Cmd` at all, and a
generator that emits java submit files.

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

**A submit file written on Windows kept its carriage returns.**
`getline_implementation` trims the whole line with `isspace()` before it is
split into name and value, so the `\r` of a CRLF ending never reaches a value.
The Go lexer trimmed only `" \t"`, so

```
executable = /bin/sleep\r\n
```

gave `Cmd = "/bin/sleep\r"` — a path that cannot be executed — and `log = j.log`
a `UserLog` nobody can open. The lexer now trims and skips HTCondor's set
(`" \t\r\v\f"`, `\n` excluded because it ends the value) at both ends of a
value. A `\r` away from the end of the line is not trailing whitespace and is
still kept, on both sides.

**A macro name starting with a digit silently truncated the file.**
`is_valid_param_name()` accepts any run of `condor_isidchar()`
(`[A-Za-z0-9_./]`) and says nothing about the first character, so `0 = x`,
`0abc = x` and `a/b = 1` all name macros and `condor_submit` accepts them. The
Go lexer read `0` as a number and `/` as illegal, the grammar rejected the
line, and — because it has no error production and a default reduction had
already stored the statements read so far — `config.Parse` returned the
*truncated* file with a nil error. A user who wrote one line the lexer disliked
lost that line and every submit command after it, without being told.

Two changes. The lexer now scans the first token of a statement as HTCondor
scans a name: the run of name characters before the first whitespace or
operator. And `ParseSubmitFile` uses `config.ParseStrict`, so a line that is
genuinely bad fails the file the way HTCondor's does, instead of being returned
as a short one. An illegal name such as `a-b = 1` is rejected by both sides.

The same charset governs a job **attribute** name, which `+Attr` and `MY.Attr`
both reach — `Parse_macros` builds `"MY." + name` from the same scan, without
running `is_valid_param_name` on it. `+0 = 7`, `+0.5 = 7` and `MY.0 = 7` all
set attributes in C++; Go rejected the first two (a separate site: the lexer
required a Go identifier after the `+`) and, before the statement-start fix,
dropped the third. The token after a `+` is now read with the same scan.

What remains, recorded as seed reasons: `+a-b = 7` makes an attribute `a-b` in
C++, since that form skips validation, where Go rejects the file; and submit's
`-Attr` form has no `-` token in the Go lexer at all, so `-Foo = 7` is rejected
where C++ accepts it.

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
universe; C++ honours them only for a container or docker job. `container_image`
and `WantSIF` join them, below.

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

## The container image

`container_image` was out of the generator's vocabulary until the shim called
`config()`; see the section above. It is in now, which takes coverage to 255 of
258 — what is left is `getenv`, its alternate spelling and the `f_error`
`request_gpu_memory`, none of which can be compared.

It diverged immediately, three ways:

- **`ContainerImage` is a basename in C++, a path in Go.** Once C++ decides to
  transfer the image it rewrites the attribute to `condor_basename` of the
  path, because that is what the file transfer will leave in the sandbox, and
  it only does any of this for a container job. Go stores the path as written,
  in any universe. The starter is told to run a path the sandbox does not have.
- **`ContainerImageFullPath` is C++-only.** It is where C++ keeps the
  submit-side path when it rewrites `ContainerImage`, and it is what late
  materialization reads to build each proc's input transfer list. Go sets
  nothing, so a transferred image carries no record of where it came from.
- **`WantSIF` is set whatever the universe.** C++ sets exactly one of `WantSIF`,
  `WantDockerImage` and `WantSandboxImage`, chosen from the image type, and only
  inside the container-universe block.

The decision tree C++ walks before any of that — `transfer_container = false`,
a `CONTAINER_SHARED_FS` prefix, a `docker://` or `oras://` URL, each setting
`ContainerImageSource` and returning without transferring — has no Go
counterpart either; `ContainerImageSource` was already recorded.
