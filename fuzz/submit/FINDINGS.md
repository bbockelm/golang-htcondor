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

The values differ too, which the `args`/`arguments` entries in
`knownDivergent` currently hide: C++ runs the text through `ArgList` and gets
back a canonical form, so `arguments = a  b` is `"a b"` on the C++ side and
`"a  b"` on the Go side, and trailing whitespace — which only a line
continuation can produce, since the reader trims the line otherwise — is
dropped by C++ and kept by Go. Fixing the naming split will expose this, so it
is written down here rather than discovered twice.

**`Cmd` and `UserLog` were relative.** FIXED. C++ resolved the executable and
the log into absolute paths and Go stored them as written, so a job whose
`executable` or `log` was relative recorded a path that only resolved from the
submit directory. The fuzzer found the `Cmd` half unprompted, within seconds,
from a mutated seed (`eXeCutABle=0queue`). `cmd`, `userlog` and `iwd` are
compared now; the rule they follow is written up in `submit.go` alongside
`fullPath`.

**`queue 2 in (a b)` produces the wrong number of jobs.** C++ makes 4 procs
(2 per item over 2 items); Go makes 2.

## Late materialization

`max_materialize`, `max_idle` and `materialize_max_idle` make `condor_submit`
submit a **job factory**: it sends the cluster ad, a submit digest and the
itemdata rows, and the schedd materializes procs itself, keeping at most
`max_idle` of them idle at a time. None of this needs a schedd to check —
`want_factory_submit()` and `make_digest()` are `SubmitHash` methods, so the
oracle reports the whole client half.

This was a gap and is now implemented. `SubmitFile.SubmitLate` sends a factory
when the file asks for one and materializes procs itself when it does not;
`Schedd.Submit` uses it when the schedd advertises `LateMaterialize`, and
falls back to eager materialization when the schedd refuses or is too old,
which is what `condor_submit` does — those keywords ask for a factory, they do
not insist on one. `TestGoLateMaterializationMatchesCondorSubmit` compares the
decision, the limit, the loop variables, the itemdata rows and the digest
against the oracle for every seed in `factorySeeds`.

`max_materialize` is **not** an ad attribute on either side.
`want_factory_submit` reads it and `condor_submit` passes it to
`set_Factory()` as a protocol argument, so there is nothing on the ad to
compare. The test asserts the oracle really does set an attribute before
checking Go for it, so a case like this cannot be mistaken for a Go bug again.

### What the digest turned up

**The itemdata filename is the one thing a client cannot compute.** The queue
statement at the end of the digest reads the rows back from a file the *schedd*
named in its reply to `SendMaterializeData`, so the digest can only be finished
after the rows have been sent. `oracle.Factory` takes that filename as an
argument to stand in for the schedd; `JobFactory.Digest` takes it for real.

**`queue 5` puts `Item=` in the digest.** `condor_submit` reads the first row
before building the digest, and reading from an empty list defines the macro
`Item` as empty. `Item` is not a prunable keyword, so that empty definition
lands in the digest. Nothing documents it and nothing would suggest it; it came
out of running the oracle.

It is a definition, not a default: a submit file that sets `Item = mine` and
then writes `queue 5` has that value **replaced** by the empty one, so the
digest carries `Item=` and the schedd never sees `mine`. Go kept the file's
value until a seed caught it. Where the key sits also follows from this —
an `Item` the file assigned keeps its sorted position, while one only the
empty definition created lands in the table's unsorted tail, after every key
the file wrote.

**`$(ItemIndex)` is frozen to `0` for every job the factory makes.**
`ItemIndex` and `Row` are two names for one macro in the submit hash, but
`per_proc_keys` protects only `Row`, so `ItemIndex` is expanded while the
digest is built — and no row is live then, so it takes the unlive default,
`0`. A submit file numbering its output with `$(ItemIndex)` therefore gets
`o.0` on every proc under late materialization and the real row number
without it. Go matches it, because a digest that differed would be the worse
bug.

**Keys are written in the macro table's order, which is sorted
case-insensitively — except for the tail.** `Item` above is appended after the
sort, because the hash is sorted when the file has been read and `Item` is
defined after that.

**The inline item list splits on whitespace as well as commas.**
`queue a,b in (1 2, 3 4)` is four rows of one field, not two of two. The `from`
form splits on lines, so `from (1 2\n3 4\n)` is the two-field case.

### What is not covered

The digest expands any macro that is not per-proc, which includes the submit
hash's own *defaults* — `ARCH`, `OPSYS*`, `Day`, `Month`, `JobId`,
`JobListId`, `IsLinux`, `IsWindows`, `Request_CPUs`, `Request_Memory`. Go's
config does not define that family, so a submit file referring to one of them
would produce a different digest. `ItemIndex` was the member of it this work
hit and fixed; the rest are untested in either direction and are a submit-wide
difference rather than a factory one, since the same expansion feeds an
ordinary job ad.

`SubmitRemote` does not use factories. Remote submission spools files per proc
and hands the proc ads back to the caller to do it, and a factory has no proc
ads to hand back.

A queue statement slice (`queue x from [1:10] file`) would belong in the
digest's queue statement. The Go grammar does not accept one, so
`JobFactory` reads the field rather than assuming it is empty, and a grammar
that learns to accept one writes it out instead of silently submitting every
row.

## Parse-acceptance divergence

Reported by `TestSeedParseAcceptance`, which logs rather than fails — these are
real, but failing on them would bury the semantic findings above. No seed
reaches it today.

## `queue matching` has the quoting and the lexing bugs `from` just lost

`queue matching "<glob>"` globs the pattern *with* the quotes in C++, and
`queue matching <glob>` — unquoted — is the spelling that works. Measured
against the oracle, with a directory holding two `.txt` files:

```
queue matching DIR/*.txt     cpp: 2 procs      go: syntax error at the '/'
queue matching "DIR/*.txt"   cpp: 0 matches    go: globs DIR/*.txt
```

So both halves of the `from` finding below apply again to `matching`, which
still goes through the old `MATCHING IDENT | MATCHING STRING` grammar rules.
Fixing it also means handling the `files`/`dirs`/`any` qualifiers, which this
parser does not implement, so it is recorded here rather than folded into the
`from` change.

## The queue line is not macro-expanded

`SubmitHash::parse_q_args` runs `expand_macro()` over the whole queue line
before it parses anything, so a macro can produce the item list itself:

```
L = a b
queue in ($(L))
```

is two procs in C++ and one -- whose item is the literal text `$(L)` -- in Go.
The same goes for `queue from $(F)`, where C++ opens the file `$(F)` names and
Go looks for a file called `$(F)`. Expanding the queue line needs the macro
table at lex time, which this parser does not have at that point, so it is
recorded rather than fixed.

## The oracle was under-reporting until it called config()

`condor_submit` calls `config()` before it builds a `SubmitHash`, and parts of
the submit code reach `param()` as a result. The shim did not, so those lookups
ran against an uninitialized config. Two consequences, both fixed:

- `make_job_ad` dereferenced what `param()` returned, so a submit file as short
  as `container_image = docker://busybox` + `queue` took the whole fuzz process
  down. Real `condor_submit` parses the same file fine. The oracle was missing
  a step the tool performs, and it was twice mistaken for a bug in
  `libcondor_utils` on that evidence.
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

**A quoted item file had its quotes stripped.** `queue from "items.txt"`
opens a file whose name *begins and ends with a double quote* in C++:
`parse_queue_args` assigns the remainder of the line to `items_filename`,
trims it, and hands it to `Open_macro_source`; nothing between ever looks at
quoting. Measured against the oracle, with the files really on disk:

```
queue from DIR/plain.txt          cpp: 2 procs   (the file is found)
queue from "DIR/plain.txt"        cpp: can't open file "DIR/plain.txt"
queue from DIR/"quoted.txt"       cpp: 2 procs   (a file named "quoted.txt")
queue from DIR/has space.txt      cpp: 2 procs
queue from "DIR/has space.txt"    cpp: can't open file "DIR/has space.txt"
```

Single quotes behave identically, and a quote anywhere else in the line is an
ordinary filename character. The last two lines are the ones worth keeping in
mind: **a path containing a space is written without quotes**, and that is the
only spelling that works. This parser used to strip a surrounding quote pair,
which was recorded here as a chosen divergence on the grounds that quoting was
the only way to express such a path. That reasoning was wrong -- the verbatim
rule *is* how such a path is expressed -- so the stripping is gone and the two
parsers agree.

The one thing that depended on the stripping was internal: the pre-pass that
rewrites `queue VARS from ((rows))` into `queue VARS from <tempfile>` quoted
the temp path, because the grammar once accepted only an IDENT or a STRING
there. It writes the path bare now. A temp path containing a space is pinned
by a test of its own, since every temp directory a developer is likely to have
is space-free and nothing else would notice.

**An inline item list had to be parenthesised.** HTCondor anchors the queue
parse on the `in`/`from` keyword and takes the rest of the line as the item
list -- `parse_queue_args` only looks for a `(` to decide whether the list is
bracketed or spans lines, never to decide whether there is one. So
`queue in a b` is two jobs, and `queue 2 in a b` is four. Go's grammar
required the parentheses and failed the file, which for a submit file that
was *not* rejected elsewhere meant the user got an error where
`condor_submit` would have run their jobs. `queue in 0 00` was the fuzzer's
reproducer; `queue name in (alice bob)` and `queue name from ( ... )`, both
listed here as parse-acceptance divergences, had already been fixed by the
split-items change and are parity seeds now.

The tail of an `in`/`from` is read by the lexer now, the way HTCondor reads
it: split on whitespace and commas for `in`, taken whole -- quotes, spaces
and all -- as the item file's name for `from`. Two details the oracle settled:
a leading `files`/`dirs`/`any`/`table` or `[slice]` only counts as a qualifier
when something on the line terminates it, so `queue in files` is the single
item "files" while `queue in files x` is an error; and an item list that is
empty (`queue 2 in ()`) queues the count with every loop variable expanding to
nothing, rather than queueing nothing at all -- Go used to reject that file
outright. The qualifiers themselves are still unimplemented, and a queue line
that uses one is now rejected rather than read as items, because reading
`[1:2]` as an item would silently submit the wrong jobs.

**Whitespace before a line-continuation backslash.** `getline_implementation`
trims the physical line with `isspace()` *and then* looks for the trailing
backslash, so whitespace sitting before the backslash is kept, the
continuation is joined on with nothing between — the next line's leading
whitespace having been trimmed in turn — and whitespace *after* the backslash
still continues the line. For

```
+Note = "a   \
   b"
```

C++ produces `"a   b"`; Go trimmed the run to nothing and inserted one space,
producing `"a b"`, so any value assembled across lines — an `arguments`, a
`requirements`, a `transfer_input_files` list — reached the job with different
text than `condor_submit` would have given it. Files with exactly one space
before the backslash agree by coincidence, which is why this hid for so long,
and why both of the lexer's continuation tests passed throughout.

The inserted space was the same bug seen from the other end, and the fuzzer
found that end too, in

```
eXeCutABle=\
queue
```

where C++ contributes nothing between the two halves and resolves `Cmd` to
`<iwd>/queue`, while Go contributed its separator and produced `<iwd>/ queue`
— a path with a space in it, which cannot exist. One rule covers both: the
join never inserts anything, and what survives around it is decided by the
trim that has already happened on each side.

The lexer now follows that physical-line model: trim the line back to where
it started, then test its last character for the backslash, then join the
next line — itself trimmed of its leading whitespace — straight on.

Two further rules fell out of writing it that way, each with a test. A blank
continuation line ends the value and does not re-trim what came before it, so
`X = v   \` followed by an empty line keeps the three spaces. And the
backslash test looks at the whole logical line assembled so far, not at the
physical line just read — `end_ptr[-1]` in the C++ — so `X = a\\` followed by
an empty line and then `b` continues onto `b` rather than stopping.

**`+a-b = 7`, `-Foo = 7`, and `+A =`.** All three are the same code path in
`Parse_macros`: a submit line whose name begins with `+` or `-` becomes
`insert_macro("MY." + name+1, (*name=='+') ? rhs : "")`, with no
`is_valid_param_name()` anywhere. Three consequences, none of which Go had:

- the attribute name is whatever was scanned before the first whitespace or
  operator, so `+a-b = 7` makes an attribute literally named `a-b` — a name
  the same file may not give a macro. Go rejected the file.
- `-Attr` is **not** the inverse of `+Attr` and removes nothing: it stores an
  empty value, and `SetForcedAttributes` turns an empty value into the literal
  `undefined`. `-Foo = 7` puts `Foo = undefined` on the ad, and a `-Foo` after
  a `+Foo` overrides it. The Go lexer had no `-` token at that position at all
  and rejected the file.
- an empty value means the same thing whichever sigil wrote it, so `+A =`,
  `MY.A =` and `+A = $(nosuch)` all set `A = undefined`. Go left the attribute
  off the ad, which is a different answer for any expression that reads it:
  absent means the attribute is inherited from the cluster ad, `undefined`
  means it is not.

**A non-ASCII parameter name was accepted.** `condor_isidchar()` compares
against `'a'..'z'`, `'A'..'Z'` and `'0'..'9', so `café = 1` fails
`is_valid_param_name()` and HTCondor rejects the file; the Go lexer read the
name with `unicode.IsLetter` and accepted it, defining a macro that nothing
else could refer to. The charset is ASCII here now. A job **attribute** name
is the opposite case and was already right: `+café = 1` is accepted by both,
because the `+` form skips the check.

**The VM and Xen keywords were stored under their own names.** `vm_memory`
wrote `VM_Memory`, `vm_vcpus` wrote `VM_VCPUs`, `vm_disk` wrote `VM_Disk` and
the `xen_*` keywords wrote `Xen_*`. Nothing in HTCondor reads any of those, so
the submit file looked honoured and the vmgahp built the VM from its own
defaults: a job that asked for 8 GB and 4 CPUs got whatever the execute node
defaults to, with no error anywhere to say the request had been dropped. The
attributes are HTCondor's now — `JobVMMemory`, `JobVM_VCPUS`, `JobVMType`,
`JobVMNetworking`, `JobVMNetworkingType`, `JobVMCheckpoint`, `JobVM_MACADDR`,
`JobVMVNCConsole`, `VMPARAM_vm_Disk`, `VMPARAM_No_Output_VM` and
`VMPARAM_Xen_*` — and the `RequestMemory` a VM job inherits from its VM points
at `MY.JobVMMemory` rather than at an attribute that does not exist.

Four things the names alone did not cover, each read off `SetVMParams()` and
confirmed against the oracle:

- **`vm_type` gates the rest.** It is stored lower-cased, and it decides what
  `condor_submit` reads at all: the `xen_*` keywords only for `xen`, `vm_disk`
  only for `xen` or `kvm`. Under any other type those keywords are silently
  dropped, and Go now drops them too. `vm_networking_type` is read only when
  `vm_networking` is on.
- **Three attributes are always present.** `JobVMCheckpoint`,
  `JobVMNetworking` and `JobVMVNCConsole` land in every VM job ad, false when
  the submit file says nothing, and `JobVM_VCPUS` defaults to 1.
- **`vm_memory` and `vm_vcpus` fall back to the request.** The submit macro
  table gives them built-in defaults of `$(Request_Memory)` and
  `$(Request_CPUs)`, so a VM job that only sets `request_memory` gives its VM
  that much memory. The fallback is the macro's *text*, not the evaluated
  request, so `request_cpus = 2*2` leaves the VM with two CPUs.
- **`xen_kernel` is not always a file.** `included` boots the kernel out of
  the disk image and `vmx` asks for hardware virtualization; neither is a
  kernel file, so `xen_initrd` and `xen_root` do not apply to them, and `vmx`
  sets `JobVMHardwareVT`. `xen_kernel_params` loses one layer of quoting.

`vm_vnc` and `vm_no_output_vm`, which Go had no code for at all, are
implemented as part of the same pass.

The generator used to write only a kvm VM, on the reasoning that xen needs a
kernel and a root device of its own. That is about booting a VM; `SubmitHash`
decides textually and stats nothing, so `xen_kernel = included` or `vmx` needs
no companion at all and any other value is simply *taken for* a kernel file,
which only makes `xen_root` required. The vm prelude now picks a type and
emits that type's companions, so the whole `VMPARAM_Xen_*` family is compared
by the oracle-backed sweep rather than by hand-written expectations. The
keyword-coverage count does not move -- it counts a keyword as reached when it
appears in the corpus text, and `xen_kernel` appeared all along, in files
SubmitHash then rejected. What moves is what is compared: over the 600-file
sweep, `VMPARAM_Xen_Kernel`, `_Root`, `_Initrd` and `_Kernel_Params` go from
never reaching an accepted ad to 15 or so each.
`submit_vm_test.go` is the same ground covered without the oracle, for CI.

**The accounting group was charged to the wrong entity.** The accountant
reads `AccountingGroup` as `<group>.<user>`, so a value with no dot in it is
a submitter *alias*, not a group. Go stored `accounting_group = Proj-1`
verbatim, which charged a submitter named `Proj-1` and left the real group's
quota, priority factor and share untouched — the job ran outside the group it
said it belonged to. C++ completes the group with a user and always has:
`accounting_group_user` when the file gives one, otherwise the submitting
account (`SubmitHash::init_base_ad`'s `submit_username`, which is
`condor_submit`'s `my_username()`). Nothing looks for a dot already in the
group, so `accounting_group = Proj.bob` becomes `Proj.bob.<user>`, a nested
group. `accounting_group_user` alone, with no group, charges that user by
name. `AcctGroup` and `AcctGroupUser` are written alongside, and neither
existed in Go's ads.

`nice_user` came with it: it is shorthand for `accounting_group =
$(NICE_USER_ACCOUNTING_GROUP_NAME)` (default `nice-user`) plus a default
`MaxJobRetirementTime` of 0, and a `nice_user` job with a group of its own
keeps its group and ignores the flag. Go set a `NiceUser` attribute HTCondor
does not read and no accounting group at all, so a job asking to be run at
low priority was charged — and scheduled — as an ordinary one.

The submitting account is host-derived, so the Go parser now takes it as a
parse option (`SubmitParseOptions.SubmitUser`) and falls back to the account
running the parse, the way `condor_submit` does. The fuzzer passes
`oracle.SubmitUser`, the same name the shim pins the C++ side to, which is
what makes `AccountingGroup` comparable at all.

**A docker image did not make a container job.** `WantDocker` marks the
docker *universe* and nothing else; `docker_image` on its own is an implicit
**container** job, which C++ marks with `WantContainer` plus the image-kind
flag `WantDockerImage`. Go wrote `WantDocker` for every `docker_image`
whatever the universe, so a `universe = container` job (and a plain vanilla
one naming an image) asked for a docker execute node instead of a container
one — on an Apptainer-only pool, the OSPool and CHTC norm, it matches
nothing and sits idle. Go also wrote the flag for universes that ignore the
keyword entirely; the want-flags are now set only where the container
topping applies (vanilla and local), which is the rule `SetUniverse` follows.

That universe gate was also the recorded `WantSIF` divergence: Go classified
a `container_image` correctly but wrote the flag for a vm, grid or scheduler
job too, where C++ never reads the keyword. `WantSIF`, `WantDockerImage` and
`WantSandboxImage` now agree for every image kind in every universe, so all
three are compared from here on. `ContainerImage` itself still diverges, over
the basename rewrite.

**`machine_count` asked for one machine.** It is not an attribute: HTCondor
turns it into the `MinHosts`/`MaxHosts` pair the dedicated scheduler reads,
and only for a parallel or MPI job. Go wrote `MachineCount`, which nothing
reads, and the pair defaulted to 1 — a parallel job that asked for 16
machines got one. `node_count` is the alternate spelling. Every other
universe gets the default pair of 1, which Go did not write either; MPI is
the one universe with no default, because an MPI job must say how many
machines it wants.

**Three more attributes nothing read.** `remote_initialdir` is `RemoteIwd`
(stored as written — it names a directory on a machine this one knows
nothing about, so it is not resolved against `Iwd`), `checkpoint_exit_code`
is `SuccessCheckpointExitCode`, and both `concurrency_limits` and
`concurrency_limits_expr` are `ConcurrencyLimits`. A job that named a
concurrency limit consumed none of it and was throttled by nothing; the list
form is lower-cased, sorted and comma-joined now, because the negotiator
looks the names up literally and `"A, b"` is not the key `"a,b"`.

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

**A job evicted for using too much memory was never retried with more.** That
is what `retry_request_memory`, `retry_request_memory_max` and
`retry_request_memory_increase` are for, and the Go parser implemented none of
them, so a submit file that asked for automatic retry got a job that went on
hold on its first eviction exactly as if the file had never mentioned it.

The feature is not a policy expression. The job carries a job **transform**, as
text, in `TransformBody_RequestMemory`, and names `RequestMemory` in
`TransformOnEvict` so the schedd runs that transform when the job is vacated.
The transform's own `REQUIREMENTS` line is what keeps it from firing on every
eviction: it runs only for vacate sub-code 102, the one that means the job went
over its memory request. A body nothing names in `TransformOnEvict` is never
run, which is why both halves have to be written.

Four things the keyword names do not show:

- **`retry_request_memory_max` alone is not a maximum.** It is a single retry
  value, and the job ad gets no `MaxRequestMemory` at all — just
  `SET RequestMemory <value>`. `MaxRequestMemory` and `NextRequestMemory`
  appear only when an *increase* is given as well, because they are the two
  halves of `EVALSET RequestMemory MIN({NextRequestMemory, MaxRequestMemory})`.
  `NextRequestMemory` is an expression **over** `RequestMemory`
  (`RequestMemory + 128`), which is what makes each retry larger than the last;
  the ceiling is what stops it.
- **An increase with no ceiling is not an expression.** There is nothing to
  stop it growing, so condor_submit evaluates it once, against the request the
  job starts with, and stores the single number: `request_memory = 100` with
  `retry_request_memory_increase = 128` is `SET RequestMemory 228`, not
  `RequestMemory + 128`.
- **`request_memory = 100, 2048` is the same feature**, a second value on the
  request itself, and it supersedes the `retry_` commands because
  condor_submit never reads them in that case. A list of three or more values
  of either spelling becomes `RetryRequestMemory` plus an index the transform
  walks. Go rejected the comma outright before this, so the file did not parse.
- **The whole family is reachable only when `request_memory` is a size.**
  `request_memory = ifThenElse(...)` or a VM job's `MY.VM_Memory` takes it out
  of play, since the transform has no number to grow from.

The transform body is **text inside a job attribute**, which makes the
spelling of any expression in it load-bearing in a way an expression-valued
attribute's is not. `retry_request_memory = MAX({RequestMemory, MemoryUsage})
* 2` has to reach the schedd as `MAX({ RequestMemory,MemoryUsage }) * 2`, the
way HTCondor's own unparser writes it, where Go's `Expr.String()` writes
`(MAX({RequestMemory, MemoryUsage}) * 2)` — same tree, different text, and the
differ caught it. Both sides also reject what the other rejects: a sequence
that does not increase, an increment that is zero or negative, and an increment
that is an expression naming no `RequestMemory` (`MemoryUsage * 2` would hand
every retry the same value).

Deliberately left: the disk half of the same C++ function — `retry_request_disk`
and the second value of `request_disk = a, b` — and `on_evict_checks`, which is
the other writer of `TransformOnEvict`. Because `on_evict_checks` is still
unimplemented, `transformonevict` stays in `knownDivergentGenerated` and the
sweep cannot compare it; `TestOnEvictMemoryTransformMatchesOracle` compares it
directly on files that use no `on_evict_checks`, so what the retry family
writes there is checked even though the sweep skips the attribute. The
`SUBMIT_REQUEST_MISSING_UNITS` warning, and the warning that
`retry_request_memory_increase` is ignored when the list form is used, are not
reproduced: the Go parser has nowhere to put a warning, and neither changes the
ad.

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

This was the largest class and the most misleading, because the ad looks
populated and nothing reads it: a job submitted through the Go parser carried
the setting under a name HTCondor does not use.

Every member of it is fixed: the cron and retry attributes, the VM and Xen
family, the accounting group, the container want-flags, the machine count,
`remote_initialdir`, `checkpoint_exit_code` and the concurrency limits. See
"Fixed" above for what each one did to a job, and `differ.go` for the drift
that is left.

## Values that differ where both sides set the attribute

- **`KillSig` becomes a number.** C++ keeps the name (`"SIGTERM"`); Go
  converts it to `15`. Same for `remove_kill_sig`.
- **`JobLeaseDuration` floor.** C++ raises a short lease to its 20-second
  minimum; Go stores whatever was written.
- **Quote stripping.** `file_remaps`, `on_exit_hold_reason` and
  `periodic_hold_reason` are `f_strip_quotes` keywords: C++ removes the
  surrounding quotes, Go keeps them inside the stored string.
- **List canonicalization, in both directions.** `ec2_tag_names` is
  `f_as_list`, so C++ canonicalizes the separators and Go does not;
  `encrypt_input_files` and its three siblings are `f_as_string`, so C++
  stores them verbatim and Go canonicalizes. The file transfer matches these
  literally.

- **List canonicalization, in both directions.** `concurrency_limits` is
  `f_as_list`, so C++ canonicalizes the separators and Go does not;
  `encrypt_input_files` and its three siblings are `f_as_string`, so C++
  stores them verbatim and Go canonicalizes. The negotiator and the file
  transfer both match these literally.

- **Quotes around a hold reason.** `on_exit_hold_reason` and
  `periodic_hold_reason` are assigned as EXPRESSIONS, so a quoted reason
  becomes a ClassAd string with no quotes in its value; Go stores the text it
  was given and the quotes end up inside the string. Both belong to
  `SetPeriodicExpressions`, not to the simple-keyword pass.
- **`concurrency_limits` and `ec2_tag_names`** are not list-flagged keywords:
  `SetConcurrencyLimits` lower-cases, validates and SORTS the names, and
  `handleAVPairs` collects the EC2 tags from the `ec2_tag_<Name>` macros as
  well. Go stores the text it was given in both cases, and the negotiator
  matches limit names literally.
- **A filename containing a space** survives in `TransferInput` on the C++
  side and is split away by Go, so the file is never transferred.
- **`stream_input` / `stream_output` / `stream_error`** produce opposite
  `TransferIn`/`TransferOut`/`TransferErr` booleans, so one side streams the
  stream and the other transfers it.
- **Iwd resolution, again.** The `Cmd`/`UserLog` finding generalized to every
  path-valued keyword the Go parser implements; see "Grid credential and data
  files were stored as written" under "Fixed". What is left of it is the
  `aws_`/`gs_`/`s3_` spellings of the access-key files, which Go does not
  implement at all — and which C++ does *not* resolve, since they are plain
  `f_as_string` table entries rather than grid keywords.

- **Iwd resolution, again.** The known `Cmd`/`UserLog` finding generalizes to
  every path-valued keyword the Go parser does implement. C++ resolves them
  against `Iwd`; Go stores them as written. The grid family's own file
  keywords are fixed, below.
- **`Env` vs `Environment`.** The Args/Arguments naming split has a twin: for
  V1-shaped environments Go emits `Env`, C++ emits `Environment`.

## Keywords the Go parser ignores outside their universe

`docker_image` and `container_service_names` are set by Go whatever the
universe; C++ honours them only for a container or docker job. `container_image`
joins them, below. The want-flags no longer do — see the fixed material.

## Keywords with no Go implementation at all

About 100 attributes are set by C++ and by nothing in Go. The full list is in
`knownDivergentGenerated`; the families are
the tool-daemon (TDP) settings, the buffer settings, the Java settings, the
noop-job settings, the parallel-script settings, the submit-event notes,
`kill_sig` and its siblings, `core_size`,
`stack_size`, `keep_claim_idle`, `max_job_retirement_time`,
`next_job_start_delay`, `allowed_execute_duration`, `allowed_job_duration`,
`manifest`, `output_destination`, `output_directory`, `scitokens_file`,
`project_name`, `primary_unix_group`, `jobset`, `dag_node_name` and the
DAGMan bookkeeping, `periodic_vacate` and the `*_subcode` reasons.

The families still in `knownDivergentGenerated` are the EC2/GCE/Azure grid
settings, the tool-daemon (TDP) settings, `kill_sig` and its siblings,
`scitokens_file`, `project_name`, `periodic_vacate` and the `*_subcode`
reasons. The buffer, Java, noop-job, parallel-script and submit-event-note
families, `core_size`, `stack_size`, `keep_claim_idle`,
`max_job_retirement_time`, `next_job_start_delay`, the `allowed_*_duration`
pair, `manifest`, `output_destination`, `output_directory`,
`primary_unix_group`, `jobset` and `dag_node_name` were all on this list and
are fixed; see "Fixed" below.

## Fixed

**Grid credential and data files were stored as written.** `SetGridParams`
runs every cloud credential and data file it reads through `full_path`, so the
job ad records an absolute path: `EC2AccessKeyId`, `EC2SecretAccessKey`,
`EC2KeyPairFile`, `EC2UserDataFile`, `GceAuthFile`, `GceJsonFile` and
`AzureAuthFile`. Go stored the submitter's text. The gridmanager that later
opens one of these is a daemon in its own working directory, not the directory
`condor_submit` ran in, so `gce_auth_file = auth.json` reached it as a bare
name resolved against the wrong directory — a credential the job could not
read, for a file that was sitting in the submit directory all along.

Resolution is against `Iwd`, not against the submitting directory the
executable uses, so `initialdir` moves these files and does not move the
executable. The two mechanisms behind this are worth keeping apart, because
only one of them is a table. `SimpleSubmitKeyword` carries an `f_filemask`
field and `do_simple_commands` resolves every `f_as_string` keyword that has
one — but that is just `log`, `dagman_log`, `output_directory` and
`starter_log` (plus `executable`, which is also `f_special` and so resolves
against the submitting directory instead). The grid files carry no mask at
all; `SetGridParams` calls `full_path` on each by hand. Reading the mask would
have said they were ordinary strings.
`TestFileRoleKeywordsAreAccountedFor` guards the half that is a table: a new
`f_filemask` keyword upstream now fails that test instead of silently
diverging.

Three more behaviors came out of porting the resolution, all measured against
`SubmitHash`. `ec2_key_pair_file` is a second accepted spelling of
`ec2_keypair_file`, which Go did not know. A named `ec2_keypair` makes the
file meaningless, and C++ warns and drops it rather than recording a path the
gridmanager would write a new key to; Go recorded both. And one EC2 credential
value is not a filename at all: `FROM INSTANCE` tells the gridmanager to use
the instance's own IAM role, is matched without regard to case, and setting
either half of the credential to it sets both — so resolving it would have
turned "use the IAM role" into a path to a file that does not exist.

What is deliberately left: the `aws_`/`gs_`/`s3_` spellings of the access-key
files, which Go does not implement. They are not a resolution gap — they are
plain `f_as_string` entries in the keyword table, so `SetSimpleJobParams`
stores them verbatim and overwrites whatever `SetGridParams` resolved earlier
in `make_job_ad`. `gce_metadata_file`, `output_directory`, `starter_log`,
`dagman_log`, `x509userproxy` and `scitokens_file` are resolved by C++ too,
but Go implements none of them, so they stay in the "no Go implementation"
list rather than here.

**Every cloud setting a grid job named went nowhere.** The whole EC2, GCE and
Azure family -- 21 attributes -- was read by condor_submit and by nothing in
Go, so a job that named an AMI, an availability zone, a VPC subnet, an elastic
IP, an EBS volume list, a block device mapping, an IAM profile, a GCE metadata
file or a preemptible flag reached the grid manager with none of it. The
instance came up in the provider's default zone, on the default subnet, with
no volumes attached and no elastic IP, and nothing in the submission said so.
Worse for the credentials: `ec2_access_key_id` and `ec2_secret_access_key`
name key FILES, which condor_submit resolves against `Iwd`, and Go set
neither -- so an EC2 job had no credentials at all and the grid manager had
nothing to sign a RunInstances call with.

What the C++ turned out to say, against assumptions worth writing down:

- The grid TYPE -- the first word of `grid_resource` -- gates far less than it
  looks. It decides which settings are REQUIRED (an ec2 job needs an AMI and
  both credentials, a gce job an image and a machine type, an azure job all
  five of image, location, size, admin username and admin key) and whether the
  job gets the implicit Name tag. Every other keyword in the family is read
  whatever the type, so `grid_resource = batch slurm` plus `ec2_ami_id` still
  puts `EC2AmiID` in the ad. Writing them only for a matching grid type would
  have been its own divergence.
- Four attribute names do not follow from their keyword:
  `ec2_ebs_volumes` is `EC2ElasticBlockStorageVolumes`, `ec2_parameter_names`
  is `EC2ParamNames`, and `ec2_elastic_ip` and `ec2_vpc_ip` end in a
  lower-case `Ip` where every sibling is capitalized. Attribute names fold
  case, so only the first two would have broken a job -- but they would have
  broken it silently.
- `aws_region` and the `aws_`/`s3_`/`gs_` key-file keywords are NOT part of
  the grid family at all. They are plain entries in HTCondor's simple keyword
  table, read in every universe, stored verbatim with no `Iwd` resolution --
  and read AFTER the grid pass, so in a grid job the verbatim value overwrites
  the absolute path the grid pass resolved. A vanilla job transferring an
  `s3://` input needs them, which is why they are not universe-gated.
- `"FROM INSTANCE"` under either half of the credential pair sets BOTH halves,
  and is kept as the magic string rather than resolved as a path.
- `ec2_keypair_file` is dropped when `ec2_keypair` is also set, and
  `ec2_iam_profile_name` is kept only when `ec2_iam_profile_arn` is set too.
- EC2 tags and GCE labels are collected from `ec2_tag_<Name>` /
  `cloud_label_<Name>` -- either the submit prefix or the attribute prefix --
  merged with the names the list keyword gave, and recorded in an order that
  is observable: the sorted order HTCondor's macro table walks in. An ec2 job
  also gets its executable as the implicit `Name` tag, which is what the AWS
  console shows as the instance name, unless `WantNameTag = false`.
- Arbitrary RunInstances parameters (`ec2_parameter_<Name>` to
  `EC2Param_<Name>`) join their names with `", "` where tag names join with
  `","`, and the de-duplication compares a listed name with its dots turned
  into underscores against the raw scanned name -- so a name holding a dot
  never matches itself and is listed twice. Reproduced as written.
- `gce_metadata` is re-joined from its comma-separated fields, dropping the
  spacing: `a=1, b=2` is stored `a=1,b=2`, or the metadata server is handed a
  key named `" b"`.

Acceptance is unchanged: condor_submit aborts a submission whose grid type is
missing a required setting, and validates the `ec2_ebs_volumes` syntax, and
the Go parser still does neither.

The generated sweep can never reach any of this beyond `grid_resource = batch
slurm`, which is the only grid prelude the generator writes, so the ec2, gce
and azure shapes -- and the implicit Name tag above all -- are covered by
seeds instead.

**Fifty-five settings went to the wrong place, or nowhere, because the value's
shape was decided keyword by keyword.** HTCondor does not decide it keyword by
keyword. `SimpleSubmitKeyword` packs a flag word per keyword -- the value type
in the low five bits (`f_as_bool`, `f_as_int`, `f_as_uint`, `f_as_string`,
`f_as_list`), plus `f_strip_quotes`, `f_alt_name` and a file role -- and
`do_simple_commands` walks the table applying them. Ninety-six keywords are
handled that way; the Go parser had a hand-written block for forty-nine of
them and nothing at all for the other forty-seven. Each block decided for
itself what the value was, so the shape came out wrong in both directions at
once:

- **`encrypt_input_files` and its three siblings are `f_as_string`,** stored
  exactly as written. Go canonicalized them, stripping the space after each
  comma. The file transfer matches these names literally, so a file the
  submitter listed as `a.txt, b.txt` was looked for under a name the submit
  file never contained.
- **`email_attributes` is the one `f_as_list` keyword in the whole table,**
  and its separators ARE canonicalized. Go never read the keyword at all; what
  it wrote to `EmailAttributes` was the `notification` setting, a different
  keyword entirely, so every job carried `EmailAttributes = "NEVER"` and the
  attributes the submitter asked to have mailed were dropped.
- **`mount_under_scratch` is `f_as_string | f_strip_quotes`,** a directory
  list. Go ran it through `parseBool`, which turns `/tmp,/var/tmp` into
  `true`.
- **A value that was not a plain integer was dropped.** Eighteen of the blocks
  ran `parseInt` and skipped the attribute when it failed, but nineteen of
  these keywords are `f_as_expr` and the integer ones accept an expression
  too: `max_job_retirement_time = 3600 * 2`, `keep_claim_idle =
  $(MinJobRuntime)` and `allowed_job_duration = 60 * 60 * 24` all parsed, all
  set nothing, and the job ran with no limit instead of the one it asked for.
- **An empty value set the attribute to empty,** where `submit_param` returns
  nothing for it and HTCondor leaves the attribute off the ad entirely.
- **`checkpoint_exit_code` and `remote_initialdir` went to
  `CheckpointExitCode` and `RemoteInitialDir`,** which are not attributes
  HTCondor reads; the real ones are `SuccessCheckpointExitCode` and
  `RemoteIwd`. A self-checkpointing job's success exit code meant nothing and
  a `remote_initialdir` moved no job.
- **`jar_files` was written only for a java job,** and `log` was the only
  file-role keyword resolved against `Iwd`: `starter_log`, `dagman_log` and
  `output_directory` carry a file role too and were not written at all.

The fix is the table, not the forty-nine blocks. `simpleSubmitKeywords` in
`submit_simple_keywords.go` carries all ninety-six rows with their flags, and
one pass applies them the way `do_simple_commands` does.
`TestSimpleKeywordTableMatchesOracle` checks every field of every row against
the table the linked `libcondor_utils` actually carries, so a keyword added
upstream fails as a missing row rather than as a job ad nobody reads, and
`TestSimpleKeywordValueShapes` pins one keyword per flag against the oracle,
so the flags are shown to be acted on rather than merely recorded.

Three things this fuzzer had recorded backwards, all of them checkable against
`get_submit_keywords()`: `concurrency_limits` and `ec2_tag_names` are not
`f_as_list` (they are `f_special_concurr` and `f_special_grid`, with list
handling of their own), and `file_remaps`, `on_exit_hold_reason` and
`periodic_hold_reason` are not `f_strip_quotes` (they are `f_as_expr`, and the
quotes vanish because the value is parsed as an expression rather than stored
as text). `file_remaps` is in the simple pass and is fixed with the rest; the
other four are not, and are recorded above with what they actually do.

Where it stops is the `f_special` bit, which the table itself carries. The
attributes a `SetXXX` method DERIVES are still Go's to catch up on:
`JobStarterDebug` defaulting to true when `starter_log` is set, the
20-second `JobLeaseDuration` floor, and the `Requirements` clauses that read
`TransferCheckpointFiles` and `CudaVersion` all live in `SetAutoAttributes`
and `SetRequirements`, which run after this pass.

**A cron job never deferred, and a cron job's timing went nowhere.** There is
no `CronWindow` or `CronPrepTime` job attribute: `cron_window` and
`deferral_window` are two spellings of `DeferralWindow`, and `cron_prep_time`
and `deferral_prep_time` two spellings of `DeferralPrepTime`, with the `cron_`
spelling winning when a file uses both. Go wrote the submit keyword's own name,
so a job submitted with `cron_minute = 0` and `cron_window = 600` reached the
starter with its schedule but no window and no prep time: the starter that
missed the execute time by a second had no slack to run in, and no warning that
the window it was told about had been dropped. Three more pieces of the same
family. A deferred job always carries **both** timing attributes, with
`DeferralWindow = 0` and `DeferralPrepTime = 300` defaulted in when the file is
silent. The timing values are *expressions*, so `deferral_time = (time() +
3600)` is legal and Go's `parseInt` was dropping it on the floor. And Go wrote
`DeferralWindow` for a file with no schedule at all, where condor_submit writes
nothing. `cron_minute` and its four siblings were always right, and still are.

**A `max_retries` job never retried.** Three separate bugs, all in one
expression. The count went to `MaxRetries`, which nothing reads, instead of
`JobMaxRetries`. `retry_until` became a `RetryUntil` attribute, which is not an
attribute at all in HTCondor -- a plain integer there is a *futility exit code*
and becomes `ExitCode =?= <code>`, anything else is a boolean expression, and
either way it is folded into `OnExitRemove`. And `OnExitRemove` itself was left
as the submitter wrote it, where condor_submit replaces it with

```
NumJobCompletions > JobMaxRetries || ExitCode =?= <success code> [ || <retry_until> ] [ || <on_exit_remove> ]
```

so the job that was supposed to be retried was removed from the queue on its
first failure instead. The three settings are entangled in ways the keyword
table does not show: each of `max_retries`, `success_exit_code` and
`retry_until` turns retries on by itself, retries also default `JobMaxRetries`
to `DEFAULT_JOB_MAX_RETRIES` (2) and `OnExitHold` to `false`, and
`success_exit_code` makes the expression compare against `JobSuccessExitCode`
rather than baking the number in. An `OnExitRemove` the submitter set directly
with `+OnExitRemove` or `MY.OnExitRemove` is left alone, unless
`success_exit_code` or `retry_until` asked for a change -- which is why this
has to run after the `+Attr` pass rather than where its submit commands are
read.

The submitter's `on_exit_remove` is OR'd onto the end of the generated
expression, and the parenthesization of that join is load-bearing: every
ClassAd operator binds at least as tightly as `||` except the ternary, so
parenthesizing anything else would regroup `(a || b) || c` into `a || (b || c)`
-- the same value, a different tree. Only a ternary gets parentheses, which is
what `WrapExprTreeInParensForOp` does.

Both families now evaluate their values the way condor_submit does rather than
scanning a number off the front: `max_retries = 2+3` is five, and
`retry_until = 1+1` is exit code 2. Both also reject what condor_submit
rejects -- a negative `cron_window`, a non-integer `max_retries`, a
`retry_until` outside int range -- instead of silently dropping the setting.
Measured over the 600-file generated sweep, this added no file that
condor_submit accepts and the Go parser refuses.

What is deliberately left: `ScheddInterval`. C++ writes it only so the
deferral clause of its generated `Requirements` can read it, and Go generates
neither that clause nor a `Requirements` resembling C++'s. It belongs with the
`Requirements` divergence at the top of this file, not with the cron
attributes, which now agree.

## The container image

`container_image` was out of the generator's vocabulary until the shim called
`config()`; see the section above. It is in now, which takes coverage to 255 of
258 — what is left is `getenv`, its alternate spelling and the `f_error`
`request_gpu_memory`, none of which can be compared.

It diverged immediately, three ways. Two are still open; the third, the
image-kind want-flag, is in the fixed material above:

- **`ContainerImage` is a basename in C++, a path in Go.** Once C++ decides to
  transfer the image it rewrites the attribute to `condor_basename` of the
  path, because that is what the file transfer will leave in the sandbox, and
  it only does any of this for a container job. Go stores the path as written,
  in any universe. The starter is told to run a path the sandbox does not have.
- **`ContainerImageFullPath` is C++-only.** It is where C++ keeps the
  submit-side path when it rewrites `ContainerImage`, and it is what late
  materialization reads to build each proc's input transfer list. Go sets
  nothing, so a transferred image carries no record of where it came from.
The decision tree C++ walks before any of that — `transfer_container = false`,
a `CONTAINER_SHARED_FS` prefix, a `docker://` or `oras://` URL, each setting
`ContainerImageSource` and returning without transferring — has no Go
counterpart either; `ContainerImageSource` was already recorded.
