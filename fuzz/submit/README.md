# Differential submit-file fuzzing

This package answers one question: **does the Go submit-file parser build the
same job ad that HTCondor's C++ `SubmitHash` builds?**

`src/condor_utils/submit_utils.cpp` is where submit-file semantics actually
live — roughly 400KB of accumulated behavior that no specification describes.
The only trustworthy oracle for "what does this submit file mean" is that code,
so this package links it and runs both parsers over the same input.

It follows the same shape as `fuzz/config` (config language) and the ClassAd
differential fuzzer in `golang-classads/fuzz`.

## The two modes

The oracle (`oracle/shim.cc`) drives `SubmitHash` exactly as `condor_submit`
does — `parse_up_to_q_line`, then `SubmitStepFromQArgs` over the queue
statement, calling `make_job_ad` per proc — and can emit either:

| Mode | What it emits | Corresponds to |
|------|---------------|----------------|
| `ModeAds` | each proc's complete job ad, parent chain merged | `condor_submit -dry-run` |
| `ModePlacement` | the cluster ad plus each proc's own attributes, after `fold_job_into_base_ad` | what the schedd actually stores per ad |
| `Factory()` | the factory decision, materialize limit, loop variables, itemdata rows and submit digest | what a late-materialization submit sends instead of proc ads |

`Factory()` needs no schedd either: whether a submission is a factory, its
limit, the itemdata and the digest are all computed client-side by
`SubmitHash`. Only the schedd's expansion of the digest would need one, and
that is the schedd's behavior rather than the parser's.

`ModeAds` is what the fuzz target compares today. `ModePlacement` exists and is
verified, but the Go side of that comparison is not wired up yet — see
"Placement mode" below.

## Running it

The oracle is behind the `libcondor_utils` build tag, so ordinary builds, `go
vet ./...` and CI are unaffected (`oracle/stub.go` keeps the package
compiling). To run against a local HTCondor build tree:

```sh
source hack/submit-fuzz-env.sh      # HTCONDOR_SRC / HTCONDOR_BUILD override the tree
go test -tags libcondor_utils -c -o /tmp/subfuzz.test ./fuzz/submit/
( cd fuzz/submit && /tmp/subfuzz.test -test.run 'TestSeeds|TestKnown' -test.v )
```

To fuzz:

```sh
hack/submit-fuzz.sh 10m                       # FuzzSubmitAds
hack/submit-fuzz.sh 10m FuzzSubmitGenerated   # the generated target
```

Both build the test binary and run it directly rather than using `go test`.
On macOS, SIP strips `DYLD_LIBRARY_PATH` when `go test` re-execs its workers,
and `libcondor_utils`' install name carries no `@rpath` prefix, so embedded
rpaths do not help — the binary has to be exec'd by something that still has
the library path.

## The two fuzz targets

`FuzzSubmitAds` mutates submit **text**, starting from the hand-written seeds.

`FuzzSubmitGenerated` mutates the **script a generator reads** (`gen.go`). The
generator takes the fuzzer's bytes as a series of decisions -- which keyword to
emit, which shape of value, which queue statement -- and its vocabulary comes
from `oracle.Keywords()`, which is HTCondor's own submit-keyword table as the
linked `SubmitHash` sees it. A keyword added upstream therefore enters the
generator with no change here.

The reason for the second target is measurable: `TestKeywordCoverage` counts
how much of HTCondor's vocabulary a corpus reaches.

| corpus | keywords reached (of 258 in 26.2.0) |
|--------|-------------------------------------|
| hand-written seeds | 19 |
| seeds + generator | 254 |

The seed figure moves as seeds are added; the test prints both every run.

The gap is keywords whose values have a syntax of their own, which byte
mutation does not produce: a `cron_minute` needs a cron field, a
`grid_resource` needs a grid type and its arguments, a `request_memory` needs
a size. `gen.go` writes real generators for those families -- cron fields
(`*`, ranges, lists, steps, per-field bounds), grid resources, sizes with
`K`/`M`/`G`/`T` units, file paths and file lists, ClassAd expressions,
enumerations whose value set SubmitHash checks (`notification`,
`when_to_transfer_output`, `kill_sig`, ...), attribute-name lists, environment
and remap strings -- and falls back to the keyword's declared type
(`f_as_bool` / `f_as_int` / `f_as_uint` / `f_as_string` / `f_as_list`, and
`f_as_expr` as the default) for the rest.

It also picks a universe first and draws only from the keywords that universe
allows, emitting whatever that universe requires (`grid_resource` for grid,
`vm_type` for vm, the class name for java), because SubmitHash rejects the
file otherwise and the family is never compared. Two spellings of one
attribute are never written into the same file, which is what keeps an
`f_alt_err` pair -- where using both spellings is an error -- apart.

Generation is a pure function of the input bytes, so a fuzz reproducer is the
bytes.

Six keywords are deliberately out of the vocabulary, each recorded in
`Vocab.Skipped`: `request_gpu_memory` and `request_gpus_memory` (flagged
`f_error`, SubmitHash rejects them), `getenv` and `get_env` (they read the
host environment, which only the C++ side is allowed to do here),
`x509userproxy` (SubmitHash reads and validates the proxy off the host), and
`container_image` (it crashes the oracle -- see FINDINGS.md).

## How a divergence is judged

Comparing the two ads directly would drown in noise, so each attribute falls
into one of three buckets, all of them explicit in `differ.go`:

- **`hostDerived`** — value comes from the clock, the machine, or the account
  rather than the submit file (`QDate`, `Iwd`, `CondorVersion`, the `stat`-based
  sizes). Never compared. Every name here is a hole in the oracle, so the list
  is deliberately short and each entry says why.
- **`knownDivergent`** — the two parsers genuinely disagree today. Each entry
  records what the difference is. This table *is* the inventory of Go/C++ drift.
- **`knownDivergentGenerated`** — the same thing for what the generated target
  found. Kept separate only so the provenance of a finding stays visible.
- **everything else** — must match. Values are compared structurally (parsed as
  ClassAd expressions), so unparser formatting differences are not divergences.

Seeds carry the same idea at file granularity: a seed with no `reason` must
agree, and a seed **with** a `reason` must still diverge. Fixing the Go side
turns a known case red and tells you to promote it to parity, so a fix cannot
silently regress. `TestKnownDivergencesStillDiverge` does the same for the
attribute table.

## Determinism

The oracle pins the submit time and user (`kSubmitTime`, `kSubmitUser`) and
disables every filesystem check (`setDisableFileChecks`,
`setFakeFileCreationChecks`), so a fuzzer-authored `executable` cannot make the
answer depend on what happens to exist on disk.

The Go side runs with `AllowLocalAccess` off, which is the right setting for
untrusted text: `include command` runs a shell command, and `$ENV()` and
`queue ... from <file>` read the host. The C++ side has no such switch, so
those constructs are a documented divergence rather than something compared.

## Placement mode

`ModePlacement` is the second half of the question and the one that guards
issue #746: not "what does the ad contain" but "which ad does each attribute
land in". The C++ side is implemented and verified; wiring the Go side needs
the placement split that `SendClusterAttributes`/`SendProcAttributes` perform,
which lives unexported in the root package. Two workable routes:

1. put that fuzz target in package `htcondor`, where `selectAttributes` is
   visible, importing this `oracle` package; or
2. compare end-to-end against a real schedd's `job_queue.log`, reusing the
   machinery in `schedd_submit_clusterad_test.go` — slower, but it exercises
   the actual QMGMT path rather than a reimplementation of it.

Route 1 is cheap enough to fuzz; route 2 is a corpus-replay test.

## Findings

See [FINDINGS.md](FINDINGS.md).
