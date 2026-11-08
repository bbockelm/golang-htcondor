# Reservations

## Status

Implemented across a stack of PRs. The estimate stamping is not yet
written; see "Not yet built" below.

## The problem

A class needs N cores at a fixed time. The pool is full of other
people's jobs. Freeing cores means evicting some of them, and the naive
answer — kill whatever is running when the class starts — throws away
hours of work.

Measured on ap2001, 134 GPU cores, 35 seats: doing nothing and killing at
the bell evicts **7.6 jobs older than half an hour** per class start and
discards 11.1 core-hours.

## The cost model

The operator declares a threshold (`FORGIVE`, 30 minutes by default):
**evicting a job that has run less than that is free.** Everything else
follows from this one rule.

It is a policy choice, not a measurement. The work is still discarded; it
is discarded cheaply enough that the site has decided not to count it.
The throughput ledger below counts it anyway, because pretending
otherwise would make the design look better than it is.

## Two derived quantities

### Age at the bell is invariant

For a job that keeps running, `Age(t) + W(t) = T_class - job_start`.
The clock advancing and the deadline approaching cancel exactly. A
ranking built on it therefore never flaps, which is what makes a
60-second control loop stable without damping.

### The guarantee is absorbing

A core is *guaranteed* cheap at the bell when `Age + W <= FORGIVE`. Since
`Age >= 0`, that implies `W <= FORGIVE`: the core is already inside the
forgiveness window. So if the job keeps running its age at the bell stays
under the line, and if it ends the core can only pick up something
younger. **A core that enters the guaranteed set never leaves it.**

The awkward consequence, and the one that shapes the whole design: `G` is
*identically empty* while `W > FORGIVE`. Nothing is guaranteed until the
last half hour. A reservation cannot wait for cores to become free; it
has to hold them back in advance, on a prediction.

## The algorithm

Each tick (60 s):

1. **Census.** One collector query per tick, projecting only the
   attributes below, constrained to the site's permissible execute
   points. Group slot ads by machine: a partitionable slot's unclaimed
   capacity is `Free`, each dynamic slot is a `Dslot`.

2. **Classify.** `ProjectedWaste = 0 if AgeAtClass <= FORGIVE else
   AgeAtClass`. `Guaranteed` is `ProjectedWaste == 0`.

3. **Target.** For each reservation in a window or its planning lead,
   `Target = (seats in a window, standing outside) - running`, and zero
   once the project already holds `seats`. A reservation exists to make
   room, not to idle capacity nobody is using.

4. **Assign.** Divide the pool across reservations in **bell order,
   soonest first**, so no core is promised twice. Seats are counted as
   the limiting resource, not as cores: a machine with a spare GPU and no
   spare memory seats nobody. A reservation later in the day sees its
   guarantee count fall as an earlier one takes the cores it would have
   relied on — the interaction a single global census gets wrong.

5. **Size.** `Want(seats, guaranteed) = ceil((seats + 2*sqrt(seats) -
   guaranteed) / 0.9)`. The margin tracks two standard deviations of the
   binomial; sigma grows as the square root of the reservation because
   the pool it draws from does. Since `G` is empty during planning,
   `Want(target, 0)` is exact there rather than an approximation.

6. **Place.** Among seats of equal cost, prefer the machine that will
   **free up soonest**. A hold only governs the *next* admission, so a
   machine still running the same job at the bell never makes an
   admission decision and holding it achieves nothing. Measured: ranking
   by predicted time left picks a machine that turns over 84.3% of the
   time against 52.9% for ranking by age, at a one-hour bell.

7. **Actuate.** Releases first, so a machine moving between reservations
   is never briefly held for neither. Holds next. Evictions last, so
   nothing is preempted for a seat that was not secured.

Holding continues *through* the window, not just up to the bell. A
machine released at the bell goes back to the pool at the moment the
reservation starts using it: the first seat the project finishes with is
refilled by somebody else, and the window the drain paid for leaks away
one seat at a time. During the window the pushed deadline is the bell,
now in the past, so the sieve stops admitting on an estimate and admits
the project alone.

Inside the last `FORGIVE` before the bell nothing is held, for the same
reason there is no quiet period: anything started from there is under
the line at the bell anyway, and holding only costs admissions.

### Why over-provision

Holding exactly as many machines as seats leaves no room for the ones
that do not come good. The extra machines are not insurance against a
bad estimate — the loop re-sizes every tick and corrects itself — they
buy **selection**: a larger pool of young jobs to choose from at the
bell. Going from 35 held to 48 for a 35-seat class barely changes how
many jobs are killed (19.9 → 14.4) but collapses the expensive ones
(8.15 → 0.50).

### Why no quiet period

Stopping admissions early sounds safer and is worse. Anything still
running after you stop admitting is, by definition, at least as old as
the quiet period, so every survivor is an expensive eviction. At equal
reservation size: 1.29 expensive kills at 86.7% utilization with
continuous admission, against 1.31 at 80.6% stopping 30 minutes out.

### Why the controller keeps no memory

What is held is read back from the pool every tick, never remembered. A
controller restarted mid-drain, a push that failed, or a deadline left by
a process that died all have to be *visible* before they can be
corrected. A controller that trusted its own recollection would disagree
with the pool silently.

## The attribute contract

### Read from slot ads

| Attribute | |
|---|---|
| `Name`, `Machine`, `SlotType`, `PartitionableSlot`, `DynamicSlot`, `BackfillSlot` | slot identity and shape |
| `State`, `Activity` | whether a slot is running anything |
| `Cpus`, `GPUs`, `Memory` (MiB), `Disk` (KiB) | capacity |
| `JobStart` | when the running job started. `ATTR_JOB_START`, published by `Claim::publish`. **Not** `JobStartDate`, which is the job ad's — reading the wrong one makes every job look brand new and the whole pool look free to evict. |
| `RemoteProject` | the running job's project. The job-side spelling is `ProjectName`; the startd copies it across. |
| `MyAddress` | where to send a command. A census without it is read-only. |
| `START` | read **unevaluated**, to decide whether the execute point carries the stanza. A slot ad's `START` evaluates to true or false, and judging on that would be nonsense. |
| `_condor_PrivRemoteAdminCapability` | the administrative session. Private: the query must ask for it and be authorized at ADMINISTRATOR, or it silently comes back absent. |

A d-slot's `Name` is what an eviction is made by: the startd vacates a
claim by slot name, so a census that does not carry it cannot evict at
all. It refuses rather than guessing which d-slot an index meant —
vacating the wrong one preempts somebody who was not in the way and
leaves the one who was.

Backfill slots are excluded: their resources are already counted as free
on the partitionable slot they came from, and counting them twice lets a
reservation promise the same core once per counting.

### Written to machine ads

| Attribute | |
|---|---|
| `ReservationStart` | the sieve |
| `ReservationDeadline` | the bell, unix seconds |
| `ReservationUntil` | the end of the window, unix seconds |
| `ReservationProject` | whose seats these are |

Pushed with `CA_UPDATE_MACHINE_AD`. Four properties of that mechanism
constrain everything above, and none is discoverable from the API
surface:

- **The merge is per attribute into one ad shared by every slot.**
  Holding is per machine, not per slot.
- **There is no delete path and no expiry.** An attribute lives until the
  startd restarts. Hence times are *absolute*, not flags: one left behind
  by a dead controller stops constraining anything by itself.
- **Therefore no reservation's name may appear in an attribute name.** A
  semester of classes would otherwise leave hundreds of dead keys on
  every execute point.
- **`START` cannot be pushed.** Every other attribute becomes an operand
  of the slot's own expression evaluation and stays there. `START` alone
  is republished from the startd's configuration on every refresh, so a
  pushed one is overwritten within seconds — silently: the push is
  accepted and the other attributes in it stick. `TestStartCannotBePushed`
  measures this against 26.2.0, and asserts that a non-`START` attribute
  from the same push *did* land, so "the push did nothing" is excluded.

The wire command is `CA_AUTH_CMD` = **1000**, not `CA_UPDATE_MACHINE_AD`
= 1009. 1009 only names the verb string carried inside the ad, which the
startd maps back to its switch; sending 1009 is rejected as unknown. The
request ad also carries `MyType = "Command"` and `TargetType = "Reply"`,
and the startd merges the `Command` attribute itself into every slot ad
because `updateExtrasClassAd` does not exclude it.

### Authorization

Every command rides `_condor_PrivRemoteAdminCapability`, the
ADMINISTRATOR session each DaemonCore daemon mints for itself and ships
to the collector when `SEC_ENABLE_REMOTE_ADMINISTRATION` is on (default
true). Its `ValidCommands` is `GetCommandsInAuthLevel(ADMINISTRATOR,
true)`, which walks ADMINISTRATOR -> WRITE -> READ and so covers both
`CA_AUTH_CMD` (registered at WRITE) and `VACATE_CLAIM` (ADMINISTRATOR).

The collector moves it into the private ad and sends it only to a query
that asks for private attributes and verifies at ADMINISTRATOR. So the
access point needs ADMINISTRATOR *at the collector*, and the execute
points need nothing configured beyond the stanza below.

It lives half an hour and is re-minted on every collector update, so it
is re-read on an interval and once more after a denial: an expired
capability and lost authorization are otherwise the same error.

### The EP config

```
START = $(START) && ( ReservationStart ?: True )
```

One stanza, once, in the execute point's configuration file, never
changed per reservation. It cannot be installed remotely, so the
prober's job is to *detect* execute points without it and name them on
the admin page. (`DC_CONFIG_RUNTIME` would set it, but needs
`ENABLE_RUNTIME_CONFIG` plus a `SETTABLE_ATTRS` entry on each execute
point, which is more site configuration than writing the line.)

### The sieve

```
( time() >= ( ReservationUntil ?: 0 ) )
|| ( ( ReservationProject ?: "" ) != "" && TARGET.ProjectName =?= ReservationProject )
|| ( ( TARGET.RuntimeP90Bucket ?: -1 ) >= 0
     && time() + TARGET.RuntimeP90Bucket <= ( ReservationDeadline ?: 0 ) )
```

A constant, so concurrent pushes are byte-identical and racing is
harmless. Three decisions in it are not obvious:

- **Operators only, no functions.** `strlen` is a ClassAd function in
  HTCondor's C++ and absent from the Go implementation that composes and
  tests this. A sieve that parses differently in the two places is worse
  than a wordier one.
- **No large sentinel for an unstamped job.** An "effectively infinite"
  runtime is only infinite relative to the deadline, and a deadline far
  enough out makes it finite again. The `>= 0` guard also refuses a
  *negative* estimate, which would otherwise be admitted.
- **The project clause is guarded on a non-empty project.** With
  `ReservationProject` absent, the bare comparison is
  `undefined =?= undefined`, which is **true**, so an unguarded sieve
  admits every job that names no project. An empty string does not
  reproduce it, so a test that sets `""` passes against the broken
  version.

A submitter can write `RuntimeP90Bucket` themselves and the sieve cannot
tell. The backstop is that eviction does not consult it: a job that lied
its way onto a reserved core is preempted at the bell like any other.


## What it costs

Per class start, 134 GPU cores holding 35 seats, 6 h lead:

| | No reservation | With one |
|---|---|---|
| Evictions of jobs older than 30 min | 7.6 | **0** |
| Committed work discarded | 10.8 core-h | 6.7 core-h |
| Setup overhead (job starts × 65 s) | 9.3 core-h | 16.3 core-h |
| Idle caused by the sieve | 0% | 0% |

Net **+2.9 core-hours**, about 0.36% of the drain window. The reservation
*reduces* discarded work, because it evicts younger jobs; it loses on
churn, because held machines run more, shorter jobs and each start costs
a measured 65 s mean of input transfer and setup.

Lead time is the operational requirement: 6 h is where it saturates
(zero expensive evictions), 2 h is close (98% clean), 1 h is materially
worse (71%).

## When not to use it

`q_u = E[min(L, FORGIVE)] / E[L]` is the share of wall-clock a core
spends on a job younger than `FORGIVE` — computable in one pass over
`condor_history`, no instrumentation. It was 20.1% for ap2001 GPU jobs.

- `N >= C / q_u` (about 5× the class size): the pool already holds enough
  young jobs at any moment. Kill the youngest at the bell and skip all of
  this.
- Below about `2.5 × C`: not reachable at any hold count. The controller
  reports the shortfall rather than pretending.

## Not yet built

`RuntimeP90Bucket` stamping on idle jobs. The sieve refuses unstamped
jobs on a held machine, so this is the whole idle queue, not just the
jobs that might match.

Measured against 25 days of ap2001 history, reconstructing the standing
idle population hour by hour:

| standing idle jobs | |
|---|---|
| median | 43,600 |
| p90 | 133,000 |
| peak | 174,000 |

So the one-time backfill is tens of thousands of `SetAttribute` calls,
and it is a *lower bound* — history holds only jobs that eventually ran.
Steady state is 33,600 completions/day, about 0.4 first stamps a second.

Re-stamping is the harder half. Comparing each job's bucket at submit
with its bucket just before it started — two samples per job, so again a
lower bound — 44.7% change at least once, and among jobs idle more than
a day it is 89%. The queue is dominated by long-waiting jobs, so on a
daily timescale this approaches re-stamping everything.

Two consequences for whoever writes it. The backfill wants batched
`SetAttribute` under one transaction rather than the obvious loop. And
because the sieve refuses a *missing* stamp but accepts a *stale* one,
re-stamping can be rate-limited to a budget per tick without any
correctness risk — which is the knob to have before turning it on.


## Why not OCUs

HTCondor has a mechanism that looks like the answer and is half of it.

An **OCU** (Owned Capacity Unit, HTCONDOR-3031, in since 24.10) is a
persistent claim the schedd holds on a user's behalf. It is created out
of band -- `htcondor ocu create`, or `Schedd.create_ocu` -- rather than
submitted as a job, it is matched by the negotiator like an idle job,
and once granted it is **never given back**: when the job on it
finishes, the schedd keeps the claim and looks for another of that
user's jobs to put on it. Jobs opt in with `OCUWanted`; jobs belonging
to somebody else opt in to *borrowing* an idle one with `OCUWilling`,
and are vacated when the owner wants it back.

That is exactly the half of this problem the rest of this document does
badly, and none of the half it does well.

### What it does, measured

Against 26.2.0, one execute point with one CPU, so the contest for the
slot is unambiguous:

| | |
|---|---|
| The claim persists across jobs | **Yes.** It sat `Claimed Idle` with `OCU = true` indefinitely after its job ended, and never returned to the pool. |
| It is acquired by a deadline | **No.** It is negotiated like any idle job: it waits for capacity to come free. |
| It drains or preempts to get the claim | **No.** |
| It can be scoped to a project | **No.** `create_ocu` with a project name is refused: `Owner not found: cs301`. OCUs hang off a user record. |
| Consenting jobs backfill an idle claim | **Yes.** An `OCUWilling` job ran on it; a plain job submitted at the same moment never did, for the life of the test. |
| The owner gets it back | **Not as documented.** See below. |

The last one is worth stating precisely because it is the whole point of
the mechanism. With a borrower running, an `OCUWanted` job of the
claim's own owner stayed idle indefinitely while the borrower was
vacated and re-matched ten times in a minute. A second job carrying
**both** `OCUWanted` and `OCUWilling` took the claim as soon as the
borrower was removed, and the schedd counted it as an owner activation.

So in this build the matching gate and the accounting disagree. The gate
(`FindRunnableJob`) compares the claim's `RemoteOwner`/`RemoteProject`
against the job's, and an idle OCU claim carries neither, so every job
falls into the "somebody else's OCU claim" branch and is refused unless
it says `OCUWilling`. The eviction loop meanwhile counts `OCUWanted`
jobs, so it fires correctly and preempts the borrower -- which then wins
the re-match, being the older `OCUWilling` job. The claim churns and
nobody is served.

### Why it is not a substitute

The hard part here is **acquisition by a deadline**. A class needs N
cores at 14:00, and the pool is full. An OCU does not drain anything; it
waits in the negotiator's queue like any other idle request. On a busy
pool a reservation made at 08:00 would accumulate claims slowly, in
whatever order capacity happened to free up, with no way to say "by
14:00" and no way to prefer the machines that will turn over. And while
it waits it idles every core it has taken.

The measurements above say what that costs: a core spends 20.1% of its
wall clock on a job younger than `FORGIVE`, so a pool of 134 cores frees
about one core every few minutes by luck. Reaching 48 held machines by a
bell six hours out is feasible by luck; reaching them by a bell two
hours out is not.

### The twist that would help

They compose, and the composition is better than either.

- **Before the bell**, the sieve is the right instrument. It drains by
  *prediction*: admit only work that finishes in time, which costs no
  idle capacity as long as the queue has short work in it.
- **During the window**, the OCU is the right instrument. A persistent
  claim restricted to its owner is what `ReservationUntil` and
  `ReservationProject` are imitating, badly, in a machine ad that cannot
  be deleted -- and `OCUWilling` gives the reservation something this
  design has no answer for at all: *consented* backfill of a seat the
  class is not using, instead of refusing the core to everybody.

The deeper point is about the backfill rule. `OCUWilling` is
preemption-based: let anyone in and kill them when the owner shows up.
This document's whole cost model says that is the expensive way --
7.6 jobs older than half an hour discarded per class start. The sieve is
prediction-based: let in only what finishes in time, and preempt nobody.
**A borrower chosen by the estimate rather than by consent is strictly
better than either**: the claim stays busy, and the handover costs
nothing because the borrower was already going to end.

In HTCondor terms that is a small change in one place -- when
`FindRunnableJob` considers a job for somebody else's OCU claim, also
require that it fit before that reservation's next bell. The estimate
already exists; what it lacks is anywhere to be consulted inside the
schedd.

### What would have to change first

In rough order of how much it blocks:

1. **Project-scoped OCUs.** Seats belong to a class, not to a user, and
   students do not share an account. The matching code already compares
   `RemoteProject`, so this is closer than it looks; `create_ocu`
   refusing a project name is the gap.
2. **The owner can take back its own claim.** An `OCUWanted` job has to
   match its own OCU without also declaring itself preemptible, and has
   to win against the borrower it just displaced.
3. **A deadline on the request.** Without one an OCU cannot be asked for
   by 14:00, which is the whole requirement.
4. **Multi-access-point reach.** OCUs live in one schedd's user record.
   A class whose students submit from several access points needs the
   claims where their jobs are, or a way to share them.

None of that is this repository's to change, and none of it is needed
for what is built here. It is recorded because the first three would
each let this subsystem delete code rather than add it, and because
anyone reading this design will ask the question.


## Open questions

- An exceeded job's estimate snaps back to the unconditioned median
  rather than keeping the last conditioned value. Pre-existing, more
  visible since conditioning was made unconditional.
- The simulation models cores as interchangeable. With partitionable
  slots and multi-resource seats, a machine contributes `min` over
  resources of carvable seats, which could move the hold counts.
