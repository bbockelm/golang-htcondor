# Reservations

## Status

Implemented across a stack of PRs, including the estimate stamping.

The intended direction is to hold the capacity with HTCondor's own
persistent claims instead of with machine attributes this pushes by
hand. See "Building this on OCUs". The permanent-reservation half of
that is built and switched off by default; the scheduled half is not
built, and both are waiting on schedd fixes listed there.

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

## Stamping the idle queue

A held machine admits nothing unless the jobs carry `RuntimeP90Bucket`.
Without stamping, a drain costs the whole machine for its whole lead
instead of costing nothing, so this is not an optimisation -- it is what
makes the sieve a sieve rather than a gate.

**The stamp goes on the CLUSTER ad, not on each proc.** A proc inherits
an attribute from its cluster ad, and the inherited value reaches the
startd's `START`: one `SetAttribute(cluster, -1, ...)` let all three
procs of a cluster onto a held machine
(`TestClusterAdStampGovernsEveryProc`, against 26.2.0).

That is the whole difference between a feasible design and an infeasible
one. Reconstructing the standing idle population of the measured access
point hour by hour over 25 days:

| | median | p75 | p90 | max |
|---|---|---|---|---|
| idle jobs | 43,567 | 82,349 | 132,902 | 173,848 |
| distinct clusters | **371** | 1,049 | 1,591 | 2,676 |
| distinct owners | 23 | 26 | 29 | 36 |

About 121 jobs per cluster. Per-proc stamping is tens of thousands of
`SetAttribute` calls for the backfill alone, and these are lower bounds
-- history holds only jobs that eventually ran. Per-cluster, the whole
queue is one pass at the median and two at the worst moment observed.

Re-stamping is the part that would have been painful per-proc. Comparing
each job's bucket at submit with its bucket just before it started --
two samples per job, so again a lower bound -- 44.7% change at least
once, and among jobs idle more than a day it is 89%. The queue is
dominated by long-waiting jobs, so on a daily timescale this approaches
re-stamping everything. Per cluster that is a few hundred writes a day.

A cluster is stamped with the **largest** estimate among its idle procs.
A cluster whose procs really differ is then described by its longest,
which costs some admissions and never admits a job that will not fit.

### What the sieve's asymmetry buys

The sieve refuses a *missing* stamp and accepts a *stale* one. So
stamping can fall arbitrarily far behind without ever admitting a job
that does not fit: falling behind costs admissions, not correctness.
That is why the pass has a budget at all, why unstamped clusters are
written before stale ones, and why the plan is stable -- a budget too
small for the queue then makes progress instead of rewriting a different
arbitrary subset each pass.

### The autocluster cost, and the cap that pays it

`RuntimeP90Bucket` is referenced by the execute points' `START`. The
negotiator collects the `TARGET.*` references it finds in the startd
ads and sends them to the schedd as `AutoClusterAttrs`, so this
attribute **will** be significant and the schedd **will** split
autoclusters on it. That cost is paid by the whole pool, not just by
the reservation.

Two things keep it small, and the first is not enough on its own.
Measured over 720,867 idle-job estimates on the access point this was
built against:

| | distinct values |
|---|---|
| raw `P90Seconds` | 7,765 |
| rounded to the 30-minute grain | 194 |
| **capped at the 6-hour lead** | **13** |

Rounding is the obvious move and it is a 40x improvement, but 194
distinct values is still far more autocluster splitting than this
feature is worth.

The cap is what makes it cheap, and it is **exact rather than
approximate**: the sieve asks one question of this number -- does the
job finish before the bell -- and the bell is never further away than
the longest reservation's lead. Every value past that horizon is the
same answer. Distinguishing them buys nothing and costs splits.

Most of the saving is the tail. 63% of clusters estimate inside half an
hour and 15.5% estimate past six hours; capping collapses that 15.5%
to one value.

The cap is one grain *beyond* the horizon, not at it. Capping exactly
at the horizon would make a job of unknown length compare equal against
a deadline exactly a horizon away and be admitted -- turning "we cannot
tell how long this is" into "it fits".

A submitter can also write the attribute themselves and the sieve cannot
tell. The backstop is that eviction does not consult it: a job that lied
its way onto a reserved core is preempted at the bell like any other.


## Building this on OCUs

The design above holds machines with attributes it pushes into their
machine ads. HTCondor has a mechanism for the same job -- **OCUs**,
Owned Capacity Units -- and the intended direction is to move onto it.

The move is in two steps, and only the first is built.

### What an OCU is

A persistent claim the schedd holds for a user. Created out of band
(`CREATE_OCU_FOR_USERREC`, `Schedd.create_ocu`, `Schedd.CreateOCU`),
negotiated like an idle job, and meant never to be given back: when the
job running on it ends, the schedd is to keep the claim and look for
another of that user's jobs. "What a claim does not yet hold" below is
how much of that is true today.

Three things about the management interface are not in the API surface,
and all three were measured against 26.2.0:

- **Creating or removing a claim needs more than WRITE.** The commands
  are registered at WRITE and then checked again inside the handler:
  the caller must be a queue super user or named in `OCU_SUPER_USERS`.
  A caller with WRITE and neither gets a refusal from inside the
  handler rather than from the security layer.
- **The owner must already have a user record.** The schedd looks the
  owner up by name and refuses a claim for a name it does not hold.
  Records are created on a user's first submission, so a user who has
  never submitted to this schedd cannot be given a claim.
- **A claim with no `Submitter` is never negotiated for.** The claim is
  only offered to the negotiator under a submitter whose owner set
  contains it, and that set is populated from the `Submitter` attribute
  on the create request. Without one the claim waits for ever and
  nothing says why.

The query command is `READ` with no further gate and no constraint in
the protocol: it answers with every claim of every owner, so narrowing
is the caller's job.

### Why it is the right shape

A reservation **is** a persistent claim scoped to an owner and a
project, which is what an OCU is. Everything this design builds by hand
-- `ReservationStart`, `ReservationDeadline`, `ReservationUntil`,
`ReservationProject`, the actuator that pushes them, the `START` stanza
every execute point needs, the prober that checks for it -- exists only
because the claim is not held by HTCondor. Hand it over and all of that
is deleted.

It also fixes the worst property of the current contract. Machine
attributes cannot be deleted and have no expiry, which is why every
value here is an absolute time. A claim has an owner and a lifetime of
its own, so none of that applies.

### Step one: permanent reservations

An always-on reservation has no bell. It wants capacity from now on,
with no deadline to drain towards and no moment at which anything has
to be evicted -- which is exactly what an OCU already is.

So the always-on case needs none of the machinery the scheduled case
does: no deadline, no sieve, no `START` stanza on each execute point,
no prober, no estimate stamping, no eviction, and no drain. The whole
controller is a count:

- A reservation wants `Seats` claims and no more. Unlike the
  machine-attribute path there is nothing to subtract for jobs already
  running -- a claim running a job is still the same claim -- and
  `Standing` does not apply, because a claim with no job on it already
  *is* idle capacity kept for the project.
- A claim whose reservation is gone, disabled or no longer always-on is
  released. Nothing else releases one deliberately, so this is how
  capacity is given back.
- Shrinking releases the newest claims. The oldest are likeliest to
  have settled onto a machine, and a claim given back has to be
  re-acquired by waiting.

It is read-not-remembered like the rest of this design: the schedd's
own list of claims is the record, compared every pass against what the
reservations ask for.

Switched on with `HTTP_API_RESERVATION_CLAIMS`, separately from
`HTTP_API_RESERVATIONS` and off by default, because it changes where a
running reservation's capacity comes from and because the schedd has to
be configured to accept the request. With it on, the machine-attribute
controller leaves always-on reservations alone -- otherwise both would
hold the same reservation and every seat would be counted twice.

### What a claim does not yet hold

A claim is created, negotiated, and takes a dynamic slot, which it then
holds: `Claimed/Idle`, with no `RemoteOwner` because nothing is running
there, and `OCUState = I`. On an idle pool it holds it indefinitely.

**It does not hold it against an ordinary job.** Measured against
26.2.0 on a two-cpu pool, one cpu running a job and the claim holding
the other:

| | |
|---|---|
| t+20s | the claim holds `slot1_2`, `Claimed/Idle`, `OCUState = I` |
| t+40s | a plain job -- no `OCUWanted`, no `OCUWilling` -- is submitted, and sits idle |
| t+50s | that job is **running on `slot1_2`**, and `OCUState` is back to `U` |

The schedd log is explicit about both ends of it:

```
19:16:43 Assigning match slot1_2@... for bbockelm@localhost to OCU 2
19:17:14 (the plain job is submitted)
19:17:18 Match record (slot1_2@... for bbockelm@localhost, -1.-1) deleted
```

Four seconds after an ordinary job enters the queue, the OCU's match
record -- the one carrying the sentinel job id `-1.-1` -- is deleted,
which releases the claim. The cpu that frees is then matched to that
job. The claim itself survives in the user record and is re-negotiated
for, but on a busy pool there is nothing left to take.

So a persistent claim does not reserve anything: the next ordinary job
takes the capacity.

One guard against exactly this is present and cannot fire.
`Scheduler::StartJob` opens with

```cpp
JobQueueJob * job = GetJobAd(rec->jid);
// Don't try to start a "job" if we are claiming an OCU holder claim
if (job == nullptr) {
    if (getOCU(rec->jid) != nullptr) { return; }
}
```

but `rec->jid` was reset to `{-1,-1}` when the claim was handed to the
OCU, and `getOCU` looks an OCU up by id -- always a positive number
from the cluster counter -- so `getOCU(-1)` is always null and the
early return is unreachable. The real id is kept beside it in
`rec->ocu_originator`. Whether that is the path the deletion takes was
not established; that the guard is dead was.

Whether a job *entitled* to the claim can be placed on it cannot be
measured from outside while this holds. Both answers look identical --
the job ends up on the claim's slot either way, because the claim is
dropped and the slot is then matched like any other -- and the one
signal that would separate them, `OCUState` reaching `R`, is
unreachable. Reading `FindRunnableJob` says such jobs would be refused:
it compares the claim's `RemoteOwner` and `RemoteProject` against the
job's, and nothing sets either on an idle claim, so every job, the
owner's included, reads as somebody else's and is required to be
`OCUWilling`. That is a reading of the code, not a measurement.

One further thing is stuck in consequence, and is worth fixing at the
same time because it is what makes the rest hard to see: **`OCUState`
can never reach `R`.** The schedd sets it by looking `OCUId` up on the
match ad, and nothing anywhere puts `OCUId` there, so the transition is
unreachable. A claim holding a machine and a claim running a job are
indistinguishable from outside, and the only states ever observed are
`U` and `I`.

Worth knowing while measuring any of this: the collector's view of the
partitionable slot lags the startd by an update interval, so "no cpus
free" is briefly true before the claim has actually taken one. The
claim's slot -- a dynamic slot that is `Claimed/Idle` with no
`RemoteOwner` -- is the only reliable signal that it is holding
anything.

The query reply is otherwise complete: it returns the stored claim ad,
which is the create request plus `OCUId` and `OCUName`, so whatever was
sent at creation -- owner, project, the resource request -- comes back.

Until the holding is fixed, a permanent reservation held this way holds
nothing at all. That is why the switch is off by default, and it is the
thing to fix before this is worth turning on.

### Step two: scheduled reservations

Not built, and it needs more than step one does. The difference is the
bell: a scheduled reservation has a deadline, and a claim acquired by
waiting does not respect deadlines.

**How the capacity would be acquired: drain, then cancel.** An OCU does
not drain anything. It is negotiated like an idle job and waits for
capacity to come free, with no deadline and no preference for machines
about to turn over. Something has to free the capacity for it, and that
something is `condor_drain`.

Draining is a better fit than it first appears:

- `DRAIN_JOBS` is ADMINISTRATOR, which the administrative capability an
  execute point publishes already covers. Nothing to configure per node.
- The drain request carries its own `StartExpr`. **The sieve ships with
  each drain** rather than living in `DEFAULT_DRAINING_START_EXPR` or in
  a machine attribute, so it stops being persistent state. This is
  strictly better than pushing it.
- While draining, `START` is the drain's expression, so only work the
  sieve admits may start.

Three things about draining decide the algorithm, and none is obvious:

**1. The retirement clock starts when the JOB started, not when the
drain started.** `evalRetirementRemaining` is
`MaxJobRetirementTime - getJobTotalRunTime()`. So at drain start a job
older than `MAXJOBRETIREMENTTIME` has zero retirement and is preempted
at once, while a job that just began gets the remainder. That is exactly
inverted from this design's cost rule, which says killing a young job is
free and killing an old one is not: retirement sacrifices the oldest
work first.

With the default `MAXJOBRETIREMENTTIME = 0` a graceful drain preempts
everything immediately -- the naive "kill at the bell", six hours early.
A site with a large `MAXJOBRETIREMENTTIME` instead gets "stop admitting,
let what is running finish", which is precisely the behaviour this
design wants. **So the value of `MAXJOBRETIREMENTTIME` on the execute
points decides whether this approach is cheap or ruinous**, and it has
to be checked before anything is drained. There is no "peaceful" drain
the way there is a peaceful shutdown; graceful draining with an
unbounded retirement time is the equivalent, and jobs admitted *while*
draining get a retirement time of zero either way.

**2. A running job that matches the drain's `StartExpr` is treated as
interruptible.** `retirementExpired` replaces such a job's own
retirement with the coordinated drain deadline. So the sieve does not
only govern admission; it also classifies what is already there.

**3. A completed drain takes the capacity back.** When every claimed
slot was accepted while draining, `checkForDrainCompletion` declares
final draining: `START` is set to false, claim ids are invalidated,
`MaxJobRetirementTime` is overridden to 0, and **all claims are
released -- including the OCU's**. Draining means "empty this machine",
not "give this machine to someone".

So the controller must **cancel the drain once the OCU has its seats**,
before the last pre-existing job finishes. `CANCEL_DRAIN_JOBS` restores
the normal `START` and does not release claims, so the OCU keeps what it
took. Losing that race costs the claim and nothing worse: the OCU
re-negotiates.

**Choosing borrowers by estimate rather than by consent.** `OCUWilling`
is preemption-based backfill: let anyone in, kill them when the owner
shows up. This design's own measurements say that is the expensive way
-- 7.6 jobs older than half an hour discarded per class start. A
borrower chosen by the runtime estimate costs nothing at handover,
because it was already going to end. That is the same sieve, applied to
borrowing rather than to admission, and it belongs **on the OCU**: only
the OCU knows when its seats are next wanted. Not configuration -- two
reservations on one pool want different answers.

### What has to change in HTCondor

The first two block step one. The rest block step two.

| | |
|---|---|
| A claim must survive an ordinary job | Measured: a plain job entitled to nothing takes the claim's slot within a negotiation cycle, and the claim reverts to unmatched. Until this holds, nothing else here matters -- there is no capacity left to argue about. |
| An idle claim must say whose it is | From reading `FindRunnableJob`: it compares the claim's `RemoteOwner` and `RemoteProject` against the job's, and nothing sets either on an idle claim, so every job -- the owner's own included -- reads as somebody else's. Setting them on the OCU's match ad where `ATTR_OCU` is already forced would do it. |
| A claim must take the jobs it is entitled to | Not measurable until the first row is fixed: a job on the claim's slot and a job on a slot the claim just lost look identical from outside, and `OCUState` cannot distinguish them. |
| An OCU must be able to say who may borrow it | Today the only gate is the borrower's own `OCUWilling`, which is any job of any user. A reservation's capacity should be borrowable on terms the reservation sets. |
| OCUs must be matchable to draining slots | `(Draining =!= true)` is ANDed onto every OCU request in `ScheddNegotiate`, so drained capacity can never reach the OCU it was drained for. |
| Borrower eviction must be bounded and ordered | It takes *every* borrowed claim of a submitter whenever the owner is short by even one seat, in match-table order, with a fast vacate. |

One smaller one, worth fixing with the first because it is what makes
the rest hard to see: `OCUState` can never reach `R`, because `OCUId`
is never put on the match ad it is looked up from.

The first row says "whose claim is this", which is not the question
`RemoteOwner`/`RemoteProject` answer on a *slot* ad -- those say who is
running on a slot now, and writing them into the stored claim ad makes
the schedd treat it as occupied.

### What stays

The estimator and the bucket stamping, unchanged: the sieve is the same
expression whether it arrives in a drain request or a machine
attribute, and it still needs `RuntimeP90Bucket` on the idle queue. The
window arithmetic, the lead, the forgiveness rule and the cost model
are all independent of how the claim is held.

### Per access point, on purpose

An OCU lives in one schedd's user record, so a reservation built on
OCUs serves the jobs of one access point. **That is the intended
model**, not a limitation to work around: a class submits from the
access point it was given, and a reservation that silently spanned
access points would hold capacity for jobs its owner cannot see.

It is a real difference from what is built now, which holds machines by
machine attribute and so serves any access point's jobs. Anything
relying on that has to be re-examined before the move.


## Open questions

- An exceeded job's estimate snaps back to the unconditioned median
  rather than keeping the last conditioned value. Pre-existing, more
  visible since conditioning was made unconditional.
- The simulation models cores as interchangeable. With partitionable
  slots and multi-resource seats, a machine contributes `min` over
  resources of carvable seats, which could move the hold counts.
