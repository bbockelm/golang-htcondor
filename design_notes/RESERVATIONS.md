# Reservations

## Status

Implemented across a stack of PRs; the actuator (pushing to startds) and
the estimate stamping are not yet written. See "Not yet built" below.

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

Backfill slots are excluded: their resources are already counted as free
on the partitionable slot they came from, and counting them twice lets a
reservation promise the same core once per counting.

### Written to machine ads

Pushed with `CA_UPDATE_MACHINE_AD`. Three properties of that mechanism
constrain everything above, and none is discoverable from the API
surface:

- **The merge is per attribute into one ad shared by every slot.**
  Holding is per machine, not per slot.
- **There is no delete path and no expiry.** An attribute lives until the
  startd restarts. Hence deadlines are *absolute*, not flags: one left
  behind by a dead controller stops constraining anything by itself.
- **Therefore no reservation's name may appear in an attribute name.** A
  semester of classes would otherwise leave hundreds of dead keys on
  every execute point. Operands use a small fixed set of reusable slots.

The wire command is `CA_AUTH_CMD` = **1000**, not `CA_UPDATE_MACHINE_AD`
= 1009. 1009 only names the verb string carried inside the ad, which the
startd maps back to its switch; sending 1009 is rejected as unknown. The
request ad also carries `MyType = "Command"` and `TargetType = "Reply"`,
and the startd merges the `Command` attribute itself into every slot ad
because `updateExtrasClassAd` does not exclude it.

### The EP config

```
START = $(START) && ( ReservationStart ?: True )
```

One stanza, once, never changed per reservation. The controller pushes
`ReservationStart` as a complete expression plus the operands it refers
to. Composed deterministically from the same inputs by every controller,
so concurrent pushes are byte-identical and racing is harmless.

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

- The actuator. The `Actuator` interface exists; the CEDAR client to
  implement it does not yet live anywhere (it was wrongly proposed for
  the cedar library, which is protocol framing rather than uses of it).
- `RuntimeP90Bucket` stamping on idle jobs. The sieve refuses unstamped
  jobs on a held machine, so this is the whole idle queue, not just the
  jobs that might match. Throughput against a real schedd is unmeasured
  and is the biggest open risk.
- Auto-provisioning the `START` stanza, and the periodic permission probe.

## Open questions

- An exceeded job's estimate snaps back to the unconditioned median
  rather than keeping the last conditioned value. Pre-existing, more
  visible since conditioning was made unconditional.
- The simulation models cores as interchangeable. With partitionable
  slots and multi-resource seats, a machine contributes `min` over
  resources of carvable seats, which could move the hold counts.
