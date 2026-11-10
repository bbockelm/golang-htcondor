# Reservations

Holding pool capacity for a project at recurring times — a course, a
demo, anything with a timetable — or continuously, without throwing away
work that was already running. Part of the [HTTP API + MCP server](server.md) documentation.

## What a reservation is

A reservation names a **project**, one **instance** described by a submit
file, how much capacity it needs (`seats`), how much spare capacity to
keep available (`standing`), and a **timing** with a duration. Jobs use
the reservation by carrying the project as their `ProjectName`.

`standing` is headroom, not a floor. It is how much *unused* capacity to
keep on top of whatever the project is already running, capped by
`seats`: with `standing = 2` and five instances in use, two more are held
and idle, so the sixth user to arrive finds capacity waiting instead of
waiting for the next controller tick and a drain after it. Running jobs
do not count against it, and it is asked for exactly — the
over-provisioning that precedes a window pays for machines that may not
come good in time, and headroom has no moment it has to be good by.

Each occurrence is a **window**. The moment it opens is the **bell**.
Before the bell the controller holds cores back so the seats are cheap to
free when it rings; after it, unclaimed seats stay reserved for the
project for `hold` (15 minutes by default) and then return to the pool.

Occurrences close together are one window. Two back-to-back sessions are
one hold: releasing cores between them and draining again costs more than
keeping them, and a gap shorter than the forgiveness threshold is free
either way.

A recurrence can be bounded. A schedule says when a reservation happens
but not for how long it goes on, so a reservation booked for one term
would otherwise hold capacity every Monday for ever. A reservation may
have a **start**, and then either an **end** or a number of
**occurrences** — one or the other, since they say the same thing two
ways, and a count needs a start to count from. An occurrence that begins
before the end runs its full duration: a window that opened in time is
not cut short because the recurrence ended part way through it. The count
counts scheduled starts rather than windows, so fifteen sessions is
fifteen sessions even where two of them merge into one hold.

## How a reservation is timed

`schedule_kind` says which of three timings is authoritative. A
reservation stored before this field existed has no kind and is read as
`cron`, which is what it already was.

| `schedule_kind` | Timing | Field read |
|---|---|---|
| `cron` | A hand-typed five-field cron expression. | `schedule` |
| `recurrence` | A structured recurrence. | `recurrence` |
| `always` | None: capacity is held continuously. | neither |

The two schedules are **peers, not layers**. Neither is derived from the
other and nothing converts between them, because the recurrence is
deliberately more expressive than cron: a step on cron's day-of-week
field steps weekday *indices*, not weeks, and cron cannot count weekdays
within a month at all. A converter would have to round "every other
Tuesday" to an expression that runs on different days from the one the
admin typed, and a lossy conversion used for display is how a page comes
to show a schedule that is not the one being run.

### The structured recurrence

```json
"schedule_kind": "recurrence",
"recurrence": {
  "freq": "weekly",
  "interval": 2,
  "by_weekday": [2],
  "time_of_day": "14:00"
}
```

| Field | Meaning |
|---|---|
| `freq` | `daily`, `weekly` or `monthly`. |
| `interval` | The "every N" — days, weeks or months. Above one it needs a start date. |
| `by_weekday` | Weekdays, `0` for Sunday through `6` for Saturday. Required for `weekly`. |
| `by_monthday` | Days of the month, 1–31. |
| `by_setpos` | `1`–`5` for first through fifth, `-1` last, `-2` next to last, `0` unused. |
| `day_kind` | What `by_setpos` counts when it is not counting one weekday: `day`, `weekday` or `weekend`. |
| `time_of_day` | `HH:MM` on a 24-hour clock, read in the reservation's zone. |

So "every other Tuesday" is `weekly` with `interval: 2` and
`by_weekday: [2]`; "the 1st and the 15th" is `monthly` with
`by_monthday: [1, 15]`; "the last Friday of the month" is `monthly` with
`by_setpos: -1` and `by_weekday: [5]`; and "the first weekday of the
month" is `monthly` with `by_setpos: 1` and `day_kind: "weekday"`.

Three rules are worth knowing because they are where a recurrence can
surprise an operator:

- **A day a period does not have is skipped, not moved.** There is no
  31st of February and no fifth Monday in most months, so those months
  hold no occurrence. Clamping to the 28th or taking the fourth Monday
  would hold capacity on a day nobody booked.
- **An interval is counted from the start date.** The week or month the
  start date falls in is the first one the interval admits, whether or
  not the start date is itself a matching day — so "every other week from
  Wednesday the 4th, on Mondays" means the Monday of the 4th's week and
  every second Monday after. A reservation with an interval above one and
  no start date is refused: "every other week" has no meaning until
  somebody says which week, and anchoring on an arbitrary instant would
  pick the alternating weeks by accident.
- **Times of day are wall clock.** 14:00 stays 14:00 across a daylight
  saving change, so a fortnight across a spring-forward is 14 days on the
  calendar and 335 hours on the clock. A time the spring-forward deleted
  happens at the first instant it exists, never earlier than it says.

### Always on

`"schedule_kind": "always"` holds capacity continuously: no schedule, no
windows, and none of `duration`, `lead` or `hold`, which describe a
window it does not have. It is the standing rule with no window ever
opening — `standing` unused instances kept available at all times, up to
`seats` — so an always-on reservation with no standing capacity caps what
the project may occupy and holds nothing of its own. It can still be
bounded by a start and an end date; a count of occurrences is refused,
since there are none to count.

## The cost rule

Evicting a job that has run less than **30 minutes** is treated as free.
Everything the controller does follows from that one rule, so it is worth
being explicit that it is a *policy choice*, not a measurement: the work
is still discarded, it is just discarded cheaply enough not to count.

Two quantities follow from it. A running job's **age at the bell** is
invariant — the clock advances and the bell approaches by the same amount
— so rankings built on it never flap. And a core is **guaranteed** cheap
only once the bell is within the forgiveness window, because both ways of
qualifying imply it. That is the awkward consequence worth internalising:
**no core is guaranteed until the last 30 minutes**, which is exactly why
a reservation has to hold cores back in advance rather than wait for them
to appear.

## How the drain works

Every minute the controller reads the pool, works out which machines
could host a seat, and holds back more of them than it needs — holding
exactly as many machines as seats leaves no room for the ones that do not
come good. Held machines run a sieve: they admit only jobs predicted to
finish before the bell, or anything at all once the bell is inside the
forgiveness window, where whatever starts is cheap to evict anyway.

Which machines get held is decided by how soon each is likely to free up,
not by how old its current job is. A hold only governs the *next*
admission, so a machine that will still be running the same job at the
bell never makes an admission decision and holding it achieves nothing.

Lead time is what the policy actually runs on. Replaying a month of real
history, six hours of lead produced no evictions of jobs older than half
an hour; two hours was close; one hour was materially worse. The default
is six.

## What it costs

Measured against 25 days of ap2001 history, on 134 GPU cores holding 35
seats with six hours of lead:

| | No reservation | With one |
|---|---|---|
| Evictions of jobs older than 30 min | 7.6 per class | **0** |
| Committed work discarded | 10.8 core-h | 6.7 core-h |
| Setup overhead from extra job starts | 9.3 core-h | 16.3 core-h |
| Idle caused by the sieve | 0% | 0% |

The reservation **reduces** the work discarded, because it evicts younger
jobs. It costs about 0.36% of the drain window's capacity overall, almost
all of it in per-job setup from running more, shorter jobs on held
machines. The sieve itself idles nothing as long as the queue has short
work in it; on a thin queue that would not hold.

A rule of thumb from the same data: if the reservation needs less than
about a fifth of the cores it can draw on, the pool already holds enough
young jobs at any moment and you need no reservation at all — just take
the youngest. Below about two and a half times the class size, no amount
of holding will reach the seats.

## Configuring the execute points

One stanza, once, in the EPs' configuration. Nothing in it changes per
reservation.

```
START = $(START) && ( ReservationStart ?: True )
```

`?:` is the ClassAd defaulting operator: it yields `ReservationStart` when
that is defined and `True` when it is not, so an execute point with no
reservation on it is unconstrained.

**This line has to be in the configuration file.** The access point
cannot install it for you. A startd republishes `START` from its own
configuration every time it refreshes its ad, so a pushed `START` is
overwritten within seconds — and nothing reports a failure. The push is
accepted, the other attributes in it stick, and the machine goes on
admitting everything while the controller counts it as held.

The admin page names any permissible execute point it finds without the
stanza, and shows the line to add. Until you add it, a reservation on
that machine does nothing.

### What the controller does push

`ReservationStart` — the sieve itself — plus the operands it reads.
Those are ordinary attributes and they do stick. Three things about that
mechanism are worth knowing before you deploy it, because they shape
everything above:

- The attributes are **merged per attribute** into one ad shared by every
  slot on the machine. Holding is per machine, not per slot.
- There is **no delete path and no expiry**. An attribute pushed this way
  lives until the startd restarts. That is why the controller pushes
  absolute times rather than flags: a time in the past stops constraining
  anything by itself, so a controller that dies leaves the pool to
  recover on its own.
- For the same reason, **no reservation's name ever appears in an
  attribute name**. The operands use a small fixed set of reusable slots,
  so a semester of classes does not leave hundreds of dead keys on every
  execute point.

| Attribute | |
|---|---|
| `ReservationStart` | the sieve |
| `ReservationDeadline` | the bell, unix seconds. Nothing starts that will not have finished by then. |
| `ReservationUntil` | the end of the window, unix seconds. Past it the machine is the pool's again. |
| `ReservationProject` | the `ProjectName` whose jobs the machine is held for. |

### Authorization

The access point administers an execute point with the capability that
execute point publishes to the collector
(`SEC_ENABLE_REMOTE_ADMINISTRATION`, on by default). The collector hands
it only to a client authorized at ADMINISTRATOR level.

So the access point needs **ADMINISTRATOR at the collector**, and the
execute points need nothing beyond the stanza. If your site has turned
remote administration off, the access point's own identity needs
`ALLOW_WRITE` and `ALLOW_ADMINISTRATOR` on every execute point instead.

An access point that has lost that authorization is the failure worth
watching for: nothing errors, no reservation complains, and every class
starts on a pool that was never drained. The admin page's health check
writes to one randomly chosen execute point every few minutes for no
other reason than to notice.

The access point also says how many execute points it can administer,
on its first read of the pool and whenever the answer changes:

```
reservations: all 48 execute points published an administrative capability
reservations: 31 of 48 execute points published an administrative capability; the rest are commanded as this access point
reservations: none of 48 execute points published an administrative capability, so every command goes as this access point; check that it holds ADMINISTRATOR at the collector and that the execute points have SEC_ENABLE_REMOTE_ADMINISTRATION
```

The last is an error, because it is the state in which nothing works
and nothing else says so. Without a capability the command is still
sent, as the access point itself, and an execute point that never
agreed to take orders from it refuses at authentication — closing the
connection without a reply, so the access point sees a read error
rather than a denial. Every failed command now names which credentials
it carried:

```
sent with this access point's own credentials, because the execute point published no administrative capability: startd: reading the CA_UPDATE_MACHINE_AD reply: ... EOF
```

That is the difference between fixing the collector's authorization and
fixing an execute point's configuration, and it is not visible from the
execute point's own log: on the startd side a capability that was used
shows as `PERMISSION GRANTED to collector-side@matchsession`, and a
fallback shows only `DC_AUTHENTICATE: Command not authorized`.

## What the access point writes to the queue

Reservations need idle jobs to carry an upper bound on how long they
would run — `RuntimeP90Bucket`, in seconds, rounded up to half an hour.
A held execute point refuses a job without one, so **without this a
drain costs the whole machine rather than nothing**.

The access point writes it, every five minutes while a reservation
needs it, from the runtime estimator. It writes the **cluster** ad: a proc inherits the attribute
from its cluster, including for matchmaking, and an idle queue has far
fewer clusters than jobs — 43,567 jobs in 371 clusters on the access
point this was measured on. So a full pass over a large queue is a few
hundred writes, not tens of thousands.

A cluster is stamped with the largest estimate among its idle procs, so
a mixed cluster is described by its longest job and never admits one
that will not fit.

**Each write is made as the owner of the job it edits**, on a
short-lived credential minted for them from the pool's signing key —
one connection and one transaction per owner. A job's own owner may
already edit it, so this asks the schedd for no privilege over anyone's
queue; the access point does **not** need to be a queue superuser, and
making it one would be a far larger grant for the same result. A job
whose ad carries neither `User` nor `Owner` is left unstamped rather
than written as the access point.

This needs a token signing key and a `TRUST_DOMAIN`. Without them there
is no identity to write as, so stamping does not run at all and says so
in the log.

Falling behind is safe: a held machine refuses a job with no stamp and
accepts one with a stale stamp, so a budget too small for the queue
costs admissions and never lets the wrong job in.

Two consequences worth knowing before you turn it on.

**The attribute splits autoclusters.** It is referenced by the execute
points' `START`, so the negotiator reports it to the schedd as a
significant attribute and the schedd groups jobs by it. That cost falls
on the whole pool. Two things keep it small: the estimate is rounded up
to half an hour, and it is capped one grain beyond the longest
reservation's lead — past that the sieve cannot tell two values apart
anyway. On the queue this was measured against, that is 7,765 distinct
values unrounded, 194 rounded, and 13 capped.

Raising a reservation's lead widens the cap, so a longer lead costs a
little more matchmaking.

**A submitter can set the attribute themselves** and the sieve cannot
tell. Eviction does not consult it, so a job that lies its way onto a
reserved core is preempted at the bell like any other.

## When any of this runs

Nothing here touches the pool or the queue while nothing is booked. With
the subsystem switched on but no reservation engaged, the controller,
the stamping pass and the configuration probe each read the reservation
store — which is local — find nothing, and stop there. No collector
query, no queue query, no write to anyone's cluster ad.

A reservation engages the subsystem from the start of its planning lead
until its window has closed and the machines it held have been released,
and the stamping pass and the probe wake twenty minutes ahead of that,
so the queue is stamped and the pool's configuration is confirmed before
the first machine is held. A standing reservation — one with seats held
whether or not a class is in session — engages it throughout its
recurrence.

Outside its recurrence a reservation engages nothing at all, standing
seats included. A term that is over is the case worth being deliberate
about: its windows have stopped coming and nobody is watching it any
more, so a reservation left in the table goes quiet rather than holding
part of the pool for a class that finished.

Deleting or disabling a reservation that is holding machines still
releases them: the controller goes quiet only after a pass that found
nothing reserved and read back a pool with nothing held.

## Turning it on

Off unless configured. A reservation holds capacity by evicting other
people's jobs, so no site starts doing that because it upgraded.

| Setting | |
|---|---|
| `HTTP_API_RESERVATIONS` | `True` runs the subsystem: the admin API, the admin page and the controller. |
| `HTTP_API_RESERVATION_STAMP_BUDGET` | How many cluster ads one stamping pass writes. Defaults to 2000, which covers a far larger queue than most access points have. |
| `HTTP_API_RESERVATION_EP_CONSTRAINT` | A ClassAd expression over the slot ad limiting which execute points reservations may draw seats from. Empty means every startd the collector reports. |

Most sites will want the constraint. A class should take the teaching
nodes, not whatever the collector happens to report:

```
HTTP_API_RESERVATION_EP_CONSTRAINT = TeachingNode =?= True
```

With the subsystem off the endpoints answer `503` naming the setting, and
the admin page is not offered at all.

## Administering them

`/admin/reservations` in the web UI, over
`/api/v1/admin/reservations`. Creating or editing one validates
everything at once — the cron expression, the time zone, the seat counts,
and whether the submit file actually renders — so a mistake comes back to
the form rather than surfacing hours later in a drain.

The page previews the upcoming windows for a schedule, showing both when
capacity is held and when the controller would start draining for each.
Neither a cron expression nor a recurrence reads back easily; nobody
should have to take one on trust. The preview stops where the recurrence
does, so a reservation booked for a term reads as one.

Two endpoints answer it, and they are the same enumeration:

| Endpoint | For |
|---|---|
| `GET /api/v1/admin/reservations/{id}/windows` | A saved reservation. |
| `POST /api/v1/admin/reservations/windows` | A draft in the request body, not yet saved. |

Both take `?days=N` (1–365, two weeks by default) and answer
`{"windows": [...], "schedule_kind": "..."}`. The kind goes with the list
because an empty list has two meanings: an always-on reservation has no
windows because it never stops holding, and a finished one has none
because it is over.

The draft form takes a whole reservation rather than a recurrence alone,
because the windows depend on more than the recurrence — the duration
decides where each one ends and the bounds decide which occurrences exist
at all. It validates only the timing, so a draft can be previewed before
the submit file is written, and it writes nothing.

Schedules are read in a named IANA zone, so a reservation at 14:00 stays
at 14:00 when the offset changes under it.

## Further reading

- [Runtime and drain estimates](server-estimates.md) — where the
  predictions the sieve relies on come from.
- [Configuration](server-config.md)
