# Reservations

Holding pool capacity for a project at recurring times — a class, a demo,
anything with a timetable — without throwing away work that was already
running. Part of the [HTTP API + MCP server](server.md) documentation.

## What a reservation is

A reservation names a **project**, a **seat** described by a submit file,
how many seats it needs (`seats`), how many to keep between windows
(`standing`), and a five-field cron **schedule** with a duration. Jobs
claim a seat by carrying the project as their `ProjectName`.

Each occurrence is a **window**. The moment it opens is the **bell**.
Before the bell the controller holds cores back so the seats are cheap to
free when it rings; after it, unclaimed seats stay reserved for the
project for `hold` (15 minutes by default) and then return to the pool.

Occurrences close together are one window. Two back-to-back classes are
one hold: releasing cores between them and draining again costs more than
keeping them, and a gap shorter than the forgiveness threshold is free
either way.

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

One stanza, once, on the EPs. Nothing in it changes per reservation.

```
START = $(START) && ( ReservationStart =?= undefined || ReservationStart )
```

The controller pushes `ReservationStart` as a complete expression, plus
the operands it refers to, into the machine ad.

Three things about that mechanism are worth knowing before you deploy it,
because they shape everything above:

- The attributes are **merged per attribute** into one ad shared by every
  slot on the machine. Holding is per machine, not per slot.
- There is **no delete path and no expiry**. An attribute pushed this way
  lives until the startd restarts. That is why the controller pushes
  absolute deadlines rather than flags: a deadline in the past stops
  constraining anything by itself, so a controller that dies leaves the
  pool to recover on its own.
- For the same reason, **no reservation's name ever appears in an
  attribute name**. The operands use a small fixed set of reusable slots,
  so a semester of classes does not leave hundreds of dead keys on every
  execute point.

## Administering them

`/admin/reservations` in the web UI, over
`/api/v1/admin/reservations`. Creating or editing one validates
everything at once — the cron expression, the time zone, the seat counts,
and whether the submit file actually renders — so a mistake comes back to
the form rather than surfacing hours later in a drain.

The page previews the upcoming windows for a schedule, showing both when
seats are held and when the controller would start draining for each.
A cron expression is unreadable; nobody should have to take it on trust.

Schedules are read in a named IANA zone, so a class at 14:00 stays at
14:00 when the offset changes under it.

## Further reading

- [Runtime and drain estimates](server-estimates.md) — where the
  predictions the sieve relies on come from.
- [Configuration](server-config.md)
