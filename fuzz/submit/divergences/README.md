# Recorded divergences

One file per attribute the differential harness does not fail on. The file's
name is the attribute, lower-cased; the file's contents are the reason, which
is the text the report prints beside the attribute.

```
seed/<attr>.md                  a divergence the hand-written seeds reach
generated/<attr>.md             one only the generated corpus reaches
host/<attr>.md                  not a divergence: the value is host-derived,
                                so the two sides cannot agree by construction
universe/<universe>/<attr>.md   excused inside one job universe only
```

`seed/` and `generated/` are compared identically — the split records which
sweep found a divergence, nothing more. `divergences.go` loads all of it with
`go:embed` into the maps `record()` consults.

## Adding one

Write the file. The reason is a finding, not an excuse: say what the
difference IS, what reads the attribute, and what the consequence is for a
job. "Go does not implement X" is a starting point, not a reason.

## When the sweep cannot prove it

`TestRecordedDivergencesStillDiverge` decides an entry is stale from an
ABSENCE: the attribute was compared and never diverged. That reasoning does
not hold for every entry — some are about something the merged-ad comparison
cannot see, like WHERE an attribute is written, and some need a submit file
the generator does not write. An entry like that ends with

```
Sweep cannot prove this: <why, and what checks it instead>
```

and the sweep reports it instead of failing. The reason has to name what does
check the entry, so the marker cannot become a way to park an entry nothing
looks at.

## Removing one

Delete the file. That is how a fix gets locked in:
`TestRecordedDivergencesStillDiverge` fails when an entry stops reproducing,
so an entry left behind after a fix is a test failure rather than a quiet
hole in the comparison.

Each entry being its own file is deliberate. Several fixes land in the same
week, each one deleting an entry, and as map literals they conflicted with
each other every time — on the one file whose merge rule is easy to get
wrong, since an entry deleted by *either* side is a fix and the resolution is
the intersection. Separate files make that rule structural.

A `host/` entry is held to a different standard: it is a hole in the oracle,
not a finding, and every one of them is a comparison that is not happening.
Keep that directory short and justify each file.
