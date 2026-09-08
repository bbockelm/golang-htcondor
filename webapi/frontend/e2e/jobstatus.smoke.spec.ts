import { expect, test } from '@playwright/test';

import { interpretJobStatus, STATUS_AD_ATTRS } from '../src/lib/jobStatus';

// The job watch sends a projection, not the whole ad. If that projection
// omits an attribute interpretJobStatus reads, the page reaches a state
// it can never leave -- and the stream looks perfectly healthy while it
// happens, because it is: it is carrying the wrong columns.
//
// That shipped once. The projection had JobCurrentStartDate (when the
// job was matched) and not JobCurrentStartExecutingDate (when the
// executable began), so a running session sat on "Transferring input"
// indefinitely while a fresh tab, which fetches the whole ad, was right.
//
// This runs the interpreter against ads containing ONLY the projected
// attributes. An attribute the state machine needs but nobody streams
// disappears in the filter and the status it gates becomes unreachable.

type Ad = Record<string, unknown>;

function projected(ad: Ad): Ad {
  const out: Ad = {};
  for (const k of STATUS_AD_ATTRS) {
    if (k in ad) out[k] = ad[k];
  }
  return out;
}

const cases: { status: string; ad: Ad }[] = [
  { status: 'idle', ad: { JobStatus: 1 } },
  // JobStatus 2 with no executing date: the pre-execution phase.
  { status: 'transferring_input', ad: { JobStatus: 2 } },
  // The case that was unreachable.
  { status: 'executing', ad: { JobStatus: 2, JobCurrentStartExecutingDate: 1788700000 } },
  { status: 'removed', ad: { JobStatus: 3 } },
  { status: 'closed', ad: { JobStatus: 4 } },
  { status: 'spooling', ad: { JobStatus: 5, HoldReasonCode: 16 } },
  { status: 'held', ad: { JobStatus: 5, HoldReasonCode: 3 } },
];

for (const c of cases) {
  test(`${c.status} is reachable from the streamed projection`, async () => {
    // Sanity: the full ad produces it. If this fails the expectation is
    // wrong, not the projection.
    expect(interpretJobStatus({ job: c.ad as never }), 'full ad').toBe(c.status);

    // And the projection carries enough to produce it too.
    expect(
      interpretJobStatus({ job: projected(c.ad) as never }),
      `${c.status} needs an attribute STATUS_AD_ATTRS does not list`,
    ).toBe(c.status);
  });
}
