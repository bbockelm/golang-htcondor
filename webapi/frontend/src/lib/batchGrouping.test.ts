import { describe, expect, it } from 'vitest';
import { readFileSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { groupIntoBatches, type Batch } from './batches';
import type { ClassAd } from './api';

// What a batch is, pinned between this file's groupIntoBatches and the
// server's port of it (webapi/batches): both are checked against the same
// fixture, so a change to either rule has to change the fixture -- and
// with it the other side. Read at run time rather than imported: the
// release image builds the frontend without the rest of the tree.

interface Expected {
  batchID: number;
  name: string;
  owner?: string;
  isDag: boolean;
  jobCount: number;
  clusterIds: number[];
  submittedUnix?: number;
  statusCounts: Record<string, number>;
  dagNodes: Batch['dagNodes'] | null;
  selectConstraint: string;
  removeConstraint: string;
}

interface Fixture {
  cases: { name: string; ads: ClassAd[]; expected: Expected[] }[];
}

const here = path.dirname(fileURLToPath(import.meta.url));
const fixture = JSON.parse(
  readFileSync(path.resolve(here, '../../../batches/testdata/grouping.json'), 'utf8'),
) as Fixture;

function nonZero(counts: Record<string, number>): Record<string, number> {
  return Object.fromEntries(Object.entries(counts).filter(([, n]) => n !== 0));
}

describe('groupIntoBatches matches webapi/batches/testdata/grouping.json', () => {
  it('has cases', () => {
    expect(fixture.cases.length).toBeGreaterThan(0);
  });

  it.each(fixture.cases.map((c) => [c.name, c] as const))('%s', (_name, c) => {
    const got = groupIntoBatches(c.ads).map((b) => ({
      batchID: b.batchID,
      name: b.name,
      owner: b.owner,
      isDag: b.isDag,
      jobCount: b.jobCount,
      clusterIds: [...b.clusterIds].sort((x, y) => x - y),
      submittedUnix: b.submittedUnix,
      statusCounts: nonZero(b.statusCounts),
      dagNodes: b.dagNodes,
      selectConstraint: b.selectConstraint,
      removeConstraint: b.removeConstraint,
    }));
    const want = c.expected.map((e) => ({
      batchID: e.batchID,
      name: e.name,
      owner: e.owner,
      isDag: e.isDag,
      jobCount: e.jobCount,
      clusterIds: [...e.clusterIds].sort((x, y) => x - y),
      submittedUnix: e.submittedUnix,
      statusCounts: e.statusCounts,
      dagNodes: e.dagNodes ?? undefined,
      selectConstraint: e.selectConstraint,
      removeConstraint: e.removeConstraint,
    }));
    expect(got).toEqual(want);
  });
});
