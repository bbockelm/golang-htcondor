import { describe, expect, it } from 'vitest';
import type { ClassAd } from '@/lib/api';
import {
  archiveStatus,
  countArchiveStatuses,
  filterAdsByArchiveStatus,
  filterAdsByOwner,
  filterAdsByText,
  ownersOf,
} from './archive';

const history: ClassAd[] = [
  { ClusterId: 1, ProcId: 0, JobStatus: 4, ExitCode: 0, Owner: 'alice', Cmd: '/bin/ok' },
  { ClusterId: 2, ProcId: 0, JobStatus: 4, ExitCode: 127, Owner: 'bob', Cmd: '/bin/missing' },
  { ClusterId: 3, ProcId: 0, JobStatus: 4, ExitBySignal: true, ExitCode: 9, Owner: 'bob', Cmd: '/bin/oom' },
  { ClusterId: 4, ProcId: 0, JobStatus: 3, Owner: 'alice', Cmd: '/bin/gone' },
  { ClusterId: 5, ProcId: 0, JobStatus: 4, Owner: 'carol', Cmd: '/bin/quiet' },
];

describe('archiveStatus', () => {
  it('separates the ways a job can fail', () => {
    expect(archiveStatus(history[0]).key).toBe('completed');
    expect(archiveStatus(history[1]).key).toBe('failed');
    expect(archiveStatus(history[2]).key).toBe('killed');
    expect(archiveStatus(history[3]).key).toBe('removed');
  });

  it('puts the exit code in the label, since that is the actionable part', () => {
    // "Failed" tells you nothing you could act on; "Failed (127)" says
    // the executable was not found.
    expect(archiveStatus(history[1]).label).toBe('Failed (127)');
  });

  it('treats a missing exit code as success, not as failure', () => {
    // The schedd does not always record one. A job that finished with
    // no recorded failure is not a failure.
    expect(archiveStatus(history[4]).key).toBe('completed');
  });

  it('does not read a signalled job\'s exit code as an exit status', () => {
    // ExitCode beside ExitBySignal is whatever happened to be in the
    // ad; calling it "Failed (9)" would invent an exit status.
    expect(archiveStatus(history[2]).label).toBe('Killed');
  });
});

describe('archive filters', () => {
  it('counts each outcome', () => {
    const counts = countArchiveStatuses(history);
    expect(counts.completed).toBe(2);
    expect(counts.failed).toBe(1);
    expect(counts.killed).toBe(1);
    expect(counts.removed).toBe(1);
  });

  it('treats an empty status selection as no filter', () => {
    expect(filterAdsByArchiveStatus(history, new Set())).toHaveLength(5);
  });

  it('narrows to the selected outcomes', () => {
    const bad = filterAdsByArchiveStatus(history, new Set(['failed', 'killed'] as const));
    expect(bad.map((a) => a.ClusterId)).toEqual([2, 3]);
  });

  it('narrows to one user exactly, not by substring', () => {
    expect(filterAdsByOwner(history, 'bob').map((a) => a.ClusterId)).toEqual([2, 3]);
    // A substring match would make "bob" also select "bobby".
    expect(filterAdsByOwner([{ Owner: 'bobby' }], 'bob')).toHaveLength(0);
    expect(filterAdsByOwner(history, '')).toHaveLength(5);
  });

  it('keeps the selected user in the picker when nothing loaded is theirs', () => {
    // The other filters can leave the loaded set with none of the
    // selected user's records -- pick carol, then narrow to the failed
    // jobs, and she has none. Dropping her from the options would make
    // the control that produced this state disappear, leaving the user
    // looking at an empty table with no way back.
    const noCarol = filterAdsByArchiveStatus(history, new Set(['failed'] as const));
    expect(ownersOf(noCarol, 'carol')).toEqual(['bob', 'carol']);
    expect(ownersOf([], 'carol')).toEqual(['carol']);
    expect(ownersOf(history)).toEqual(['alice', 'bob', 'carol']);
  });

  it('matches text against the outcome label as well as the fields', () => {
    expect(filterAdsByText(history, 'killed').map((a) => a.ClusterId)).toEqual([3]);
    expect(filterAdsByText(history, 'bob missing').map((a) => a.ClusterId)).toEqual([2]);
  });
});
