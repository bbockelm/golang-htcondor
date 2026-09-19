import { describe, expect, it } from 'vitest';
import type { ClassAd } from './api';
import { groupByMachine, parseSlot, summarize, usageFor } from './pool';

// A partitionable machine: the partitionable slot holds the UNALLOCATED
// leftovers (2 cpus free), and a claimed dynamic slot holds the 6 in use.
// TotalCpus=8 is the machine capacity, repeated on every slot ad.
const partitionableMachine: ClassAd[] = [
  {
    Name: 'slot1@ep1',
    Machine: 'ep1',
    SlotType: 'Partitionable',
    PartitionableSlot: true,
    Cpus: 2,
    Memory: 4096,
    GPUs: 0,
    TotalCpus: 8,
    TotalMemory: 16384,
    TotalGpus: 0,
    State: 'Unclaimed',
    Activity: 'Idle',
  },
  {
    Name: 'slot1_1@ep1',
    Machine: 'ep1',
    SlotType: 'Dynamic',
    DynamicSlot: true,
    Cpus: 6,
    Memory: 12288,
    GPUs: 0,
    TotalCpus: 8,
    TotalMemory: 16384,
    TotalGpus: 0,
    State: 'Claimed',
    Activity: 'Busy',
    RemoteOwner: 'alice@ep1',
  },
];

// A static machine: two fixed slots, one claimed one idle. Capacity is the
// sum of the static slots (TotalCpus reports the machine total, 2).
const staticMachine: ClassAd[] = [
  {
    Name: 'slot1@ep2',
    Machine: 'ep2',
    SlotType: 'Static',
    Cpus: 1,
    Memory: 1024,
    TotalCpus: 2,
    TotalMemory: 2048,
    State: 'Claimed',
    Activity: 'Busy',
  },
  {
    Name: 'slot2@ep2',
    Machine: 'ep2',
    SlotType: 'Static',
    Cpus: 1,
    Memory: 1024,
    TotalCpus: 2,
    TotalMemory: 2048,
    State: 'Unclaimed',
    Activity: 'Idle',
  },
];

describe('usageFor', () => {
  it('counts the dynamic carve-out as used and the partitionable leftover as free', () => {
    const u = usageFor(partitionableMachine.map(parseSlot));
    expect(u.totalCpus).toBe(8); // machine capacity, counted once
    expect(u.usedCpus).toBe(6); // the claimed dynamic slot
    expect(u.usedMemoryMB).toBe(12288);
    // The partitionable slot itself is never counted as used even though
    // it is a slot with Cpus.
  });

  it('counts a claimed static slot as used and an idle one as free', () => {
    const u = usageFor(staticMachine.map(parseSlot));
    expect(u.totalCpus).toBe(2); // TotalCpus counted once per machine
    expect(u.usedCpus).toBe(1); // only the Claimed static slot
  });

  it('does not double-count TotalCpus across a machine with many slots', () => {
    const u = usageFor(
      [...partitionableMachine, ...staticMachine].map(parseSlot),
    );
    expect(u.totalCpus).toBe(10); // 8 (ep1) + 2 (ep2), not per-slot
    expect(u.usedCpus).toBe(7); // 6 (ep1 dynamic) + 1 (ep2 static)
  });
});

describe('groupByMachine', () => {
  it('groups slots by machine and sorts by name', () => {
    const groups = groupByMachine(
      [...staticMachine, ...partitionableMachine].map(parseSlot),
    );
    expect(groups.map((g) => g.machine)).toEqual(['ep1', 'ep2']);
    expect(groups[0].slots).toHaveLength(2);
    expect(groups[0].usage.usedCpus).toBe(6);
    expect(groups[0].stateCounts).toEqual({ Unclaimed: 1, Claimed: 1 });
  });
});

describe('summarize', () => {
  it('reports distinct machines, total slots, and pool-wide usage', () => {
    const s = summarize(
      [...partitionableMachine, ...staticMachine].map(parseSlot),
    );
    expect(s.machines).toBe(2);
    expect(s.slots).toBe(4);
    expect(s.usage.totalCpus).toBe(10);
    expect(s.usage.usedCpus).toBe(7);
  });
});

describe('parseSlot', () => {
  it('coerces string-valued numbers and detects partitionable via SlotType', () => {
    const s = parseSlot({
      Name: 'slot1@x',
      Machine: 'x',
      SlotType: 'Partitionable',
      Cpus: '4', // some fields can arrive as strings
      TotalCpus: 4,
    });
    expect(s.cpus).toBe(4);
    expect(s.partitionable).toBe(true);
  });
});
