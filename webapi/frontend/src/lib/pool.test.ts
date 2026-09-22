import { describe, expect, it } from 'vitest';
import type { ClassAd } from './api';
import {
  gpuDevices,
  groupByMachine,
  parseSlot,
  runningJobsFor,
  summarize,
  usageFor,
} from './pool';

// A GPU machine as a partitionable slot: 128 cpus / 8 GPUs total, 32 cpus
// and 2 GPUs free, 6 running jobs. Note the capital-GPU attribute spelling
// the startd actually publishes (TotalGPUs, not TotalGpus).
const gpuNode: ClassAd[] = [
  {
    Name: 'slot1@gpu1',
    Machine: 'gpu1',
    SlotType: 'Partitionable',
    PartitionableSlot: true,
    Cpus: 32,
    Memory: 131072,
    GPUs: 2,
    TotalCpus: 128,
    TotalMemory: 524288,
    TotalGPUs: 8,
    NumDynamicSlots: 6,
    State: 'Unclaimed',
    Activity: 'Idle',
  },
];

// A backfill slot on the same machine re-advertising the same cores/GPUs.
const backfillSlot: ClassAd = {
  Name: 'slot1_backfill@gpu1',
  Machine: 'gpu1',
  SlotType: 'Backfill',
  BackfillSlot: true,
  Cpus: 96,
  Memory: 393216,
  GPUs: 6,
  TotalCpus: 128,
  TotalMemory: 524288,
  TotalGPUs: 8,
  State: 'Claimed',
  Activity: 'Busy',
};

describe('usageFor', () => {
  it('reads the capital-GPU total and derives GPU usage from the leftover', () => {
    const u = usageFor(gpuNode.map(parseSlot));
    expect(u.totalGpus).toBe(8); // TotalGPUs, not the mis-cased TotalGpus
    expect(u.usedGpus).toBe(6); // 8 total - 2 free
    expect(u.totalCpus).toBe(128);
    expect(u.usedCpus).toBe(96); // 128 - 32
  });

  it('excludes backfill slots from capacity and usage (they overlap primary cores)', () => {
    const withBackfill = [...gpuNode, backfillSlot].map(parseSlot);
    const u = usageFor(withBackfill);
    // Totals and usage are unchanged by the backfill slot: no double count.
    expect(u.totalCpus).toBe(128);
    expect(u.usedCpus).toBe(96);
    expect(u.totalGpus).toBe(8);
    expect(u.usedGpus).toBe(6);
  });

  it('is case-insensitive about attribute names (ClassAds are)', () => {
    const lowered: ClassAd = {
      name: 'slot1@x',
      machine: 'x',
      slottype: 'Partitionable',
      partitionableslot: true,
      cpus: 4,
      totalcpus: 16,
      gpus: 1,
      totalgpus: 4,
      state: 'Unclaimed',
    };
    const u = usageFor([parseSlot(lowered)]);
    expect(u.totalCpus).toBe(16);
    expect(u.usedCpus).toBe(12);
    expect(u.totalGpus).toBe(4);
    expect(u.usedGpus).toBe(3);
  });
});

describe('runningJobsFor', () => {
  it('uses NumDynamicSlots on a partitionable slot and skips backfill', () => {
    expect(runningJobsFor([...gpuNode, backfillSlot].map(parseSlot))).toBe(6);
  });
  it('counts a claimed static slot as one job', () => {
    const staticSlots: ClassAd[] = [
      { Name: 's1@ep', Machine: 'ep', SlotType: 'Static', Cpus: 1, TotalCpus: 2, State: 'Claimed' },
      { Name: 's2@ep', Machine: 'ep', SlotType: 'Static', Cpus: 1, TotalCpus: 2, State: 'Unclaimed' },
    ];
    expect(runningJobsFor(staticSlots.map(parseSlot))).toBe(1);
  });
});

describe('summarize', () => {
  it('counts primary machines, running jobs, owner nodes, and backfill cpus', () => {
    const ownerNode: ClassAd = {
      Name: 'slot1@ep2',
      Machine: 'ep2',
      SlotType: 'Partitionable',
      PartitionableSlot: true,
      Cpus: 8,
      TotalCpus: 8,
      NumDynamicSlots: 0,
      State: 'Owner',
    };
    const s = summarize([...gpuNode, backfillSlot, ownerNode].map(parseSlot));
    expect(s.machines).toBe(2); // gpu1, ep2 (backfill is on gpu1, not a new machine)
    expect(s.runningJobs).toBe(6);
    expect(s.ownerNodes).toBe(1); // ep2
    expect(s.backfillCpus).toBe(96); // the claimed backfill slot
  });
});

describe('groupByMachine', () => {
  it('marks an Owner node and keeps its usage', () => {
    const groups = groupByMachine(gpuNode.map(parseSlot));
    expect(groups).toHaveLength(1);
    expect(groups[0].owner).toBe(false);
    expect(groups[0].runningJobs).toBe(6);
    expect(groups[0].usage.usedGpus).toBe(6);
  });
});

describe('gpuDevices', () => {
  it('reads flat CUDA* device properties', () => {
    const devs = gpuDevices({
      AssignedGPUs: 'CUDA0',
      CUDADeviceName: 'NVIDIA A100',
      CUDACapability: '8.0',
      CUDAGlobalMemoryMb: 40960,
      CUDADriverVersion: '12.2',
    });
    expect(devs).toHaveLength(1);
    expect(devs[0].name).toBe('NVIDIA A100');
    expect(devs[0].capability).toBe('8.0');
    expect(devs[0].globalMemoryMb).toBe(40960);
  });

  it('reads nested per-device ads as HTCondor publishes them', () => {
    // The nested ad is at <Resource>_<sanitized id> (GPUs_GPU_aaaa), not at
    // the bare device id, and carries an Id echoing AssignedGPUs. Capability
    // lives only in the common GPUs_* props; DriverVersion is a number.
    const devs = gpuDevices({
      AssignedGPUs: 'GPU-aaaa, GPU-bbbb',
      GPUs_Capability: 9,
      GPUs_DriverVersion: 12.6,
      GPUs_GPU_aaaa: {
        Id: 'GPU-aaaa',
        DeviceName: 'H100',
        GlobalMemoryMb: 81920,
        DriverVersion: 12.6,
      },
      GPUs_GPU_bbbb: {
        Id: 'GPU-bbbb',
        DeviceName: 'H100',
        GlobalMemoryMb: 81920,
        DriverVersion: 12.6,
      },
    });
    expect(devs.map((d) => d.id)).toEqual(['GPU-aaaa', 'GPU-bbbb']);
    expect(devs[0].name).toBe('H100');
    expect(devs[0].capability).toBe('9'); // number coerced, from the common prop
    expect(devs[0].driverVersion).toBe('12.6'); // number coerced
    expect(devs[1].globalMemoryMb).toBe(81920);
  });

  it('returns [] for a CPU-only slot', () => {
    expect(gpuDevices({ Name: 'slot1@x', Cpus: 4 })).toEqual([]);
  });
});
