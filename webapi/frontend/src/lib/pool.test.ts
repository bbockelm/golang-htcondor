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

// The backfill partition on the SAME machine, as CHTC advertises it: a
// second partitionable slot flagged BackfillSlot that re-advertises the
// machine's Total* and reports its own (residual) free. Here it has carved
// out most of the machine to 20 backfill jobs: 16 cpu / 1 GPU left free.
const backfillSlot: ClassAd = {
  Name: 'backfill1@gpu1',
  Machine: 'gpu1',
  SlotType: 'Partitionable',
  PartitionableSlot: true,
  BackfillSlot: true,
  Cpus: 16,
  Memory: 24576,
  GPUs: 1,
  TotalCpus: 128,
  TotalMemory: 524288,
  TotalGPUs: 8,
  NumDynamicSlots: 20,
  State: 'Unclaimed',
  Activity: 'Idle',
};

// A machine whose primary partition is idle (all free) but whose backfill
// partition is nearly full -- the case that used to report 0 used.
const idlePrimaryBackfillNode: ClassAd[] = [
  {
    Name: 'slot1@e1',
    Machine: 'e1',
    SlotType: 'Partitionable',
    PartitionableSlot: true,
    Cpus: 128,
    GPUs: 8,
    TotalCpus: 128,
    TotalGPUs: 8,
    NumDynamicSlots: 0,
    State: 'Unclaimed',
  },
  {
    Name: 'backfill1@e1',
    Machine: 'e1',
    SlotType: 'Partitionable',
    PartitionableSlot: true,
    BackfillSlot: true,
    Cpus: 4,
    GPUs: 1,
    TotalCpus: 128,
    TotalGPUs: 8,
    NumDynamicSlots: 80,
    State: 'Unclaimed',
  },
];

describe('usageFor', () => {
  it('reads the capital-GPU total and derives GPU usage from the leftover', () => {
    const u = usageFor(gpuNode.map(parseSlot));
    expect(u.totalGpus).toBe(8); // TotalGPUs, not the mis-cased TotalGpus
    expect(u.usedGpus).toBe(6); // 8 total - 2 free
    expect(u.totalCpus).toBe(128);
    expect(u.usedCpus).toBe(96); // 128 - 32
  });

  it('counts backfill usage without double-counting machine capacity', () => {
    const withBackfill = [...gpuNode, backfillSlot].map(parseSlot);
    const u = usageFor(withBackfill);
    // Capacity is the machine's, counted once (not 256/16).
    expect(u.totalCpus).toBe(128);
    expect(u.totalGpus).toBe(8);
    // Used is driven by the residual free = min across the two partitions:
    // cpu min(32,16)=16 -> 112 used; gpu min(2,1)=1 -> 7 used.
    expect(u.usedCpus).toBe(112);
    expect(u.usedGpus).toBe(7);
  });

  it('shows a node as used when only its backfill partition is busy', () => {
    const u = usageFor(idlePrimaryBackfillNode.map(parseSlot));
    expect(u.totalCpus).toBe(128);
    expect(u.usedCpus).toBe(124); // 128 - min(128, 4)
    expect(u.totalGpus).toBe(8);
    expect(u.usedGpus).toBe(7); // 8 - min(8, 1)
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
  it('uses NumDynamicSlots and includes backfill jobs', () => {
    // primary 6 + backfill 20 = 26 real running jobs on the node.
    expect(runningJobsFor([...gpuNode, backfillSlot].map(parseSlot))).toBe(26);
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
    expect(s.runningJobs).toBe(26); // primary 6 + backfill 20
    expect(s.ownerNodes).toBe(1); // ep2
    expect(s.backfillCpus).toBe(112); // backfill partition: 128 total - 16 free
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
