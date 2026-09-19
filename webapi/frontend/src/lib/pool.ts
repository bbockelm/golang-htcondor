// Pool-overview helpers: turn the collector's raw StartdAd ClassAds into
// the typed slots, per-execute-node groups, and capacity/usage totals the
// /pool page renders. Pure functions so they can be unit-tested without a
// collector.

import type { ClassAd } from '@/lib/api';

// num/str/bool read a ClassAd attribute defensively: collector ads arrive
// as JSON where numbers are numbers and strings are strings, but an
// attribute may be absent or (rarely) an unevaluated expression string.
export function num(ad: ClassAd, key: string): number | undefined {
  const v = ad[key];
  if (typeof v === 'number') return v;
  if (typeof v === 'string' && v.trim() !== '' && !Number.isNaN(Number(v))) {
    return Number(v);
  }
  return undefined;
}

export function str(ad: ClassAd, key: string): string | undefined {
  const v = ad[key];
  return typeof v === 'string' ? v : undefined;
}

export function bool(ad: ClassAd, key: string): boolean {
  const v = ad[key];
  if (typeof v === 'boolean') return v;
  if (typeof v === 'string') return v.toLowerCase() === 'true';
  return false;
}

export interface Slot {
  name: string; // Name, e.g. "slot1_2@host" — the collector by-name key
  machine: string; // Machine
  slotType: string; // "Partitionable" | "Dynamic" | "Static" | ""
  partitionable: boolean;
  dynamic: boolean;
  cpus?: number; // Cpus (this slot)
  memoryMB?: number; // Memory
  diskKB?: number; // Disk
  gpus?: number; // GPUs
  totalCpus?: number; // TotalCpus (machine-wide)
  totalMemoryMB?: number; // TotalMemory
  totalGpus?: number; // TotalGpus
  state?: string; // State
  activity?: string; // Activity
  remoteOwner?: string; // RemoteOwner (who is running here, if claimed)
  arch?: string; // Arch
  opsys?: string; // OpSysAndVer || OpSys
  raw: ClassAd;
}

export function parseSlot(ad: ClassAd): Slot {
  const slotType = str(ad, 'SlotType') ?? '';
  return {
    name: str(ad, 'Name') ?? '',
    machine: str(ad, 'Machine') ?? str(ad, 'Name') ?? '',
    slotType,
    partitionable: bool(ad, 'PartitionableSlot') || slotType === 'Partitionable',
    dynamic: bool(ad, 'DynamicSlot') || slotType === 'Dynamic',
    cpus: num(ad, 'Cpus'),
    memoryMB: num(ad, 'Memory'),
    diskKB: num(ad, 'Disk'),
    gpus: num(ad, 'GPUs'),
    totalCpus: num(ad, 'TotalCpus'),
    totalMemoryMB: num(ad, 'TotalMemory'),
    totalGpus: num(ad, 'TotalGpus'),
    state: str(ad, 'State'),
    activity: str(ad, 'Activity'),
    remoteOwner: str(ad, 'RemoteOwner'),
    arch: str(ad, 'Arch'),
    opsys: str(ad, 'OpSysAndVer') ?? str(ad, 'OpSys'),
    raw: ad,
  };
}

// The projection the /pool query requests. Anything not listed is not
// returned by the collector, so keep this in sync with parseSlot.
export const SLOT_PROJECTION = [
  'Name',
  'Machine',
  'SlotType',
  'PartitionableSlot',
  'DynamicSlot',
  'Cpus',
  'Memory',
  'Disk',
  'GPUs',
  'TotalCpus',
  'TotalMemory',
  'TotalDisk',
  'TotalGpus',
  'State',
  'Activity',
  'RemoteOwner',
  'Arch',
  'OpSys',
  'OpSysAndVer',
].join(',');

// A slot counts as "in use" when it holds a claim. A partitionable slot is
// never itself in use — its Cpus/Memory are the machine's UNALLOCATED
// leftovers; the claims live in the dynamic slots carved off it.
export function slotInUse(s: Slot): boolean {
  return !s.partitionable && s.state === 'Claimed';
}

export interface ResourceUsage {
  usedCpus: number;
  totalCpus: number;
  usedMemoryMB: number;
  totalMemoryMB: number;
  usedGpus: number;
  totalGpus: number;
}

// usageFor computes used-vs-total over a set of slots, matching how
// condor_status accounts a partitionable pool: total is the machine
// capacity (TotalCpus, counted once per machine), used is the resources
// held by claimed non-partitionable slots (dynamic carve-outs + claimed
// static slots).
export function usageFor(slots: Slot[]): ResourceUsage {
  const u: ResourceUsage = {
    usedCpus: 0,
    totalCpus: 0,
    usedMemoryMB: 0,
    totalMemoryMB: 0,
    usedGpus: 0,
    totalGpus: 0,
  };
  const seenMachine = new Set<string>();
  for (const s of slots) {
    if (!seenMachine.has(s.machine)) {
      seenMachine.add(s.machine);
      u.totalCpus += s.totalCpus ?? 0;
      u.totalMemoryMB += s.totalMemoryMB ?? 0;
      u.totalGpus += s.totalGpus ?? 0;
    }
    if (slotInUse(s)) {
      u.usedCpus += s.cpus ?? 0;
      u.usedMemoryMB += s.memoryMB ?? 0;
      u.usedGpus += s.gpus ?? 0;
    }
  }
  return u;
}

export interface NodeGroup {
  machine: string;
  slots: Slot[];
  usage: ResourceUsage;
  stateCounts: Record<string, number>;
}

// groupByMachine collapses the flat slot list into one group per execute
// node, each with its own usage totals and a State breakdown, sorted by
// machine name.
export function groupByMachine(slots: Slot[]): NodeGroup[] {
  const byMachine = new Map<string, Slot[]>();
  for (const s of slots) {
    const arr = byMachine.get(s.machine);
    if (arr) arr.push(s);
    else byMachine.set(s.machine, [s]);
  }
  const groups: NodeGroup[] = [];
  for (const [machine, machineSlots] of byMachine) {
    const stateCounts: Record<string, number> = {};
    for (const s of machineSlots) {
      const k = s.state ?? 'Unknown';
      stateCounts[k] = (stateCounts[k] ?? 0) + 1;
    }
    groups.push({
      machine,
      slots: machineSlots,
      usage: usageFor(machineSlots),
      stateCounts,
    });
  }
  groups.sort((a, b) => a.machine.localeCompare(b.machine));
  return groups;
}

export interface PoolSummary {
  machines: number;
  slots: number;
  usage: ResourceUsage;
  stateCounts: Record<string, number>;
}

export function summarize(slots: Slot[]): PoolSummary {
  const machines = new Set<string>();
  const stateCounts: Record<string, number> = {};
  for (const s of slots) {
    machines.add(s.machine);
    const k = s.state ?? 'Unknown';
    stateCounts[k] = (stateCounts[k] ?? 0) + 1;
  }
  return {
    machines: machines.size,
    slots: slots.length,
    usage: usageFor(slots),
    stateCounts,
  };
}

// slotStateStyle maps a slot State to a Tailwind pill (bg/text) — green
// for available (Unclaimed), indigo for in-use (Claimed), amber for
// transitional (Draining/Matched/Preempting), gray otherwise.
export function slotStateStyle(state: string | undefined): string {
  switch (state) {
    case 'Unclaimed':
      return 'bg-green-100 text-green-800';
    case 'Claimed':
      return 'bg-indigo-100 text-indigo-800';
    case 'Owner':
      return 'bg-gray-100 text-gray-700';
    case 'Matched':
    case 'Draining':
    case 'Drained':
    case 'Preempting':
      return 'bg-amber-100 text-amber-800';
    default:
      return 'bg-gray-100 text-gray-600';
  }
}

// gib formats a MiB count as a compact GiB string for display.
export function gib(mib: number | undefined): string {
  if (mib === undefined) return '—';
  return `${(mib / 1024).toFixed(mib < 1024 * 10 ? 1 : 0)} GiB`;
}

// textHaystack is the lowercased blob the free-text filter matches a slot
// against: identity, platform, state, and the current owner.
export function textHaystack(s: Slot): string {
  return [
    s.name,
    s.machine,
    s.slotType,
    s.state,
    s.activity,
    s.remoteOwner,
    s.arch,
    s.opsys,
  ]
    .filter(Boolean)
    .join(' ')
    .toLowerCase();
}
