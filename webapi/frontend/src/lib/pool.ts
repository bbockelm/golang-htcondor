// Pool-overview helpers: turn the collector's raw StartdAd ClassAds into
// typed slots, per-execute-node groups, and capacity/usage totals. Pure
// functions so they can be unit-tested without a collector.
//
// Two facts from HTCondor drive this file:
//   - ClassAd attribute names are case-INSENSITIVE, but the collector JSON
//     keys arrive in whatever case the daemon emitted (GPUs, TotalGPUs,
//     capital GPU). So every read goes through a lowercased index.
//   - Usage matches condor_status -compact: total comes from the machine
//     Total* attrs, "free" from the bare Cpus/Memory/GPUs on the
//     partitionable slot, and used = total - free. Backfill slots
//     re-advertise the same physical resources and must not be counted.

import type { ClassAd } from '@/lib/api';

// AdIndex maps lowercased attribute name -> value, so lookups are
// case-insensitive like real ClassAds.
type AdIndex = Map<string, unknown>;

function indexAd(ad: ClassAd): AdIndex {
  const m: AdIndex = new Map();
  for (const k of Object.keys(ad)) m.set(k.toLowerCase(), ad[k]);
  return m;
}

function inum(m: AdIndex, key: string): number | undefined {
  const v = m.get(key.toLowerCase());
  if (typeof v === 'number') return v;
  if (typeof v === 'string' && v.trim() !== '' && !Number.isNaN(Number(v))) {
    return Number(v);
  }
  return undefined;
}

function istr(m: AdIndex, key: string): string | undefined {
  const v = m.get(key.toLowerCase());
  return typeof v === 'string' ? v : undefined;
}

function ibool(m: AdIndex, key: string): boolean {
  const v = m.get(key.toLowerCase());
  if (typeof v === 'boolean') return v;
  if (typeof v === 'string') return v.toLowerCase() === 'true';
  return false;
}

export interface Slot {
  name: string;
  machine: string;
  slotType: string;
  partitionable: boolean;
  dynamic: boolean;
  backfill: boolean; // BackfillSlot; re-advertises primary resources
  cpus?: number; // Cpus (free, on a partitionable slot)
  memoryMB?: number; // Memory
  diskKB?: number; // Disk
  gpus?: number; // GPUs (free on a partitionable slot)
  totalCpus?: number; // TotalCpus (machine)
  totalMemoryMB?: number; // TotalMemory (machine)
  totalGpus?: number; // TotalGPUs (machine) -- capital GPU
  numDynamicSlots?: number; // NumDynamicSlots (partitionable): running jobs
  state?: string; // State (Owner/Unclaimed/Claimed/Backfill/...)
  activity?: string;
  remoteOwner?: string; // RemoteOwner
  assignedGpus?: string; // AssignedGPUs (device-id list)
  arch?: string;
  opsys?: string;
  raw: ClassAd;
}

export function parseSlot(ad: ClassAd): Slot {
  const m = indexAd(ad);
  const slotType = istr(m, 'SlotType') ?? '';
  const state = istr(m, 'State');
  return {
    name: istr(m, 'Name') ?? '',
    machine: istr(m, 'Machine') ?? istr(m, 'Name') ?? '',
    slotType,
    partitionable: ibool(m, 'PartitionableSlot') || slotType === 'Partitionable',
    dynamic: ibool(m, 'DynamicSlot') || slotType === 'Dynamic',
    backfill: ibool(m, 'BackfillSlot') || state === 'Backfill',
    cpus: inum(m, 'Cpus'),
    memoryMB: inum(m, 'Memory'),
    diskKB: inum(m, 'Disk'),
    gpus: inum(m, 'GPUs'),
    totalCpus: inum(m, 'TotalCpus'),
    totalMemoryMB: inum(m, 'TotalMemory'),
    // Machine-wide total GPUs; fall back to this slot's full complement.
    totalGpus: inum(m, 'TotalGPUs') ?? inum(m, 'TotalSlotGPUs'),
    numDynamicSlots: inum(m, 'NumDynamicSlots'),
    state,
    activity: istr(m, 'Activity'),
    remoteOwner: istr(m, 'RemoteOwner'),
    assignedGpus: istr(m, 'AssignedGPUs'),
    arch: istr(m, 'Arch'),
    opsys: istr(m, 'OpSysAndVer') ?? istr(m, 'OpSys'),
    raw: ad,
  };
}

// The projection the /pool query requests. Keep in sync with parseSlot;
// note the capital-GPU spelling the startd actually publishes.
export const SLOT_PROJECTION = [
  'Name',
  'Machine',
  'SlotType',
  'PartitionableSlot',
  'DynamicSlot',
  'BackfillSlot',
  'Cpus',
  'Memory',
  'Disk',
  'GPUs',
  'TotalCpus',
  'TotalMemory',
  'TotalGPUs',
  'TotalSlotGPUs',
  'NumDynamicSlots',
  'State',
  'Activity',
  'RemoteOwner',
  'AssignedGPUs',
  'Arch',
  'OpSys',
  'OpSysAndVer',
].join(',');

export interface ResourceUsage {
  usedCpus: number;
  totalCpus: number;
  usedMemoryMB: number;
  totalMemoryMB: number;
  usedGpus: number;
  totalGpus: number;
}

function emptyUsage(): ResourceUsage {
  return {
    usedCpus: 0,
    totalCpus: 0,
    usedMemoryMB: 0,
    totalMemoryMB: 0,
    usedGpus: 0,
    totalGpus: 0,
  };
}

// isPrimary is a slot that contributes to the machine's real capacity: not
// a backfill slot (those re-advertise the same cores) and not a per-job
// dynamic slot (its resources are already inside the partitionable total).
function isPrimary(s: Slot): boolean {
  return !s.backfill;
}

// usageFor computes used-vs-total over a set of slots, matching
// condor_status -compact:
//   - total per machine is the machine capacity (TotalCpus/TotalMemory/
//     TotalGPUs), counted once per machine;
//   - a partitionable slot's used portion is capacity - its free leftover;
//   - a claimed static slot contributes its own size;
//   - dynamic slots contribute nothing (already in the leftover) and
//     backfill slots are skipped entirely (they overlap primary cores).
export function usageFor(slots: Slot[]): ResourceUsage {
  const u = emptyUsage();
  const seen = new Set<string>();
  for (const s of slots) {
    if (!isPrimary(s)) continue;
    if (!seen.has(s.machine)) {
      seen.add(s.machine);
      u.totalCpus += s.totalCpus ?? 0;
      u.totalMemoryMB += s.totalMemoryMB ?? 0;
      u.totalGpus += s.totalGpus ?? 0;
    }
    if (s.partitionable) {
      u.usedCpus += Math.max(0, (s.totalCpus ?? 0) - (s.cpus ?? 0));
      u.usedMemoryMB += Math.max(0, (s.totalMemoryMB ?? 0) - (s.memoryMB ?? 0));
      u.usedGpus += Math.max(0, (s.totalGpus ?? 0) - (s.gpus ?? 0));
    } else if (!s.dynamic && s.state === 'Claimed') {
      u.usedCpus += s.cpus ?? 0;
      u.usedMemoryMB += s.memoryMB ?? 0;
      u.usedGpus += s.gpus ?? 0;
    }
  }
  return u;
}

// runningJobsFor counts jobs running on these machines without fetching the
// per-job dynamic slots: a partitionable slot publishes NumDynamicSlots
// (its live children), and a claimed static slot is one job. Backfill
// slots are excluded from the primary count.
export function runningJobsFor(slots: Slot[]): number {
  let n = 0;
  for (const s of slots) {
    if (!isPrimary(s)) continue;
    if (s.partitionable) n += s.numDynamicSlots ?? 0;
    else if (!s.dynamic && s.state === 'Claimed') n += 1;
  }
  return n;
}

// backfillCpusInUse sums the cores currently claimed by backfill slots,
// reported separately because they run opportunistically on the primary
// slots' idle cores (so they must not inflate the primary usage).
export function backfillCpusInUse(slots: Slot[]): number {
  let n = 0;
  for (const s of slots) {
    if (s.backfill && s.state === 'Claimed') n += s.cpus ?? 0;
  }
  return n;
}

// isOwnerNode reports whether the machine is in Owner state (its owner is
// using it, so it is unavailable to the pool) -- read from the primary
// partitionable/static slot, ignoring backfill.
function ownerState(slots: Slot[]): boolean {
  const primary = slots.find((s) => isPrimary(s) && (s.partitionable || !s.dynamic));
  return primary?.state === 'Owner';
}

export interface NodeGroup {
  machine: string;
  slots: Slot[];
  usage: ResourceUsage;
  runningJobs: number;
  owner: boolean;
}

export function groupByMachine(slots: Slot[]): NodeGroup[] {
  const byMachine = new Map<string, Slot[]>();
  for (const s of slots) {
    const arr = byMachine.get(s.machine);
    if (arr) arr.push(s);
    else byMachine.set(s.machine, [s]);
  }
  const groups: NodeGroup[] = [];
  for (const [machine, machineSlots] of byMachine) {
    groups.push({
      machine,
      slots: machineSlots,
      usage: usageFor(machineSlots),
      runningJobs: runningJobsFor(machineSlots),
      owner: ownerState(machineSlots),
    });
  }
  groups.sort((a, b) => a.machine.localeCompare(b.machine));
  return groups;
}

export interface PoolSummary {
  machines: number;
  runningJobs: number;
  ownerNodes: number;
  backfillCpus: number;
  usage: ResourceUsage;
}

export function summarize(slots: Slot[]): PoolSummary {
  const primaryMachines = new Set<string>();
  for (const s of slots) if (isPrimary(s)) primaryMachines.add(s.machine);
  const groups = groupByMachine(slots);
  return {
    machines: primaryMachines.size,
    runningJobs: runningJobsFor(slots),
    ownerNodes: groups.filter((g) => g.owner).length,
    backfillCpus: backfillCpusInUse(slots),
    usage: usageFor(slots),
  };
}

// gib formats a MiB count as a compact GiB string.
export function gib(mib: number | undefined): string {
  if (mib === undefined) return '—';
  return `${gibNum(mib)} GiB`;
}

// gibNum is gib() without the unit suffix, for tables that carry "GiB" in
// the column header and need the cells to be bare, right-alignable numbers.
export function gibNum(mib: number | undefined): string {
  if (mib === undefined) return '—';
  return (mib / 1024).toFixed(mib < 1024 * 10 ? 1 : 0);
}

// pct renders used/total as an integer percentage, blank when no capacity.
export function pct(used: number, total: number): string {
  if (!total) return '—';
  return `${Math.round((used / total) * 100)}%`;
}

// slotStateStyle maps a slot State to a Tailwind pill.
export function slotStateStyle(state: string | undefined): string {
  switch (state) {
    case 'Unclaimed':
      return 'bg-green-100 text-green-800';
    case 'Claimed':
      return 'bg-indigo-100 text-indigo-800';
    case 'Owner':
      return 'bg-orange-100 text-orange-800';
    case 'Backfill':
      return 'bg-purple-100 text-purple-800';
    case 'Matched':
    case 'Draining':
    case 'Drained':
    case 'Preempting':
      return 'bg-amber-100 text-amber-800';
    default:
      return 'bg-gray-100 text-gray-600';
  }
}

// textHaystack is the lowercased blob the free-text filter matches a slot
// against.
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
    s.backfill ? 'backfill' : '',
  ]
    .filter(Boolean)
    .join(' ')
    .toLowerCase();
}

// ---- GPU device details (slot page) --------------------------------------

export interface GpuDevice {
  id: string; // e.g. "GPU-abcd" / "CUDA0"
  name?: string;
  capability?: string;
  globalMemoryMb?: number;
  driverVersion?: string;
}

// gpuDevices extracts per-device GPU properties from a slot ad, tolerant of
// both publishing styles: nested per-device ClassAds keyed by device id
// (the modern default), and the flat CUDA*/OCL* attributes (older). Returns
// [] when the slot has no GPU device detail.
export function gpuDevices(ad: ClassAd): GpuDevice[] {
  const m = indexAd(ad);
  // Device ids: AssignedGPUs is what this slot holds; DetectedGPUs is the
  // machine's full set. Prefer Assigned (slot-relevant), else Detected.
  const idList = istr(m, 'AssignedGPUs') ?? istr(m, 'DetectedGPUs') ?? '';
  const ids = idList
    .split(',')
    .map((s) => s.trim())
    .filter(Boolean);

  const devices: GpuDevice[] = [];
  for (const id of ids) {
    // Nested style: a nested ad keyed by the device id (e.g. ad["CUDA0"]).
    const nested = m.get(id.toLowerCase());
    if (nested && typeof nested === 'object' && !Array.isArray(nested)) {
      const nm = indexAd(nested as ClassAd);
      devices.push({
        id,
        name: istr(nm, 'DeviceName'),
        capability: istr(nm, 'Capability'),
        globalMemoryMb: inum(nm, 'GlobalMemoryMb'),
        driverVersion: istr(nm, 'DriverVersion') ?? istr(nm, 'DriverVersionStr'),
      });
      continue;
    }
    devices.push({ id });
  }

  // Flat style / common-property fallback: if we found ids but no nested
  // props (or no ids at all but flat CUDA* attrs exist), surface the
  // common CUDA* properties as a single synthesized row.
  const flatName = istr(m, 'CUDADeviceName') ?? istr(m, 'OCLDeviceName');
  const haveDetail = devices.some((d) => d.name || d.capability);
  if (!haveDetail && flatName) {
    const flat: GpuDevice = {
      id: ids[0] ?? 'GPU',
      name: flatName,
      capability: istr(m, 'CUDACapability'),
      globalMemoryMb: inum(m, 'CUDAGlobalMemoryMb'),
      driverVersion: istr(m, 'CUDADriverVersion'),
    };
    if (devices.length > 0) devices[0] = { ...devices[0], ...flat };
    else devices.push(flat);
  }
  return devices;
}
