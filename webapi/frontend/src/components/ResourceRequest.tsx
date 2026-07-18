'use client';

// ResourceRequestPanel renders the resource-request fields a user
// typically wants to set on a job: CPU / memory / disk plus an
// optional GPU section. The component owns no state — callers pass
// `value` / `onChange` and render whatever they want around it. The
// same widget drives:
//
//   - the interactive page (Jupyter + Terminal launchers)
//   - the submit-builder's "step 4: Resources"
//   - the custom-template editor on the submit page
//
// GPU subfields collapse when request_gpus = 0 (the common case)
// so the form stays small for non-GPU users.

import { useId } from 'react';

// HTCondor's request_gpus / gpus_minimum_* / cuda_version submit
// commands all map onto these fields. require_gpus is a free-form
// ClassAd expression layered on top of the structured fields.
export interface ResourceRequest {
  cpus: number;
  memoryMB: number;
  diskMB: number;
  gpus: number;
  // GPU subfields are only meaningful when gpus > 0. We keep them
  // around even when gpus == 0 so the user can flip back without
  // losing what they typed; persistence layers (submit body, API
  // request) drop them at the boundary.
  gpuMinCapability: string;
  gpuMinMemoryMB: number;
  gpuMinRuntime: string;
  cudaVersion: string;
  requireGpus: string;
}

export const DEFAULT_RESOURCE_REQUEST: ResourceRequest = {
  cpus: 1,
  memoryMB: 1024,
  diskMB: 1024,
  gpus: 0,
  gpuMinCapability: '',
  gpuMinMemoryMB: 8192,
  gpuMinRuntime: '',
  cudaVersion: '',
  requireGpus: '',
};

const CUDA_CAPS = ['', '5.0', '6.0', '7.0', '7.5', '8.0', '8.6', '9.0'];

export interface ResourceRequestPanelProps {
  value: ResourceRequest;
  onChange: (next: ResourceRequest) => void;
  // Caps on the validated ranges. Mostly defensive; the interactive
  // backend enforces its own (1..64 cpus, etc.). Submit page is more
  // permissive since submitted batches aren't pinned to one host.
  limits?: Partial<{
    minCpus: number;
    maxCpus: number;
    minMemoryMB: number;
    maxMemoryMB: number;
    minDiskMB: number;
    maxDiskMB: number;
  }>;
  // Headline shown above the panel; omit for embedded use where the
  // surrounding section card already has one.
  title?: string;
  hint?: string;
  // gpuSubfieldsOnly hides the CPU / memory / disk / GPU-count rows
  // and renders just the GPU subfields (capability, memory, runtime,
  // CUDA version, require_gpus). Used by the submit page's per-field
  // override UI: when the user has the GPU override checkbox on AND
  // request_gpus > 0, we still want them to be able to tune the
  // subfields, but the count + the other top-level rows are already
  // shown by the per-field rows above.
  gpuSubfieldsOnly?: boolean;
}

export function ResourceRequestPanel({
  value,
  onChange,
  limits,
  title,
  hint,
  gpuSubfieldsOnly,
}: ResourceRequestPanelProps) {
  const lim = {
    minCpus: limits?.minCpus ?? 1,
    maxCpus: limits?.maxCpus ?? 64,
    minMemoryMB: limits?.minMemoryMB ?? 256,
    maxMemoryMB: limits?.maxMemoryMB ?? 256 * 1024,
    minDiskMB: limits?.minDiskMB ?? 256,
    maxDiskMB: limits?.maxDiskMB ?? 1024 * 1024,
  };

  const patch = (p: Partial<ResourceRequest>) => onChange({ ...value, ...p });
  const numId = useId();

  // GPU subfield grid — extracted so we can render it standalone via
  // gpuSubfieldsOnly without duplicating the field list.
  const gpuSubfields = (
    <div className="grid grid-cols-1 md:grid-cols-2 gap-3 pt-1">
      <SelectField
        label="Min CUDA capability"
        value={value.gpuMinCapability}
        onChange={(v) => patch({ gpuMinCapability: v })}
        options={CUDA_CAPS.map((c) => ({
          value: c,
          label: c === '' ? '(any)' : c,
        }))}
      />
      <NumField
        label="Min GPU memory (MiB)"
        min={0}
        step={1024}
        value={value.gpuMinMemoryMB}
        onChange={(n) => patch({ gpuMinMemoryMB: n })}
        hint="gpus_minimum_memory"
      />
      <TextField
        label="Min CUDA runtime"
        value={value.gpuMinRuntime}
        onChange={(v) => patch({ gpuMinRuntime: v })}
        placeholder="e.g. 11.0"
        hint="gpus_minimum_runtime"
      />
      <TextField
        label="CUDA version"
        value={value.cudaVersion}
        onChange={(v) => patch({ cudaVersion: v })}
        placeholder="e.g. 12.1"
        hint="cuda_version"
      />
      <TextField
        label="require_gpus expression"
        value={value.requireGpus}
        onChange={(v) => patch({ requireGpus: v })}
        placeholder="e.g. Capability >= 7.0 && GlobalMemoryMb >= 16000"
        hint="Free-form ClassAd expression layered on top of the structured fields above."
        fullWidth
      />
    </div>
  );

  if (gpuSubfieldsOnly) {
    return gpuSubfields;
  }

  return (
    <div className="space-y-4">
      {(title || hint) && (
        <div>
          {title && (
            <h3 className="text-sm font-semibold text-gray-800">{title}</h3>
          )}
          {hint && <p className="text-xs text-gray-500">{hint}</p>}
        </div>
      )}

      <div className="grid grid-cols-3 gap-4">
        <NumField
          label="CPUs"
          id={`${numId}-cpu`}
          min={lim.minCpus}
          max={lim.maxCpus}
          value={value.cpus}
          onChange={(n) => patch({ cpus: n })}
        />
        <NumField
          label="Memory (MiB)"
          id={`${numId}-mem`}
          min={lim.minMemoryMB}
          max={lim.maxMemoryMB}
          step={256}
          value={value.memoryMB}
          onChange={(n) => patch({ memoryMB: n })}
        />
        <NumField
          label="Disk (MiB)"
          id={`${numId}-disk`}
          min={lim.minDiskMB}
          max={lim.maxDiskMB}
          step={256}
          value={value.diskMB}
          onChange={(n) => patch({ diskMB: n })}
        />
      </div>

      <div className="rounded border border-gray-200 bg-gray-50 p-3 space-y-3">
        <div className="flex items-center gap-3">
          <label className="text-sm font-medium text-gray-700" htmlFor={`${numId}-gpu`}>
            GPUs
          </label>
          <input
            id={`${numId}-gpu`}
            type="number"
            min={0}
            max={16}
            value={value.gpus}
            onChange={(e) => patch({ gpus: clampInt(e.target.value, 0, 16, 0) })}
            className="w-20 rounded border border-gray-300 px-2 py-1 text-sm"
          />
          <span className="text-xs text-gray-500">
            {value.gpus === 0
              ? 'No GPU; subfields are skipped.'
              : value.gpus === 1
                ? '1 GPU requested.'
                : `${value.gpus} GPUs requested.`}
          </span>
        </div>

        {value.gpus > 0 && gpuSubfields}
      </div>
    </div>
  );
}

function NumField({
  label,
  id,
  min,
  max,
  step,
  value,
  onChange,
  hint,
}: {
  label: string;
  id?: string;
  min?: number;
  max?: number;
  step?: number;
  value: number;
  onChange: (n: number) => void;
  hint?: string;
}) {
  return (
    <label className="block">
      <span className="block text-sm font-medium text-gray-700">{label}</span>
      <input
        id={id}
        type="number"
        min={min}
        max={max}
        step={step}
        value={value}
        onChange={(e) => onChange(clampInt(e.target.value, min, max, value))}
        className="mt-1 w-full rounded border border-gray-300 px-3 py-1.5 text-sm"
      />
      {hint && <span className="block text-[11px] text-gray-400 mt-0.5">{hint}</span>}
    </label>
  );
}

function TextField({
  label,
  value,
  onChange,
  placeholder,
  hint,
  fullWidth,
}: {
  label: string;
  value: string;
  onChange: (v: string) => void;
  placeholder?: string;
  hint?: string;
  fullWidth?: boolean;
}) {
  return (
    <label className={`block ${fullWidth ? 'md:col-span-2' : ''}`}>
      <span className="block text-sm font-medium text-gray-700">{label}</span>
      <input
        type="text"
        value={value}
        onChange={(e) => onChange(e.target.value)}
        placeholder={placeholder}
        className="mt-1 w-full rounded border border-gray-300 px-3 py-1.5 font-mono text-xs"
      />
      {hint && <span className="block text-[11px] text-gray-400 mt-0.5">{hint}</span>}
    </label>
  );
}

function SelectField({
  label,
  value,
  onChange,
  options,
}: {
  label: string;
  value: string;
  onChange: (v: string) => void;
  options: { value: string; label: string }[];
}) {
  return (
    <label className="block">
      <span className="block text-sm font-medium text-gray-700">{label}</span>
      <select
        value={value}
        onChange={(e) => onChange(e.target.value)}
        className="mt-1 w-full rounded border border-gray-300 bg-white px-3 py-1.5 text-sm"
      >
        {options.map((o) => (
          <option key={o.value} value={o.value}>
            {o.label}
          </option>
        ))}
      </select>
    </label>
  );
}

function clampInt(
  raw: string,
  min: number | undefined,
  max: number | undefined,
  fallback: number,
): number {
  const n = parseInt(raw, 10);
  if (Number.isNaN(n)) return fallback;
  if (min !== undefined && n < min) return min;
  if (max !== undefined && n > max) return max;
  return n;
}
