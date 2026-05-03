'use client';

import { useEffect, useRef, useState } from 'react';
import {
  decodeEnvironment,
  encodeEnvironment,
  getAttribute,
  removeAttribute,
  setAttribute,
  type EnvVar,
} from '@/lib/submitFile';

interface QuickFieldsProps {
  text: string;
  onChange: (text: string) => void;
}

const UNIVERSES = ['vanilla', 'docker', 'container', 'parallel', 'scheduler', 'local'];

const CPU_STEPS = [1, 2, 4, 8, 16, 32];
const MEM_STEPS = [256, 512, 1024, 2048, 4096, 8192, 16384, 32768];
const DISK_STEPS = [1024, 2048, 4096, 8192, 16384, 32768, 65536];
const GPU_STEPS = [0, 1, 2, 4, 8];
const GPU_MEM_STEPS = [4096, 8192, 16384, 24576, 40960, 81920];
const CUDA_CAPS = ['', '5.0', '6.0', '7.0', '7.5', '8.0', '8.6', '9.0'];

// QuickFields is a convenience builder. The textarea remains canonical
// at submit time. Every form change immediately patches the textarea so
// the user sees the edit reflected. Initial values are read from the
// textarea on first mount; subsequent textarea edits don't reset the
// form (intentional — direct edits are the user dropping to a lower
// level of abstraction).
export function QuickFields({ text, onChange }: QuickFieldsProps) {
  const initialised = useRef(false);

  // --- Basics ---
  const [executable, setExecutable] = useState('');
  const [args, setArgs] = useState('');
  const [universe, setUniverse] = useState('vanilla');
  const [cpus, setCpus] = useState<number>(1);
  const [memMB, setMemMB] = useState<number>(1024);
  const [diskMB, setDiskMB] = useState<number>(1024);
  const [outputFile, setOutputFile] = useState('');
  const [errorFile, setErrorFile] = useState('');
  const [logFile, setLogFile] = useState('');

  // --- GPU ---
  const [gpus, setGpus] = useState<number>(0);
  const [gpuMemMB, setGpuMemMB] = useState<number>(8192);
  const [gpuMinCap, setGpuMinCap] = useState('');
  const [gpuMinRuntime, setGpuMinRuntime] = useState('');
  const [cudaVersion, setCudaVersion] = useState('');
  const [requireGPUs, setRequireGPUs] = useState('');

  // --- Environment ---
  const [envVars, setEnvVars] = useState<EnvVar[]>([]);

  // --- Section open/close ---
  const [openBasics, setOpenBasics] = useState(false);
  const [openGPU, setOpenGPU] = useState(false);
  const [openEnv, setOpenEnv] = useState(false);

  useEffect(() => {
    if (initialised.current) return;
    initialised.current = true;
    setExecutable(getAttribute(text, 'executable') ?? '');
    setArgs(getAttribute(text, 'arguments') ?? '');
    setUniverse(getAttribute(text, 'universe') ?? 'vanilla');
    setCpus(snapTo(CPU_STEPS, parseIntOr(getAttribute(text, 'request_cpus'), 1)));
    setMemMB(snapTo(MEM_STEPS, parseIntOr(getAttribute(text, 'request_memory'), 1024)));
    setDiskMB(snapTo(DISK_STEPS, parseIntOr(getAttribute(text, 'request_disk'), 1024)));
    setOutputFile(getAttribute(text, 'output') ?? '');
    setErrorFile(getAttribute(text, 'error') ?? '');
    setLogFile(getAttribute(text, 'log') ?? '');
    const initialGpus = parseIntOr(getAttribute(text, 'request_gpus'), 0);
    setGpus(snapTo(GPU_STEPS, initialGpus));
    setGpuMemMB(snapTo(GPU_MEM_STEPS, parseIntOr(getAttribute(text, 'gpus_minimum_memory'), 8192)));
    setGpuMinCap(getAttribute(text, 'gpus_minimum_capability') ?? '');
    setGpuMinRuntime(getAttribute(text, 'gpus_minimum_runtime') ?? '');
    setCudaVersion(getAttribute(text, 'cuda_version') ?? '');
    setRequireGPUs(getAttribute(text, 'require_gpus') ?? '');
    const decoded = decodeEnvironment(getAttribute(text, 'environment'));
    if (decoded) setEnvVars(decoded);
    // Auto-open GPU section if the user already has GPU fields set.
    if (initialGpus > 0) setOpenGPU(true);
  }, [text]);

  // Generic helper: update local state and patch the textarea.
  const update =
    (setter: (v: string) => void, key: string) => (value: string) => {
      setter(value);
      onChange(setAttribute(text, key, value));
    };
  const updateNumber =
    (setter: (v: number) => void, key: string) => (value: number) => {
      setter(value);
      onChange(setAttribute(text, key, String(value)));
    };

  // GPU = 0 means "no GPU" — drop the GPU-related lines entirely so the
  // submit file stays clean.
  const updateGpus = (value: number) => {
    setGpus(value);
    let next = setAttribute(text, 'request_gpus', value > 0 ? String(value) : '');
    if (value === 0) {
      // Remove all dependent GPU fields too.
      for (const k of [
        'gpus_minimum_memory',
        'gpus_minimum_capability',
        'gpus_minimum_runtime',
        'cuda_version',
        'require_gpus',
      ]) {
        next = removeAttribute(next, k);
      }
    } else if (!openGPU) {
      // Convenience: opening the GPU section so the user can immediately
      // tweak the constraint fields.
      setOpenGPU(true);
    }
    onChange(next);
  };

  // Env-vars: re-encode the whole list on any change.
  const updateEnv = (next: EnvVar[]) => {
    setEnvVars(next);
    const encoded = encodeEnvironment(next);
    if (encoded === null) {
      onChange(removeAttribute(text, 'environment'));
    } else {
      onChange(setAttribute(text, 'environment', encoded));
    }
  };

  return (
    <div className="space-y-3">
      <Section title="Basics" open={openBasics} setOpen={setOpenBasics}
        hint="Executable, args, resource requests, log/output/error">
        <div className="grid grid-cols-1 md:grid-cols-2 gap-4 text-sm">
          <Field label="executable">
            <input
              value={executable}
              onChange={(e) => update(setExecutable, 'executable')(e.target.value)}
              className="w-full rounded border border-gray-300 px-2 py-1 font-mono text-xs"
              placeholder="/bin/bash"
            />
          </Field>
          <Field label="universe">
            <select
              value={universe}
              onChange={(e) => update(setUniverse, 'universe')(e.target.value)}
              className="w-full rounded border border-gray-300 px-2 py-1 text-xs"
            >
              {UNIVERSES.map((u) => (
                <option key={u} value={u}>{u}</option>
              ))}
            </select>
          </Field>
          <Field label="arguments" className="md:col-span-2">
            <input
              value={args}
              onChange={(e) => update(setArgs, 'arguments')(e.target.value)}
              className="w-full rounded border border-gray-300 px-2 py-1 font-mono text-xs"
              placeholder={`"-c 'echo hello'"`}
            />
          </Field>
          <Slider
            label={`request_cpus = ${cpus}`}
            steps={CPU_STEPS}
            value={cpus}
            onChange={updateNumber(setCpus, 'request_cpus')}
          />
          <Slider
            label={`request_memory = ${memMB} MB`}
            steps={MEM_STEPS}
            value={memMB}
            onChange={updateNumber(setMemMB, 'request_memory')}
          />
          <Slider
            label={`request_disk = ${diskMB} MB`}
            steps={DISK_STEPS}
            value={diskMB}
            onChange={updateNumber(setDiskMB, 'request_disk')}
          />
          <Field label="output">
            <input
              value={outputFile}
              onChange={(e) => update(setOutputFile, 'output')(e.target.value)}
              className="w-full rounded border border-gray-300 px-2 py-1 font-mono text-xs"
              placeholder="output.txt"
            />
          </Field>
          <Field label="error">
            <input
              value={errorFile}
              onChange={(e) => update(setErrorFile, 'error')(e.target.value)}
              className="w-full rounded border border-gray-300 px-2 py-1 font-mono text-xs"
              placeholder="error.txt"
            />
          </Field>
          <Field label="log">
            <input
              value={logFile}
              onChange={(e) => update(setLogFile, 'log')(e.target.value)}
              className="w-full rounded border border-gray-300 px-2 py-1 font-mono text-xs"
              placeholder="job.log"
            />
          </Field>
        </div>
      </Section>

      <Section
        title="GPU"
        open={openGPU}
        setOpen={setOpenGPU}
        hint={gpus > 0 ? `${gpus} GPU(s) requested` : 'request_gpus = 0; section disabled'}
      >
        <div className="space-y-4">
          <Slider
            label={`request_gpus = ${gpus}`}
            steps={GPU_STEPS}
            value={gpus}
            onChange={updateGpus}
          />
          {gpus > 0 && (
            <div className="grid grid-cols-1 md:grid-cols-2 gap-4 text-sm">
              <Field label="gpus_minimum_capability">
                <select
                  value={gpuMinCap}
                  onChange={(e) => update(setGpuMinCap, 'gpus_minimum_capability')(e.target.value)}
                  className="w-full rounded border border-gray-300 px-2 py-1 text-xs"
                >
                  {CUDA_CAPS.map((c) => (
                    <option key={c} value={c}>{c === '' ? '(any)' : c}</option>
                  ))}
                </select>
              </Field>
              <Slider
                label={`gpus_minimum_memory = ${gpuMemMB} MiB`}
                steps={GPU_MEM_STEPS}
                value={gpuMemMB}
                onChange={updateNumber(setGpuMemMB, 'gpus_minimum_memory')}
              />
              <Field label="gpus_minimum_runtime">
                <input
                  value={gpuMinRuntime}
                  onChange={(e) => update(setGpuMinRuntime, 'gpus_minimum_runtime')(e.target.value)}
                  className="w-full rounded border border-gray-300 px-2 py-1 font-mono text-xs"
                  placeholder="e.g. 11.0"
                />
              </Field>
              <Field label="cuda_version">
                <input
                  value={cudaVersion}
                  onChange={(e) => update(setCudaVersion, 'cuda_version')(e.target.value)}
                  className="w-full rounded border border-gray-300 px-2 py-1 font-mono text-xs"
                  placeholder="e.g. 12.1"
                />
              </Field>
              <Field label="require_gpus" className="md:col-span-2">
                <input
                  value={requireGPUs}
                  onChange={(e) => update(setRequireGPUs, 'require_gpus')(e.target.value)}
                  className="w-full rounded border border-gray-300 px-2 py-1 font-mono text-xs"
                  placeholder='e.g. Capability >= 7.0 && GlobalMemoryMb >= 16000'
                />
                <span className="block text-[11px] text-gray-400 mt-1">
                  Free-form ClassAd expression layered on top of the structured fields above.
                </span>
              </Field>
            </div>
          )}
        </div>
      </Section>

      <Section
        title="Environment"
        open={openEnv}
        setOpen={setOpenEnv}
        hint={
          envVars.filter((v) => v.name.trim()).length > 0
            ? `${envVars.filter((v) => v.name.trim()).length} variable(s)`
            : 'No environment overrides'
        }
      >
        <EnvEditor vars={envVars} onChange={updateEnv} />
      </Section>
    </div>
  );
}

function Section({
  title,
  hint,
  open,
  setOpen,
  children,
}: {
  title: string;
  hint?: string;
  open: boolean;
  setOpen: (v: boolean) => void;
  children: React.ReactNode;
}) {
  return (
    <div className="rounded border border-gray-200 bg-white">
      <button
        type="button"
        onClick={() => setOpen(!open)}
        className="w-full flex items-center justify-between px-4 py-2 text-left text-sm font-medium text-gray-700 hover:bg-gray-50"
      >
        <span>
          {title}
          {hint && <span className="ml-2 text-xs font-normal text-gray-500">— {hint}</span>}
        </span>
        <span className="text-gray-400">{open ? '▾' : '▸'}</span>
      </button>
      {open && <div className="border-t border-gray-100 p-4">{children}</div>}
    </div>
  );
}

function Field({
  label,
  children,
  className,
}: {
  label: string;
  children: React.ReactNode;
  className?: string;
}) {
  return (
    <label className={`block ${className ?? ''}`}>
      <span className="block text-xs font-medium text-gray-600 mb-1">{label}</span>
      {children}
    </label>
  );
}

function Slider({
  label,
  steps,
  value,
  onChange,
}: {
  label: string;
  steps: number[];
  value: number;
  onChange: (v: number) => void;
}) {
  // Index-into-steps trick keeps the slider's tick marks evenly spaced
  // even when the underlying values grow exponentially.
  const idx = Math.max(0, steps.indexOf(value));
  return (
    <div>
      <span className="block text-xs font-medium text-gray-600 mb-1">{label}</span>
      <input
        type="range"
        min={0}
        max={steps.length - 1}
        step={1}
        value={idx}
        onChange={(e) => onChange(steps[parseInt(e.target.value, 10)])}
        className="w-full"
      />
      <div className="flex justify-between text-[10px] text-gray-400 mt-1">
        {steps.map((s) => (
          <span key={s}>{s}</span>
        ))}
      </div>
    </div>
  );
}

function EnvEditor({
  vars,
  onChange,
}: {
  vars: EnvVar[];
  onChange: (next: EnvVar[]) => void;
}) {
  const setRow = (i: number, patch: Partial<EnvVar>) => {
    const next = vars.map((v, j) => (j === i ? { ...v, ...patch } : v));
    onChange(next);
  };
  const addRow = () => onChange([...vars, { name: '', value: '' }]);
  const removeRow = (i: number) => onChange(vars.filter((_, j) => j !== i));

  // We don't reject invalid names at type-time, but we surface them
  // visually so the user notices before submission.
  const nameInvalid = (name: string): boolean =>
    name !== '' && !/^[A-Za-z_][A-Za-z0-9_]*$/.test(name);

  return (
    <div className="space-y-2">
      {vars.length === 0 && (
        <p className="text-xs text-gray-500">
          No environment variables set. Add one to inject it into the job.
        </p>
      )}
      {vars.length > 0 && (
        <div className="overflow-x-auto rounded border border-gray-200">
          <table className="min-w-full text-xs">
            <thead className="bg-gray-50">
              <tr>
                <th className="px-2 py-1 text-left text-[10px] uppercase tracking-wide text-gray-500">name</th>
                <th className="px-2 py-1 text-left text-[10px] uppercase tracking-wide text-gray-500">value</th>
                <th className="px-2 py-1 w-8"></th>
              </tr>
            </thead>
            <tbody className="divide-y divide-gray-100">
              {vars.map((v, i) => (
                <tr key={i}>
                  <td className="px-2 py-1">
                    <input
                      value={v.name}
                      onChange={(e) => setRow(i, { name: e.target.value })}
                      className={`w-44 rounded border px-1 py-0.5 font-mono text-xs ${
                        nameInvalid(v.name)
                          ? 'border-red-300 bg-red-50'
                          : 'border-gray-200'
                      }`}
                      placeholder="VAR_NAME"
                    />
                  </td>
                  <td className="px-2 py-1">
                    <input
                      value={v.value}
                      onChange={(e) => setRow(i, { value: e.target.value })}
                      className="w-full rounded border border-gray-200 px-1 py-0.5 font-mono text-xs"
                      placeholder="value"
                    />
                  </td>
                  <td className="px-2 py-1 text-right">
                    <button
                      type="button"
                      onClick={() => removeRow(i)}
                      className="text-xs text-red-600 hover:text-red-800"
                      title="Remove variable"
                    >
                      ✕
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
      <button
        type="button"
        onClick={addRow}
        className="text-xs rounded border border-gray-300 px-2 py-1 text-gray-700 hover:bg-gray-50"
      >
        + variable
      </button>
      <p className="text-[11px] text-gray-400">
        Spaces and quotes in values are escaped automatically into HTCondor&apos;s
        new-syntax <code className="font-mono">environment = &quot;...&quot;</code> form.
      </p>
    </div>
  );
}

function parseIntOr(s: string | undefined, fallback: number): number {
  if (s == null) return fallback;
  const n = parseInt(s, 10);
  return Number.isNaN(n) ? fallback : n;
}

function snapTo(steps: number[], value: number): number {
  let best = steps[0];
  let bestDiff = Math.abs(steps[0] - value);
  for (const s of steps) {
    const diff = Math.abs(s - value);
    if (diff < bestDiff) {
      best = s;
      bestDiff = diff;
    }
  }
  return best;
}
