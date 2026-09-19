'use client';

// SubmitLinesField is a collapsed-by-default disclosure that lets a power
// user add extra HTCondor submit commands to an interactive launch. It
// stays out of the way like the GPU subfields — a single summary line
// until opened — so the common case (no extra lines) sees a modest form.
//
// The value passes straight through to the create request's `submit_lines`.
// The server validates it (interactive.ValidateCallerSubmitLines): commands
// that would define the session — executable, universe, queue, … — are
// rejected, and operator site policy is applied after these lines regardless.

import { useId, useState } from 'react';

export function SubmitLinesField({
  value,
  onChange,
}: {
  value: string;
  onChange: (v: string) => void;
}) {
  // Start open only if there is already text — a remembered draft should
  // not be hidden — otherwise collapsed (off by default).
  const [open, setOpen] = useState(value.trim() !== '');
  const id = useId();

  return (
    <div className="rounded-sm border border-gray-200 bg-gray-50 p-3">
      <button
        type="button"
        onClick={() => setOpen((o) => !o)}
        aria-expanded={open}
        aria-controls={id}
        className="flex w-full items-center gap-2 text-left text-sm font-medium text-gray-700"
      >
        <span className="text-gray-400">{open ? '▾' : '▸'}</span>
        Extra submit lines
        <span className="font-normal text-xs text-gray-500">
          (advanced — optional)
        </span>
      </button>

      {open && (
        <div className="mt-3 space-y-1">
          <textarea
            id={id}
            value={value}
            onChange={(e) => onChange(e.target.value)}
            rows={4}
            spellCheck={false}
            className="w-full rounded-sm border border-gray-300 px-3 py-1.5 font-mono text-xs"
            placeholder={'+ProjectName = "MyProject"\nconcurrency_limits = mylimit:1'}
          />
          <p className="text-xs text-gray-500">
            Appended to the job&apos;s submit description, one{' '}
            <code className="font-mono">name = value</code> per line.
            Commands that define the session (executable, universe, queue,
            …) are rejected; site policy still applies.
          </p>
        </div>
      )}
    </div>
  );
}
