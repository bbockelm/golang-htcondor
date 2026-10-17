'use client';

// Pieces the directory views share: authorization chips in the operator's
// colors, the source badge, and a modal shell.

import { useEffect, useRef } from 'react';
import type { DirAuthorization } from '@/lib/placementAdmin';

// safeColor admits hex triplets, rgb()/hsl() and bare color keywords into an
// inline style; anything else gets the neutral chip. Same allowlist as the
// Users tab.
const COLOR_RE = /^(#[0-9a-f]{3,8}|[a-z]+|(rgb|hsl)a?\([0-9.,%\s/]+\))$/i;

export function safeColor(color?: string): string | undefined {
  if (!color) return undefined;
  const trimmed = color.trim();
  return COLOR_RE.test(trimmed) ? trimmed : undefined;
}

export function AuthzChip({
  authz,
}: {
  authz: Pick<DirAuthorization, 'name' | 'label' | 'color' | 'description'>;
}) {
  const color = safeColor(authz.color);
  return (
    <span
      className="inline-flex items-center gap-1.5 rounded-full border px-2 py-0.5 text-xs font-medium text-gray-800"
      style={{ borderColor: color ?? '#d1d5db' }}
      title={authz.description || authz.name}
    >
      <span
        aria-hidden="true"
        className="h-2 w-2 shrink-0 rounded-full"
        style={{ backgroundColor: color ?? '#9ca3af' }}
      />
      {authz.label || authz.name}
    </span>
  );
}

export function AuthzChips({
  names,
  byName,
}: {
  names?: string[];
  byName: Map<string, DirAuthorization>;
}) {
  if (!names || names.length === 0) {
    return <span className="text-xs text-gray-400">—</span>;
  }
  return (
    <span className="flex flex-wrap gap-1">
      {names.map((n) => (
        <AuthzChip key={n} authz={byName.get(n.toUpperCase()) ?? { name: n }} />
      ))}
    </span>
  );
}

export function SourceBadge({ source }: { source?: string }) {
  const mapfile = source === 'mapfile';
  return (
    <span
      className={`rounded-full px-2 py-0.5 text-[10px] font-medium ${
        mapfile ? 'bg-amber-100 text-amber-800' : 'bg-emerald-100 text-emerald-800'
      }`}
      title={mapfile ? 'Read-only: defined in the map file' : 'Editable'}
    >
      {source || 'unknown'}
    </span>
  );
}

export function formatWhen(value?: string, absent = '—'): string {
  if (!value) return absent;
  return new Date(value).toLocaleString();
}

// Modal is a centered dialog that closes on Escape or a backdrop click.
export function Modal({
  title,
  onClose,
  children,
  wide,
}: {
  title: string;
  onClose: () => void;
  children: React.ReactNode;
  wide?: boolean;
}) {
  const ref = useRef<HTMLDivElement>(null);
  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if (e.key === 'Escape') onClose();
    };
    document.addEventListener('keydown', onKey);
    ref.current?.focus();
    return () => document.removeEventListener('keydown', onKey);
  }, [onClose]);
  return (
    <div
      className="fixed inset-0 z-40 flex items-start justify-center overflow-y-auto bg-black/30 p-4 sm:p-10"
      onMouseDown={(e) => {
        if (e.target === e.currentTarget) onClose();
      }}
    >
      <div
        ref={ref}
        role="dialog"
        aria-modal="true"
        aria-label={title}
        tabIndex={-1}
        className={`w-full ${wide ? 'max-w-2xl' : 'max-w-lg'} rounded-lg bg-white p-5 shadow-xl focus:outline-none`}
      >
        <div className="mb-4 flex items-center justify-between">
          <h2 className="text-base font-semibold text-gray-900">{title}</h2>
          <button
            type="button"
            onClick={onClose}
            aria-label="Close"
            className="rounded-sm px-2 text-gray-400 hover:text-gray-700"
          >
            ×
          </button>
        </div>
        {children}
      </div>
    </div>
  );
}

export const inputClass =
  'mt-1 w-full rounded-sm border border-gray-300 px-2 py-1 text-sm focus:border-brand-400 focus:outline-hidden focus:ring-1 focus:ring-brand-400 disabled:bg-gray-50 disabled:text-gray-500';

export function Field({
  label,
  children,
  hint,
}: {
  label: string;
  children: React.ReactNode;
  hint?: string;
}) {
  return (
    <label className="block text-xs">
      <span className="block text-gray-700">{label}</span>
      {children}
      {hint && <span className="mt-0.5 block text-gray-400">{hint}</span>}
    </label>
  );
}

// CheckboxList picks a subset of options.
export function CheckboxList({
  options,
  selected,
  onChange,
  render,
  empty,
  disabled,
}: {
  options: string[];
  selected: string[];
  onChange: (next: string[]) => void;
  render?: (name: string) => React.ReactNode;
  empty: string;
  disabled?: boolean;
}) {
  if (options.length === 0) {
    return <span className="mt-1 block text-xs text-gray-400">{empty}</span>;
  }
  const chosen = new Set(selected);
  return (
    <div className="mt-1 flex flex-wrap gap-x-4 gap-y-1">
      {options.map((o) => (
        <label key={o} className="flex items-center gap-2 text-xs">
          <input
            type="checkbox"
            disabled={disabled}
            checked={chosen.has(o)}
            onChange={() => {
              const next = new Set(chosen);
              if (next.has(o)) next.delete(o);
              else next.add(o);
              // Keep the options' order rather than click order.
              onChange(options.filter((x) => next.has(x)));
            }}
            className="rounded-sm border-gray-300"
          />
          {render ? render(o) : o}
        </label>
      ))}
    </div>
  );
}

// toLocalInput renders an ISO time for a datetime-local input.
export function toLocalInput(iso?: string): string {
  if (!iso) return '';
  const d = new Date(iso);
  const pad = (n: number) => String(n).padStart(2, '0');
  return `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())}T${pad(d.getHours())}:${pad(d.getMinutes())}`;
}

// fromLocalInput turns a datetime-local value back into RFC 3339.
export function fromLocalInput(v: string): string | null {
  if (!v) return null;
  const d = new Date(v);
  return Number.isNaN(d.getTime()) ? null : d.toISOString().replace(/\.\d{3}Z$/, 'Z');
}
