'use client';

// Per-slot detail: the parsed summary (node, type, resources, state,
// owner) plus the full raw ClassAd the collector returned for this slot.

import Link from 'next/link';
import { useQuery } from '@tanstack/react-query';
import { api, ApiError } from '@/lib/api';
import { useResolvedParams } from '@/lib/useResolvedParams';
import { parseSlot, slotStateStyle, gib } from '@/lib/pool';

export default function SlotDetailClient() {
  const { name } = useResolvedParams<{ name: string }>('/pool/slots/[name]');
  // usePathname may hand back the URL-encoded segment; decode defensively
  // (a no-op for an already-decoded name with no %xx escapes).
  const slotName = name && name !== '_' ? decodeURIComponent(name) : '';

  const { data, isLoading, error } = useQuery({
    queryKey: ['slot', slotName],
    queryFn: () => api.collector.get('startd', slotName),
    refetchInterval: 15_000,
    enabled: !!slotName,
    retry: false,
  });

  const slot = data ? parseSlot(data) : null;
  const notFound = error instanceof ApiError && error.status === 404;

  return (
    <div className="max-w-4xl space-y-6">
      <div>
        <Link href="/pool" className="text-sm text-brand-700 hover:underline">
          ← Pool
        </Link>
        <h1 className="mt-1 break-all font-mono text-xl font-bold text-gray-900">
          {slotName || 'Slot'}
        </h1>
      </div>

      {isLoading ? (
        <p className="text-sm text-gray-400">Loading slot…</p>
      ) : notFound ? (
        <p className="rounded-lg border border-gray-200 bg-white p-4 text-sm text-gray-600">
          No slot named <span className="font-mono">{slotName}</span> is
          currently in the collector. It may have drained or the node may have
          gone away.
        </p>
      ) : error ? (
        <p className="text-sm text-red-600">
          Could not load the slot: {(error as Error).message}
        </p>
      ) : slot && data ? (
        <>
          <div className="rounded-lg border border-gray-200 bg-white p-4">
            <dl className="grid grid-cols-2 gap-x-6 gap-y-3 sm:grid-cols-3">
              <Field label="Execute node">
                <Link
                  href="/pool"
                  className="text-brand-700 hover:underline"
                >
                  {slot.machine}
                </Link>
              </Field>
              <Field label="Slot type">{slot.slotType || '—'}</Field>
              <Field label="State / Activity">
                <span
                  className={`inline-flex rounded-full px-2 py-0.5 text-xs font-medium ${slotStateStyle(
                    slot.state,
                  )}`}
                >
                  {slot.state ?? '?'}
                </span>
                {slot.activity && (
                  <span className="ml-1 text-gray-400">/ {slot.activity}</span>
                )}
              </Field>
              <Field label="CPUs">{slot.cpus ?? '—'}</Field>
              <Field label="Memory">{gib(slot.memoryMB)}</Field>
              <Field label="GPUs">{slot.gpus ?? '—'}</Field>
              <Field label="Owner">{slot.remoteOwner ?? '—'}</Field>
              <Field label="Arch">{slot.arch ?? '—'}</Field>
              <Field label="OS">{slot.opsys ?? '—'}</Field>
            </dl>
          </div>

          <RawAd ad={data} />
        </>
      ) : null}
    </div>
  );
}

function Field({
  label,
  children,
}: {
  label: string;
  children: React.ReactNode;
}) {
  return (
    <div>
      <dt className="text-xs uppercase tracking-wide text-gray-500">{label}</dt>
      <dd className="mt-0.5 text-sm text-gray-900">{children}</dd>
    </div>
  );
}

// RawAd dumps every attribute the collector returned, sorted, so the page
// is useful for debugging a slot regardless of which attributes the
// summary surfaces.
function RawAd({ ad }: { ad: Record<string, unknown> }) {
  const keys = Object.keys(ad).sort((a, b) => a.localeCompare(b));
  return (
    <div className="overflow-x-auto rounded-lg border border-gray-200 bg-white">
      <table className="min-w-full text-sm">
        <thead className="bg-gray-50 text-xs uppercase tracking-wide text-gray-500">
          <tr>
            <th className="px-3 py-2 text-left">Attribute</th>
            <th className="px-3 py-2 text-left">Value</th>
          </tr>
        </thead>
        <tbody className="divide-y divide-gray-100">
          {keys.map((k) => (
            <tr key={k}>
              <td className="whitespace-nowrap px-3 py-1.5 font-mono text-xs text-gray-700">
                {k}
              </td>
              <td className="px-3 py-1.5 font-mono text-xs break-all text-gray-900">
                {formatValue(ad[k])}
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

function formatValue(v: unknown): string {
  if (v === null || v === undefined) return '';
  if (typeof v === 'string' || typeof v === 'number' || typeof v === 'boolean') {
    return String(v);
  }
  return JSON.stringify(v);
}
