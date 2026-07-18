'use client';

import { useState } from 'react';
import { api, type JobLogEvent, type JobLogResponse } from '@/lib/api';

// LogViewerPanel renders the parsed HTCondor user-log for a job. The
// fetch is explicit ("Load log" / "Refresh") because the schedd has to
// retrieve the entire sandbox to extract this one file — same reasoning
// as the stdout/stderr previews.
export function LogViewerPanel({ jobID }: { jobID: string }) {
  const [data, setData] = useState<JobLogResponse | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);

  const load = () => {
    if (loading) return;
    setLoading(true);
    setError(null);
    api.jobs
      .log(jobID)
      .then((res) => setData(res))
      .catch((e: unknown) =>
        setError(e instanceof Error ? e.message : String(e)),
      )
      .finally(() => setLoading(false));
  };

  return (
    <div className="rounded border border-gray-200 bg-white p-4 space-y-3">
      <div className="flex items-center justify-between">
        <h2 className="text-sm font-medium text-gray-900">Job Log</h2>
        <div className="flex items-center gap-2">
          {data && data.truncated && (
            <span className="rounded-full bg-amber-100 px-1.5 py-0.5 text-[10px] uppercase tracking-wide text-amber-800">
              truncated
            </span>
          )}
          <button
            onClick={load}
            disabled={loading}
            className="text-xs rounded border border-gray-300 bg-white px-2 py-1 text-gray-700 hover:bg-gray-50 disabled:opacity-50"
          >
            {loading ? 'Loading…' : data ? 'Refresh' : 'Load log'}
          </button>
        </div>
      </div>

      {error && (
        <p className="text-sm text-red-700">Could not load log: {error}</p>
      )}

      {!data && !error && !loading && (
        <p className="text-xs text-gray-500">
          The HTCondor user log gives a time-lapse of the job — submit,
          execute, hold, terminate. Click <em>Load log</em> to fetch it.
        </p>
      )}

      {data && data.events.length === 0 && (
        <p className="text-xs italic text-gray-500">
          No events yet — the schedd hasn&apos;t flushed any to{' '}
          <code className="font-mono">{data.filename}</code>.
        </p>
      )}

      {data && data.events.length > 0 && (
        <ol className="space-y-2">
          {data.events.map((ev, i) => (
            <li key={i}>
              <EventRow ev={ev} />
            </li>
          ))}
        </ol>
      )}

      {data && data.parseError && (
        <p className="text-xs text-amber-800 bg-amber-50 border border-amber-200 rounded px-2 py-1">
          Parser stopped early: {data.parseError}
        </p>
      )}
    </div>
  );
}

// EventRow renders one userlog.Event with a tone-coded gutter, an
// icon-ish glyph, a one-line headline, and event-specific detail
// fields. Falls back to verbatim body for unknown event kinds.
function EventRow({ ev }: { ev: JobLogEvent }) {
  const tone = toneFor(ev);
  return (
    <div className={`rounded border ${tone.border} ${tone.bg} p-2 text-sm`}>
      <div className="flex items-start gap-2">
        <span
          aria-hidden
          className={`mt-0.5 inline-flex h-5 w-5 shrink-0 items-center justify-center rounded-full ${tone.iconBg} text-[11px] ${tone.iconText}`}
        >
          {tone.glyph}
        </span>
        <div className="min-w-0 flex-1">
          <div className="flex flex-wrap items-baseline gap-x-2">
            <span className={`font-medium ${tone.title}`}>
              {headlineFor(ev)}
            </span>
            <span className="text-[11px] text-gray-500 font-mono">
              {fmtTime(ev.event_time)}
            </span>
          </div>
          <Details ev={ev} />
        </div>
      </div>
    </div>
  );
}

// Details picks the right per-event renderer. Anything we don't have a
// special case for falls through to GenericDetails (attributes table +
// optional verbatim body in a collapsible).
function Details({ ev }: { ev: JobLogEvent }) {
  switch (ev.kind) {
    case 'Submit':
      return ev.submit_host ? (
        <Field label="From" mono>
          {ev.submit_host}
        </Field>
      ) : null;

    case 'Execute':
      return (
        <div className="mt-1 space-y-0.5 text-xs">
          {ev.execute_host && (
            <Field label="On" mono>
              {ev.execute_host}
            </Field>
          )}
          {ev.attributes?.SlotName && (
            <Field label="Slot" mono>
              {ev.attributes.SlotName}
            </Field>
          )}
          {ev.attributes?.CondorScratchDir && (
            <Field label="Scratch" mono>
              {ev.attributes.CondorScratchDir}
            </Field>
          )}
        </div>
      );

    case 'JobHeld':
      return (
        <div className="mt-1 space-y-0.5 text-xs">
          {ev.hold_reason && <Field label="Reason">{ev.hold_reason}</Field>}
          {(ev.hold_reason_code != null ||
            ev.hold_reason_sub_code != null) && (
            <Field label="Code" mono>
              {ev.hold_reason_code ?? '?'}
              {ev.hold_reason_sub_code != null
                ? ` / ${ev.hold_reason_sub_code}`
                : ''}
            </Field>
          )}
        </div>
      );

    case 'JobReleased':
      return ev.body ? <BodyText body={ev.body} /> : null;

    case 'JobAborted':
      return ev.abort_reason ? (
        <Field label="Reason">{ev.abort_reason}</Field>
      ) : null;

    case 'JobTerminated': {
      const lines: React.ReactNode[] = [];
      if (ev.terminated_normally) {
        lines.push(
          <Field key="exit" label="Exit" mono>
            return value {ev.return_value ?? 0}
          </Field>,
        );
      } else if (ev.terminated_by_signal != null) {
        lines.push(
          <Field key="signal" label="Killed by signal" mono>
            {ev.terminated_by_signal}
          </Field>,
        );
      }
      const usage = pickAny(ev.attributes, ['MemoryUsage', 'ResidentSetSize']);
      if (usage) {
        lines.push(
          <Field key="usage" label="Resources">
            {usage}
          </Field>,
        );
      }
      return (
        <div className="mt-1 space-y-0.5 text-xs">
          {lines}
          {ev.body && <BodyText body={ev.body} collapsible />}
        </div>
      );
    }

    case 'ImageSizeUpdate': {
      const mem = ev.attributes?.MemoryUsage;
      const rss = ev.attributes?.ResidentSetSize;
      const desc = ev.description.replace(/^Image size of job updated:\s*/, '');
      return (
        <div className="mt-1 space-y-0.5 text-xs">
          {desc && (
            <Field label="Image size" mono>
              {desc} KB
            </Field>
          )}
          {mem && (
            <Field label="Memory" mono>
              {mem} MB
            </Field>
          )}
          {rss && (
            <Field label="RSS" mono>
              {rss} KB
            </Field>
          )}
        </div>
      );
    }

    case 'FileTransfer':
      return ev.body ? <BodyText body={ev.body} /> : null;

    default:
      return <GenericDetails ev={ev} />;
  }
}

function GenericDetails({ ev }: { ev: JobLogEvent }) {
  const entries = ev.attributes ? Object.entries(ev.attributes) : [];
  if (entries.length === 0 && !ev.body) return null;
  return (
    <div className="mt-1 space-y-0.5 text-xs">
      {entries.slice(0, 5).map(([k, v]) => (
        <Field key={k} label={k} mono>
          {v}
        </Field>
      ))}
      {ev.body && <BodyText body={ev.body} collapsible />}
    </div>
  );
}

function Field({
  label,
  mono = false,
  children,
}: {
  label: string;
  mono?: boolean;
  children: React.ReactNode;
}) {
  return (
    <div className="flex flex-wrap gap-x-2 text-xs">
      <span className="text-gray-500">{label}:</span>
      <span
        className={`min-w-0 ${mono ? 'font-mono' : ''} text-gray-800 break-all`}
      >
        {children}
      </span>
    </div>
  );
}

function BodyText({
  body,
  collapsible = false,
}: {
  body: string;
  collapsible?: boolean;
}) {
  const trimmed = body.replace(/\s+$/, '');
  if (!trimmed) return null;
  if (!collapsible) {
    return (
      <pre className="mt-1 max-h-40 overflow-auto rounded border border-gray-200 bg-white p-1.5 text-[11px] font-mono whitespace-pre-wrap text-gray-700">
        {trimmed}
      </pre>
    );
  }
  return (
    <details className="mt-1 text-[11px]">
      <summary className="cursor-pointer text-gray-500 hover:text-gray-700">
        Show raw body
      </summary>
      <pre className="mt-1 max-h-60 overflow-auto rounded border border-gray-200 bg-white p-1.5 font-mono whitespace-pre-wrap text-gray-700">
        {trimmed}
      </pre>
    </details>
  );
}

// headlineFor produces the one-line summary at the top of each event.
// Most kinds get a short rephrasing of the C++ formatter's output;
// unknown kinds fall back to the verbatim Description so we never lose
// information.
function headlineFor(ev: JobLogEvent): string {
  switch (ev.kind) {
    case 'Submit':
      return 'Submitted';
    case 'Execute':
      return 'Started executing';
    case 'ImageSizeUpdate':
      return 'Image size updated';
    case 'JobHeld':
      return 'Held';
    case 'JobReleased':
      return 'Released';
    case 'JobAborted':
      return 'Aborted';
    case 'JobTerminated':
      if (ev.terminated_by_signal != null) {
        return `Terminated abnormally (signal ${ev.terminated_by_signal})`;
      }
      return `Terminated (exit ${ev.return_value ?? 0})`;
    case 'JobEvicted':
      return 'Evicted';
    case 'JobSuspended':
      return 'Suspended';
    case 'JobUnsuspended':
      return 'Unsuspended';
    case 'JobDisconnected':
      return 'Disconnected';
    case 'JobReconnected':
      return 'Reconnected';
    case 'JobReconnectFailed':
      return 'Reconnect failed';
    case 'ShadowException':
      return 'Shadow exception';
    case 'RemoteError':
      return 'Remote error';
    case 'FileTransfer':
      return 'File transfer';
    case 'Checkpointed':
      return 'Checkpointed';
    case 'JobAdInformation':
      return 'Job ad updated';
    case 'Unknown':
      return ev.description || `Event ${ev.event_number}`;
    default:
      return ev.description || ev.kind;
  }
}

// toneFor maps event kinds to gutter/icon styling. Three buckets:
// - "ok" (green): things going right (started, normal exit)
// - "info" (blue): structural events (submit, release, reconnect)
// - "warn" (amber): pause-y states (held, suspended, image-update)
// - "error" (red): things going wrong (abort, abnormal exit, fail)
// - "muted" (gray): everything else
type Tone = {
  glyph: string;
  border: string;
  bg: string;
  title: string;
  iconBg: string;
  iconText: string;
};
function toneFor(ev: JobLogEvent): Tone {
  const tones: Record<string, Tone> = {
    ok: {
      glyph: '✓',
      border: 'border-emerald-200',
      bg: 'bg-emerald-50',
      title: 'text-emerald-900',
      iconBg: 'bg-emerald-200',
      iconText: 'text-emerald-900',
    },
    info: {
      glyph: 'i',
      border: 'border-sky-200',
      bg: 'bg-sky-50',
      title: 'text-sky-900',
      iconBg: 'bg-sky-200',
      iconText: 'text-sky-900',
    },
    warn: {
      glyph: '!',
      border: 'border-amber-200',
      bg: 'bg-amber-50',
      title: 'text-amber-900',
      iconBg: 'bg-amber-200',
      iconText: 'text-amber-900',
    },
    error: {
      glyph: '×',
      border: 'border-rose-200',
      bg: 'bg-rose-50',
      title: 'text-rose-900',
      iconBg: 'bg-rose-200',
      iconText: 'text-rose-900',
    },
    muted: {
      glyph: '·',
      border: 'border-gray-200',
      bg: 'bg-gray-50',
      title: 'text-gray-800',
      iconBg: 'bg-gray-200',
      iconText: 'text-gray-700',
    },
  };

  switch (ev.kind) {
    case 'Submit':
    case 'JobReleased':
    case 'JobReconnected':
      return tones.info;
    case 'Execute':
      return tones.ok;
    case 'JobTerminated':
      if (ev.terminated_normally && (ev.return_value ?? 0) === 0) {
        return tones.ok;
      }
      return tones.error;
    case 'JobHeld':
    case 'JobSuspended':
    case 'ImageSizeUpdate':
    case 'JobDisconnected':
    case 'JobEvicted':
      return tones.warn;
    case 'JobAborted':
    case 'JobReconnectFailed':
    case 'ShadowException':
    case 'RemoteError':
      return tones.error;
    default:
      return tones.muted;
  }
}

function fmtTime(iso: string): string {
  if (!iso) return '';
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return iso;
  return d.toLocaleString();
}

function pickAny(
  attrs: Record<string, string> | undefined,
  keys: string[],
): string | undefined {
  if (!attrs) return undefined;
  const parts: string[] = [];
  for (const k of keys) {
    if (attrs[k]) parts.push(`${k}=${attrs[k]}`);
  }
  return parts.length > 0 ? parts.join(', ') : undefined;
}
