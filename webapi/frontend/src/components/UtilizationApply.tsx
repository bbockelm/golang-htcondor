'use client';

// Applying a workflow's suggestions to its jobs that have not started
// yet. The advice on this page is about the next submission; for a
// workflow still in the queue, the cheapest next submission is the jobs
// already waiting.
//
// Two steps, inline: a review that lists exactly which requests change
// from what to what (and which suggestions cannot be applied), then the
// apply. The request names advice by id; the server writes the values
// from its own advice, so nothing on this page decides what a job gets.

import { useState } from 'react';
import { useMutation, useQueryClient } from '@tanstack/react-query';
import { api } from '@/lib/api';
import {
  applicableIds,
  applyPlan,
  describeSet,
  type UtilAdaptiveResource,
  type UtilApplyResponse,
  type UtilWorkflow,
} from '@/lib/utilization';
import type { JobsQuery } from '@/components/UtilizationJobs';

export function ApplyPanel({
  workflow,
  waitingJobs,
  waitingAdaptive,
  query,
}: {
  workflow: UtilWorkflow;
  waitingJobs: number | null;
  // Request attributes that are formulas on the waiting jobs.
  waitingAdaptive?: UtilAdaptiveResource[];
  query: JobsQuery;
}) {
  const qc = useQueryClient();
  const plan = applyPlan(workflow, waitingAdaptive);
  const ids = applicableIds(plan.changes);
  const [step, setStep] = useState<'offer' | 'review'>('offer');
  const [chosen, setChosen] = useState<Set<string>>(() => new Set(ids));

  const apply = useMutation<UtilApplyResponse, Error, string[]>({
    mutationFn: (advice) =>
      api.utilizationApply({
        w: workflow.key,
        advice,
        days: query.days,
        owned_by_me: query.owned_by_me,
        constraint: query.constraint,
        owners: query.owners && query.owners.length ? query.owners.join(',') : undefined,
        limit: query.limit,
        schedd: query.schedd,
      }),
    // The waiting count and the queue changed; ask again rather than show
    // the numbers from before the edit.
    onSuccess: () => {
      void qc.invalidateQueries({ queryKey: ['utilization-workflow'] });
      void qc.invalidateQueries({ queryKey: ['utilization-jobs'] });
      void qc.invalidateQueries({ queryKey: ['utilization'] });
    },
  });

  if (apply.data) return <ApplyResult result={apply.data} workflow={workflow} />;
  if (!waitingJobs || waitingJobs <= 0 || plan.changes.length === 0) return null;

  const n = waitingJobs.toLocaleString();
  const toggle = (id: string) =>
    setChosen((prev) => {
      const next = new Set(prev);
      if (next.has(id)) next.delete(id);
      else next.add(id);
      return next;
    });

  return (
    <section
      aria-labelledby="wf-apply"
      className="rounded-lg border border-brand-200 bg-brand-50/40 px-4 py-3"
      data-testid="apply-panel"
    >
      <h3 id="wf-apply" className="font-semibold text-gray-900">
        {n} {waitingJobs === 1 ? 'job' : 'jobs'} of this workflow {waitingJobs === 1 ? 'is' : 'are'} still waiting —
        apply these requests to {waitingJobs === 1 ? 'it' : 'them'}
      </h3>
      {step === 'offer' ? (
        <button
          type="button"
          onClick={() => setStep('review')}
          className="mt-2 rounded-sm bg-brand-600 px-3 py-1.5 text-sm font-medium text-white hover:bg-brand-700"
        >
          Review the changes
        </button>
      ) : (
        <div className="mt-2 space-y-3 text-sm">
          <table className="w-full max-w-2xl text-left text-sm" data-testid="apply-changes">
            <thead className="text-xs text-gray-500">
              <tr>
                <th className="py-1 pr-2 font-normal" />
                <th className="py-1 pr-3 font-normal">Request</th>
                <th className="py-1 pr-3 font-normal">Now</th>
                <th className="py-1 font-normal">Becomes</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-brand-100">
              {plan.changes.map((c) => (
                // A formula request on the waiting jobs is left alone by
                // the server, so its row is shown but cannot be ticked.
                <tr key={`${c.advice.id}/${c.attr}`} className={c.adaptive ? 'text-gray-400' : undefined} data-disabled={c.adaptive || undefined}>
                  <td className="py-1 pr-2">
                    <input
                      type="checkbox"
                      checked={!c.adaptive && chosen.has(c.advice.id)}
                      disabled={c.adaptive}
                      onChange={() => toggle(c.advice.id)}
                      aria-label={`Apply ${c.attr}`}
                    />
                  </td>
                  <td className="py-1 pr-3 font-mono text-xs">{c.attr}</td>
                  <td className={`py-1 pr-3 ${c.adaptive ? '' : 'text-gray-700'}`}>{c.from}</td>
                  <td className={`py-1 ${c.adaptive ? 'italic' : 'font-medium text-gray-900'}`}>
                    {c.adaptive ? 'formula request — not changed' : c.to}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
          {plan.blocked.length > 0 && (
            <div className="text-xs text-gray-600" data-testid="apply-blocked">
              Not applied to waiting jobs:
              <ul className="ml-4 list-disc">
                {plan.blocked.map((a) => (
                  <li key={a.id}>{a.title}</li>
                ))}
              </ul>
            </div>
          )}
          {ids.length === 0 ? (
            <div className="flex flex-wrap items-center gap-2">
              <p className="text-sm text-gray-700" data-testid="apply-none">
                Nothing to apply: the waiting jobs request these as formulas, which are not changed.
              </p>
              <button
                type="button"
                onClick={() => setStep('offer')}
                className="rounded-sm border border-gray-300 bg-white px-3 py-1.5 text-sm text-gray-700 hover:bg-gray-50"
              >
                Close
              </button>
            </div>
          ) : (
            <div className="flex flex-wrap items-center gap-2">
              <button
                type="button"
                disabled={chosen.size === 0 || apply.isPending}
                onClick={() => apply.mutate(ids.filter((id) => chosen.has(id)))}
                className="rounded-sm bg-brand-600 px-3 py-1.5 text-sm font-medium text-white hover:bg-brand-700 disabled:opacity-50"
              >
                {apply.isPending ? 'Applying…' : `Apply to ${n} waiting ${waitingJobs === 1 ? 'job' : 'jobs'}`}
              </button>
              <button
                type="button"
                onClick={() => setStep('offer')}
                disabled={apply.isPending}
                className="rounded-sm border border-gray-300 bg-white px-3 py-1.5 text-sm text-gray-700 hover:bg-gray-50"
              >
                Cancel
              </button>
            </div>
          )}
          {apply.error && <p className="text-sm text-red-700">Could not apply: {apply.error.message}</p>}
        </div>
      )}
    </section>
  );
}

// groupReasons counts jobs by the reason they were passed over, so 300
// jobs skipped for one reason read as one line.
function groupReasons(items: { job: string; reason: string }[]): { reason: string; jobs: string[] }[] {
  const by = new Map<string, string[]>();
  for (const it of items) by.set(it.reason, [...(by.get(it.reason) ?? []), it.job]);
  return [...by.entries()].map(([reason, jobs]) => ({ reason, jobs }));
}

function ApplyResult({ result, workflow }: { result: UtilApplyResponse; workflow: UtilWorkflow }) {
  const set = describeSet(result.set);
  const title = (id: string) => workflow.advice.find((a) => a.id === id)?.title ?? id;
  return (
    <section className="rounded-lg border border-gray-200 bg-white px-4 py-3 text-sm" data-testid="apply-result" role="status">
      <p className="font-semibold text-gray-900">
        {result.edited > 0
          ? `Changed ${result.edited.toLocaleString()} waiting ${result.edited === 1 ? 'job' : 'jobs'}${set.length ? `: now requesting ${set.join(', ')}` : ''}.`
          : 'No waiting jobs were changed.'}
      </p>
      {result.declined.length > 0 && (
        <div className="mt-1 text-gray-700">
          Not applied:
          <ul className="ml-4 list-disc">
            {result.declined.map((d) => (
              <li key={d.advice}>
                {title(d.advice)} — {d.reason}
              </li>
            ))}
          </ul>
        </div>
      )}
      {result.skipped.length > 0 && (
        <div className="mt-1 text-gray-700">
          Left as they were:
          <ul className="ml-4 list-disc">
            {groupReasons(result.skipped).map((g) => (
              <li key={g.reason}>
                {g.jobs.length.toLocaleString()} {g.jobs.length === 1 ? 'job' : 'jobs'} — {g.reason}
              </li>
            ))}
          </ul>
        </div>
      )}
      {result.failed.length > 0 && (
        <div className="mt-1 text-red-700">
          Could not change:
          <ul className="ml-4 list-disc">
            {groupReasons(result.failed).map((g) => (
              <li key={g.reason}>
                {g.jobs.slice(0, 5).join(', ')}
                {g.jobs.length > 5 && ` and ${(g.jobs.length - 5).toLocaleString()} more`} — {g.reason}
              </li>
            ))}
          </ul>
        </div>
      )}
    </section>
  );
}
