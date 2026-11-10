'use client';

import { useEffect, useRef } from 'react';

import type { SubmitResponse } from '@/lib/api';
import { batchHref } from '@/lib/similar';

// batchViewHref is where "view the batch" goes for a submission.
//
// A batch has its own page, which is the thing to open: it shows the
// whole submission rather than one job of it, and the server resolves
// any of a batch's clusters to it. In multi-AP mode there is no such
// page -- a batch there can span access points -- so the jobs listing
// filtered to the cluster is the closest equivalent.
export function batchViewHref(result: SubmitResponse): string {
  if (result.schedd) return batchHref(result.cluster_id, false);
  return `/batches/${result.cluster_id}`;
}

// SubmittedDialog is what a successful submit opens instead of
// navigating away.
//
// The page used to push the first job's detail view on success, which
// answered "did it go in" and destroyed everything needed to send a
// second one: the template body, the table, the inline scripts, the
// attached files. Iterating on a job -- the normal case, since the
// first version of a submit file is rarely the one that works -- meant
// coming back and building the draft again from nothing.
//
// So neither button navigates this tab. "View batch" opens the batch in
// a new one, leaving this page exactly as it was behind it; "Submit
// more" just closes. Both keep the draft, which is the point.
export function SubmittedDialog({
  result,
  onDismiss,
}: {
  result: SubmitResponse;
  onDismiss: () => void;
}) {
  const count = result.job_ids.length;
  const href = batchViewHref(result);
  // Focus the dialog on open so Escape and the buttons are reachable
  // from the keyboard without a click first -- the user's hands are on
  // the keyboard, having just come from the submit button.
  const ref = useRef<HTMLDivElement>(null);
  useEffect(() => {
    ref.current?.focus();
  }, []);

  return (
    <div
      className="fixed inset-0 z-50 flex items-center justify-center bg-black/40 p-4"
      onClick={onDismiss}
    >
      <div
        ref={ref}
        role="dialog"
        aria-labelledby="submitted-dialog-title"
        aria-modal="true"
        tabIndex={-1}
        onClick={(e) => e.stopPropagation()}
        onKeyDown={(e) => {
          if (e.key === 'Escape') onDismiss();
        }}
        className="w-full max-w-lg rounded-sm bg-white p-5 shadow-lg outline-none"
      >
        <h2
          id="submitted-dialog-title"
          className="text-lg font-semibold text-gray-900"
        >
          Submitted {count} job{count === 1 ? '' : 's'}
        </h2>
        <p className="mt-1 text-xs text-gray-500">
          Batch {result.cluster_id}
          {result.schedd ? ` on ${result.schedd}` : ''}. Your draft is
          still here, so you can change it and submit again.
        </p>

        {result.warnings && result.warnings.length > 0 && (
          <div className="mt-3 rounded-sm border border-amber-200 bg-amber-50 p-2 text-xs text-amber-900">
            <div className="font-medium">
              Check this before you rely on the results
            </div>
            <ul className="mt-1 list-disc space-y-1 pl-4">
              {result.warnings.map((w) => (
                <li key={w}>{w}</li>
              ))}
            </ul>
          </div>
        )}

        <div className="mt-5 flex items-center justify-end gap-2">
          <button
            type="button"
            onClick={onDismiss}
            className="rounded-sm border border-gray-300 bg-white px-3 py-1.5 text-sm text-gray-700 hover:bg-gray-50"
          >
            Submit more
          </button>
          <a
            href={href}
            target="_blank"
            rel="noopener noreferrer"
            onClick={onDismiss}
            className="rounded bg-brand-600 px-3 py-1.5 text-sm font-medium text-white hover:bg-brand-700"
          >
            View batch
          </a>
        </div>
      </div>
    </div>
  );
}
