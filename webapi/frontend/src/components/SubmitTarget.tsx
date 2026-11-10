'use client';

import { submitTargets, type APAssignment } from '@/lib/api';

// SubmitTarget says which access point a submission goes to, in
// multi-AP mode, and offers the others the caller may choose. Renders
// nothing outside multi-AP mode.
export function SubmitTarget({
  multiAP,
  assignment,
  value,
  onChange,
  label = 'Access point',
}: {
  multiAP: boolean;
  assignment?: APAssignment;
  value: string;
  onChange: (schedd: string) => void;
  // The select's accessible name, where a page has more than one.
  label?: string;
}) {
  if (!multiAP) return null;
  const targets = submitTargets(assignment);
  if (targets.length === 0) {
    return (
      <div role="alert" className="rounded-sm border border-red-200 bg-red-50 px-3 py-2 text-sm text-red-700">
        You cannot submit here: {assignment?.error ?? 'no access point is assigned to you'}.
      </div>
    );
  }
  const current = targets.includes(value) ? value : targets[0];
  return (
    <div className="flex flex-wrap items-center gap-2 text-sm text-gray-700">
      <span>Will submit to</span>
      {targets.length === 1 ? (
        <code className="rounded-sm bg-gray-100 px-1.5 py-0.5 text-xs">{current}</code>
      ) : (
        <select
          aria-label={label}
          value={current}
          onChange={(e) => onChange(e.target.value)}
          className="rounded-sm border border-gray-300 px-2 py-1 font-mono text-xs"
        >
          {targets.map((t, i) => (
            <option key={t} value={t}>
              {i === 0 ? `${t} (home)` : t}
            </option>
          ))}
        </select>
      )}
    </div>
  );
}
