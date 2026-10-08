'use client';

import { useAccessPoints } from '@/lib/multiap';

// ScheddFilter narrows a multi-AP listing to one access point. The empty
// value means every access point.
export function ScheddFilter({
  value,
  onChange,
}: {
  value: string;
  onChange: (schedd: string) => void;
}) {
  const { data } = useAccessPoints(true);
  const names = (data?.aps ?? []).map((a) => a.schedd);
  // Keep a value from the URL selectable even before the list loads.
  if (value && !names.includes(value)) names.unshift(value);
  return (
    <label className="flex items-center gap-2 text-sm text-gray-600">
      Access point
      <select
        value={value}
        onChange={(e) => onChange(e.target.value)}
        className="rounded-sm border border-gray-300 bg-white px-2 py-1 text-sm"
      >
        <option value="">All</option>
        {names.map((n) => (
          <option key={n} value={n}>
            {n}
          </option>
        ))}
      </select>
    </label>
  );
}
