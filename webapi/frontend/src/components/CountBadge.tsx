// CountBadge is a small count beside a label, with the label read out for
// screen readers; nothing when the count is zero or unknown.
export function CountBadge({ count, label }: { count?: number; label: string }) {
  if (!count) return null;
  return (
    <span
      aria-label={`${count} ${label}`}
      className="ml-1.5 inline-flex min-w-5 items-center justify-center rounded-full bg-amber-500 px-1.5 text-[11px] font-semibold leading-5 text-white"
    >
      {count}
    </span>
  );
}
