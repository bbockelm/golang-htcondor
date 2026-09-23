'use client';

import type { DisplayStatus } from '@/lib/api';
import { statusPillCls } from '@/app/jobs/[id]/JobDetailClient';
import { DISPLAY_STATUS_LABEL, DISPLAY_STATUS_ORDER } from '@/lib/batches';
import { StatusStrip } from '@/components/StatusStrip';

// The queue's status strip: the seven live job states plus the
// "Uploading Inputs" pseudo-status. See StatusStrip for the selection
// semantics.
export function JobStatusStrip({
  counts,
  selected,
  onToggle,
  onClear,
  total,
}: {
  counts: Record<DisplayStatus, number>;
  selected: Set<DisplayStatus>;
  onToggle: (key: DisplayStatus) => void;
  onClear: () => void;
  total: number;
}) {
  // A chip for every status present, plus any selected status that has
  // gone empty — without the latter, filtering down to a status that
  // then drains (the last held job released, say) would leave the user
  // looking at an empty table with no control to undo it.
  const chips = DISPLAY_STATUS_ORDER.filter(
    (k) => (counts[k] ?? 0) > 0 || selected.has(k),
  ).map((key) => ({
    key,
    label: DISPLAY_STATUS_LABEL[key],
    cls: statusPillCls(key),
    count: counts[key] ?? 0,
  }));

  return (
    <StatusStrip
      chips={chips}
      selected={selected}
      onToggle={onToggle}
      onClear={onClear}
      total={total}
      label="Filter by status"
    />
  );
}
