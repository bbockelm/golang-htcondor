'use client';

import { useEffect, useRef, useState } from 'react';

// ConfirmButton renders a destructive action as a two-click affordance:
//
//   [ Remove ]                ← idle
//                  click
//   [ Cancel ] [ Confirm ]    ← armed: Confirm fires; Cancel disarms
//                  click outside / Escape / 5 s
//   [ Remove ]                ← back to idle (no fire)
//
// We deliberately avoid native window.confirm() popups so the action stays
// inline in the row/page where the user clicked it (the parent ask was to
// show a confirm button, not a modal). The "armed" state auto-disarms after
// 5 seconds so a half-clicked Remove doesn't sit dangerous indefinitely.
//
// Variants:
//   compact   – tighter padding / smaller text for table rows
//   destructive (default) – red on confirm
//
// On firing onConfirm, we transition to a "pending" state until the parent
// either clears it (resolves the mutation) or unmounts us.

interface ConfirmButtonProps {
  onConfirm: () => void;
  pending?: boolean;
  // Idle button label (e.g. "Remove"). Defaults to "Remove".
  label?: string;
  // Confirm button label. Defaults to "Confirm".
  confirmLabel?: string;
  // Label of the "back out" button shown alongside Confirm while
  // armed. Defaults to "Cancel".
  cancelLabel?: string;
  // Tooltip / aria-label for the idle button.
  title?: string;
  // Compact rendering for inline use in table rows.
  compact?: boolean;
  // Auto-disarm timeout in ms; 0 disables. Default 5 000.
  disarmAfterMs?: number;
  // When true, render the idle button disabled.
  disabled?: boolean;
}

export function ConfirmButton({
  onConfirm,
  pending = false,
  label = 'Remove',
  confirmLabel = 'Confirm',
  cancelLabel = 'Cancel',
  title,
  compact = false,
  disarmAfterMs = 5000,
  disabled = false,
}: ConfirmButtonProps) {
  const [armed, setArmed] = useState(false);
  const wrapRef = useRef<HTMLDivElement>(null);

  // Disarm on outside click, Escape, or after a timeout.
  useEffect(() => {
    if (!armed) return;

    const onClick = (ev: MouseEvent) => {
      if (!wrapRef.current) return;
      if (!wrapRef.current.contains(ev.target as Node)) {
        setArmed(false);
      }
    };
    const onKey = (ev: KeyboardEvent) => {
      if (ev.key === 'Escape') setArmed(false);
    };
    document.addEventListener('mousedown', onClick);
    document.addEventListener('keydown', onKey);

    let to: ReturnType<typeof setTimeout> | undefined;
    if (disarmAfterMs > 0) {
      to = setTimeout(() => setArmed(false), disarmAfterMs);
    }
    return () => {
      document.removeEventListener('mousedown', onClick);
      document.removeEventListener('keydown', onKey);
      if (to) clearTimeout(to);
    };
  }, [armed, disarmAfterMs]);

  const sizeCls = compact ? 'px-2 py-0.5 text-xs' : 'px-3 py-1.5 text-sm';

  return (
    <div ref={wrapRef} className="inline-flex items-center gap-1">
      <button
        type="button"
        disabled={disabled || pending}
        onClick={(e) => {
          e.stopPropagation();
          // While armed, this same button is the "Cancel" affordance:
          // clicking it disarms (no fire). When idle, clicking it
          // arms.
          setArmed((a) => !a);
        }}
        className={`rounded border ${sizeCls} ${
          armed
            ? 'border-gray-300 bg-white text-gray-700 hover:bg-gray-50'
            : 'border-gray-300 bg-white text-gray-700 hover:bg-gray-50'
        } disabled:opacity-50 disabled:cursor-not-allowed`}
        title={title}
        aria-label={armed ? cancelLabel : (title ?? label)}
      >
        {pending ? '…' : armed ? cancelLabel : label}
      </button>
      {armed && (
        <button
          type="button"
          autoFocus
          disabled={pending}
          onClick={(e) => {
            e.stopPropagation();
            setArmed(false);
            onConfirm();
          }}
          className={`rounded border border-red-600 bg-red-600 ${sizeCls} font-medium text-white hover:bg-red-700 disabled:opacity-60`}
        >
          {confirmLabel}
        </button>
      )}
    </div>
  );
}
