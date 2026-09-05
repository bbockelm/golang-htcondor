'use client';

import { useEffect, useState } from 'react';
import { useMutation, useQueryClient } from '@tanstack/react-query';
import { api, type Session } from '@/lib/api';

// SuperuserBanner warns, on every page, that this session's next action may
// land on somebody else's job.
//
// It is deliberately loud and deliberately not dismissible. The whole risk of
// superuser mode is that the UI looks identical while the meaning of every
// button has changed, so the warning has to be impossible to overlook and
// impossible to silence while leaving the mode on. The only way to make it go
// away is to turn the mode off, which is the action we want to be easy.
export function SuperuserBanner({ session }: { session: Session | undefined }) {
  const qc = useQueryClient();
  const [now, setNow] = useState(() => Date.now());

  const active = !!session?.superuser_active;

  // Tick once a second so the remaining time counts down. Only while armed —
  // there is nothing to animate otherwise, and a permanent interval on every
  // page would be a silly thing to pay for a banner nobody is seeing.
  useEffect(() => {
    if (!active) return;
    const id = setInterval(() => setNow(Date.now()), 1000);
    return () => clearInterval(id);
  }, [active]);

  const disarm = useMutation({
    mutationFn: () => api.auth.setSuperuserMode(false),
    onSuccess: () => qc.invalidateQueries({ queryKey: ["session"] }),
  });

  if (!active) return null;

  const expiresAt = session?.superuser_expires_at
    ? new Date(session.superuser_expires_at).getTime()
    : null;
  const remainingMs = expiresAt !== null ? expiresAt - now : null;

  // The mode has lapsed but the session query has not refetched yet. Say so
  // rather than showing a stale countdown; the next refetch clears the banner.
  const lapsed = remainingMs !== null && remainingMs <= 0;

  return (
    <div
      role="alert"
      className="sticky top-0 z-30 flex flex-wrap items-center gap-x-3 gap-y-1 border-b-2 border-red-700 bg-red-600 px-4 py-2 text-sm font-medium text-white"
    >
      <span aria-hidden className="text-base leading-none">
        ⚠
      </span>
      <span className="font-semibold uppercase tracking-wide">
        Superuser mode
      </span>
      <span className="font-normal">
        Actions you take may apply to <strong>other users&apos; jobs</strong>,
        and are recorded against your name.
      </span>
      {session?.superuser_note && (
        // Shown because the note always describes a downgrade in how well
        // the action can be attributed, and each one has a concrete fix.
        <span className="basis-full text-xs font-normal opacity-90">
          {session.superuser_note}
        </span>
      )}
      <span className="ml-auto flex items-center gap-3">
        {lapsed ? (
          <span className="font-normal opacity-90">expired</span>
        ) : (
          remainingMs !== null && (
            <span className="font-normal tabular-nums opacity-90">
              {formatRemaining(remainingMs)} left
            </span>
          )
        )}
        <button
          type="button"
          onClick={() => disarm.mutate()}
          disabled={disarm.isPending}
          className="rounded-sm border border-white/60 bg-white/10 px-2 py-0.5 text-xs font-semibold hover:bg-white/20 disabled:opacity-60"
        >
          {disarm.isPending ? "Turning off…" : "Turn off"}
        </button>
      </span>
    </div>
  );
}

// formatRemaining renders a duration as m:ss, or h:mm:ss past an hour.
function formatRemaining(ms: number): string {
  const total = Math.max(0, Math.floor(ms / 1000));
  const h = Math.floor(total / 3600);
  const m = Math.floor((total % 3600) / 60);
  const s = total % 60;
  const pad = (n: number) => String(n).padStart(2, "0");
  return h > 0 ? `${h}:${pad(m)}:${pad(s)}` : `${m}:${pad(s)}`;
}
