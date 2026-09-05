'use client';

import { useSyncExternalStore } from 'react';
import { scopeStore, type Scope } from '@/lib/scope';

// useScope is the read side of the shared listing scope. Every page that
// lists jobs uses it, so switching on one switches all of them.
export function useScope(): [Scope, (next: Scope) => void] {
  const scope = useSyncExternalStore(
    scopeStore.subscribe,
    scopeStore.getSnapshot,
    scopeStore.getServerSnapshot,
  );
  return [scope, scopeStore.setScope];
}

// ScopeToggle is the Mine/Everyone segmented control shared by the
// dashboard, /jobs and /archive. Render it only for admins: a non-admin
// session is confined by the server no matter what it selects, so
// offering the choice would just be a button that does nothing.
export function ScopeToggle({ className = '' }: { className?: string }) {
  const [scope, setScope] = useScope();
  return (
    <div
      className={`flex items-center gap-1 rounded-sm border border-gray-300 bg-white p-0.5 text-xs ${className}`}
      role="group"
      aria-label="Listing scope"
    >
      <ScopeButton current={scope} value="mine" onSelect={setScope}>
        Mine
      </ScopeButton>
      <ScopeButton current={scope} value="all" onSelect={setScope}>
        Everyone
      </ScopeButton>
    </div>
  );
}

function ScopeButton({
  current,
  value,
  onSelect,
  children,
}: {
  current: Scope;
  value: Scope;
  onSelect: (next: Scope) => void;
  children: React.ReactNode;
}) {
  const active = current === value;
  return (
    <button
      type="button"
      onClick={() => onSelect(value)}
      aria-pressed={active}
      className={`rounded px-2 py-0.5 ${
        active ? 'bg-gray-200 text-gray-900' : 'text-gray-600 hover:bg-gray-100'
      }`}
    >
      {children}
    </button>
  );
}
