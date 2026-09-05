// Shared "Mine / Everyone" listing scope.
//
// The selector appears on the dashboard, /jobs and /archive, and picking
// one on any of them should hold on the others: an admin who switches to
// "Everyone" to chase somebody's job does not want /archive to quietly
// snap back to their own records.
//
// The value lives in localStorage rather than in React state so it also
// survives a reload, and it is read through useSyncExternalStore rather
// than an effect. That matters for two reasons: this app is a static
// export, so the pre-rendered HTML cannot know the stored value and a
// naive read during render would be a hydration mismatch; and
// useSyncExternalStore gives us cross-tab agreement for free through the
// storage event.
//
// Non-admin sessions never see the selector, and the server confines
// them regardless of what is stored here — this is a display preference,
// not an authorization input.

export type Scope = 'mine' | 'all';

const STORAGE_KEY = 'htcondor.listingScope';

// DEFAULT_SCOPE is also the server-render snapshot. "Mine" is the
// conservative default: a pool-wide view is something you ask for.
const DEFAULT_SCOPE: Scope = 'mine';

// cached is what getSnapshot returns. useSyncExternalStore compares
// snapshots by identity and re-renders until two agree, so this MUST be
// a stable value rather than a fresh read of localStorage each call.
let cached: Scope | null = null;

const listeners = new Set<() => void>();

function parse(raw: string | null): Scope {
  return raw === 'all' ? 'all' : DEFAULT_SCOPE;
}

function read(): Scope {
  try {
    return parse(window.localStorage.getItem(STORAGE_KEY));
  } catch {
    // Private windows and "block site data" make even reading throw.
    // A preference is not worth failing a render over.
    return DEFAULT_SCOPE;
  }
}

function getSnapshot(): Scope {
  if (cached === null) {
    cached = read();
  }
  return cached;
}

// getServerSnapshot answers for the pre-rendered HTML, which has no
// localStorage. Returning the default keeps hydration consistent; the
// first client snapshot then corrects it if the user stored something
// else.
function getServerSnapshot(): Scope {
  return DEFAULT_SCOPE;
}

// Another tab writing the key fires `storage` here. Re-read rather than
// trusting event.newValue so a removed key falls back cleanly. A null
// key means the whole store was cleared.
function onStorage(e: StorageEvent) {
  if (e.key !== null && e.key !== STORAGE_KEY) return;
  cached = read();
  notify();
}

function notify() {
  listeners.forEach((l) => l());
}

function subscribe(onChange: () => void): () => void {
  // One window listener for all subscribers, attached with the first and
  // dropped with the last. Attaching per subscriber would make each
  // cross-tab event fan out once per mounted component.
  if (listeners.size === 0) {
    window.addEventListener('storage', onStorage);
  }
  listeners.add(onChange);
  return () => {
    listeners.delete(onChange);
    if (listeners.size === 0) {
      window.removeEventListener('storage', onStorage);
    }
  };
}

function setScope(next: Scope) {
  if (cached === next) return;
  cached = next;
  try {
    window.localStorage.setItem(STORAGE_KEY, next);
  } catch {
    // Storage refused; the choice still applies to this page view.
  }
  notify();
}

export const scopeStore = { subscribe, getSnapshot, getServerSnapshot, setScope };
