// Who a session may see the jobs of, for links that lead to one user's
// listing (/users/<owner>).

import type { Session } from '@/lib/api';

// sameUser compares a queue Owner with the session's identity. The queue
// stores a bare account name; a session identity may be fully qualified
// (user@domain), so compare on the local part.
export function sameUser(owner: string, username: string | undefined): boolean {
  if (!owner || !username) return false;
  const local = (s: string) => s.split('@')[0].toLowerCase();
  return local(owner) === local(username);
}

// mayListUser says whether a link to owner's listing would show this
// session anything: an administrator sees everyone's jobs, anyone else
// only their own. A link that led to "you can only see your own jobs"
// would be a dead end, so it is not offered.
export function mayListUser(owner: string, session: Session | undefined): boolean {
  if (!session) return false;
  return !!session.is_admin || sameUser(owner, session.username);
}
