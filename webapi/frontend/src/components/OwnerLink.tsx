'use client';

import Link from 'next/link';
import { useQuery } from '@tanstack/react-query';
import { api } from '@/lib/api';
import { mayListUser } from '@/lib/users';

// OwnerLink is a job's owner, linked to that user's listing when this
// session can see their jobs, and plain text when it cannot.
export function OwnerLink({ owner }: { owner: string | undefined }) {
  const { data: session } = useQuery({
    queryKey: ['session'],
    queryFn: api.auth.me,
  });
  if (!owner) return <>—</>;
  if (!mayListUser(owner, session)) return <>{owner}</>;
  return (
    <Link
      href={`/users/${encodeURIComponent(owner)}`}
      className="text-brand-700 hover:underline"
      title={`Everything ${owner} has in the queue`}
    >
      {owner}
    </Link>
  );
}
