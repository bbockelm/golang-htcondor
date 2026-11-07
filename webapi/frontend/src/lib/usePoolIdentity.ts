import { useQuery } from '@tanstack/react-query';
import { api } from '@/lib/api';

// usePoolIdentityRestricted reports whether this site withholds who is
// running on a slot from this session (HTTP_API_POOL_QUERY_IDENTITY).
//
// Read from the session rather than passed down the tree: every pool view
// needs the same answer, and the session query is already cached under
// this key, so asking for it again costs no request.
//
// Advisory. It decides what the pool pages ASK for -- a projection naming
// an attribute the caller may not read is refused outright, so requesting
// it anyway would empty the page rather than blank one column -- and what
// they say about the gap. The server applies the same rule to what it
// answers, so a stale or absent flag cannot reveal anything.
export function usePoolIdentityRestricted(): boolean {
  const { data } = useQuery({ queryKey: ['session'], queryFn: api.auth.me });
  return data?.pool_identity_restricted === true;
}
