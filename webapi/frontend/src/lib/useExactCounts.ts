import { useMemo } from 'react';
import { keepPreviousData, useQuery } from '@tanstack/react-query';
import { api } from '@/lib/api';
import { fetchExactCounts, type ExactCounts } from '@/lib/exactCounts';

// useExactCounts runs the second, narrow query for the clusters whose
// progress the listing could not settle (see exactCounts.ts). Undefined
// when there are none.
export function useExactCounts({
  clusters,
  ownedByMe,
  schedd,
}: {
  clusters: number[];
  ownedByMe: boolean;
  schedd?: string;
}): ExactCounts | undefined {
  const enabled = clusters.length > 0;
  const q = useQuery({
    queryKey: ['batch-counts', ownedByMe, schedd, clusters.join(',')],
    enabled,
    queryFn: async () => ({
      clusters: new Set(clusters),
      ads: await fetchExactCounts(clusters, api.jobs.list, { ownedByMe, schedd }),
    }),
    // The previous answer stays on screen while a changed cluster list is
    // fetched; withExactCounts only uses it for the clusters it covers.
    placeholderData: keepPreviousData,
    refetchInterval: 30_000,
  });
  const failed = q.isError && (!q.data || q.isPlaceholderData);
  return useMemo((): ExactCounts | undefined => {
    if (!enabled) return undefined;
    if (failed) return { status: 'failed' };
    if (q.data) return { status: 'ready', clusters: q.data.clusters, ads: q.data.ads };
    return { status: 'loading' };
  }, [enabled, failed, q.data]);
}
