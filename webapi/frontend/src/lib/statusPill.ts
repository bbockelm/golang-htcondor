import type { DisplayStatus } from '@/lib/api';

// statusPillCls maps a DisplayStatus key to a Tailwind class for the
// pill badge. Shared by the job page's StatusBadge, the listings and the DAG graph.
export function statusPillCls(key: DisplayStatus): string {
  switch (key) {
    case 'running':
      return 'bg-green-100 text-green-800';
    case 'idle':
      return 'bg-blue-100 text-blue-800';
    case 'held':
      return 'bg-red-100 text-red-800';
    case 'completed':
      return 'bg-gray-100 text-gray-700';
    case 'uploading':
      // Uploading is genuinely "in progress" from the user's POV;
      // amber matches the "transferring output" mood.
      return 'bg-amber-100 text-amber-800';
    case 'transferring':
    case 'suspended':
    case 'removed':
      return 'bg-amber-100 text-amber-800';
    case 'unknown':
    default:
      return 'bg-gray-100 text-gray-500';
  }
}
