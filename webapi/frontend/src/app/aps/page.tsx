'use client';

import { AccessPointsTable } from '@/components/AccessPointsTable';
import { useMultiAP } from '@/lib/multiap';

export default function AccessPointsPage() {
  const multiAP = useMultiAP();
  return (
    <div className="space-y-4">
      <div className="flex items-baseline gap-3 flex-wrap">
        <h1 className="text-2xl font-bold text-gray-900">Access Points</h1>
        <span className="text-sm text-gray-500">
          The access points this server shows jobs from.
        </span>
      </div>
      {multiAP ? (
        <AccessPointsTable />
      ) : (
        <p className="text-sm text-gray-500">This server serves a single access point.</p>
      )}
    </div>
  );
}
