'use client';

// /placement: request a placement token for the signed-in person. Reached by
// every session, including one with no local account on this access point.

import { useState } from 'react';
import { useQuery } from '@tanstack/react-query';
import { api, type PlacementIssued } from '@/lib/api';
import {
  IssuedTokenDetails,
  PlacementTokenRequest,
  UserConfigSnippet,
  placementTokenFileName,
} from '@/components/PlacementTokenRequest';

export default function PlacementPage() {
  const session = useQuery({ queryKey: ['session'], queryFn: api.auth.me });
  const [issued, setIssued] = useState<PlacementIssued | null>(null);
  const name =
    session.data?.placement?.display_name ||
    session.data?.placement?.identity ||
    session.data?.username ||
    '';

  return (
    <div className="max-w-2xl space-y-4">
      <div>
        <h1 className="text-2xl font-bold text-gray-900">Placement token</h1>
        <p className="text-sm text-gray-500">
          A placement token lets HTCondor tools on your own computer submit and manage jobs
          on this access point.
        </p>
      </div>
      {session.data?.placement?.identity && (
        <p className="text-sm text-gray-700">
          Signed in as <span className="font-mono">{session.data.placement.identity}</span>.
        </p>
      )}

      {issued ? (
        <IssuedToken issued={issued} name={name} onAnother={() => setIssued(null)} />
      ) : (
        <PlacementTokenRequest onIssued={setIssued} />
      )}
    </div>
  );
}

function IssuedToken({
  issued,
  name,
  onAnother,
}: {
  issued: PlacementIssued;
  name: string;
  onAnother: () => void;
}) {
  const [downloaded, setDownloaded] = useState(false);
  const download = () => {
    if (!issued.token) return;
    // The token never touches the server's disk: it is handed to the
    // browser as a file made here.
    const blob = new Blob([issued.token + '\n'], { type: 'application/jwt' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = placementTokenFileName();
    document.body.appendChild(a);
    a.click();
    a.remove();
    URL.revokeObjectURL(url);
    setDownloaded(true);
  };

  return (
    <div className="space-y-4 rounded-lg border border-green-200 bg-white p-4">
      <h2 className="text-lg font-semibold text-gray-900">Token granted</h2>
      <IssuedTokenDetails issued={issued} name={name} />
      <div className="space-y-2 text-sm">
        <p className="text-gray-700">
          The token is shown only once. Save it as <code>{placementTokenFileName()}</code>.
        </p>
        <div className="flex flex-wrap items-center gap-3">
          <button
            type="button"
            onClick={download}
            className="rounded-sm bg-brand-600 px-3 py-1.5 text-sm font-medium text-white hover:bg-brand-700"
          >
            Download token
          </button>
          {downloaded && <span className="text-gray-500">Download started.</span>}
        </div>
        <textarea
          readOnly
          aria-label="Token"
          rows={3}
          value={issued.token ?? ''}
          onFocus={(e) => e.currentTarget.select()}
          className="w-full break-all rounded-sm border border-gray-300 px-2 py-1 font-mono text-xs"
        />
      </div>
      <UserConfigSnippet text={issued.user_config} />
      <button
        type="button"
        onClick={onAnother}
        className="text-sm text-brand-700 hover:underline"
      >
        Request another token
      </button>
    </div>
  );
}
