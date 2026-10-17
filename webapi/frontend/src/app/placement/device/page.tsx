'use client';

// /placement/device: confirm a token request started by placement-client or
// another device-flow client. /auth/code sends the browser here with the code.

import { useState } from 'react';
import { useRouter, useSearchParams } from 'next/navigation';
import { useMutation, useQuery } from '@tanstack/react-query';
import { ApiError, api, type PlacementIssued } from '@/lib/api';
import { PlacementTokenRequest, UserConfigSnippet } from '@/components/PlacementTokenRequest';

const CODE_RE = /^[A-Z]{4}-[A-Z]{4}$/;

export default function PlacementDevicePage() {
  const params = useSearchParams();
  const raw = (params?.get('user_code') ?? '').trim().toUpperCase().slice(0, 9);
  const code = CODE_RE.test(raw) ? raw : '';

  return (
    <div className="max-w-2xl space-y-4">
      <div>
        <h1 className="text-2xl font-bold text-gray-900">
          {code ? 'Confirm token request' : 'Enter code'}
        </h1>
      </div>
      {code ? <DeviceRequest code={code} /> : <EnterCode initial={raw} />}
    </div>
  );
}

function EnterCode({ initial }: { initial: string }) {
  const router = useRouter();
  const [value, setValue] = useState(initial);
  const normalized = value.trim().toUpperCase();
  const valid = CODE_RE.test(normalized);
  return (
    <form
      className="space-y-3 rounded-lg border border-gray-200 bg-white p-4 text-sm"
      onSubmit={(e) => {
        e.preventDefault();
        if (valid) router.push(`/placement/device?user_code=${encodeURIComponent(normalized)}`);
      }}
    >
      <p className="text-gray-700">
        Enter the code shown by the program that asked for a token.
      </p>
      {initial && !CODE_RE.test(initial) && (
        <p className="text-red-600">That code is not in the form XXXX-XXXX.</p>
      )}
      <label className="block">
        <span className="block font-medium text-gray-800">Code</span>
        <input
          type="text"
          value={value}
          maxLength={9}
          placeholder="XXXX-XXXX"
          onChange={(e) => setValue(e.target.value)}
          className="mt-1 w-40 rounded-sm border border-gray-300 px-2 py-1 font-mono uppercase"
        />
      </label>
      <button
        type="submit"
        disabled={!valid}
        className="rounded-sm bg-brand-600 px-3 py-1.5 font-medium text-white hover:bg-brand-700 disabled:opacity-50"
      >
        Continue
      </button>
    </form>
  );
}

function DeviceRequest({ code }: { code: string }) {
  const request = useQuery({
    queryKey: ['placement', 'device', code],
    queryFn: () => api.placement.deviceRequest(code),
    retry: false,
  });
  const [issued, setIssued] = useState<PlacementIssued | null>(null);
  const cancel = useMutation({ mutationFn: () => api.placement.denyDevice(code) });

  if (request.isLoading) return <p className="text-gray-400">Loading…</p>;
  if (request.error) {
    const err = request.error as Error;
    return (
      <p className="text-sm text-red-600">
        {err instanceof ApiError && err.status === 404
          ? `The code ${code} was not recognized.`
          : err.message}
      </p>
    );
  }
  const req = request.data;
  if (!req) return null;

  if (cancel.isSuccess) {
    return <Done>You have canceled the request. You may now close this tab.</Done>;
  }
  if (issued) {
    return (
      <div className="space-y-4">
        <Done>
          The token will be provided to {req.client_name}. You may close this tab and return
          there.
        </Done>
        <UserConfigSnippet text={issued.user_config} />
      </div>
    );
  }
  if (req.state === 'expired') {
    return <Done>This request has expired. Start again from the program that asked.</Done>;
  }
  if (req.state !== 'pending') {
    return <Done>This request has already been answered.</Done>;
  }

  return (
    <div className="space-y-4">
      <p className="text-sm text-gray-700">
        <span className="font-medium">{req.client_name}</span> is asking for a placement token.
        Check that the code <span className="font-mono">{req.user_code}</span> matches the one
        it shows.
      </p>
      <PlacementTokenRequest userCode={code} onIssued={setIssued} />
      <div className="flex items-center gap-3">
        <button
          type="button"
          onClick={() => {
            if (confirm('Deny this request? The program will need to start again.')) cancel.mutate();
          }}
          disabled={cancel.isPending}
          className="rounded-sm border border-red-300 px-3 py-1.5 text-sm font-medium text-red-700 hover:bg-red-50 disabled:opacity-50"
        >
          Deny request
        </button>
        {cancel.error && (
          <span className="text-sm text-red-600">{(cancel.error as Error).message}</span>
        )}
      </div>
    </div>
  );
}

function Done({ children }: { children: React.ReactNode }) {
  return (
    <div className="rounded-lg border border-gray-200 bg-white p-4 text-sm text-gray-800">
      {children}
    </div>
  );
}
