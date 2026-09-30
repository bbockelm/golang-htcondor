'use client';

// One VS Code session: what it is doing while it starts, and the editor
// itself once there is one.
//
// The waiting states are the point. Through the proxy a session with no
// slot and a broken one are identical -- both 502 -- and queue latency
// is the likeliest reason somebody gives up on this, so the page says
// which it is rather than showing a blank frame.

import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import Link from 'next/link';
import { useRouter } from 'next/navigation';

import { api, type AppSummary } from '@/lib/api';
import { useResolvedParams } from '@/lib/useResolvedParams';
import { ConfirmButton } from '@/components/ConfirmButton';

export default function VSCodeDetailClient() {
  const { id } = useResolvedParams<{ id: string }>('/interactive/vscode/[id]');
  const router = useRouter();
  const queryClient = useQueryClient();

  const { data, isLoading, error } = useQuery({
    queryKey: ['apps', id],
    queryFn: () => api.apps.get(id),
    // Only while it is still coming up. Once the editor is mounted the
    // iframe is doing the talking and re-rendering around it risks
    // tearing it down.
    refetchInterval: (q) =>
      (q.state.data as AppSummary | undefined)?.url ? false : 3_000,
    enabled: Boolean(id) && id !== '_',
  });

  const remove = useMutation({
    mutationFn: () => api.apps.remove(id),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['apps'] });
      router.push('/interactive');
    },
  });

  return (
    <div className="space-y-4">
      <div className="flex items-center gap-3">
        <h1 className="text-2xl font-bold text-gray-900">VS Code</h1>
        {data?.job_id && (
          <Link
            href={`/jobs/${encodeURIComponent(data.job_id)}`}
            className="font-mono text-sm text-brand-600 hover:underline"
          >
            job {data.job_id}
          </Link>
        )}
        <div className="ml-auto flex items-center gap-3">
          <Link href="/interactive" className="text-sm text-gray-600 hover:underline">
            All sessions
          </Link>
          <ConfirmButton
            compact
            label="End session"
            confirmLabel="End"
            onConfirm={() => remove.mutate()}
            pending={remove.isPending}
          />
        </div>
      </div>

      {isLoading && <p className="text-gray-400 text-sm">Loading…</p>}
      {error && (
        <p className="text-red-600 text-sm">
          Could not load this session: {(error as Error).message}
        </p>
      )}

      {data && !data.url && <Waiting app={data} />}

      {data?.url && (
        <iframe
          // Keyed by the URL so React replaces the element rather than
          // reusing one that loaded an error page while the server was
          // still coming up -- the failure JupyterLab hit here, where a
          // reconciled iframe stayed blank forever.
          key={data.url}
          src={data.url}
          title="VS Code"
          className="w-full rounded-sm border border-gray-200 bg-white"
          style={{ height: 'calc(100vh - 12rem)' }}
        />
      )}
    </div>
  );
}

function Waiting({ app }: { app: AppSummary }) {
  const message = describe(app);
  return (
    <div className="rounded-sm border border-gray-200 bg-white p-6">
      <p className="text-gray-800">{message.title}</p>
      {message.detail && (
        <p className="mt-1 text-sm text-gray-500">{message.detail}</p>
      )}
      {app.state === 'waiting' && (
        <p className="mt-3 text-sm text-gray-500">
          The session is in the queue. It opens by itself once a machine
          is free; nothing here needs doing.
        </p>
      )}
    </div>
  );
}

function describe(app: AppSummary): { title: string; detail?: string } {
  switch (app.state) {
    case 'waiting':
      return { title: 'Waiting for a slot…', detail: app.detail };
    case 'starting':
      return { title: 'Starting the editor…', detail: app.detail };
    case 'held':
      return { title: 'This session is held.', detail: app.detail };
    case 'ended':
      return { title: 'This session has ended.', detail: app.detail };
    default:
      return { title: app.state, detail: app.detail };
  }
}
