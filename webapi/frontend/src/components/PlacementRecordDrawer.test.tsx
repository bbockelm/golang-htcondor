import { fireEvent, render, screen, waitFor } from '@testing-library/react';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import type { PlacementRecord } from '@/lib/api';

const record = vi.fn();
const setSuspended = vi.fn();
vi.mock('@/lib/api', async () => {
  const actual = await vi.importActual<typeof import('@/lib/api')>('@/lib/api');
  return {
    ...actual,
    api: {
      ...actual.api,
      placement: {
        ...actual.api.placement,
        record: (...a: unknown[]) => record(...a),
        setSuspended: (...a: unknown[]) => setSuspended(...a),
      },
    },
  };
});

const active: PlacementRecord = {
  kind: 'account',
  name: 'alice@ap.example',
  found: true,
  enabled: true,
  stats: { NumIdle: 3, NumRunning: 2, TotalCompletedJobs: 40 },
  members: ['alice@idp.example'],
};

async function renderDrawer() {
  const { PlacementRecordDrawer } = await import('./PlacementRecordDrawer');
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  render(
    <QueryClientProvider client={client}>
      <PlacementRecordDrawer target={{ kind: 'accounts', name: 'alice@ap.example' }} onClose={() => {}} />
    </QueryClientProvider>,
  );
}

describe('PlacementRecordDrawer', () => {
  beforeEach(() => {
    record.mockReset();
    setSuspended.mockReset();
  });

  it('shows the job counters and suspends', async () => {
    record.mockResolvedValue(active);
    setSuspended.mockResolvedValue({ ...active, enabled: false, disable_reason: 'suspended by root via web UI' });
    await renderDrawer();
    expect(await screen.findByText('Active')).toBeInTheDocument();
    expect(screen.getByText('Idle').nextSibling).toHaveTextContent('3');
    expect(screen.getByText('Completed (history)').nextSibling).toHaveTextContent('40');
    expect(screen.getByText('alice@idp.example')).toBeInTheDocument();

    fireEvent.click(screen.getByRole('button', { name: 'Suspend' }));
    await waitFor(() => expect(setSuspended).toHaveBeenCalledWith('accounts', 'alice@ap.example', true));
    expect(await screen.findByText('Suspended')).toBeInTheDocument();
    expect(screen.getByText('Reason: suspended by root via web UI')).toBeInTheDocument();
    expect(screen.getByRole('button', { name: 'Unsuspend' })).toBeInTheDocument();
  });

  it('offers no action without a record', async () => {
    record.mockResolvedValue({ ...active, found: false, stats: undefined });
    await renderDrawer();
    expect(await screen.findByText('No jobs submitted yet')).toBeInTheDocument();
    expect(screen.queryByRole('button', { name: 'Suspend' })).not.toBeInTheDocument();
  });
});
