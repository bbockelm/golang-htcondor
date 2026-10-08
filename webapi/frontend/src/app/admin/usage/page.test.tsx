import { fireEvent, render, screen, waitFor, within } from '@testing-library/react';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import type { AdminUsageResponse, UsageRow } from '@/lib/api';

const usage = vi.fn();
vi.mock('@/lib/api', async () => {
  const actual = await vi.importActual<typeof import('@/lib/api')>('@/lib/api');
  return {
    ...actual,
    api: { ...actual.api, admin: { ...actual.api.admin, usage: (...a: unknown[]) => usage(...a) } },
  };
});

function row(name: string, over: Partial<UsageRow> = {}): UsageRow {
  return {
    name,
    calls: 0,
    ok: 0,
    error: 0,
    refused: 0,
    unknown_tool: 0,
    users: 0,
    clients: 0,
    avg_seconds: 0,
    p95_seconds: null,
    last_call: null,
    ...over,
  };
}

const recent = new Date(Date.now() - 5 * 60 * 1000).toISOString();

const response: AdminUsageResponse = {
  enabled: true,
  filter: {},
  totals: row('', {
    name: undefined, calls: 1234, ok: 1200, error: 20, refused: 10, unknown_tool: 4,
    users: 2, clients: 2, last_call: recent,
  }),
  by_tool: [
    row('query_jobs', { calls: 1000, ok: 990, error: 10, users: 2, avg_seconds: 0.12, p95_seconds: 0.25, last_call: recent }),
    row('watch_jobs', { calls: 234, ok: 210, error: 10, refused: 10, unknown_tool: 4, users: 1, avg_seconds: 400, p95_over_seconds: 300 }),
  ],
  by_user: [row('alice', { calls: 1000, ok: 1000, clients: 1 }), row('bob', { calls: 234, ok: 200, clients: 1 })],
  by_client: [row('claude-code', { calls: 1234, users: 2 })],
  options: { tools: ['query_jobs', 'watch_jobs'], users: ['alice', 'bob'], clients: ['claude-code'] },
};

async function renderPage() {
  const { default: Page } = await import('./page');
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  render(
    <QueryClientProvider client={client}>
      <Page />
    </QueryClientProvider>,
  );
}

describe('admin usage page', () => {
  beforeEach(() => usage.mockReset());

  it('says plainly when nothing is recorded', async () => {
    usage.mockResolvedValue({ enabled: false });
    await renderPage();
    expect(await screen.findByText('Usage is not being recorded on this server.')).toBeInTheDocument();
    expect(screen.queryByRole('table')).toBeNull();
  });

  it('renders the totals and one table per dimension', async () => {
    usage.mockResolvedValue(response);
    await renderPage();

    expect(await screen.findByTestId('figure-Calls')).toHaveTextContent('1,234');
    expect(screen.getByTestId('figure-Unknown tool')).toHaveTextContent('4');
    expect(screen.getByTestId('figure-Last call')).toHaveTextContent('5m ago');

    const tools = screen.getByRole('region', { name: 'Tools' });
    const qj = within(tools).getByRole('button', { name: 'query_jobs' }).closest('tr')!;
    expect(qj).toHaveTextContent('120 ms');
    expect(qj).toHaveTextContent('≤ 250 ms');
    // Past the last boundary is "longer than", not a number.
    const wj = within(tools).getByRole('button', { name: 'watch_jobs' }).closest('tr')!;
    expect(wj).toHaveTextContent('> 5 min');

    expect(within(screen.getByRole('region', { name: 'Users' })).getByText('bob')).toBeInTheDocument();
    expect(within(screen.getByRole('region', { name: 'Clients' })).getByText('claude-code')).toBeInTheDocument();
  });

  it('filters to a user when their row is clicked', async () => {
    usage.mockResolvedValue(response);
    await renderPage();

    const users = await screen.findByRole('region', { name: 'Users' });
    fireEvent.click(within(users).getByRole('button', { name: 'alice' }));
    await waitFor(() => expect(usage).toHaveBeenLastCalledWith({ user: 'alice' }));

    fireEvent.click(await screen.findByRole('button', { name: 'Clear filter' }));
    await waitFor(() => expect(usage).toHaveBeenLastCalledWith({}));
  });

  it('filters to a tool from the select', async () => {
    usage.mockResolvedValue(response);
    await renderPage();

    fireEvent.change(await screen.findByLabelText('Tool'), { target: { value: 'watch_jobs' } });
    await waitFor(() => expect(usage).toHaveBeenLastCalledWith({ tool: 'watch_jobs' }));
  });
});
