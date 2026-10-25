import { fireEvent, render, screen, waitFor, within } from '@testing-library/react';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
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
    outcomes: {},
    users: 0,
    clients: 0,
    avg_seconds: 0,
    p95_seconds: null,
    last_call: null,
    ...over,
  };
}

// The page reads the clock for "5m ago", so it is fixed (see the
// describe below): only Date, so react-query's timers still run.
const NOW = Date.UTC(2026, 9, 14, 17, 0);
const recent = new Date(NOW - 5 * 60 * 1000).toISOString();

const KINDS = [
  { kind: 'mcp', label: 'MCP tools', enabled: true },
  { kind: 'rest', label: 'REST API', enabled: true },
];

const MCP_OUTCOMES = ['ok', 'error', 'refused', 'unknown_tool'];

const mcpResponse: AdminUsageResponse = {
  enabled: true,
  kinds: KINDS,
  kind: 'mcp',
  noun: 'tool',
  title: 'Tool',
  outcomes: MCP_OUTCOMES,
  filter: {},
  totals: row('', {
    name: undefined,
    calls: 1234,
    outcomes: { ok: 1200, error: 20, refused: 10, unknown_tool: 4 },
    users: 2, clients: 2, last_call: recent,
  }),
  by_name: [
    row('query_jobs', { calls: 1000, outcomes: { ok: 990, error: 10 }, users: 2, avg_seconds: 0.12, p95_seconds: 0.25, last_call: recent }),
    row('watch_jobs', { calls: 234, outcomes: { ok: 210, error: 10, refused: 10, unknown_tool: 4 }, users: 1, avg_seconds: 400, p95_over_seconds: 300 }),
  ],
  by_user: [
    row('alice', { calls: 1000, outcomes: { ok: 1000 }, clients: 1 }),
    row('bob', { calls: 234, outcomes: { ok: 200 }, clients: 1 }),
  ],
  by_client: [row('claude-code', { calls: 1234, users: 2 })],
  options: { names: ['query_jobs', 'watch_jobs'], users: ['alice', 'bob'], clients: ['claude-code'] },
};

// The REST tab is the same shape with a different vocabulary: a
// different first column and six outcomes instead of four.
const restResponse: AdminUsageResponse = {
  enabled: true,
  kinds: KINDS,
  kind: 'rest',
  noun: 'endpoint',
  title: 'Endpoint',
  outcomes: ['ok', 'denied', 'not_found', 'rate_limited', 'client_error', 'error'],
  filter: {},
  totals: row('', {
    name: undefined,
    calls: 900,
    outcomes: { ok: 850, denied: 30, not_found: 10, rate_limited: 5, client_error: 4, error: 1 },
    users: 3, clients: 2, last_call: recent,
  }),
  by_name: [
    row('GET /api/v1/jobs', { calls: 700, outcomes: { ok: 700 }, users: 3, avg_seconds: 0.04 }),
    row('DELETE /api/v1/jobs/{id}', { calls: 200, outcomes: { ok: 150, denied: 30 }, users: 2, avg_seconds: 0.2 }),
  ],
  by_user: [row('alice', { calls: 900, outcomes: { ok: 850 }, clients: 2 })],
  // The recorded value is the client id; the label is what to show.
  by_client: [
    row('web UI', { calls: 800, outcomes: { ok: 780 }, users: 3 }),
    row('oauth:client_17', { label: 'OpenClaw MCP', calls: 100, outcomes: { ok: 70, denied: 30 }, users: 1 }),
  ],
  options: {
    names: ['GET /api/v1/jobs', 'DELETE /api/v1/jobs/{id}'],
    users: ['alice'],
    clients: ['web UI', 'oauth:client_17'],
  },
  client_labels: { 'oauth:client_17': 'OpenClaw MCP' },
};

// byKind answers each request with the response for the kind asked
// for, so a tab switch in a test exercises the same path it does in
// the browser.
function byKind() {
  return (kind: string) => Promise.resolve(kind === 'rest' ? restResponse : mcpResponse);
}

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
  beforeEach(() => {
    usage.mockReset();
    vi.useFakeTimers({ toFake: ['Date'] });
    vi.setSystemTime(NOW);
  });
  afterEach(() => vi.useRealTimers());

  it('says plainly when nothing is recorded', async () => {
    usage.mockResolvedValue({ enabled: false, kinds: KINDS });
    await renderPage();
    expect(await screen.findByText('MCP usage is not being recorded on this server.')).toBeInTheDocument();
    expect(screen.queryByRole('table')).toBeNull();
  });

  it('renders the totals and one table per dimension', async () => {
    usage.mockResolvedValue(mcpResponse);
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
    usage.mockResolvedValue(mcpResponse);
    await renderPage();

    const users = await screen.findByRole('region', { name: 'Users' });
    fireEvent.click(within(users).getByRole('button', { name: 'alice' }));
    await waitFor(() => expect(usage).toHaveBeenLastCalledWith('mcp', { user: 'alice' }));

    fireEvent.click(await screen.findByRole('button', { name: 'Clear filter' }));
    await waitFor(() => expect(usage).toHaveBeenLastCalledWith('mcp', {}));
  });

  it('filters to a tool from the select', async () => {
    usage.mockResolvedValue(mcpResponse);
    await renderPage();

    fireEvent.change(await screen.findByLabelText('Tool'), { target: { value: 'watch_jobs' } });
    await waitFor(() => expect(usage).toHaveBeenLastCalledWith('mcp', { name: 'watch_jobs' }));
  });

  // The two kinds have different columns and a different first
  // dimension. The page takes both from the response, so this is what
  // catches a regression that hard-codes either.
  it('switches to the REST tab and renders its own vocabulary', async () => {
    usage.mockImplementation(byKind());
    await renderPage();
    await screen.findByRole('region', { name: 'Tools' });

    fireEvent.click(screen.getByRole('tab', { name: 'REST API' }));

    const endpoints = await screen.findByRole('region', { name: 'Endpoints' });
    expect(within(endpoints).getByRole('button', { name: 'GET /api/v1/jobs' })).toBeInTheDocument();
    // An outcome only REST has.
    expect(screen.getByTestId('figure-Rate limited')).toHaveTextContent('5');
    // And none of the MCP-only ones.
    expect(screen.queryByTestId('figure-Unknown tool')).toBeNull();
    expect(screen.queryByRole('region', { name: 'Tools' })).toBeNull();
  });

  // The client column shows the OAuth2 client's name, but a filter
  // has to send back the id the server recorded: resolving the label
  // in place would make every such filter miss.
  it('shows a client label but filters on the recorded value', async () => {
    usage.mockImplementation(byKind());
    await renderPage();
    fireEvent.click(screen.getByRole('tab', { name: 'REST API' }));

    const clients = await screen.findByRole('region', { name: 'Clients' });
    const labelled = within(clients).getByRole('button', { name: 'OpenClaw MCP' });
    expect(within(clients).queryByText('oauth:client_17')).toBeNull();

    fireEvent.click(labelled);
    await waitFor(() =>
      expect(usage).toHaveBeenLastCalledWith('rest', { client: 'oauth:client_17' }),
    );
  });

  // Each tab keeps its own filter: a tool name means nothing to the
  // REST tab, and carrying it across would show an empty table for no
  // visible reason.
  it('keeps each tab’s filter separate', async () => {
    usage.mockImplementation(byKind());
    await renderPage();

    fireEvent.change(await screen.findByLabelText('Tool'), { target: { value: 'watch_jobs' } });
    await waitFor(() => expect(usage).toHaveBeenLastCalledWith('mcp', { name: 'watch_jobs' }));

    fireEvent.click(screen.getByRole('tab', { name: 'REST API' }));
    await waitFor(() => expect(usage).toHaveBeenLastCalledWith('rest', {}));

    fireEvent.click(screen.getByRole('tab', { name: 'MCP tools' }));
    await waitFor(() => expect(usage).toHaveBeenLastCalledWith('mcp', { name: 'watch_jobs' }));
  });
});
