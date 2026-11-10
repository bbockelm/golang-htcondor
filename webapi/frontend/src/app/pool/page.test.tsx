import { act, render, screen, waitFor } from '@testing-library/react';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import type { ClassAd } from '@/lib/api';
import { callHook, chatPanelProps, resetChatPanelSpy } from '@/test/chatPanelSpy';

vi.mock('@/components/ChatPanel', async () => (await import('@/test/chatPanelSpy')).chatPanelMock());
vi.mock('next/navigation', () => ({
  useRouter: () => ({ replace: vi.fn(), push: vi.fn() }),
  useSearchParams: () => new URLSearchParams(),
  usePathname: () => '/pool',
}));

const collectorList = vi.fn();
const chatInfo = vi.fn();
vi.mock('@/lib/api', async () => {
  const actual = await vi.importActual<typeof import('@/lib/api')>('@/lib/api');
  return {
    ...actual,
    api: {
      ...actual.api,
      chat: { ...actual.api.chat, info: () => chatInfo() },
      collector: { ...actual.api.collector, list: (...a: unknown[]) => collectorList(...a) },
      pool: {
        ...actual.api.pool,
        drainEstimates: () => Promise.reject(new actual.ApiError(501, 'not here')),
      },
    },
  };
});

function slot(machine: string, extra: ClassAd = {}): ClassAd {
  return {
    Name: `slot1@${machine}`,
    Machine: machine,
    SlotType: 'Partitionable',
    PartitionableSlot: true,
    State: 'Unclaimed',
    Activity: 'Idle',
    Cpus: 8,
    Memory: 16384,
    TotalCpus: 16,
    TotalMemory: 32768,
    NumDynamicSlots: 2,
    ...extra,
  };
}

// What the fake collector holds; a GPU expression answers only the GPU node.
const cpuNode = slot('cpu-01.example.org');
const gpuNode = slot('gpu-01.example.org', { TotalGPUs: 4, TotalSlotGPUs: 4, GPUs: 1 });

async function renderPage() {
  const { default: Page } = await import('./page');
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  render(
    <QueryClientProvider client={client}>
      <Page />
    </QueryClientProvider>,
  );
}

describe('pool page chat', () => {
  beforeEach(() => {
    collectorList.mockReset();
    chatInfo.mockReset();
    resetChatPanelSpy();
    collectorList.mockImplementation((p: { constraint?: string }) =>
      Promise.resolve({
        ads: p.constraint?.includes('TotalSlotGPUs') ? [gpuNode] : [cpuNode, gpuNode],
      }),
    );
  });

  it('offers the assistant when chat is enabled', async () => {
    chatInfo.mockResolvedValue({ enabled: true });
    await renderPage();
    expect(await screen.findByRole('button', { name: 'Open chat assistant' })).toBeInTheDocument();
    const props = chatPanelProps();
    expect(props.page).toBe('pool');
    expect(props.confirmableTools).toEqual([]);
    await waitFor(() => expect(chatPanelProps().pageContext).toContain('In view: 2 execute nodes'));
  });

  it('offers the assistant when no slot matches the filter', async () => {
    chatInfo.mockResolvedValue({ enabled: true });
    collectorList.mockReset();
    collectorList.mockResolvedValue({ ads: [] });
    await renderPage();
    expect(await screen.findByRole('button', { name: 'Open chat assistant' })).toBeInTheDocument();
  });

  it('hides the assistant when chat is disabled', async () => {
    chatInfo.mockResolvedValue({ enabled: false });
    await renderPage();
    await screen.findByText('cpu-01.example.org');
    expect(screen.queryByRole('button', { name: 'Open chat assistant' })).toBeNull();
  });

  it('set_constraint sends the expression to the collector and narrows the table', async () => {
    chatInfo.mockResolvedValue({ enabled: true });
    await renderPage();
    await screen.findByText('cpu-01.example.org');

    act(() => {
      callHook('set_constraint', { constraint: 'TotalSlotGPUs > 0' });
    });
    await waitFor(() =>
      expect(collectorList).toHaveBeenLastCalledWith(
        expect.objectContaining({ constraint: '(SlotType =!= "Dynamic") && (TotalSlotGPUs > 0)' }),
      ),
    );
    await waitFor(() => expect(screen.queryByText('cpu-01.example.org')).toBeNull());
    expect(screen.getByText('gpu-01.example.org')).toBeInTheDocument();
    expect(screen.getByDisplayValue('TotalSlotGPUs > 0')).toBeInTheDocument();
    expect(chatPanelProps().pageContext).toContain('ClassAd expression "TotalSlotGPUs > 0"');
  });

  it('set_filter narrows by text, and expand_machine opens a node in view', async () => {
    chatInfo.mockResolvedValue({ enabled: true });
    await renderPage();
    await screen.findByText('cpu-01.example.org');

    act(() => {
      callHook('set_filter', { query: 'gpu-01' });
    });
    await waitFor(() => expect(screen.queryByText('cpu-01.example.org')).toBeNull());

    // A node the filter hides cannot be opened.
    let missing: unknown;
    act(() => {
      missing = callHook('expand_machine', { machine: 'cpu-01.example.org' });
    });
    expect(missing).toMatchObject({ ok: false });

    let opened: unknown;
    act(() => {
      opened = callHook('expand_machine', { machine: 'GPU-01.example.org' });
    });
    expect(opened).toEqual({ ok: true, expanded: 'gpu-01.example.org' });
    const row = screen.getByText('gpu-01.example.org').closest('tr')!;
    await waitFor(() => expect(row).toHaveAttribute('aria-expanded', 'true'));
  });
});
