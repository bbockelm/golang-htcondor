import { fireEvent, render, screen } from '@testing-library/react';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import type { DagGraphResponse } from '@/lib/api';

const dagGraph = vi.fn();
vi.mock('@/lib/api', async () => {
  const actual = await vi.importActual<typeof import('@/lib/api')>('@/lib/api');
  return {
    ...actual,
    api: { ...actual.api, jobs: { ...actual.api.jobs, dagGraph: (...a: unknown[]) => dagGraph(...a) } },
  };
});

import { ApiError } from '@/lib/api';
import { DagGraphPanel } from './DagGraphPanel';

// A fan-out: one setup, ten work nodes (one of them failed), one gather.
const graph: DagGraphResponse = {
  cluster: 90,
  dag_file: 'fanout.dag',
  dot_file: 'fanout.dag.dot',
  status_file: 'fanout.dag.status',
  node_count: 12,
  edge_count: 20,
  group_count: 3,
  groups: [
    { id: 'setup', label: 'setup', description: '/bin/prepare', count: 1, parent_ids: [], status: { done: 1 } },
    { id: 'work', label: 'work', description: '/bin/crunch', count: 10, parent_ids: ['setup'], status: { done: 9, failed: 1 } },
    { id: 'gather', label: 'gather', description: '/bin/collect', count: 1, parent_ids: ['work'], status: { unready: 1 } },
  ],
  nodes: [],
  state_sources: ['status-file'],
  status_file_time: 1_790_000_000,
  fetched_at: new Date(1_790_000_000 * 1000).toISOString(),
  took_ms: 1240,
} as unknown as DagGraphResponse;

// Braces matter: a function returned from beforeEach is run as a
// teardown, and mockReset() returns the mock itself.
beforeEach(() => {
  dagGraph.mockReset();
});

describe('DagGraphPanel', () => {
  it('loads on request and draws the workflow', async () => {
    dagGraph.mockResolvedValue(graph);
    render(<DagGraphPanel jobId="90.0" />);
    expect(dagGraph).not.toHaveBeenCalled();
    fireEvent.click(screen.getByRole('button', { name: 'Load graph' }));
    expect(dagGraph).toHaveBeenCalledWith('90.0', undefined);
    expect(await screen.findAllByText('work')).not.toHaveLength(0);
    expect(screen.getByRole('button', { name: 'Refresh' })).toBeTruthy();
  });

  it('names the access point in multi-AP mode', async () => {
    dagGraph.mockResolvedValue(graph);
    render(<DagGraphPanel jobId="90.0" schedd="ap1.example.org" />);
    fireEvent.click(screen.getByRole('button', { name: 'Load graph' }));
    expect(dagGraph).toHaveBeenCalledWith('90.0@ap1.example.org', undefined);
  });

  it('refreshes with the slow re-read', async () => {
    dagGraph.mockResolvedValue(graph);
    render(<DagGraphPanel jobId="90.0" />);
    fireEvent.click(screen.getByRole('button', { name: 'Load graph' }));
    fireEvent.click(await screen.findByRole('button', { name: 'Refresh' }));
    expect(dagGraph).toHaveBeenLastCalledWith('90.0', { refresh: true });
  });

  it('links to the batch page only when given one', () => {
    const { unmount } = render(<DagGraphPanel jobId="90.0" batchHref="/batches/90" />);
    expect(screen.getByRole('link', { name: 'Open batch page' })).toHaveAttribute('href', '/batches/90');
    unmount();
    render(<DagGraphPanel jobId="90.0" />);
    expect(screen.queryByRole('link', { name: 'Open batch page' })).toBeNull();
  });

  it('shows the reason when the workflow has nothing to draw', async () => {
    dagGraph.mockRejectedValue(new ApiError(409, 'This workflow has not written its DAG file yet.'));
    render(<DagGraphPanel jobId="90.0" />);
    fireEvent.click(screen.getByRole('button', { name: 'Load graph' }));
    expect(await screen.findByText('This workflow has not written its DAG file yet.')).toBeTruthy();
    expect(screen.queryByText(/Could not load/)).toBeNull();
  });

  it('reports a failure as one', async () => {
    dagGraph.mockRejectedValue(new Error('network down'));
    render(<DagGraphPanel jobId="90.0" />);
    fireEvent.click(screen.getByRole('button', { name: 'Load graph' }));
    expect(await screen.findByText('Could not load the workflow graph: network down')).toBeTruthy();
  });
});
