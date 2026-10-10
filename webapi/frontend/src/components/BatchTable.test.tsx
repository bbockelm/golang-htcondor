import { fireEvent, render, screen, within } from '@testing-library/react';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { describe, expect, it, vi } from 'vitest';
import { BatchTable } from './BatchTable';
import { groupIntoBatches } from '@/lib/batches';
import { batchView } from '@/lib/batchView';
import { PROGRESS_WHY } from '@/lib/batchProgress';
import type { ClassAd, DisplayStatus } from '@/lib/api';

vi.mock('next/navigation', () => ({
  useRouter: () => ({ push: vi.fn() }),
}));

const ads: ClassAd[] = [
  {
    ClusterId: 10, ProcId: 0, JobStatus: 2, Owner: 'alice',
    Cmd: '/bin/train', QDate: 1000, JobBatchName: 'training',
  },
  {
    ClusterId: 11, ProcId: 0, JobStatus: 1, Owner: 'bob',
    Cmd: '/bin/sim', QDate: 3000, JobBatchName: 'sim',
  },
  {
    ClusterId: 11, ProcId: 1, JobStatus: 1, Owner: 'bob',
    Cmd: '/bin/sim', QDate: 3000, JobBatchName: 'sim',
  },
];

function table(props: Partial<Parameters<typeof BatchTable>[0]> = {}) {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(
    <QueryClientProvider client={client}>
      <BatchTable
        batches={groupIntoBatches(ads)}
        expanded={new Set()}
        setExpanded={vi.fn()}
        highlighted={null}
        onChange={vi.fn()}
        {...props}
      />
    </QueryClientProvider>,
  );
}

// The rendered batch rows, in the order the table put them.
function batchNames(): string[] {
  return screen
    .getAllByRole('row')
    // Skip the header and the "showing N of M" footer, neither of which
    // has a batch name.
    .filter((r) => r.getAttribute('aria-expanded') !== null)
    .map((r) => within(r).getAllByRole('cell')[1].textContent ?? '');
}

describe('BatchTable', () => {
  it('leaves the user column out when every row is the same user', () => {
    table();
    expect(screen.queryByRole('button', { name: /User/ })).toBeNull();
    expect(screen.queryByRole('link', { name: 'alice' })).toBeNull();
  });

  it('links each user to their own page when showing several', () => {
    table({ showOwner: true });
    expect(screen.getByRole('link', { name: 'alice' })).toHaveAttribute(
      'href',
      '/users/alice',
    );
  });

  it('opens the user page instead of expanding the row', () => {
    const setExpanded = vi.fn();
    table({ showOwner: true, setExpanded });
    // The pill sits inside a row whose click handler expands the batch;
    // both firing would expand a batch on the way to another page.
    fireEvent.click(screen.getByRole('link', { name: 'alice' }));
    expect(setExpanded).not.toHaveBeenCalled();
  });

  it('starts newest-first and re-sorts when a column is clicked', () => {
    table();
    // QDate 3000 beats 1000.
    expect(batchNames()[0]).toContain('sim');

    fireEvent.click(screen.getByRole('button', { name: /Jobs/ }));
    // Ascending job count: the one-job batch leads.
    expect(batchNames()[0]).toContain('training');

    fireEvent.click(screen.getByRole('button', { name: /Jobs/ }));
    // Clicking the same column again reverses it.
    expect(batchNames()[0]).toContain('sim');
  });
});

describe('BatchTable in multi-AP mode', () => {
  const multi: ClassAd[] = [
    { ClusterId: 1, ProcId: 0, JobStatus: 5, Owner: 'alice', schedd: 'ap1.example.org', job_id: '1.0@ap1.example.org' },
    { ClusterId: 1, ProcId: 0, JobStatus: 5, Owner: 'alice', schedd: 'ap2.example.org', job_id: '1.0@ap2.example.org' },
  ];

  it('shows the access point and offers no actions', () => {
    table({ batches: groupIntoBatches(multi), multiAP: true });
    expect(screen.getByRole('button', { name: /Access point/ })).toBeTruthy();
    expect(screen.getByText('ap1.example.org')).toBeTruthy();
    expect(screen.getByText('ap2.example.org')).toBeTruthy();
    expect(screen.queryByText('Actions')).toBeNull();
    expect(screen.queryByTitle(/Remove batch/)).toBeNull();
  });

  it('links each job by its complete id', () => {
    table({
      batches: groupIntoBatches(multi),
      multiAP: true,
      expanded: new Set(groupIntoBatches(multi).map((b) => `${b.schedd}\u0000${b.batchID}`)),
    });
    const link = screen.getByRole('link', { name: '1.0@ap2.example.org' });
    expect(link.getAttribute('href')).toBe('/jobs/1.0%40ap2.example.org');
    // Held jobs: the single-AP table would offer Release.
    expect(screen.queryByText('Release')).toBeNull();
  });
});

describe('BatchTable progress', () => {
  const queue: ClassAd[] = [
    // 10 submitted, 3 finished: 5 running, 2 held left.
    ...[2, 2, 2, 2, 2, 5, 5].map((s, i) => ({
      ClusterId: 20, ProcId: i, JobStatus: s, Owner: 'alice', QDate: 100,
      JobBatchName: 'sweep', TotalSubmitProcs: 10,
    })),
    // 4 submitted, 3 finished.
    { ClusterId: 21, ProcId: 0, JobStatus: 1, Owner: 'alice', QDate: 200, JobBatchName: 'quick', TotalSubmitProcs: 4 },
  ];

  it('shows how many jobs are done, from every job rather than the filtered ones', () => {
    const view = batchView(queue, new Set<DisplayStatus>(['held']), '', true);
    table({ batches: view.batches, progress: view.progress });
    expect(screen.getByRole('button', { name: /Progress/ })).toBeTruthy();
    const cell = screen.getByText('3 / 10');
    expect(cell.closest('[title]')?.getAttribute('title')).toMatch(/^3 of 10 jobs done/);
  });

  it('sorts by the share done', () => {
    const view = batchView(queue, new Set(), '', true);
    table({ batches: view.batches, progress: view.progress });
    fireEvent.click(screen.getByRole('button', { name: /Progress/ }));
    // 3/10 before 3/4 ascending.
    expect(batchNames()[0]).toContain('sweep');
    fireEvent.click(screen.getByRole('button', { name: /Progress/ }));
    expect(batchNames()[0]).toContain('quick');
  });

  it('shows a dash, with the reason, when the count is unknown', () => {
    const view = batchView(queue, new Set(), '', false);
    table({ batches: view.batches, progress: view.progress });
    const dashes = screen.getAllByTitle(PROGRESS_WHY.partial);
    expect(dashes).toHaveLength(2);
  });

  it('leaves the column out when not given progress', () => {
    table();
    expect(screen.queryByRole('button', { name: /Progress/ })).toBeNull();
  });
});
