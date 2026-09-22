import { fireEvent, render, screen, within } from '@testing-library/react';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { describe, expect, it, vi } from 'vitest';
import { BatchTable } from './BatchTable';
import { groupIntoBatches } from '@/lib/batches';
import type { ClassAd } from '@/lib/api';

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
