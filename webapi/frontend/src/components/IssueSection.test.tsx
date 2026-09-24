import { fireEvent, render, screen, within } from '@testing-library/react';
import { describe, expect, it, vi } from 'vitest';
import { IssueSectionPanel, UsersBadge } from './IssueSection';
import type { IssueCluster, IssueSection } from '@/lib/api';

vi.mock('next/navigation', () => ({ useRouter: () => ({ push: vi.fn() }) }));

function cluster(over: Partial<IssueCluster> = {}): IssueCluster {
  return {
    kind: 'hold',
    template: 'Error from <slot> memory usage exceeded request_memory',
    count: 100,
    users: 1,
    examples: [
      {
        cluster_id: 10,
        proc_id: 0,
        owner: 'alice',
        at: 1790250000,
        message: 'Error from slot1_40@a.b.example.edu: memory usage exceeded request_memory',
      },
    ],
    ...over,
  };
}

function section(clusters: IssueCluster[]): IssueSection {
  return {
    kind: 'hold',
    title: 'Holds',
    total: clusters.reduce((n, c) => n + c.count, 0),
    users: 3,
    clusters,
  };
}

describe('IssueSectionPanel', () => {
  it('shows the real message, not the masked template', () => {
    render(<IssueSectionPanel section={section([cluster()])} />);
    // The template is what the occurrences have in common; the message
    // is the thing a facilitator can act on. Leading with the template
    // would put "<slot>" where the hostname should be.
    expect(screen.getByText(/slot1_40@a\.b\.example\.edu/)).toBeInTheDocument();
  });

  it('falls back to the template when a cluster carries no example', () => {
    // Better than an empty row: the template still says what kind of
    // problem this is.
    render(<IssueSectionPanel section={section([cluster({ examples: [] })])} />);
    expect(screen.getByText(/memory usage exceeded request_memory/)).toBeInTheDocument();
  });

  it('sizes the bars against the biggest problem in the section', () => {
    const { container } = render(
      <IssueSectionPanel
        section={section([cluster({ count: 200 }), cluster({ count: 50 })])}
      />,
    );
    const bars = Array.from(container.querySelectorAll('div[style*="width"]'));
    expect(bars).toHaveLength(2);
    // Relative, not absolute: the section's shape has to be readable
    // whether the counts are in the tens or the tens of thousands.
    expect((bars[0] as HTMLElement).style.width).toBe('100%');
    expect((bars[1] as HTMLElement).style.width).toBe('25%');
  });

  it('keeps a tiny problem visible rather than drawing a zero-width bar', () => {
    const { container } = render(
      <IssueSectionPanel
        section={section([cluster({ count: 10000 }), cluster({ count: 1 })])}
      />,
    );
    const bars = Array.from(container.querySelectorAll('div[style*="width"]'));
    // 1 of 10,000 is 0.01%, which renders as nothing at all. The bar has
    // a floor so a small problem still reads as a problem rather than as
    // a rendering failure.
    const width = parseFloat((bars[1] as HTMLElement).style.width);
    expect(width).toBeGreaterThanOrEqual(2);
  });

  it('offers the extra examples only when there are extra examples', () => {
    render(<IssueSectionPanel section={section([cluster()])} />);
    expect(screen.queryByRole('button', { name: /show .* more/ })).toBeNull();
  });

  it('reveals the other examples and the folded variants on request', () => {
    const c = cluster({
      count: 300,
      users: 2,
      examples: [
        { cluster_id: 1, proc_id: 0, owner: 'alice', message: 'first' },
        { cluster_id: 2, proc_id: 1, owner: 'bob', message: 'second' },
      ],
      variants: [
        { template: 'Transfer output files failure ...', count: 200 },
        { template: 'Transfer input files failure ...', count: 100 },
      ],
      top_users: [
        { owner: 'alice', count: 200 },
        { owner: 'bob', count: 100 },
      ],
    });
    render(<IssueSectionPanel section={section([c])} />);
    expect(screen.queryByText('second')).toBeNull();

    fireEvent.click(screen.getByRole('button', { name: /show 1 more example/ }));
    expect(screen.getByText('second')).toBeInTheDocument();
    // A merge that hid what it folded together would be worse than no
    // merge: the row is named after the bigger variant, so the smaller
    // one has to be visible somewhere.
    expect(screen.getByText(/Transfer input files failure/)).toBeInTheDocument();
    expect(screen.getByRole('link', { name: /bob/ })).toHaveAttribute('href', '/users/bob');
  });
});

describe('UsersBadge', () => {
  it('distinguishes one user from several', () => {
    // The whole reason the count is on the row: one person's broken
    // submit file and a site problem look identical from the job count.
    const one = render(<UsersBadge users={1} />);
    expect(within(one.container).getByText('1 user')).toBeInTheDocument();
    one.unmount();

    const many = render(<UsersBadge users={7} />);
    const badge = within(many.container).getByText('7 users');
    expect(badge.className).toContain('amber');
  });
});
