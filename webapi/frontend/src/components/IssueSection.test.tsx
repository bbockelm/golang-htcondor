import { fireEvent, render, screen, within } from '@testing-library/react';
import { describe, expect, it, vi } from 'vitest';
import { FacetBadge, IssueSectionPanel, UsersBadge, visibleFacets } from './IssueSection';
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

  it('draws a bar per slice of the window, and nothing where nothing happened', () => {
    const { container } = render(
      <IssueSectionPanel
        section={section([cluster({ timeline: [3, 0, 0, 5] })])}
        bucketSeconds={3600}
        endsAt={1790250000}
      />,
    );
    // An empty slice draws no bar: the gap is how "it stopped" looks,
    // and a zero-height rect would be indistinguishable from a small one.
    expect(container.querySelectorAll('svg rect')).toHaveLength(2);
  });

  it('accents the most recent slice that has anything in it', () => {
    const { container } = render(
      <IssueSectionPanel
        section={section([cluster({ timeline: [4, 9, 0, 0] })])}
        bucketSeconds={3600}
        endsAt={1790250000}
      />,
    );
    const rects = Array.from(container.querySelectorAll('svg rect'));
    // "Is this still happening" is the question the row cannot answer
    // from its count, so the newest occurrence is the one thing in the
    // row drawn in a colour -- here the second bar, not the last slice.
    expect(rects[0].getAttribute('class')).toContain('fill-gray-400');
    expect(rects[1].getAttribute('class')).toContain('fill-brand-500');
  });

  it('keeps a single occurrence visible against a huge peak', () => {
    const { container } = render(
      <IssueSectionPanel section={section([cluster({ timeline: [4000, 1] })])} />,
    );
    const rects = Array.from(container.querySelectorAll('svg rect'));
    // 1/4000 of 22px rounds to nothing. A floor is what makes the tail
    // of a burst hoverable rather than invisible.
    expect(parseFloat(rects[1].getAttribute('height')!)).toBeGreaterThanOrEqual(2);
  });

  it('says in words whether it is still arriving', () => {
    const still = render(
      <IssueSectionPanel
        section={section([cluster({ timeline: [1, 1, 1, 2] })])}
        bucketSeconds={3600}
        endsAt={1790250000}
      />,
    );
    expect(still.container.querySelector('svg')!.getAttribute('aria-label')).toContain(
      'still arriving',
    );
    still.unmount();

    const stopped = render(
      <IssueSectionPanel
        section={section([cluster({ timeline: [5, 0, 0, 0] })])}
        bucketSeconds={3600}
        endsAt={1790250000}
      />,
    );
    // The shape is not available to a screen reader, so the label has to
    // carry the same finding the picture does.
    expect(stopped.container.querySelector('svg')!.getAttribute('aria-label')).toContain(
      'nothing in the last 3 hours',
    );
  });

  it('renders no sparkline at all when the server sent no timeline', () => {
    const { container } = render(<IssueSectionPanel section={section([cluster()])} />);
    expect(container.querySelector('svg')).toBeNull();
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

describe('FacetBadge', () => {
  it('names the resource when a problem is confined to one', () => {
    // The actionable case: the message reads the same everywhere and the
    // whole problem is at one CE. A count alone cannot say that.
    render(
      <FacetBadge facet={{ name: 'resource', distinct: 1, top: [{ value: 'Purdue-Anvil-CE1', count: 205 }] }} />,
    );
    // The name on its own. The badge's colour says it is a place, which
    // is what "all at ..." used to spend four words on.
    expect(screen.getByText('Purdue-Anvil-CE1')).toBeInTheDocument();
    expect(screen.queryByText(/all at/)).toBeNull();
  });

  it('wears the same hue whether or not it is concentrated', () => {
    // Colour is what tells a location from a status at a glance; a
    // spread that fell back to grey would read as a different kind of
    // fact from the concentrated one beside it.
    const one = render(
      <FacetBadge facet={{ name: 'site', distinct: 1, top: [{ value: 'Nebraska', count: 9 }] }} />,
    );
    expect(one.container.firstElementChild!.className).toContain('sky');
    one.unmount();
    const many = render(<FacetBadge facet={{ name: 'site', distinct: 9, top: [] }} />);
    expect(many.container.firstElementChild!.className).toContain('sky');
  });

  it('reports the spread when it is everywhere', () => {
    render(<FacetBadge facet={{ name: 'resource', distinct: 43, top: [] }} />);
    // "43 resources" is the other half of the same answer: this one is
    // the pool's problem, not a site's.
    expect(screen.getByText('43 resources')).toBeInTheDocument();
  });
});

describe('visibleFacets', () => {
  const site = (v: string) => ({ name: 'site', distinct: 1, top: [{ value: v, count: 5 }] });
  const resource = (v: string) => ({ name: 'resource', distinct: 1, top: [{ value: v, count: 5 }] });

  it('drops the site when the resource name already contains it', () => {
    // "MTState-Tempest-CE1  MTState-Tempest" is the same place twice,
    // the second time less precisely.
    const got = visibleFacets([resource('MTState-Tempest-CE1'), site('MTState-Tempest')]);
    expect(got.map((f) => f.name)).toEqual(['resource']);
  });

  it('keeps both when the names are genuinely different', () => {
    // A resource whose site is not in its name is telling you something.
    const got = visibleFacets([
      resource('IU-Jetstream2-Backfill'),
      site('Pervasive Technology Institute'),
    ]);
    expect(got).toHaveLength(2);
  });

  it('never folds two counts together', () => {
    // "9 sites" and "14 resources" are different measurements; neither
    // contains the other and both belong on the row.
    const got = visibleFacets([
      { name: 'site', distinct: 9, top: [] },
      { name: 'resource', distinct: 14, top: [] },
    ]);
    expect(got).toHaveLength(2);
  });
});
