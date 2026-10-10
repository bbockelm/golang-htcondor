import { act, fireEvent, render, screen, within } from '@testing-library/react';
import { afterEach, describe, expect, it, vi } from 'vitest';
import type { UtilAdvice, UtilMemoryCurvePoint, UtilThroughput, UtilWorkflow } from '@/lib/utilization';
import { utilizationFixture } from '@/lib/utilization.fixture';
import {
  AdviceCard,
  EmptyState,
  ResourceCard,
  Suggestions,
  ThroughputHeadline,
  ThroughputLead,
  TruncatedNotice,
  WorkflowDetail,
  WorkflowsTable,
} from './UtilizationPanels';
import { MemoryCurve, RangeStrip, UTIL_COLOR, mergeBins } from './UtilizationCharts';

// The page's states and its few rules that are easy to get subtly wrong:
// which denominator the headline uses, which suggestions lead, what the
// Copy button puts on the clipboard, when a range strip turns red, and
// which points the memory curve calls out.

const hrefFor = (key: string) => `/utilization?w=${key}`;

function advice(over: Partial<UtilAdvice>): UtilAdvice {
  return {
    id: 'memory-lower',
    resource: 'memory',
    severity: 'suggest',
    title: 'Request 2 GB of memory',
    detail: 'Most jobs peaked under 1.7 GB.',
    submit: ['request_memory = 2 GB', 'retry_request_memory = 6 GB'],
    saves: { unit: 'gib_hours', amount: 1200 },
    confidence: 'high',
    ...over,
  };
}

function workflow(over: Partial<UtilWorkflow>): UtilWorkflow {
  return { ...utilizationFixture.workflows[0], ...over };
}

describe('ResourceCard', () => {
  it('reports used over the measured reservation, not the whole one', () => {
    render(
      <ResourceCard
        jobs={100}
        summary={{
          resource: 'cpu',
          allocated_hours: 1000,
          allocated_hours_measured: 400,
          used_hours: 100,
          jobs_measured: 40,
        }}
      />,
    );
    const card = screen.getByTestId('resource-cpu');
    // 100 / 400. Dividing by allocated_hours would say 10%.
    expect(within(card).getByText('25%')).toBeInTheDocument();
    expect(within(card).queryByText('10%')).not.toBeInTheDocument();
    expect(card).toHaveTextContent('300 core-hours reserved but idle');
    expect(card).toHaveTextContent('measured on 40 of 100 jobs');
  });

  it('calls memory a peak', () => {
    render(
      <ResourceCard
        jobs={1}
        summary={{ resource: 'memory', allocated_hours: 2048, allocated_hours_measured: 2048, used_hours: 1024, jobs_measured: 1 }}
      />,
    );
    expect(screen.getByText('Peak memory')).toBeInTheDocument();
  });

  it('says so when nothing was measured instead of showing 0%', () => {
    render(
      <ResourceCard
        jobs={5}
        summary={{ resource: 'disk', allocated_hours: 10, allocated_hours_measured: 0, used_hours: null, jobs_measured: 0 }}
      />,
    );
    expect(screen.getByText('No usage was measured for these jobs.')).toBeInTheDocument();
    expect(screen.queryByText('0%')).not.toBeInTheDocument();
  });
});

describe('states', () => {
  it('names the window when nothing finished', () => {
    render(<EmptyState days={30} />);
    expect(screen.getByText('No jobs finished in the last 30 days.')).toBeInTheDocument();
  });

  it('says how many jobs a capped answer covers', () => {
    render(<TruncatedNotice data={{ truncated: true, jobs_considered: 50000 }} />);
    expect(screen.getByText(/most recent 50,000 jobs/)).toBeInTheDocument();
  });

  it('says nothing about a complete answer', () => {
    const { container } = render(<TruncatedNotice data={{ truncated: false, jobs_considered: 12 }} />);
    expect(container).toBeEmptyDOMElement();
  });
});

describe('Suggestions', () => {
  it('leads with warnings, then savings, and links each to its workflow', () => {
    render(
      <Suggestions
        hrefFor={hrefFor}
        workflows={[
          workflow({
            key: 'a',
            name: 'alpha',
            advice: [
              advice({ id: 'cpus-lower', title: 'Small saving', saves: { unit: 'core_hours', amount: 5 } }),
              advice({ id: 'memory-ok', title: 'Just a note', severity: 'info' }),
            ],
          }),
          workflow({
            key: 'b',
            name: 'beta',
            advice: [
              advice({ id: 'memory-raise', title: 'Raise memory', severity: 'warn', saves: null }),
              advice({ id: 'memory-lower', title: 'Big saving', saves: { unit: 'gib_hours', amount: 900 } }),
            ],
          }),
        ]}
      />,
    );
    const titles = screen.getAllByRole('heading', { level: 3 }).map((h) => h.textContent);
    expect(titles).toEqual(['Raise memory', 'Big saving', 'Small saving']);
    const first = screen.getAllByTestId('advice')[0];
    expect(within(first).getByRole('link', { name: 'beta' })).toHaveAttribute('href', '/utilization?w=b');
  });

  it('shows five and offers the rest', () => {
    const many = Array.from({ length: 7 }, (_, i) =>
      advice({ id: `a${i}`, title: `Advice ${i}`, saves: { unit: 'core_hours', amount: 100 - i } }),
    );
    render(<Suggestions hrefFor={hrefFor} workflows={[workflow({ advice: many })]} />);
    expect(screen.getAllByTestId('advice')).toHaveLength(5);
    fireEvent.click(screen.getByRole('button', { name: 'Show all 7 suggestions' }));
    expect(screen.getAllByTestId('advice')).toHaveLength(7);
  });
});

describe('AdviceCard', () => {
  afterEach(() => {
    vi.useRealTimers();
  });

  it('copies the submit lines exactly, one per line', async () => {
    const writeText = vi.fn().mockResolvedValue(undefined);
    Object.defineProperty(navigator, 'clipboard', { value: { writeText }, configurable: true });
    render(<AdviceCard advice={advice({})} />);
    await act(async () => {
      fireEvent.click(screen.getByRole('button', { name: 'Copy' }));
    });
    expect(writeText).toHaveBeenCalledWith('request_memory = 2 GB\nretry_request_memory = 6 GB');
    expect(screen.getByRole('button', { name: 'Copied' })).toBeInTheDocument();
  });

  it('marks low-confidence advice where it can be seen', () => {
    render(<AdviceCard advice={advice({ confidence: 'low' })} />);
    expect(screen.getByText('Low confidence: few jobs to go on')).toBeInTheDocument();
  });

  it('has no Copy button when there is nothing to paste', () => {
    render(<AdviceCard advice={advice({ submit: [] })} />);
    expect(screen.queryByRole('button', { name: 'Copy' })).not.toBeInTheDocument();
  });
});

describe('RangeStrip', () => {
  const request = { typical: 2048, min: 2048, max: 2048, distinct: 1 };
  const base = {
    n: 50, min: 500, p10: 800, p25: 1000, p50: 1200, p75: 1400, p90: 1700, p95: 1800, p99: 1900, max: 2000,
    histogram: [],
  };
  const fmt = (v: number) => `${v} MB`;

  it('draws the largest job in the usage colour when it fits', () => {
    const { container } = render(<RangeStrip request={request} dist={base} format={fmt} label="Peak memory" />);
    expect(container.querySelector('[data-testid="strip-max"]')).toHaveAttribute('fill', UTIL_COLOR.used);
    expect(container.querySelector('svg')).not.toHaveAccessibleName(/more than requested/);
  });

  it('turns the largest job red when it went over the request', () => {
    const { container } = render(
      <RangeStrip request={request} dist={{ ...base, max: 2600 }} format={fmt} label="Peak memory" />,
    );
    expect(container.querySelector('[data-testid="strip-max"]')).toHaveAttribute('fill', UTIL_COLOR.over);
    // And says so in words, for anyone not reading the colour.
    expect(container.querySelector('svg')).toHaveAccessibleName(/largest 2600 MB, more than requested/);
  });
});

describe('MemoryCurve', () => {
  const pts: UtilMemoryCurvePoint[] = [
    { request_mib: 1024, retry_mib: 4096, reserved_mib_hours: 300 * 1024, retry_fraction: 0.4, is_current: false, is_recommended: false },
    { request_mib: 2048, retry_mib: 4096, reserved_mib_hours: 200 * 1024, retry_fraction: 0.05, is_current: false, is_recommended: true },
    { request_mib: 4096, retry_mib: null, reserved_mib_hours: 350 * 1024, retry_fraction: 0, is_current: false, is_recommended: false },
    { request_mib: 8192, retry_mib: null, reserved_mib_hours: 700 * 1024, retry_fraction: 0, is_current: true, is_recommended: false },
  ];

  it('labels the current and the suggested request with what each reserves', () => {
    render(<MemoryCurve points={pts} />);
    expect(screen.getByText('now 8 GB')).toBeInTheDocument();
    expect(screen.getByText('suggested 2 GB')).toBeInTheDocument();
    expect(screen.getByText('200 GB-h, 5% rerun')).toBeInTheDocument();
    expect(screen.getByText(/would have reserved 71% less memory/)).toBeInTheDocument();
  });

  it('says what a suggestion that reserves more memory buys', () => {
    // Raising the request from 1 GB to 2 GB: more memory, fewer reruns.
    const raise = pts.map((p) =>
      p.request_mib === 1024 ? { ...p, is_current: true, reserved_mib_hours: 100 * 1024 } : { ...p, is_current: false },
    );
    render(<MemoryCurve points={raise} />);
    expect(screen.getByText(/reserves 100% more memory, and 5% of jobs rerun instead of 40%/)).toBeInTheDocument();
  });

  it('says when the current request is already the suggestion', () => {
    render(<MemoryCurve points={pts.map((p) => ({ ...p, is_current: p.request_mib === 2048 }))} />);
    expect(screen.getByText('now, and suggested 2 GB')).toBeInTheDocument();
    expect(screen.queryByText(/^suggested/)).not.toBeInTheDocument();
  });

  it('steps through requests from the keyboard, starting at the suggestion', () => {
    render(<MemoryCurve points={pts} />);
    const target = screen.getByLabelText(/arrow keys/);
    fireEvent.focus(target);
    expect(screen.getByRole('status')).toHaveTextContent('request_memory = 2 GB (suggested)');
    fireEvent.keyDown(target, { key: 'ArrowLeft' });
    expect(screen.getByRole('status')).toHaveTextContent('40%of jobs rerun');
  });

  it('marks only the current and suggested requests', () => {
    const { container } = render(<MemoryCurve points={pts} />);
    // Two callout dots; the other candidates are reached by hover.
    expect(container.querySelectorAll('svg[role="img"] circle')).toHaveLength(2);
  });

  it('shades the rerun strip by share of jobs, merging equal neighbours', () => {
    const { container } = render(<MemoryCurve points={pts} />);
    const steps = [...container.querySelectorAll('[data-testid="rerun-strip"]')].map((r) => r.getAttribute('data-step'));
    // 40% -> over 10%; 5% -> 2-5%; then two candidates with none, as one bar.
    expect(steps).toEqual(['4', '2', '0']);
  });
});

describe('WorkflowsTable', () => {
  it('opens a workflow from the keyboard', () => {
    const onOpen = vi.fn();
    render(<WorkflowsTable workflows={utilizationFixture.workflows} hrefFor={hrefFor} onOpen={onOpen} />);
    const row = screen.getByRole('row', { name: /^blast-search/ });
    fireEvent.keyDown(row, { key: 'Enter' });
    expect(onOpen).toHaveBeenCalledWith('wf-blast');
  });
});

describe('WorkflowDetail', () => {
  it('renders every panel for a full workflow', () => {
    const w = utilizationFixture.workflows.find((x) => x.key === 'wf-train')!;
    render(<WorkflowDetail workflow={w} days={7} backHref="/utilization" />);
    for (const title of [
      'Peak memory per job',
      'What each memory request would have reserved',
      'Run time and peak memory',
      'CPU cores kept busy per job',
      'Disk used per job',
      'How busy each job kept its GPUs',
    ]) {
      expect(screen.getByText(title)).toBeInTheDocument();
    }
  });

  it('explains a missing curve rather than drawing an empty one', () => {
    const w = utilizationFixture.workflows.find((x) => x.key === 'wf-post')!;
    render(<WorkflowDetail workflow={w} days={7} backHref="/utilization" />);
    expect(screen.getByText('Too few jobs to weigh one memory request against another.')).toBeInTheDocument();
  });
});

describe('mergeBins', () => {
  const bins = [0, 1, 2, 3, 4, 5].map((i) => ({ lo: i * 10, hi: (i + 1) * 10, count: i + 1 }));

  it('joins narrow neighbours without losing a job', () => {
    const out = mergeBins(bins, 25);
    expect(out.map((b) => [b.lo, b.hi])).toEqual([[0, 30], [30, 60]]);
    expect(out.reduce((a, b) => a + b.count, 0)).toBe(21);
  });

  it('keeps the jobs past the suggested request in bars of their own', () => {
    const out = mergeBins(bins, 25, 20);
    expect(out.map((b) => [b.lo, b.hi])).toEqual([[0, 20], [20, 50], [50, 60]]);
  });
});

describe('throughput', () => {
  const t: UtilThroughput = {
    current: { cpus: 1, memory_mib: 8192, disk_kib: 1024 * 1024, gpus: 0 },
    suggested: { cpus: 1, memory_mib: 2048, disk_kib: 1024 * 1024, gpus: 0 },
    retry_memory_mib: null,
    fit_current: 16,
    fit_suggested: 32,
    gain: 2.1,
    limited_by: 'memory',
    wait_p50: 2 * 3600,
    slots_limited: true,
    last_batch: { id: 1, jobs: 300, elapsed: 14 * 3600, estimated: 6 * 3600 },
  };

  it('leads the headline with the pool-wide gain, with its one reading aid', () => {
    render(<ThroughputHeadline gain={1.84} />);
    expect(screen.getByTestId('throughput-headline')).toHaveTextContent(
      'With all of these changes: up to 1.8× as many jobs running at once.',
    );
    expect(screen.getByText('Estimated from the machines currently in the pool.')).toBeInTheDocument();
  });

  it('hides a pool-wide gain below 1.1×, and a missing one', () => {
    const { container, rerender } = render(<ThroughputHeadline gain={1.07} />);
    expect(container).toBeEmptyDOMElement();
    rerender(<ThroughputHeadline gain={null} />);
    expect(container).toBeEmptyDOMElement();
  });

  it('puts the multiplier on a request-changing card when slots limited the jobs', () => {
    render(<AdviceCard advice={advice({})} throughput={t} />);
    expect(screen.getByTestId('advice-throughput')).toHaveTextContent('Up to 2.1× as many of these jobs could run at once.');
  });

  it('claims nothing on the card when the jobs started promptly', () => {
    render(<AdviceCard advice={advice({})} throughput={{ ...t, slots_limited: false, wait_p50: 300 }} />);
    expect(screen.queryByTestId('advice-throughput')).not.toBeInTheDocument();
    expect(screen.queryByText(/×/)).not.toBeInTheDocument();
  });

  it('keeps the line off cards that change no request', () => {
    render(<AdviceCard advice={advice({ resource: 'runtime', submit: [] })} throughput={t} />);
    expect(screen.queryByTestId('advice-throughput')).not.toBeInTheDocument();
  });

  it('states a loss plainly on the card', () => {
    render(
      <AdviceCard
        advice={advice({ resource: 'cpu', submit: ['request_cpus = 4'] })}
        throughput={{ ...t, suggested: { ...t.current, cpus: 4 }, gain: 0.6 }}
      />,
    );
    expect(screen.getByTestId('advice-throughput')).toHaveTextContent('fewer run at once (0.6×)');
  });

  it('opens a workflow with the gain and what it would have meant for the last batch', () => {
    render(<ThroughputLead throughput={t} />);
    const lead = screen.getByTestId('throughput-lead');
    expect(lead).toHaveTextContent('Up to 2.1× as many of these jobs could run at once.');
    expect(lead).toHaveTextContent(
      'Your last batch of 300 jobs took 14 h from submission to the last result; with these settings, about 6 h.',
    );
  });

  it('opens a promptly-started workflow with what the change is for instead', () => {
    render(<ThroughputLead throughput={{ ...t, slots_limited: false, wait_p50: 420 }} />);
    expect(screen.getByTestId('throughput-lead')).toHaveTextContent(
      'Your jobs started within 7 minutes, so this mainly frees the pool for others.',
    );
  });

  it('has no lead without an estimate', () => {
    const { container } = render(<ThroughputLead throughput={null} />);
    expect(container).toBeEmptyDOMElement();
  });

  it('sorts the workflows table by throughput, blanks last', () => {
    const ws = [
      workflow({ key: 'a', name: 'alpha', throughput: { ...t, gain: 1.5 } }),
      workflow({ key: 'b', name: 'beta', throughput: null }),
      workflow({ key: 'c', name: 'gamma', throughput: { ...t, gain: 3.2 } }),
      workflow({ key: 'd', name: 'delta', throughput: { ...t, gain: 4, slots_limited: false } }),
    ];
    render(<WorkflowsTable workflows={ws} hrefFor={hrefFor} onOpen={() => {}} />);
    fireEvent.click(screen.getByRole('button', { name: /Throughput/ }));
    const names = () => screen.getAllByRole('row').slice(1).map((r) => r.getAttribute('aria-label')?.split(':')[0]);
    expect(names().slice(0, 2)).toEqual(['alpha', 'gamma']);
    fireEvent.click(screen.getByRole('button', { name: /Throughput/ }));
    expect(names().slice(0, 2)).toEqual(['gamma', 'alpha']);
    const cells = screen.getAllByTestId('throughput-cell').map((c) => c.textContent);
    expect(cells).toEqual(['up to 3.2×', 'up to 1.5×', '', '']);
  });
});
