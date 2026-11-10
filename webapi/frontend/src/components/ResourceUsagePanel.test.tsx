import { render, screen, waitFor } from '@testing-library/react';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import type { MetricsResponse } from '@/lib/metrics';

// The panel's query is answered by a stand-in for the server: it filters
// the raw samples by the query's ClassAd constraint and aggregates them per
// run and time bucket, as GET /api/v1/metrics/job_metrics does. The
// constraint is evaluated, not matched as text, so what is tested is what
// the query selects.
type Sample = Record<string, number>;
let samples: Sample[] = [];
const query = vi.fn();
// The per-run request read. An access point that keeps no epoch history
// is the case this stands in for, and it is not a quiet one: the read
// fails rather than coming back empty, which is why the default here
// rejects.
const epochs = vi.fn();
vi.mock('@/lib/api', async () => {
  const actual = await vi.importActual<typeof import('@/lib/api')>('@/lib/api');
  return {
    ...actual,
    api: {
      ...actual.api,
      metrics: { query: (...a: unknown[]) => query(...a) },
      jobs: { ...actual.api.jobs, epochs: (...a: unknown[]) => epochs(...a) },
    },
  };
});

import { ResourceUsagePanel } from './ResourceUsagePanel';

// --- A ClassAd evaluator for the constraints this page writes: numbers,
// attribute references, comparisons, `is`/`isnt`, `&&`, `||`, parentheses.
type V = number | boolean | undefined;
function evaluate(expr: string, ad: Sample): V {
  const toks = expr.match(/\d+(?:\.\d+)?|[A-Za-z_]\w*|==|!=|>=|<=|&&|\|\||[()<>]/g) ?? [];
  let i = 0;
  const lookup = (name: string): V => {
    const key = Object.keys(ad).find((k) => k.toLowerCase() === name.toLowerCase());
    return key === undefined ? undefined : ad[key];
  };
  const primary = (): V => {
    const t = toks[i++];
    if (t === '(') {
      const v = or();
      i++; // ')'
      return v;
    }
    if (/^\d/.test(t)) return Number(t);
    if (t.toLowerCase() === 'undefined') return undefined;
    if (t.toLowerCase() === 'true') return true;
    if (t.toLowerCase() === 'false') return false;
    return lookup(t);
  };
  const cmp = (): V => {
    const l = primary();
    const op = toks[i]?.toLowerCase();
    if (op === 'is' || op === 'isnt') {
      i++;
      const r = primary();
      return op === 'is' ? l === r : l !== r;
    }
    if (!['==', '!=', '>=', '<=', '>', '<'].includes(op)) return l;
    i++;
    const r = primary();
    if (l === undefined || r === undefined) return undefined;
    switch (op) {
      case '==': return l === r;
      case '!=': return l !== r;
      case '>=': return l >= r;
      case '<=': return l <= r;
      case '>': return l > r;
      default: return l < r;
    }
  };
  const and = (): V => {
    let v = cmp();
    while (toks[i] === '&&') {
      i++;
      const r = cmp();
      v = v === false || r === false ? false : v === undefined || r === undefined ? undefined : true;
    }
    return v;
  };
  const or = (): V => {
    let v = and();
    while (toks[i] === '||') {
      i++;
      const r = and();
      v = v === true || r === true ? true : v === undefined || r === undefined ? undefined : false;
    }
    return v;
  };
  return or();
}

// In multi-AP mode the server also confines a job_id read to that job on
// that access point; samples carry their AP as a numeric AP field here.
const AP_IDS: Record<string, number> = { 'ap1.example.org': 1, 'ap2.example.org': 2 };
function selects(jobID: string | undefined, s: Sample): boolean {
  if (jobID === undefined) return true;
  const [num, ap] = jobID.split('@');
  const [cluster, proc] = num.split('.').map(Number);
  return s.AP === AP_IDS[ap] && s.ClusterId === cluster && s.ProcId === proc;
}

function serve(params: { constraint: string; group_by: string; bucket: number; agg: string; job_id?: string }): MetricsResponse {
  const aggs = params.agg.split(',').map((a) => a.split(':') as [string, string]);
  const groups = new Map<string, Sample[]>();
  for (const s of samples) {
    if (evaluate(params.constraint, s) !== true || !selects(params.job_id, s)) continue;
    const key = `${s[params.group_by]}|${Math.floor(s.SampleTime / params.bucket) * params.bucket}`;
    groups.set(key, [...(groups.get(key) ?? []), s]);
  }
  const rows = [...groups.entries()].map(([key, ss]) => [
    ...key.split('|'),
    ...aggs.map(([fn, attr]) => {
      const vs = ss.map((s) => s[attr]).filter((v): v is number => v !== undefined);
      if (vs.length === 0) return '';
      return String(fn === 'avg' ? vs.reduce((a, b) => a + b, 0) / vs.length : Math.max(...vs));
    }),
  ]);
  return {
    enabled: true,
    table: 'job_metrics',
    time_attr: 'SampleTime',
    bucket_seconds: params.bucket,
    columns: [
      { name: params.group_by, kind: 'group' },
      { name: 'SampleTime', kind: 'group', bucket_seconds: params.bucket },
      ...aggs.map(([fn, attr]) => ({ name: `${fn}_${attr}`, kind: 'metric' as const, func: fn, attr })),
    ],
    rows,
  };
}

// A steady one-core job sampled every 15 minutes. Its first sample is the
// run's baseline: no interval, so no rate. Between the third and fourth
// sits one taken a second after the previous, the way the mis-timed rows
// were recorded: a second's counter over one second, 276 cores.
const T0 = 1_790_000_100;
function steadyJobWithSpike(): Sample[] {
  const base = { ClusterId: 7, ProcId: 0, RunInstanceID: 1, RequestCpus: 1, RequestMemory: 2048 };
  const out: Sample[] = [{ ...base, SampleTime: T0, MemoryUsage: 400 }];
  for (let k = 1; k <= 6; k++) {
    out.push({ ...base, SampleTime: T0 + k * 900, SampleInterval: 900, CpuUtil: 0.98 + k * 0.004, MemoryUsage: 400 + k * 10 });
  }
  out.push({ ...base, SampleTime: T0 + 2 * 900 + 1, SampleInterval: 1, CpuUtil: 276, MemoryUsage: 420 });
  return out;
}

// A job stopped for outgrowing its memory and started again at more: two
// runs, the second asking for twice the first. The samples carry the
// damage the real ones do -- run 1's last sample already holds run 2's
// request, because the transform rewrote it as the shadow exited.
function climbedJob(): Sample[] {
  const base = { ClusterId: 7, ProcId: 0, RequestCpus: 1 };
  const out: Sample[] = [];
  for (let k = 0; k < 3; k++) {
    out.push({
      ...base,
      RunInstanceID: 1,
      SampleTime: T0 + k * 900,
      MemoryUsage: 1800 + k * 50,
      RequestMemory: k === 2 ? 4096 : 2048,
    });
  }
  for (let k = 0; k < 3; k++) {
    out.push({ ...base, RunInstanceID: 2, SampleTime: T0 + (k + 5) * 900, MemoryUsage: 3000 + k * 50, RequestMemory: 4096 });
  }
  return out;
}

const epochAds = (...reqs: number[]) => ({
  ads: reqs.map((RequestMemory, i) => ({ RunInstanceID: i + 1, RequestMemory, EpochAdType: 'EPOCH' })),
});

function renderPanel(jobID = '7.0', multiAP = false) {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(
    <QueryClientProvider client={client}>
      <ResourceUsagePanel jobID={jobID} status={4} multiAP={multiAP} />
    </QueryClientProvider>,
  );
}

// The values the chart draws, from each point's tooltip ("0.99 cores · <time>").
function drawnCores(): number[] {
  const figure = screen.getByText('CPU').closest('figure')!;
  return [...figure.querySelectorAll('circle > title')].map((t) => Number(t.textContent!.split(' ')[0]));
}

beforeEach(() => {
  samples = steadyJobWithSpike();
  query.mockReset();
  query.mockImplementation((_table: string, params: Parameters<typeof serve>[0]) => Promise.resolve(serve(params)));
  epochs.mockReset();
  epochs.mockRejectedValue(new Error('404: no epoch history'));
});

describe('ResourceUsagePanel', () => {
  it('does not draw a rate measured over a mis-timed one-second interval', async () => {
    renderPanel();
    await screen.findByText('CPU');
    const cores = drawnCores();
    expect(cores).toHaveLength(6);
    for (const c of cores) expect(c).toBeLessThan(1.1);
  });

  it('in multi-AP mode asks for the complete job id and draws that access point only', async () => {
    // The same 7.0 on two access points: ap2's runs at a different memory.
    samples = [
      ...steadyJobWithSpike().map((s) => ({ ...s, AP: 1 })),
      ...steadyJobWithSpike().map((s) => ({ ...s, AP: 2, MemoryUsage: s.MemoryUsage + 5000 })),
    ];
    renderPanel('7.0@ap2.example.org', true);
    const figure = (await screen.findByText('Memory')).closest('figure')!;
    const params = query.mock.calls[0][1] as { job_id?: string; constraint: string };
    expect(params.job_id).toBe('7.0@ap2.example.org');
    expect(params.constraint).not.toMatch(/ClusterId|ProcId/);
    const drawn = [...figure.querySelectorAll('circle > title')].map((t) => t.textContent!);
    expect(drawn).toHaveLength(7);
    // ap2's 5.3 GB, never ap1's 400 MB.
    for (const d of drawn) expect(d).toMatch(/^5\.3 GB /);
  });

  it('in multi-AP mode says when the job\'s access point records no usage', async () => {
    query.mockImplementation(() =>
      Promise.resolve({
        enabled: true,
        table: 'job_metrics',
        rows: [],
        job: { schedd: 'ap3.example.org', cluster: 7, proc: 0, job_id: '7.0@ap3.example.org' },
        sources: {
          aps: 3,
          fresh: 3,
          degraded: [],
          not_kept: [{ schedd: 'ap3.example.org', table: 'job_metrics', reason: 'no job_metrics' }],
        },
      }),
    );
    renderPanel('7.0@ap3.example.org', true);
    expect(await screen.findByText('Resource usage is not recorded on ap3.example.org.')).toBeInTheDocument();
  });

  it('says nothing when another access point records no usage', async () => {
    query.mockImplementation(() =>
      Promise.resolve({
        enabled: true,
        table: 'job_metrics',
        rows: [],
        job: { schedd: 'ap2.example.org', cluster: 7, proc: 0, job_id: '7.0@ap2.example.org' },
        sources: { aps: 3, fresh: 3, degraded: [], not_kept: [{ schedd: 'ap3.example.org', table: 'job_metrics' }] },
      }),
    );
    const { container } = renderPanel('7.0@ap2.example.org', true);
    await waitFor(() => expect(query).toHaveBeenCalled());
    // Let the answer land and render.
    await new Promise((r) => setTimeout(r, 50));
    expect(container).toBeEmptyDOMElement();
  });

  it('in single-AP mode asks nothing for an id that names no job', async () => {
    // Querying anyway would send no constraint: every one of the
    // caller's samples, drawn as this job's.
    renderPanel('x.y');
    renderPanel('');
    await new Promise((r) => setTimeout(r, 20));
    expect(query).not.toHaveBeenCalled();
  });

  it('keeps the run baseline, which carries memory but no rate', async () => {
    renderPanel();
    const figure = (await screen.findByText('Memory')).closest('figure')!;
    // Seven buckets: the baseline and six periodic samples.
    expect(figure.querySelectorAll('circle')).toHaveLength(7);
  });
});

// An access point without JOB_EPOCH_HISTORY cannot say what each run
// asked for. The chart has to keep working on everything else it draws,
// and fall back to the one request the ad does carry.
describe('when the access point keeps no epoch history', () => {
  it('still draws the usage it has', async () => {
    renderPanel();
    await screen.findByText('Memory');
    expect(screen.getByText('CPU')).toBeInTheDocument();
    expect(drawnCores().length).toBeGreaterThan(0);
  });

  it('draws the single requested line, not a step per run', async () => {
    renderPanel();
    const figure = (await screen.findByText('Memory')).closest('figure')!;
    expect(figure.querySelectorAll('[data-testid="requested-step"]')).toHaveLength(0);
    expect(figure.textContent).toMatch(/Requested /);
    expect(figure.textContent).not.toMatch(/→/);
  });

  it('shows nothing about the failure', async () => {
    renderPanel();
    await screen.findByText('Memory');
    expect(screen.queryByText(/epoch/i)).toBeNull();
    expect(screen.queryByText(/404|error|could not/i)).toBeNull();
  });

  it('asks only once, and not again for the same job', async () => {
    renderPanel();
    await screen.findByText('Memory');
    await waitFor(() => expect(epochs).toHaveBeenCalled());
    const constraint = (epochs.mock.calls[0][0] as { constraint?: string }).constraint;
    expect(constraint).toBe('ClusterId == 7 && ProcId == 0');
  });
});

// The same job with its run records available. This is also what makes
// the fallback tests above worth anything: without it they would pass on
// a panel that could never draw a step at all.
describe('when the access point keeps epoch history', () => {
  it('draws a step per run at what that run asked for', async () => {
    samples = climbedJob();
    epochs.mockResolvedValue(epochAds(2048, 4096));
    renderPanel();
    const figure = (await screen.findByText('Memory')).closest('figure')!;
    await waitFor(() =>
      expect(figure.querySelectorAll('[data-testid="requested-step"]')).toHaveLength(2),
    );
    const drawn = [...figure.querySelectorAll('[data-testid="requested-step"]')].map((l) =>
      l.getAttribute('data-request'),
    );
    expect(drawn).toEqual(['2048', '4096']);
  });

  it('says where the request started and ended', async () => {
    samples = climbedJob();
    epochs.mockResolvedValue(epochAds(2048, 4096));
    renderPanel();
    const figure = (await screen.findByText('Memory')).closest('figure')!;
    await waitFor(() => expect(figure.textContent).toMatch(/Requested 2 GB → 4 GB/));
  });

  it('ignores what the samples claim run 1 asked for', async () => {
    // Run 1's last sample says 4096. Its record says 2048.
    samples = climbedJob();
    epochs.mockResolvedValue(epochAds(2048, 4096));
    renderPanel();
    const figure = (await screen.findByText('Memory')).closest('figure')!;
    await waitFor(() =>
      expect(figure.querySelectorAll('[data-testid="requested-step"]')).toHaveLength(2),
    );
    const first = figure.querySelector('[data-testid="requested-step"]')!;
    expect(first.getAttribute('data-request')).toBe('2048');
  });
});
