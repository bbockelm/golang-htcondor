import { render, screen } from '@testing-library/react';
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
vi.mock('@/lib/api', async () => {
  const actual = await vi.importActual<typeof import('@/lib/api')>('@/lib/api');
  return {
    ...actual,
    api: { ...actual.api, metrics: { query: (...a: unknown[]) => query(...a) } },
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

function serve(params: { constraint: string; group_by: string; bucket: number; agg: string }): MetricsResponse {
  const aggs = params.agg.split(',').map((a) => a.split(':') as [string, string]);
  const groups = new Map<string, Sample[]>();
  for (const s of samples) {
    if (evaluate(params.constraint, s) !== true) continue;
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

function renderPanel() {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(
    <QueryClientProvider client={client}>
      <ResourceUsagePanel jobID="7.0" status={4} />
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
});

describe('ResourceUsagePanel', () => {
  it('does not draw a rate measured over a mis-timed one-second interval', async () => {
    renderPanel();
    await screen.findByText('CPU');
    const cores = drawnCores();
    expect(cores).toHaveLength(6);
    for (const c of cores) expect(c).toBeLessThan(1.1);
  });

  it('keeps the run baseline, which carries memory but no rate', async () => {
    renderPanel();
    const figure = (await screen.findByText('Memory')).closest('figure')!;
    // Seven buckets: the baseline and six periodic samples.
    expect(figure.querySelectorAll('circle')).toHaveLength(7);
  });
});
