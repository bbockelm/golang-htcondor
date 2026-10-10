import { describe, expect, it } from 'vitest';
import {
  compareAdvice,
  formatCores,
  formatKiB,
  formatMiB,
  formatPercent,
  formatResourceHours,
  formatSaves,
  idleHours,
  parseDays,
  rankAdvice,
  stripGeometry,
  usedFraction,
  throughputStatement,
  throughputAdviceId,
  formatDuration,
  type UtilAdvice,
  type UtilThroughput,
  type UtilDistribution,
  type UtilWorkflow,
} from './utilization';
import { utilizationFixture } from './utilization.fixture';

function dist(over: Partial<UtilDistribution>): UtilDistribution {
  return {
    n: 100,
    min: 0,
    p10: 0,
    p25: 0,
    p50: 0,
    p75: 0,
    p90: 0,
    p95: 0,
    p99: 0,
    max: 0,
    histogram: [],
    ...over,
  };
}

function advice(over: Partial<UtilAdvice>): UtilAdvice {
  return {
    id: 'x',
    resource: 'memory',
    severity: 'suggest',
    title: 't',
    detail: 'd',
    submit: [],
    saves: null,
    confidence: 'high',
    ...over,
  };
}

describe('formatting', () => {
  it('renders memory in the scale a submit file uses', () => {
    expect(formatMiB(512)).toBe('512 MB');
    expect(formatMiB(1536)).toBe('1.5 GB');
    expect(formatMiB(2048)).toBe('2 GB');
    expect(formatMiB(32 * 1024)).toBe('32 GB');
    expect(formatMiB(13824)).toBe('13.5 GB');
    // Big enough that a decimal is noise.
    expect(formatMiB(250.4 * 1024)).toBe('250 GB');
    expect(formatMiB(3 * 1024 * 1024)).toBe('3 TB');
  });

  it('renders disk from KiB through the same scale', () => {
    expect(formatKiB(1024 * 1024)).toBe('1 GB');
    expect(formatKiB(512 * 1024)).toBe('512 MB');
    expect(formatKiB(300)).toBe('300 KB');
  });

  it('keeps fractional cores readable', () => {
    expect(formatCores(4)).toBe('4');
    expect(formatCores(0.966)).toBe('0.97');
    expect(formatCores(2.14)).toBe('2.1');
  });

  it('never rounds a small share down to a 0% that reads as none', () => {
    expect(formatPercent(0.237)).toBe('24%');
    expect(formatPercent(0.001)).toBe('<1%');
    expect(formatPercent(0)).toBe('0%');
    expect(formatPercent(null)).toBe('—');
  });

  it('converts time-weighted figures to the unit the page names', () => {
    expect(formatResourceHours('cpu', 1234.4)).toBe('1,234 core-hours');
    expect(formatResourceHours('memory', 2048 * 10)).toBe('20 GB-hours');
    expect(formatResourceHours('disk', 1024 * 1024 * 3)).toBe('3 GB-hours');
    expect(formatResourceHours('gpu', 2.5)).toBe('2.5 GPU-hours');
  });

  it('says what a saving is in', () => {
    expect(formatSaves({ unit: 'gib_hours', amount: 5190.2 })).toBe('5,190 GB-hours of memory');
    expect(formatSaves({ unit: 'core_hours', amount: 12 })).toBe('12 core-hours');
    expect(formatSaves(null)).toBeNull();
    expect(formatSaves({ unit: 'gpu_hours', amount: 0 })).toBeNull();
  });

  it('falls back to the default window for anything the server would reject', () => {
    expect(parseDays('30')).toBe(30);
    expect(parseDays('1')).toBe(1);
    expect(parseDays('14')).toBe(7);
    expect(parseDays(null)).toBe(7);
  });
});

describe('usedFraction', () => {
  it('divides by the reservation of measured jobs only', () => {
    // Half the reservation belongs to jobs nobody measured. Counting it
    // would report 25% used; what is known is that measured jobs used half.
    const s = {
      resource: 'cpu' as const,
      allocated_hours: 400,
      allocated_hours_measured: 200,
      used_hours: 100,
      jobs_measured: 10,
    };
    expect(usedFraction(s)).toBe(0.5);
    expect(idleHours(s)).toBe(100);
  });

  it('has no answer when nothing was measured', () => {
    expect(
      usedFraction({ resource: 'gpu', allocated_hours: 5, allocated_hours_measured: 0, used_hours: null, jobs_measured: 0 }),
    ).toBeNull();
  });
});

describe('rankAdvice', () => {
  const wf = (key: string, a: UtilAdvice[]) => ({ ...utilizationFixture.workflows[0], key, advice: a }) as UtilWorkflow;

  it('puts warnings first, then the biggest saving, and leaves notes out', () => {
    const ranked = rankAdvice([
      wf('a', [
        advice({ id: 'small', saves: { unit: 'core_hours', amount: 10 } }),
        advice({ id: 'note', severity: 'info', saves: { unit: 'core_hours', amount: 1e6 } }),
      ]),
      wf('b', [
        advice({ id: 'big', saves: { unit: 'gib_hours', amount: 900 } }),
        advice({ id: 'warn', severity: 'warn' }),
        advice({ id: 'none' }),
      ]),
    ]);
    expect(ranked.map((r) => r.advice.id)).toEqual(['warn', 'big', 'small', 'none']);
    expect(ranked[1].workflow.key).toBe('b');
  });

  it('breaks a tie on confidence', () => {
    expect(compareAdvice(advice({ confidence: 'low' }), advice({ confidence: 'high' }))).toBeGreaterThan(0);
  });
});

describe('stripGeometry', () => {
  const request = { typical: 4096, min: 4096, max: 4096, distinct: 1 };

  it('spans zero to the request when every job fits under it', () => {
    const g = stripGeometry(request, dist({ p10: 1024, p25: 1500, p75: 2048, p90: 2500, max: 3000 }))!;
    expect(g.trackMax).toBe(4096);
    expect(g.request).toBe(1);
    expect(g.over).toBe(false);
  });

  it('flags a workflow whose largest job went over its request', () => {
    const g = stripGeometry(request, dist({ p25: 3000, p75: 3500, max: 5000 }))!;
    expect(g.over).toBe(true);
    // The track stretches to the largest job so the request is inside it.
    expect(g.trackMax).toBe(5000);
    expect(g.request).toBeCloseTo(4096 / 5000);
  });

  it('draws nothing without a distribution', () => {
    expect(stripGeometry(request, null)).toBeNull();
  });
});

describe('fixture', () => {
  // The fixture stands in for the server in the component tests and the
  // smoke suite; if it stops agreeing with itself it tests nothing.
  it('has histograms that account for every job', () => {
    for (const w of utilizationFixture.workflows) {
      const d = w.memory.peak_mib!;
      expect(d.histogram.reduce((a, b) => a + b.count, 0)).toBe(d.n);
    }
  });

  it('marks exactly one recommended request per curve', () => {
    for (const w of utilizationFixture.workflows) {
      if (w.memory_curve.length === 0) continue;
      expect(w.memory_curve.filter((p) => p.is_recommended)).toHaveLength(1);
    }
  });
});

describe('throughputStatement', () => {
  const base: UtilThroughput = {
    current: { cpus: 1, memory_mib: 8192, disk_kib: 10 * 1024 * 1024, gpus: 0 },
    suggested: { cpus: 1, memory_mib: 2048, disk_kib: 10 * 1024 * 1024, gpus: 0 },
    retry_memory_mib: 6144,
    fit_current: 16,
    fit_suggested: 32,
    gain: 2.13,
    limited_by: 'memory',
    wait_p50: 3 * 3600,
    slots_limited: true,
    last_batch: { id: 81291, jobs: 300, elapsed: 14 * 3600, estimated: 6.2 * 3600 },
  };

  it('claims the multiplier, and the batch time, when slots held the jobs back', () => {
    const st = throughputStatement(base)!;
    expect(st.kind).toBe('gain');
    expect(st.line).toBe('Up to 2.1× as many of these jobs could run at once.');
    expect(st.batch).toBe(
      'Your last batch of 300 jobs took 14 h from submission to the last result; with these settings, about 6.2 h.',
    );
  });

  it('claims no multiplier for jobs that started within minutes', () => {
    const st = throughputStatement({ ...base, slots_limited: false, wait_p50: 240 })!;
    expect(st.kind).toBe('unlimited');
    expect(st.line).toBe('Your jobs started within 4 minutes, so this mainly frees the pool for others.');
    expect(st.line).not.toMatch(/×/);
    expect(st.batch).toBeUndefined();
  });

  it('says plainly when the change means fewer at once', () => {
    const st = throughputStatement({
      ...base,
      suggested: { ...base.current, cpus: 4 },
      gain: 0.6,
    })!;
    expect(st.kind).toBe('loss');
    expect(st.line).toBe(
      "Requesting the cores your jobs use means fewer run at once (0.6×), but each job stops competing for cores it didn't ask for.",
    );
  });

  it('says nothing for a gain inside the noise, or no estimate', () => {
    expect(throughputStatement({ ...base, gain: 1.04 })).toBeNull();
    expect(throughputStatement(null)).toBeNull();
  });

  it('leaves out the batch sentence when there is no batch to measure', () => {
    expect(throughputStatement({ ...base, last_batch: null })!.batch).toBeUndefined();
  });
});

describe('formatDuration', () => {
  it('rounds to what a reader plans with', () => {
    expect(formatDuration(45 * 60)).toBe('45 min');
    expect(formatDuration(6.24 * 3600)).toBe('6.2 h');
    expect(formatDuration(14.4 * 3600)).toBe('14 h');
    expect(formatDuration(3.5 * 86400)).toBe('3.5 days');
  });
});

describe('throughputAdviceId', () => {
  const w = utilizationFixture.workflows.find((x) => x.key === 'wf-blast')!;
  const assemble = utilizationFixture.workflows.find((x) => x.key === 'wf-assemble')!;

  it('puts a gain on the change to the resource that caps the jobs now', () => {
    // Memory caps blast at 8 GB per job; the disk change rides along.
    expect(w.throughput!.limited_by).toBe('memory');
    expect(throughputAdviceId(w)).toMatch(/^memory-/);
  });

  it('puts a loss on the change that raises a request', () => {
    expect(assemble.throughput!.gain).toBeLessThan(1);
    expect(throughputAdviceId(assemble)).toBe('memory-raise');
  });

  it('has no card without an estimate', () => {
    expect(throughputAdviceId({ ...w, throughput: null })).toBeNull();
  });
});
