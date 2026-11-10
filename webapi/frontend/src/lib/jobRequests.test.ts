import { describe, expect, it } from 'vitest';

import { EXPR_REQUEST_MEMORY as EXPR, exprRequestJob } from './jobRequests.fixture';
import { gpusHeld, gpusUsed, hasGpus, jobRequest } from './jobRequests';

describe('jobRequest', () => {
  it('reads an expression request as the number the server evaluated, and keeps the rule', () => {
    expect(jobRequest(exprRequestJob, 'RequestMemory')).toEqual({ value: 10987, expr: EXPR });
  });

  it('reads a literal request as itself', () => {
    expect(jobRequest(exprRequestJob, 'RequestCpus')).toEqual({ value: 1 });
    expect(jobRequest({ RequestCpus: 4 }, 'RequestCpus')).toEqual({ value: 4 });
  });

  it('has no value for an expression the server could not evaluate', () => {
    const r = jobRequest({ RequestMemory: '/Expr(TARGET.Memory / 2)/' }, 'RequestMemory');
    expect(r.value).toBeUndefined();
    expect(r.expr).toBe('TARGET.Memory / 2');
  });

  it('ignores case in attribute names, as ClassAds do', () => {
    expect(jobRequest({ requestgpus: 2 }, 'RequestGPUs').value).toBe(2);
    expect(jobRequest({ RequestGpus: '/Expr(1 + 1)/', evaluated: { RequestGPUs: 2 } }, 'RequestGPUs')).toEqual({
      value: 2,
      expr: '1 + 1',
    });
  });

  it('says nothing for a job without the attribute', () => {
    expect(jobRequest({}, 'RequestDisk')).toEqual({ value: undefined });
    expect(jobRequest(undefined, 'RequestDisk')).toEqual({ value: undefined });
  });
});

describe('hasGpus', () => {
  it('is false for a job that requested zero GPUs and holds none', () => {
    expect(hasGpus({ RequestGPUs: 0, GPUsProvisioned: 0 })).toBe(false);
    expect(hasGpus({ RequestCpus: 1 })).toBe(false);
    expect(hasGpus({ RequestGPUs: 0, AssignedGPUs: '' })).toBe(false);
    expect(hasGpus(undefined)).toBe(false);
  });

  it('is true for a job that requested GPUs, literally or by expression', () => {
    expect(hasGpus({ RequestGPUs: 1 })).toBe(true);
    expect(hasGpus({ RequestGPUs: '/Expr(NumGPUs)/', evaluated: { RequestGPUs: 2 } })).toBe(true);
  });

  it('is true for a job with GPUs assigned, provisioned or in use', () => {
    expect(hasGpus({ RequestGPUs: 0, AssignedGPUs: 'GPU-0000aaaa' })).toBe(true);
    expect(hasGpus({ GPUsProvisioned: 1 })).toBe(true);
    expect(hasGpus({ GPUsUsage: 0.4 })).toBe(true);
  });
});

// The server's rule (utilization.GPUsHeld / PlausibleGPUUsage), mirrored.
describe('gpusHeld and gpusUsed', () => {
  it('counts the GPUs held: provisioned, else distinct assigned ids, else the request', () => {
    expect(gpusHeld({ RequestGPUs: 1, GPUsProvisioned: 2, AssignedGPUs: 'GPU-1a' })).toBe(2);
    expect(gpusHeld({ RequestGPUs: 1, AssignedGPUs: 'GPU-1a, GPU-1b,GPU-1a' })).toBe(2);
    expect(gpusHeld({ RequestGPUs: 3 })).toBe(3);
    expect(gpusHeld({})).toBeUndefined();
  });

  it.each([
    ['req 2, prov 2, avg 12973.47', { RequestGPUs: 2, GPUsProvisioned: 2, AssignedGPUs: 'GPU-0a,GPU-0b', GPUsAverageUsage: 12973.47 }, undefined],
    ['req 2, prov 2, avg 53.67', { RequestGPUs: 2, GPUsProvisioned: 2, GPUsAverageUsage: 53.67 }, undefined],
    ['req 4, prov 4, avg 110688.3', { RequestGPUs: 4, GPUsProvisioned: 4, GPUsAverageUsage: 110688.3 }, undefined],
    ['req 1, prov 2, two ids, avg 1.8', { RequestGPUs: 1, GPUsProvisioned: 2, AssignedGPUs: 'GPU-1a,GPU-1b', GPUsAverageUsage: 1.8 }, 1.8],
    ['req 1, two ids, avg 1.8', { RequestGPUs: 1, AssignedGPUs: 'GPU-1a,GPU-1b', GPUsAverageUsage: 1.8 }, 1.8],
    ['req 4, prov 4, avg 3.2', { RequestGPUs: 4, GPUsProvisioned: 4, GPUsAverageUsage: 3.2 }, 3.2],
    ['req 1, prov 1, avg 1.004 (jitter)', { RequestGPUs: 1, GPUsProvisioned: 1, GPUsAverageUsage: 1.004 }, 1.004],
    ['req 1, prov 1, avg 1.2', { RequestGPUs: 1, GPUsProvisioned: 1, GPUsAverageUsage: 1.2 }, undefined],
    ['req 2, prov 2, GPUsUsage only', { RequestGPUs: 2, GPUsProvisioned: 2, GPUsUsage: 1.5 }, 1.5],
    ['req 2, prov 2, GPUsUsage 9', { RequestGPUs: 2, GPUsProvisioned: 2, GPUsUsage: 9 }, undefined],
    // Neither GPUsProvisioned nor AssignedGPUs: not judged.
    ['req 1 only, avg 1.8', { RequestGPUs: 1, GPUsAverageUsage: 1.8 }, 1.8],
  ])('%s', (_name, job, want) => {
    expect(gpusUsed(job)).toBe(want);
  });
});
