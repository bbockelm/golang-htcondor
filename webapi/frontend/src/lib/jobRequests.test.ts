import { describe, expect, it } from 'vitest';

import { EXPR_REQUEST_MEMORY as EXPR, exprRequestJob } from './jobRequests.fixture';
import { jobRequest } from './jobRequests';

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
