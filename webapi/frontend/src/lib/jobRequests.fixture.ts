import type { ClassAd } from './api';

// The shape of a finished job whose memory request is a rule over its own
// usage, as the API sends it: the rule as "/Expr(...)/" and the number it
// evaluates to in the job's ad under "evaluated".
export const EXPR_REQUEST_MEMORY = 'ifthenelse(MemoryUsage =!= undefined,max({ 2048,3 * MemoryUsage / 2 }),2048)';
export const exprRequestJob: ClassAd = {
  RequestMemory: `/Expr(${EXPR_REQUEST_MEMORY})/`,
  MemoryUsage: 7325,
  ResidentSetSize: 7500000,
  MemoryProvisioned: 11008,
  RequestCpus: 1,
  RequestDisk: 6291456,
  evaluated: { RequestMemory: 10987, RequestCpus: 1, RequestDisk: 6291456 },
};
