// Links into /utilization from the job listings.
//
// /utilization reads a `constraint` the same way the job listings do --
// a ClassAd expression over job attributes -- so a batch, or whatever the
// listing has been narrowed to, opens there already narrowed to the same
// jobs. Thirty days, because a batch's history is usually longer than the
// page's default window.
export function utilizationHref(opts: { constraint?: string; schedd?: string } = {}): string {
  const qs = new URLSearchParams({ days: '30' });
  if (opts.constraint) qs.set('constraint', opts.constraint);
  if (opts.schedd) qs.set('schedd', opts.schedd);
  return `/utilization?${qs.toString()}`;
}
