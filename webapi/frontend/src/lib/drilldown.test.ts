import { describe, expect, it } from 'vitest';
import { archiveDrilldown, jobsDrilldown, statusConstraint } from './drilldown';

function constraintOf(href: string): string {
  return decodeURIComponent(new URL(href, 'http://x').searchParams.get('constraint') ?? '');
}

describe('statusConstraint', () => {
  // The tiles only add up because a job held solely for spooling is
  // counted as "uploading" rather than HELD -- the same rule the server
  // applies in dashboardStatusName. If HELD did not exclude it here, the
  // drill-down would return more jobs than the tile claimed.
  it('keeps spooling out of HELD and gives it its own constraint', () => {
    expect(statusConstraint('held')).toContain('HoldReasonCode =!= 16');
    expect(statusConstraint('uploading')).toBe('JobStatus == 5 && HoldReasonCode == 16');
  });

  // =!= not !=: against an undefined attribute, != evaluates to
  // undefined rather than true, which silently drops every row that has
  // no hold code at all.
  it('uses the is-not-identical operator so undefined does not drop rows', () => {
    expect(statusConstraint('held')).not.toMatch(/HoldReasonCode\s*!=\s*16/);
  });

  it('maps each status to its JobStatus', () => {
    expect(statusConstraint('idle')).toBe('JobStatus == 1');
    expect(statusConstraint('running')).toBe('JobStatus == 2');
    expect(statusConstraint('removed')).toBe('JobStatus == 3');
    expect(statusConstraint('completed')).toBe('JobStatus == 4');
    expect(statusConstraint('transferring_output')).toBe('JobStatus == 6');
    expect(statusConstraint('suspended')).toBe('JobStatus == 7');
  });

  it('declines to guess at a bucket it does not know', () => {
    // No link is a better answer than one that quietly shows the wrong
    // jobs.
    expect(statusConstraint('something_new')).toBeNull();
  });
});

describe('drilldown urls', () => {
  it('escapes the constraint so an expression survives the round trip', () => {
    const href = jobsDrilldown('JobStatus == 5 && HoldReasonCode == 13', 'held jobs');
    expect(constraintOf(href)).toBe('JobStatus == 5 && HoldReasonCode == 13');
    expect(new URL(href, 'http://x').searchParams.get('why')).toBe('held jobs');
  });

  it('sends finished work to the archive rather than the queue', () => {
    expect(archiveDrilldown('CompletionDate >= 1', 'x')).toMatch(/^\/archive\?/);
    expect(jobsDrilldown('JobStatus == 1', 'x')).toMatch(/^\/jobs\?/);
  });
});
