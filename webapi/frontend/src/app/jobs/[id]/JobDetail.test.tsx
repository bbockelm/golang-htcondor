import { render, screen } from '@testing-library/react';
import { describe, expect, it } from 'vitest';

import { ResourceTable, UsageBar, everRan } from './JobDetailClient';
import type { ClassAd } from '@/lib/api';

describe('everRan', () => {
  // The Output Files panel gates on this. A job that ran and went back
  // to idle or held can have left a sandbox behind, and gating on the
  // terminal states alone greys out the download for exactly the person
  // trying to find out what the failed attempt produced.
  it('is true for a job that ran and was put back in the queue', () => {
    expect(everRan({ JobStatus: 1, JobStartDate: 1790000000 } as ClassAd)).toBe(true);
    expect(everRan({ JobStatus: 5, NumJobStarts: 2 } as ClassAd)).toBe(true);
  });

  it('is false for a job that has never started', () => {
    // NumJobStarts is present and zero -- what condor_submit writes --
    // which must not read as "it ran".
    expect(everRan({ JobStatus: 1, NumJobStarts: 0 } as ClassAd)).toBe(false);
    expect(everRan({ JobStatus: 5 } as ClassAd)).toBe(false);
  });
});

describe('UsageBar', () => {
  it('reports the proportion used', () => {
    render(<UsageBar requested={4} used={1} />);
    expect(screen.getByText('25%')).toBeInTheDocument();
  });

  // Over-request is the interesting case: that is the job about to be
  // held for going over. The percentage must not be clamped away even
  // though the bar itself is.
  it('shows over-request rather than capping at 100%', () => {
    render(<UsageBar requested={1000} used={1120} />);
    expect(screen.getByText('112%')).toBeInTheDocument();
  });

  // Nothing measured is not the same as nothing used.
  it('draws nothing when usage is unknown', () => {
    const { container } = render(<UsageBar requested={4} used={undefined} />);
    expect(container.querySelector('[role="img"]')).toBeNull();
  });

  it('draws nothing when the request is zero, rather than dividing by it', () => {
    const { container } = render(<UsageBar requested={0} used={5} />);
    expect(container.querySelector('[role="img"]')).toBeNull();
  });
});

describe('ResourceTable', () => {
  // HTCondor capitalises the acronym: RequestGPUs and GPUsUsage. The
  // page read RequestGpus/GpusUsage, which a case-sensitive JSON object
  // answers with undefined, so the row was dropped from every job --
  // including the GPU ones.
  it('shows GPUs using the attribute names HTCondor actually writes', () => {
    render(<ResourceTable job={{ RequestGPUs: 2, GPUsUsage: 1.5 } as ClassAd} />);
    expect(screen.getByText('GPUs')).toBeInTheDocument();
    expect(screen.getByText('2')).toBeInTheDocument();
  });

  it('still hides the GPU row for a job that asked for none', () => {
    render(<ResourceTable job={{ RequestCpus: 1 } as ClassAd} />);
    expect(screen.queryByText('GPUs')).toBeNull();
  });

  // Memory is the one with two units in play: MemoryUsage is MiB and
  // ResidentSetSize is KiB, and taking the wrong one at face value makes
  // a job using half its request look like it used none.
  it('compares memory in one unit', () => {
    render(
      <ResourceTable
        job={{ RequestMemory: 2048, ResidentSetSize: 1024 * 1024 } as ClassAd}
      />,
    );
    expect(screen.getByText('50%')).toBeInTheDocument();
  });
});
