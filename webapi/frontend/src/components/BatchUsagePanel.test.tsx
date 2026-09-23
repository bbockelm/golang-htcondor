import { render, screen } from '@testing-library/react';
import { describe, expect, it } from 'vitest';
import { BatchUsagePanel } from './BatchUsagePanel';
import { summarizeBatchUsage } from '@/lib/batches';

describe('BatchUsagePanel', () => {
  it('scales memory and disk out of the units HTCondor reports them in', () => {
    render(
      <BatchUsagePanel
        usage={summarizeBatchUsage([
          {
            ClusterId: 1, ProcId: 0, JobStatus: 2,
            RequestMemory: 8192, RequestDisk: 20971520,
            MemoryUsage: 900, DiskUsage: 1048576,
          },
        ])}
      />,
    );
    // RequestMemory is MiB and RequestDisk is KiB; a panel that read
    // either as the other would be off by 1024x.
    expect(screen.getByText('8.0 GiB')).toBeInTheDocument();
    expect(screen.getByText('20.0 GiB')).toBeInTheDocument();
    expect(screen.getByText('900 MiB')).toBeInTheDocument();
    expect(screen.getByText('1.0 GiB')).toBeInTheDocument();
  });

  it('says nothing has been reported instead of showing 0%', () => {
    render(
      <BatchUsagePanel
        usage={summarizeBatchUsage([
          { ClusterId: 1, ProcId: 0, JobStatus: 2, RequestCpus: 4, RequestMemory: 1024 },
        ])}
      />,
    );
    // A batch that started ten seconds ago has no measurement. "0% of
    // allocation" would read as a stuck job.
    expect(screen.getByText(/have not reported usage/i)).toBeInTheDocument();
    expect(screen.queryByText('0%')).toBeNull();
  });

  it('renders nothing for a batch with no running or idle jobs', () => {
    // Every job held or finished: there is no allocation to describe,
    // and an all-dashes table would imply the data failed to load.
    const { container } = render(
      <BatchUsagePanel
        usage={summarizeBatchUsage([{ ClusterId: 1, ProcId: 0, JobStatus: 5 }])}
      />,
    );
    expect(container).toBeEmptyDOMElement();
  });
});
