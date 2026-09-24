import { render, screen } from '@testing-library/react';
import { describe, expect, it } from 'vitest';

import {
  ResourceTable,
  UsageBar,
  dagmanLogName,
  everRan,
  isSpooledJob,
  outputReadiness,
  supportsRemoteAccess,
  workflowLogAvailability,
} from './JobDetailClient';
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

describe('outputReadiness', () => {
  // everRan is true for the run happening right now -- the schedd
  // writes JobStartDate when it spawns the shadow -- so the panel used
  // to offer a first-run RUNNING job a download labelled "From an
  // earlier run attempt". Nothing has transferred back yet.
  it('does not offer the download for a job in its first run', () => {
    const r = outputReadiness(
      { JobStatus: 2, JobStartDate: 1790000000, NumJobStarts: 1 } as ClassAd,
      2,
    );
    expect(r.ready).toBe(false);
    expect(r.hint).toMatch(/running/i);
    expect(r.hint).not.toMatch(/earlier run attempt/i);
  });

  // The case the gate exists for: it ran, the attempt ended, and the
  // job is back in the queue. There may be a sandbox to look at.
  it('offers the download for an attempt that already ended', () => {
    const r = outputReadiness({ JobStatus: 1, JobStartDate: 1790000000 } as ClassAd, 1);
    expect(r.ready).toBe(true);
    expect(r.hint).toMatch(/earlier run attempt/i);
  });

  // Scheduler universe writes into its spool in place while it runs,
  // and the schedd serves those files for a running job -- so the
  // download stays offered, and says it is a snapshot rather than the
  // final answer.
  it('offers a live snapshot for a running scheduler-universe job', () => {
    const r = outputReadiness(
      {
        JobStatus: 2,
        JobUniverse: 7,
        JobStartDate: 1790000000,
        SUBMIT_Iwd: '/home/e2e/dags',
      } as ClassAd,
      2,
    );
    expect(r.ready).toBe(true);
    expect(r.hint).toMatch(/live snapshot/i);
  });

  // ... but only when it was spooled. A manager submitted from a shell
  // on the access point keeps the user's directory as its Iwd and
  // writes there, so the schedd's spool is empty and the download
  // would come back with nothing in it.
  it('waits for a scheduler-universe job that was not spooled', () => {
    const r = outputReadiness(
      { JobStatus: 2, JobUniverse: 7, JobStartDate: 1790000000 } as ClassAd,
      2,
    );
    expect(r.ready).toBe(false);
    expect(r.hint).toMatch(/output files appear once it completes/i);
  });

  it('offers a completed job its files with nothing to explain', () => {
    const r = outputReadiness({ JobStatus: 4 } as ClassAd, 4);
    expect(r.ready).toBe(true);
    expect(r.hint).toBeNull();
  });

  it('tells a held job that never ran that it has to run first', () => {
    const r = outputReadiness({ JobStatus: 5 } as ClassAd, 5);
    expect(r.ready).toBe(false);
    expect(r.hint).toMatch(/held/i);
  });
});

describe('supportsRemoteAccess', () => {
  // The schedd's GET_JOB_CONNECT_INFO switch refuses exactly these two
  // (schedd.cpp:18673); tail and ssh both go through it.
  it('is false for the universes with no starter', () => {
    expect(supportsRemoteAccess({ JobUniverse: 7 } as ClassAd)).toBe(false);
    expect(supportsRemoteAccess({ JobUniverse: 9 } as ClassAd)).toBe(false);
  });

  // Local universe runs on the access point like scheduler universe
  // does, but under a starter -- so it must not be swept in with it.
  it('is true for local universe and for vanilla', () => {
    expect(supportsRemoteAccess({ JobUniverse: 12 } as ClassAd)).toBe(true);
    expect(supportsRemoteAccess({ JobUniverse: 5 } as ClassAd)).toBe(true);
  });

  // A missing attribute must not hide a terminal that would have
  // worked.
  it('is true when the ad does not say', () => {
    expect(supportsRemoteAccess({} as ClassAd)).toBe(true);
  });
});

describe('dagmanLogName', () => {
  // The environment is authoritative because the two producers
  // disagree: condor_submit_dag writes <dagfile>.dagman.out, this
  // project's submit_dag writes <base>.dagman.out. Deriving would name
  // the wrong file for one of them.
  it('prefers the name the submitter recorded in the environment', () => {
    expect(
      dagmanLogName({
        Cmd: '/usr/bin/condor_dagman',
        Arguments: '-p 0 -f -l . -Dag diamond.dag -Lockfile diamond.dag.lock',
        Environment: '_CONDOR_DAGMAN_LOG=diamond.dagman.out _CONDOR_MAX_DAGMAN_LOG=0',
      } as ClassAd),
    ).toBe('diamond.dagman.out');
  });

  it('falls back to condor_submit_dag convention from -Dag', () => {
    expect(
      dagmanLogName({
        Cmd: '/usr/bin/condor_dagman',
        Arguments: '-p 0 -f -l . -Dag diamond.dag',
      } as ClassAd),
    ).toBe('diamond.dag.dagman.out');
  });

  it('has no answer for a job that is not a DAGMan manager', () => {
    expect(dagmanLogName({ Cmd: '/bin/sleep', Arguments: '600' } as ClassAd)).toBeUndefined();
    expect(dagmanLogName({} as ClassAd)).toBeUndefined();
  });
});

describe('isSpooledJob', () => {
  // SUBMIT_Iwd is what the schedd's rewriteSpooledJobAd writes when it
  // repoints Iwd at the spool, so its presence is exactly "Iwd is the
  // spool directory" -- which is what makes the job's files reachable
  // through this server at all.
  it('reads SUBMIT_Iwd as the spool marker', () => {
    expect(isSpooledJob({ SUBMIT_Iwd: '/home/e2e/dags' } as ClassAd)).toBe(true);
    expect(isSpooledJob({ Iwd: '/home/e2e/dags' } as ClassAd)).toBe(false);
    expect(isSpooledJob({} as ClassAd)).toBe(false);
  });
});

describe('workflowLogAvailability', () => {
  const manager = {
    Cmd: '/usr/bin/condor_dagman',
    Arguments: '-p 0 -f -l . -Dag diamond.dag',
    Environment: '_CONDOR_DAGMAN_LOG=diamond.dagman.out',
    Iwd: '/home/e2e/dags',
  };

  it('shows the log for a spooled manager', () => {
    const got = workflowLogAvailability({
      ...manager,
      Iwd: '/var/lib/condor/spool/77/0/cluster77.proc0.subproc0',
      SUBMIT_Iwd: '/home/e2e/dags',
    } as ClassAd);
    expect(got.available).toBe(true);
    expect(got.name).toBe('diamond.dagman.out');
  });

  // The fetch goes through the schedd's spool, which for a
  // shell-submitted workflow is empty: the log is in the user's own
  // directory. Say where rather than offering a button that 404s.
  it('explains where the log is when the workflow was not spooled', () => {
    const got = workflowLogAvailability(manager as ClassAd);
    expect(got.available).toBe(false);
    expect(got.name).toBe('diamond.dagman.out');
    expect(got.reason).toContain('diamond.dagman.out');
    expect(got.reason).toContain('/home/e2e/dags');
    expect(got.reason).toContain('condor_q -better-analyze');
  });

  it('has nothing to say about a job that is not a DAGMan manager', () => {
    const got = workflowLogAvailability({ Cmd: '/bin/sleep' } as ClassAd);
    expect(got.available).toBe(false);
    expect(got.name).toBeUndefined();
    expect(got.reason).toBeUndefined();
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
