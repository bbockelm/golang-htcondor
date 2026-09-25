import { render, screen } from '@testing-library/react';
import { describe, expect, it } from 'vitest';

import {
  ResourceTable,
  UsageBar,
  dagLayers,
  dagStateAsOf,
  dagStatePill,
  dagStateRank,
  dagStateShape,
  dagStatusEntries,
  dagmanLogName,
  dominantDagState,
  everRan,
  formatTookMs,
  isSpooledJob,
  outputReadiness,
  supportsRemoteAccess,
  workflowGraphAvailability,
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

// --- Workflow graph -------------------------------------------------

describe('dagLayers', () => {
  // The shape of the argument is DagGraphGroup's, narrowed to what the
  // layering reads. Tests build it inline so a change to the rest of
  // the response does not touch them.
  const g = (id: string, ...parent_ids: string[]) => ({ id, parent_ids });

  it('walks a chain one layer at a time', () => {
    expect(dagLayers([g('a'), g('b', 'a'), g('c', 'b')])).toEqual([
      ['a'],
      ['b'],
      ['c'],
    ]);
  });

  it('puts the two sides of a diamond on the same layer', () => {
    // a -> b, a -> c, b -> d, c -> d
    expect(
      dagLayers([g('a'), g('b', 'a'), g('c', 'a'), g('d', 'b', 'c')]),
    ).toEqual([['a'], ['b', 'c'], ['d']]);
  });

  it('spreads a fan-out across one layer and gathers it into the next', () => {
    expect(
      dagLayers([
        g('setup'),
        g('work1', 'setup'),
        g('work2', 'setup'),
        g('work3', 'setup'),
        g('gather', 'work1', 'work2', 'work3'),
      ]),
    ).toEqual([['setup'], ['work1', 'work2', 'work3'], ['gather']]);
  });

  // The case that separates longest-path from shortest-path layering.
  // `late` depends on the root AND on a node three deep; placed by
  // shortest path it would sit at layer 1 with an edge pointing UP from
  // layer 3, which is the one thing a layered drawing must not do.
  it('places a node below its deepest parent, not its shallowest', () => {
    const layers = dagLayers([
      g('root'),
      g('mid', 'root'),
      g('deep', 'mid'),
      g('late', 'root', 'deep'),
    ]);
    expect(layers).toEqual([['root'], ['mid'], ['deep'], ['late']]);
  });

  // A group with no edges at all is still part of the workflow. It is a
  // root, so it belongs on the top layer -- dropping it would silently
  // shrink the node count the panel reports beside the picture.
  it('keeps a disconnected group as a root', () => {
    expect(dagLayers([g('a'), g('b', 'a'), g('orphan')])).toEqual([
      ['a', 'orphan'],
      ['b'],
    ]);
  });

  // Within-layer order is first appearance in the response, not
  // discovery order, so two loads of the same workflow draw the same
  // picture.
  it('orders a layer by first appearance in the input', () => {
    const layers = dagLayers([
      g('root'),
      g('z', 'root'),
      g('a', 'root'),
      g('m', 'root'),
    ]);
    expect(layers[1]).toEqual(['z', 'a', 'm']);
  });

  // A parent naming a group that is not in the response is a dangling
  // edge (a torn DOT file, an unreadable splice). Treating it as a real
  // parent would leave the child with an indegree that never reaches
  // zero -- i.e. never drawn.
  it('draws a node whose parent is not in the graph', () => {
    expect(dagLayers([g('a'), g('b', 'ghost')])).toEqual([['a', 'b']]);
  });

  // A cycle has no layering. It must still terminate and still place
  // every group somewhere, because the server hands us one (flagged
  // approximate) rather than refusing.
  it('places every group even when the graph has a cycle', () => {
    const layers = dagLayers([g('a', 'b'), g('b', 'a'), g('c')]);
    expect(layers.flat().sort()).toEqual(['a', 'b', 'c']);
  });

  it('has no layers for no groups', () => {
    expect(dagLayers([])).toEqual([]);
  });
});

describe('dag node state urgency', () => {
  // "Where is it stuck" is the question the picture answers, so the
  // states that mean "stuck" have to sort ahead of the ones that mean
  // "fine" -- a group is coloured by the first of these it contains.
  it('ranks failed and held ahead of everything that is working', () => {
    for (const ok of ['running', 'idle', 'ready', 'done', 'submitted']) {
      expect(dagStateRank('failed')).toBeLessThan(dagStateRank(ok));
      expect(dagStateRank('held')).toBeLessThan(dagStateRank(ok));
    }
  });

  it('ranks done last of the states it knows', () => {
    for (const other of ['failed', 'held', 'running', 'idle', 'unready']) {
      expect(dagStateRank('done')).toBeGreaterThan(dagStateRank(other));
    }
  });

  // A state name this UI has not seen is not evidence of trouble. If
  // the unknown outranked `failed`, a server-side rename would recolour
  // every group in every workflow red.
  it('ranks an unrecognised state below failed', () => {
    expect(dagStateRank('brand-new-state')).toBeGreaterThan(
      dagStateRank('failed'),
    );
    expect(dagStateRank('brand-new-state')).toBeGreaterThanOrEqual(
      dagStateRank('done'),
    );
  });

  it('colours failed and held with the app red and done with the app grey', () => {
    expect(dagStatePill('failed')).toBe(dagStatePill('held'));
    expect(dagStatePill('failed')).toMatch(/red/);
    expect(dagStateShape('failed')).toMatch(/fill-red/);
    expect(dagStatePill('done')).toMatch(/gray/);
    expect(dagStateShape('running')).toMatch(/fill-green/);
  });

  it('gives an unrecognised state a colour rather than nothing', () => {
    expect(dagStatePill('brand-new-state')).not.toBe('');
    expect(dagStateShape('brand-new-state')).toMatch(/fill-/);
  });
});

describe('dagStatusEntries / dominantDagState', () => {
  it('lists the histogram most urgent first', () => {
    expect(
      dagStatusEntries({ done: 9, running: 2, failed: 1 }).map((e) => e.state),
    ).toEqual(['failed', 'running', 'done']);
  });

  it('drops the zeroes a full histogram carries', () => {
    expect(dagStatusEntries({ done: 3, failed: 0, held: 0 })).toEqual([
      { state: 'done', count: 3 },
    ]);
  });

  it('has nothing to say about a missing histogram', () => {
    expect(dagStatusEntries(undefined)).toEqual([]);
    expect(dominantDagState(undefined)).toBeUndefined();
    expect(dominantDagState({})).toBeUndefined();
  });

  // The whole point of the colour rule: the one failed node among the
  // ninety-nine done ones is what the reader came for, so it decides
  // the box's colour even though it is outnumbered 99 to 1.
  it('colours by the most urgent state present, not the most numerous', () => {
    expect(dominantDagState({ done: 99, failed: 1 })).toBe('failed');
    expect(dominantDagState({ done: 5, running: 1 })).toBe('running');
    expect(dominantDagState({ done: 5 })).toBe('done');
  });
});

describe('workflowGraphAvailability', () => {
  const manager = {
    Cmd: '/usr/bin/condor_dagman',
    Arguments: '-p 0 -f -l . -Dag fanout.dag',
    Environment: '_CONDOR_DAGMAN_LOG=fanout.dagman.out',
    Iwd: '/home/e2e/dags',
  };

  it('offers the graph for a spooled manager', () => {
    const got = workflowGraphAvailability({
      ...manager,
      Iwd: '/var/lib/condor/spool/77/0/cluster77.proc0.subproc0',
      SUBMIT_Iwd: '/home/e2e/dags',
    } as ClassAd);
    expect(got.applicable).toBe(true);
    expect(got.available).toBe(true);
    expect(got.reason).toBeUndefined();
  });

  // Same gate as the workflow log and for the same reason. The panel
  // stays, with a sentence -- offering a Load button here buys the user
  // a 409. The sentence says the FACT and what to do next; it does not
  // name the files, the spool, or why this server cannot reach them.
  it('explains itself for a manager that was not spooled', () => {
    const got = workflowGraphAvailability(manager as ClassAd);
    expect(got.applicable).toBe(true);
    expect(got.available).toBe(false);
    expect(got.reason).toContain('submitted from a shell');
    expect(got.reason).toContain('condor_q -dag');
    for (const implementation of ['.dot', 'node status file', 'spool', 'DAGMan']) {
      expect(got.reason).not.toContain(implementation);
    }
  });

  it('renders nothing at all for a job that is not a DAGMan manager', () => {
    const got = workflowGraphAvailability({
      Cmd: '/bin/sleep',
      Arguments: '600',
      SUBMIT_Iwd: '/home/e2e/dags',
    } as ClassAd);
    expect(got.applicable).toBe(false);
    expect(got.available).toBe(false);
    expect(got.reason).toBeUndefined();
  });
});

// dagStateAsOf / formatTookMs back the one line the panel keeps: how old
// the state is, and how long the load took. The rest of the provenance
// paragraph -- which files were read, out of which spool, by which of
// DAGMan's write cycles -- was a description of the server and is gone.
describe('dagStateAsOf / formatTookMs', () => {
  const at = (s: number) => new Date(s * 1000).toISOString();

  // The answer is only as fresh as whichever half is further behind.
  // With the auto-refetch gone, a cached structure can be much older
  // than DAGMan's last status write, and reporting the newer of the two
  // would tell the reader their picture is current when it is not.
  it('dates the state by the older of the two halves', () => {
    expect(
      dagStateAsOf({ fetched_at: at(1000), status_file_time: 900 }),
    ).toBe(900);
    expect(
      dagStateAsOf({ fetched_at: at(1000), status_file_time: 1100 }),
    ).toBe(1000);
  });

  it('falls back to whichever half the response carries', () => {
    expect(dagStateAsOf({ fetched_at: at(1234) })).toBe(1234);
    expect(dagStateAsOf({ status_file_time: 555 })).toBe(555);
    // A zero status_file_time means "that half did not contribute",
    // not "1970".
    expect(dagStateAsOf({ fetched_at: at(77), status_file_time: 0 })).toBe(77);
  });

  // A response with neither, or with a fetched_at that will not parse,
  // must render as nothing rather than as the epoch.
  it('says nothing rather than 1970', () => {
    expect(dagStateAsOf({})).toBe(0);
    expect(dagStateAsOf({ fetched_at: 'not a date' })).toBe(0);
  });

  it('renders a duration the way a reader reads one', () => {
    expect(formatTookMs(38)).toBe('38ms');
    expect(formatTookMs(940)).toBe('940ms');
    expect(formatTookMs(1240)).toBe('1.2s');
    expect(formatTookMs(5000)).toBe('5.0s');
    // A server that does not send the field, or sends nonsense.
    expect(formatTookMs(NaN)).toBe('');
    expect(formatTookMs(-1)).toBe('');
  });
});
