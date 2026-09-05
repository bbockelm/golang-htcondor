import { expect, test } from '@playwright/test';

import { adminPassword, loginAsAdmin } from './fixtures/login';
import { serverLog } from './fixtures/serverlog';

// A job that actually runs.
//
// The rest of the suite submits and checks the job appears in the queue,
// which stops well short of the access point's actual promise. A job can
// be accepted and then never start -- sit in a spool hold, fail to match,
// die in input transfer -- and every other test here still passes.

const password = adminPassword(
  serverLog(),
);

// Generous, because this waits on a real negotiation cycle, but bounded:
// a hang must fail the test rather than the job.
const RUN_TIMEOUT_MS = 180_000;

// How long a code-16 spool hold may persist before it is treated as
// "nobody is going to send this". The release for a job needing no
// upload lands in well under a second; this is slack, not a guess at
// how long spooling takes.
const SPOOL_GRACE_MS = 30_000;

test('a submitted job runs to completion', async ({ page }) => {
  test.setTimeout(RUN_TIMEOUT_MS + 60_000);
  await loginAsAdmin(page, password);

  const submit = await page.request.post('/api/v1/jobs', {
    data: {
      submit_file: [
        'executable = /bin/echo',
        'arguments = hello-from-e2e',
        // transfer_executable = false is what makes this a one-step
        // submit. Otherwise TransferExecutable defaults to true, the
        // schedd holds the job with HoldReasonCode 16 waiting for the
        // client to upload the executable, and it never runs -- the
        // job is submitted successfully and then sits there forever.
        // /bin/echo is present in the execute environment, so there is
        // nothing to send.
        'transfer_executable = false',
        'output = e2e-$(Cluster).out',
        'queue 1',
      ].join('\n'),
    },
  });
  expect(submit.status(), `submit failed: ${await submit.text()}`).toBeLessThan(400);
  const created = await submit.json();
  const cluster = created.cluster_id ?? created.ClusterId ?? created.cluster;
  expect(cluster).toBeTruthy();

  // Poll until the job reports Completed (JobStatus 4).
  //
  // Not "until it leaves the queue": submissions get a LeaveJobInQueue
  // expression that keeps finished jobs listed for ten days, so
  // disappearing is not the completion signal and waiting for it would
  // just burn the timeout on a job that already succeeded.
  const deadline = Date.now() + RUN_TIMEOUT_MS;
  let lastSeen = 'never queried';
  let done: Record<string, unknown> | undefined;
  const spoolDeadline = Date.now() + SPOOL_GRACE_MS;

  while (Date.now() < deadline && !done) {
    const res = await page.request.get(
      `/api/v1/jobs?owned_by_me=false&constraint=${encodeURIComponent(`ClusterId == ${cluster}`)}`,
    );
    if (res.status() === 200) {
      const body = await res.json();
      const jobs = body.jobs ?? body.Jobs ?? [];
      if (jobs.length > 0) {
        const j = jobs[0];
        const status = Number(j.JobStatus ?? j.job_status);
        const holdCode = Number(j.HoldReasonCode ?? 0);
        lastSeen = `JobStatus=${status} HoldReasonCode=${holdCode} HoldReason=${j.HoldReason ?? '-'}`;

        if (status === 4) {
          done = j;
          break;
        }
        // Holds split two ways.
        //
        // Code 16 (spooling input) is NOT a failure on sight: every
        // submission is written into the queue held with code 16, and
        // the release for a job that needs no upload lands a moment
        // later. Failing on first sight of it is a race the test loses
        // roughly always. It only means something once it persists.
        //
        // Any other hold will not clear on its own, so report it
        // immediately with its reason instead of after the full timeout.
        if (status === 5 && holdCode !== 16) {
          throw new Error(`job went on hold instead of running: ${lastSeen}`);
        }
        if (status === 5 && holdCode === 16 && Date.now() > spoolDeadline) {
          throw new Error(
            `job still waiting on an input spool after ${SPOOL_GRACE_MS / 1000}s; ` +
              `a one-step submit never sends one (set transfer_executable = false ` +
              `or upload the input): ${lastSeen}`,
          );
        }
      }
    }
    await page.waitForTimeout(3000);
  }

  expect(done, `job never completed (last seen: ${lastSeen})`).toBeTruthy();

  // Completed is not the same as succeeded: a job that exits non-zero
  // also reaches status 4.
  const exit = Number(done!.ExitCode ?? done!.exit_code ?? -1);
  expect(exit, `job completed with a non-zero exit: ${JSON.stringify(done)}`).toBe(0);
});
