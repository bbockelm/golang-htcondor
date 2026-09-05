import { expect, test } from '@playwright/test';

import { adminPassword, loginAsAdmin } from './fixtures/login';
import { serverLog } from './fixtures/serverlog';

// The real two-step submit: POST the job, then upload its input.
//
// This is what the Submit page does, and it was the gap left by the
// lifecycle test, which sidesteps the upload with
// transfer_executable = false. It matters because step one reports
// success either way: TransferExecutable defaults to true, so a job
// submitted and never uploaded to is accepted, returns 2xx, and then
// sits held on HoldReasonCode 16 forever.
//
// So this asserts the contract in both directions: held after submit,
// running after upload.

const password = adminPassword(
  serverLog(),
);

const SCRIPT = '#!/bin/sh\necho uploaded-and-ran\n';

async function jobAd(page: import('@playwright/test').Page, id: string) {
  const res = await page.request.get('/api/v1/jobs?owned_by_me=false&limit=*');
  const jobs = (await res.json()).jobs ?? [];
  return jobs.find((j: Record<string, unknown>) => `${j.ClusterId}.${j.ProcId}` === id);
}

test('a job waits on its input upload, then runs once it arrives', async ({ page }) => {
  test.setTimeout(360_000);
  await loginAsAdmin(page, password);

  // No transfer_executable = false here: this job genuinely needs its
  // executable sent, which is the case the upload step exists for.
  const submit = await page.request.post('/api/v1/jobs', {
    data: {
      submit_file: [
        'executable = uploaded.sh',
        'output = uploaded-$(Cluster).out',
        'queue 1',
      ].join('\n'),
    },
  });
  expect(submit.status(), `submit failed: ${await submit.text()}`).toBeLessThan(400);
  const created = await submit.json();
  const cluster = created.cluster_id ?? created.ClusterId ?? created.cluster;
  const id = `${cluster}.0`;

  // Step one alone leaves it held, waiting. Asserted rather than
  // assumed: if a future change auto-released these, this test should
  // say so instead of quietly testing nothing.
  await expect
    .poll(
      async () => {
        const j = await jobAd(page, id);
        return j ? `${Number(j.JobStatus)}/${Number(j.HoldReasonCode ?? 0)}` : 'absent';
      },
      { timeout: 30_000 },
    )
    .toBe('5/16');

  // Step two. Field name "executable" is the convention the Go side
  // maps to mode 0755; anything else lands 0644 and would not be
  // runnable.
  const upload = await page.request.post(`/api/v1/jobs/${id}/input/multipart`, {
    multipart: {
      executable: {
        name: 'uploaded.sh',
        mimeType: 'application/x-shellscript',
        buffer: Buffer.from(SCRIPT),
      },
    },
  });
  expect(upload.status(), `upload failed: ${await upload.text()}`).toBeLessThan(400);

  // Now it should leave the hold on its own and complete.
  //
  // A loop rather than expect.poll: a terminal hold has to abort here,
  // and returning a sentinel from a poll callback does not do that --
  // the poll simply keeps retrying an unequal value until it times out.
  // An earlier version did exactly that and took the full timeout to
  // report a hold it had already seen on the first tick.
  //
  // Generous but bounded: the job waits on a negotiation cycle in a pool
  // with very few slots, competing with the rest of the suite.
  const deadline = Date.now() + 300_000;
  let done: Record<string, unknown> | undefined;
  let last = 'never queried';
  while (Date.now() < deadline && !done) {
    const j = await jobAd(page, id);
    if (j) {
      const st = Number(j.JobStatus);
      const hc = Number(j.HoldReasonCode ?? 0);
      last = `JobStatus=${st} HoldReasonCode=${hc} HoldReason=${j.HoldReason ?? '-'}`;
      if (st === 4) {
        done = j;
        break;
      }
      if (st === 5 && hc !== 16) {
        throw new Error(`job held instead of running after upload: ${last}`);
      }
    }
    await page.waitForTimeout(3000);
  }
  expect(done, `job never completed after its upload (last seen: ${last})`).toBeTruthy();
  expect(Number(done!.ExitCode ?? -1), `job did not exit cleanly: ${JSON.stringify(done)}`).toBe(0);
});
