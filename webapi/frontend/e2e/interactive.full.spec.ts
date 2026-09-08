import { expect, test } from '@playwright/test';

import { adminPassword, loginAsAdmin } from './fixtures/login';
import { serverLog } from './fixtures/serverlog';

const password = adminPassword(serverLog());

// An interactive terminal, end to end, the way a user gets one.
//
// What was missing: TestHTTPSSHToJobIntegration drives the SSH bridge
// against a bare handler with header auth, submitting an ordinary sleep
// job itself. It never touches /api/v1/interactive/terminal, never uses
// a session cookie, and never runs in a browser -- so it stayed green
// while the interactive feature was unusable.
//
// The assertion that matters is the last one: a command typed into the
// socket comes back with its output. Everything short of that -- the
// endpoint returning 200, the job running, the page rendering -- was
// already true while the feature was broken.

type Summary = {
  job_id: string;
  cluster_id: number;
  job_status: number;
  job_current_start_executing_date?: number;
};

test('a terminal session can be created, attached to, and used', async ({ page, baseURL }) => {
  test.setTimeout(300_000);
  await loginAsAdmin(page, password);

  // 1. Create one through the endpoint the UI uses.
  const created = await page.request.post('/api/v1/interactive/terminal', { data: {} });
  expect(created.status(), `create failed: ${await created.text()}`).toBeLessThan(400);
  const summary = (await created.json()) as Summary;
  expect(summary.job_id, `no job id in ${JSON.stringify(summary)}`).toBeTruthy();
  const jobID = summary.job_id;

  // 2. Wait until the executable is actually running. JobStatus 2 alone
  //    is not enough: the sandbox is still being set up, and
  //    condor_ssh_to_job refuses until the starter is ready. This is the
  //    same attribute the session page uses to leave "transferring
  //    input", and the one the watch projection was missing.
  let last = 'never queried';
  await expect
    .poll(
      async () => {
        const res = await page.request.get('/api/v1/interactive/terminal');
        const list = (await res.json()).terminals ?? (await res.json()).sessions ?? [];
        const s = (list as Summary[]).find((t) => t.job_id === jobID);
        if (!s) return false;
        last = `status=${s.job_status} exec=${s.job_current_start_executing_date ?? 'unset'}`;
        return Boolean(s.job_current_start_executing_date);
      },
      { timeout: 240_000, intervals: [3000] },
    )
    .toBe(true);
  // `last` carries what the poll saw, so a timeout above is followed by
  // this in the report rather than a bare boolean.
  expect(last, 'the session should have reported an executing start date').toContain('exec=');

  // 3. Attach from the browser. Same-origin, so the session cookie goes
  //    with the upgrade -- which is how a user reaches this and what the
  //    header-auth test cannot cover.
  const marker = `E2E_TERM_${Date.now()}`;
  const wsBase = (baseURL ?? '').replace(/^http/, 'ws');
  const transcript = await page.evaluate(
    async ({ url, cmd, ms }) => {
      return await new Promise<{ ok: boolean; text: string; err?: string }>((resolve) => {
        const ws = new WebSocket(url);
        ws.binaryType = 'arraybuffer';
        let text = '';
        const done = (ok: boolean, err?: string) => {
          try {
            ws.close();
          } catch {
            /* already closing */
          }
          resolve({ ok, text, err });
        };
        const timer = setTimeout(() => done(false, 'timed out waiting for the marker'), ms);
        ws.onerror = () => {
          clearTimeout(timer);
          done(false, 'websocket error');
        };
        ws.onopen = () => {
          // Binary frames are terminal input; give the shell a moment to
          // print its prompt before typing.
          setTimeout(() => ws.send(new TextEncoder().encode(cmd + '\n')), 1500);
        };
        ws.onmessage = (ev) => {
          if (typeof ev.data === 'string') return; // control frame
          text += new TextDecoder().decode(new Uint8Array(ev.data as ArrayBuffer));
          // The command echoes too, so wait for it twice: once as the
          // echo of what was typed, once as the shell's output.
          const hits = text.split(cmd.split(' ')[1]).length - 1;
          if (hits >= 2) {
            clearTimeout(timer);
            done(true);
          }
        };
      });
    },
    { url: `${wsBase}/api/v1/jobs/${jobID}/ssh`, cmd: `echo ${marker}`, ms: 60_000 },
  );

  expect(
    transcript.ok,
    `never saw the command output: ${transcript.err ?? ''} transcript=${JSON.stringify(transcript.text.slice(-400))}`,
  ).toBe(true);
  expect(transcript.text, 'the shell should have echoed the marker back').toContain(marker);

  // 4. Tear it down and confirm the job actually goes.
  const removed = await page.request.delete(`/api/v1/jobs/${jobID}`);
  expect(removed.status(), `cleanup failed: ${await removed.text()}`).toBeLessThan(400);
});
