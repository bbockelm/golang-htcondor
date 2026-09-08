import { expect, test } from '@playwright/test';

import { adminPassword, loginAsAdmin } from './fixtures/login';
import { serverLog } from './fixtures/serverlog';

const password = adminPassword(serverLog());

// An interactive terminal through the UI.
//
// interactive.full.spec.ts covers the API and the socket: it POSTs the
// create endpoint and opens its own WebSocket from page.evaluate. That
// is the layer that was already healthy when a real session hung on
// "Transferring input" -- the job was running, the stream was live, the
// bridge would have attached. What was broken was the page, and no test
// looked at one.
//
// The coupling this exists to protect is one line of
// TerminalDetailClient:
//
//   {status === 'executing' && <JobTerminal jobID={id} />}
//
// The terminal mounts only when interpretJobStatus reaches 'executing',
// which needs JobCurrentStartExecutingDate. When the watch projection
// omitted that attribute the page sat on 'transferring_input' forever
// and no terminal ever appeared -- the exact reported symptom. Asserting
// that a terminal shows up, and that a command typed into it answers,
// is what catches that.

test('a terminal session becomes usable through the UI', async ({ page }) => {
  test.setTimeout(300_000);

  const errors: string[] = [];
  page.on('pageerror', (e) => errors.push(String(e)));

  await loginAsAdmin(page, password);

  // Launch from the page, not from the API: the button, the navigation
  // and the id it lands on are all part of what can break.
  await page.goto('/interactive');
  await page.getByRole('button', { name: /launch terminal/i }).click();

  // Lands on the session's own page.
  await page.waitForURL(/\/interactive\/terminal\/\d+\.\d+/, { timeout: 60_000 });
  const jobID = page.url().split('/').pop()!;
  expect(jobID, 'the URL should carry a real job id').toMatch(/^\d+\.\d+$/);

  // The pill walks through the startup states and must reach Ready --
  // visualStatus remaps 'executing' to 'ready' for a terminal. Sitting
  // on "Transferring input" is the bug this guards.
  await expect(
    page.getByText(/^Ready$/),
    'the session never reached Ready, so the terminal never mounted',
  ).toBeVisible({ timeout: 240_000 });

  // xterm.js mounts with the DOM renderer, so the screen is readable
  // text rather than a canvas.
  const rows = page.locator('.xterm-rows');
  await expect(rows, 'no xterm terminal on the page').toBeVisible({ timeout: 60_000 });

  // The shell greets before it prompts; wait for the prompt rather than
  // typing into a terminal that is not listening yet.
  await expect(rows, 'the shell never printed a prompt').toContainText(/\$|#/, {
    timeout: 60_000,
  });

  // Type into the terminal itself and read the answer off the screen.
  const marker = `UI_TERM_${Date.now()}`;
  await page.locator('.xterm').click(); // focus the textarea xterm listens on
  await page.keyboard.type(`echo ${marker}`);
  await page.keyboard.press('Enter');

  await expect(
    rows,
    'the command produced no output in the rendered terminal',
  ).toContainText(marker, { timeout: 60_000 });

  expect(errors, 'the terminal page raised page errors').toEqual([]);

  // Leave nothing running: the demo pool has very few slots.
  const removed = await page.request.delete(`/api/v1/jobs/${jobID}`);
  expect(removed.status(), `cleanup failed: ${await removed.text()}`).toBeLessThan(400);
});
