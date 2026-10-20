import { execFile, spawn } from 'node:child_process';
import { readFileSync } from 'node:fs';
import path from 'node:path';

import { expect, test, type Page } from '@playwright/test';

import { adminPassword, loginAs } from '../fixtures/login';
import { serverLog } from '../fixtures/serverlog';

// Placement onboarding, end to end, against a real pool
// (scripts/placement-e2e/harness.sh). Two people the placementd does not
// know sign in and are refused a token. newbie asks for access; an admin
// approves the request from the Requests tab, and newbie's session becomes
// the account without signing in again, then gets a token in the browser.
// postdoc is onboarded by the admin in the Directory, and gets a token
// through the standard device flow. Each token submits a job with the
// HTCondor CLI that runs as the account the admin gave that person.

const SCRIPTS = path.resolve(__dirname, '..', '..', '..', '..', 'scripts', 'placement-e2e');

function env(name: string): string {
  const v = process.env[name];
  if (!v) throw new Error(`${name} is not set; source the env file scripts/placement-e2e/harness.sh up writes`);
  return v;
}

const RUNDIR = env('E2E_RUNDIR');
const BASE_URL = env('PLACEMENT_E2E_BASE_URL');
const CA_CERT = env('E2E_CA_CERT');
const NEWBIE_PASSWORD = env('E2E_NEWBIE_PASSWORD');
const POSTDOC_PASSWORD = env('E2E_POSTDOC_PASSWORD');
// newbie's account is the one approval suggests: what a map file "*" line
// would give the identity.
const NEWBIE_ACCOUNT = `newbie@${env('E2E_UID_DOMAIN')}`;
const POSTDOC_ACCOUNT = `physpostdoc@${env('E2E_UID_DOMAIN')}`;
const PROJECT = 'Physics';
// The admin's other project, which the onboarded account is not given.
const OTHER_PROJECT = 'Staff';

interface TokenRecord {
  header: Record<string, unknown>;
  payload: Record<string, unknown>;
  record: { sub: string; scope: string; capability: boolean } | null;
  extra_claims: Record<string, unknown>;
}

function run(cmd: string, args: string[]): Promise<string> {
  return new Promise((resolve, reject) => {
    execFile(cmd, args, { maxBuffer: 1 << 22 }, (err, stdout, stderr) => {
      if (err) {
        reject(new Error(`${path.basename(cmd)} ${args.join(' ')} failed: ${err.message}\n${stdout}\n${stderr}`));
      } else {
        resolve(stdout + stderr);
      }
    });
  });
}

async function tokensDatabase(): Promise<string> {
  return (await run('condor_config_val', ['TOKENS_DATABASE'])).trim();
}

// What the token is: the JWT's own claims, and the subject, scope and
// project the placementd recorded for it.
async function tokenRecord(file: string): Promise<TokenRecord> {
  const out = await run('python3', ['-I', path.join(SCRIPTS, 'token_record.py'), file, await tokensDatabase()]);
  return JSON.parse(out) as TokenRecord;
}

function expectPlacementToken(t: TokenRecord, account: string) {
  // A capability token: no subject or scope in the JWT itself.
  expect(t.payload.cap).toBe(true);
  expect(t.payload.sub).toBeUndefined();
  expect(t.payload.scope).toBeUndefined();
  expect(t.payload.iss).toBe(env('E2E_UID_DOMAIN'));
  expect(t.record, 'the token is recorded in TOKENS_DATABASE').not.toBeNull();
  expect(t.record!.sub).toBe(account);
  expect(t.record!.capability).toBe(true);
  expect(t.record!.scope.split(' ').sort()).toEqual(['condor:/READ', 'condor:/WRITE']);
  expect(t.extra_claims.project).toBe(PROJECT);
}

// startDeviceClient runs the toy placement client and resolves with the
// verification URL once it has printed one; the client keeps polling.
function startDeviceClient(out: string) {
  const child = spawn(
    'python3',
    [
      '-I',
      path.join(SCRIPTS, 'placement_client.py'),
      '--base-url', BASE_URL,
      '--cafile', CA_CERT,
      '--project', PROJECT,
      '--authorizations', 'READ,WRITE',
      '--refused-project', OTHER_PROJECT,
      '--out', out,
    ],
    { stdio: ['ignore', 'pipe', 'pipe'] },
  );
  let stdout = '';
  let stderr = '';
  const lines = new Map<string, string>();
  let onLine: () => void = () => {};
  child.stdout.setEncoding('utf8');
  child.stdout.on('data', (chunk: string) => {
    stdout += chunk;
    for (const line of stdout.split('\n')) {
      const sp = line.indexOf(' ');
      if (sp > 0) lines.set(line.slice(0, sp), line.slice(sp + 1));
    }
    onLine();
  });
  child.stderr.setEncoding('utf8');
  child.stderr.on('data', (chunk: string) => (stderr += chunk));
  const exited = new Promise<number>((resolve) => child.on('exit', (code) => resolve(code ?? -1)));

  const verificationURL = new Promise<string>((resolve, reject) => {
    onLine = () => {
      const url = lines.get('VERIFICATION_URI_COMPLETE');
      if (url) resolve(url);
    };
    // A client that gives up before printing a URL is a failure now, not
    // after a timeout.
    void exited.then((code) =>
      reject(new Error(`placement client exited ${code} before printing a verification URL:\n${stdout}\n${stderr}`)),
    );
  });

  const finished = async () => {
    const code = await exited;
    if (code !== 0) throw new Error(`placement client exited ${code}:\n${stdout}\n${stderr}`);
    return lines;
  };
  return { verificationURL, finished, kill: () => child.kill() };
}

async function postToken(page: Page, body: object) {
  return page.request.post('/api/v1/placement/me/token', {
    headers: { 'X-Requested-With': 'XMLHttpRequest' },
    data: body,
  });
}

async function postRequest(page: Page, body: object) {
  return page.request.post('/api/v1/placement/me/request', {
    headers: { 'X-Requested-With': 'XMLHttpRequest' },
    data: body,
  });
}

async function expectRefusedToken(page: Page) {
  const resp = await postToken(page, { project: PROJECT, authorizations: ['READ'] });
  expect(resp.status()).toBe(403);
  expect((await resp.json()).message).toBe('Your identity is not authorized to receive a token on this access point.');
}

test('unknown identities get access by request and by onboarding, and their tokens run jobs', async ({ browser, playwright }) => {
  const newbieContext = await browser.newContext();
  const newbie = await newbieContext.newPage();
  const postdocContext = await browser.newContext();
  const postdoc = await postdocContext.newPage();
  const adminContext = await browser.newContext();
  const admin = await adminContext.newPage();
  const browserToken = path.join(RUNDIR, 'out', 'browser.token');
  const deviceToken = path.join(RUNDIR, 'out', 'device.token');

  await test.step('identities the placementd does not map are refused a token', async () => {
    await loginAs(newbie, 'newbie', NEWBIE_PASSWORD);
    await expect(newbie).toHaveURL(/\/placement\/?$/);
    await expect(newbie.getByRole('heading', { name: 'Placement token' })).toBeVisible();
    await expect(newbie.getByText('newbie is not authorized to use this access point.')).toBeVisible();
    // The reduced shell: none of the access point's own pages.
    await expect(newbie.getByRole('link', { name: 'Jobs' })).toHaveCount(0);
    await expectRefusedToken(newbie);

    await loginAs(postdoc, 'postdoc', POSTDOC_PASSWORD);
    await expect(postdoc.getByText('postdoc is not authorized to use this access point.')).toBeVisible();
    await expectRefusedToken(postdoc);
  });

  await test.step('newbie asks for access', async () => {
    const form = newbie.getByRole('region', { name: 'Request access' });
    await expect(form.getByText('newbie', { exact: true }).first()).toBeVisible();
    const projects = form.getByRole('textbox', { name: 'Projects', exact: true });
    // Typed in lower case: approval matches it to the directory's Physics.
    await projects.fill('physics');
    await projects.press('Enter');
    await projects.fill('Chemistry');
    await projects.press('Enter');
    await expect(form.getByRole('list', { name: 'Requested projects' }).getByRole('listitem')).toHaveCount(2);
    await form.getByLabel('Note (optional)').fill('New graduate student in physics.');
    await form.getByRole('button', { name: 'Request access' }).click();

    const pending = newbie.getByRole('region', { name: 'Access requested' });
    await expect(pending.getByText('Your request is waiting for an administrator.')).toBeVisible();
    await expect(pending.getByText('physics, Chemistry')).toBeVisible();

    // One pending request; the request names no identity; requests are
    // not this person's to list.
    let resp = await postRequest(newbie, { projects: ['Other'] });
    expect(resp.status()).toBe(409);
    expect((await resp.json()).message).toBe('You already have a pending request.');
    resp = await postRequest(postdoc, { identity: 'newbie', projects: ['Physics'] });
    expect(resp.status()).toBe(400);
    resp = await newbie.request.get('/api/v1/placement/admin/requests');
    expect(resp.status()).toBe(403);
  });

  await test.step('an admin approves the request from the Requests tab', async () => {
    await loginAs(admin, 'admin', adminPassword(serverLog()));
    await admin.goto('/admin/placement');
    await expect(admin.getByRole('link', { name: /Placement/ }).getByLabel('1 pending access requests')).toBeVisible();
    const tab = admin.getByRole('button', { name: /^Requests/ });
    await expect(tab.getByLabel('1 pending')).toBeVisible();
    await tab.click();

    const row = admin.getByTestId(/^request-row-/).filter({ hasText: 'New graduate student in physics.' });
    await expect(row).toHaveCount(1);
    await expect(row.getByText('newbie', { exact: true }).first()).toBeVisible();
    await row.getByRole('button', { name: 'Approve' }).click();

    // The Onboard user form, pre-filled from the request.
    const dialog = admin.getByRole('dialog', { name: 'Approve access request' });
    const identity = dialog.getByLabel('Identity', { exact: true });
    await expect(identity).toHaveValue('newbie');
    await expect(identity).toHaveAttribute('readonly', '');
    await expect(dialog.getByLabel(/^Account/)).toHaveValue(NEWBIE_ACCOUNT);
    await expect(dialog.getByText('New account.')).toBeVisible();
    await expect(dialog.getByRole('checkbox', { name: 'Read' })).toBeChecked();
    await expect(dialog.getByRole('checkbox', { name: 'Write' })).toBeChecked();
    await expect(dialog.getByRole('checkbox', { name: PROJECT, exact: true })).toBeChecked();
    await expect(dialog.getByRole('checkbox', { name: OTHER_PROJECT, exact: true })).not.toBeChecked();
    await expect(dialog.getByText('Chemistry')).toBeVisible();
    await expect(dialog.getByLabel('Default project')).toHaveValue(PROJECT);
    await expect(dialog.getByRole('list', { name: 'Changes' }).getByRole('listitem')).toHaveText([
      `Create account ${NEWBIE_ACCOUNT}`,
      'Create identity newbie',
    ]);
    await dialog.getByLabel('Change comment (optional)').fill('placement e2e');
    await dialog.getByRole('button', { name: 'Approve' }).click();
    await expect(dialog).toHaveCount(0);
    await expect(admin.getByText('Request approved.')).toBeVisible();
    await expect(tab.getByLabel('1 pending')).toHaveCount(0);

    await admin.getByRole('tab', { name: 'Approved' }).click();
    const approved = admin.getByTestId(/^request-row-/).filter({ hasText: 'newbie' });
    await expect(approved.getByText('approved', { exact: true })).toBeVisible();
    await expect(approved.getByText(NEWBIE_ACCOUNT)).toBeVisible();
  });

  await test.step('an admin onboards the other identity from the Directory', async () => {
    await admin.getByRole('button', { name: 'Directory' }).click();
    await expect(admin.getByRole('tab', { name: 'Identities' })).toHaveAttribute('aria-selected', 'true');

    await admin.getByRole('button', { name: 'Onboard user' }).click();
    const dialog = admin.getByRole('dialog', { name: 'Onboard user' });
    await dialog.getByLabel('Identity', { exact: true }).fill('postdoc');
    await dialog.getByLabel(/^Account/).fill(POSTDOC_ACCOUNT);
    await expect(dialog.getByText('New account.')).toBeVisible();
    // Every requestable authorization starts checked.
    await expect(dialog.getByRole('checkbox', { name: 'Read' })).toBeChecked();
    await expect(dialog.getByRole('checkbox', { name: 'Write' })).toBeChecked();
    await dialog.getByRole('checkbox', { name: PROJECT, exact: true }).check();
    await expect(dialog.getByRole('checkbox', { name: OTHER_PROJECT, exact: true })).not.toBeChecked();
    await expect(dialog.getByLabel('Default project')).toHaveValue(PROJECT);
    await expect(dialog.getByRole('list', { name: 'Changes' }).getByRole('listitem')).toHaveText([
      `Create account ${POSTDOC_ACCOUNT}`,
      'Create identity postdoc',
    ]);
    await dialog.getByLabel('Change comment (optional)').fill('placement e2e');
    await dialog.getByRole('button', { name: 'Onboard' }).click();
    await expect(dialog).toHaveCount(0);
    await expect(admin.getByText('User onboarded.')).toBeVisible();

    const rows = admin.getByTestId(/^dir-row-/);
    for (const [who, account] of [['postdoc', POSTDOC_ACCOUNT], ['newbie', NEWBIE_ACCOUNT]]) {
      const created = rows.filter({ hasText: account });
      await expect(created).toHaveCount(1);
      // The identity, then any display name.
      await expect(created.getByRole('cell').first()).toHaveText(new RegExp(`^${who}`));
      await expect(created.getByText('internal', { exact: true })).toBeVisible();
    }
    // The admin's own identity comes from the map file, and says so.
    const mapped = rows.filter({ hasText: 'apadmin@' });
    await expect(mapped.getByText('mapfile', { exact: true })).toBeVisible();

    // The approval is in the directory's history, as the admin's, naming
    // the request.
    await rows.filter({ hasText: NEWBIE_ACCOUNT }).getByRole('button', { name: 'History' }).click();
    const history = admin.getByRole('dialog', { name: 'History of newbie' });
    await expect(history.getByText(/^access request #\d+: placement e2e$/)).toBeVisible();
    await expect(history.getByText(/apadmin@/).first()).toBeVisible();
    await history.getByRole('button', { name: 'Close' }).click();
  });

  await test.step("newbie's session becomes the account, without signing in again", async () => {
    const sessionCookie = async () =>
      (await newbieContext.cookies()).find((c) => c.name === 'htcondor_session')?.value ?? '';
    const before = await sessionCookie();
    expect(before.startsWith('p.'), 'newbie starts with a placement-only session').toBe(true);

    // The page looks at a pending request now and then, and the server
    // re-checks a session at most every 30 seconds; keep asking until it
    // is due.
    const check = newbie.getByRole('button', { name: 'Check again' });
    const jobs = newbie.getByRole('link', { name: 'Jobs' });
    await expect(async () => {
      if (await check.isVisible()) await check.click();
      await expect(jobs).toBeVisible({ timeout: 2_000 });
    }).toPass({ intervals: [3_000], timeout: 90_000 });

    // The full shell, as the account, under a new session id.
    await expect(newbie.getByText(NEWBIE_ACCOUNT, { exact: true }).first()).toBeVisible();
    await expect(check).toHaveCount(0);
    const after = await sessionCookie();
    expect(after).not.toBe('');
    expect(after).not.toBe(before);
    expect(after.startsWith('p.')).toBe(false);

    // The placement-only session is gone. Asked from a client holding only
    // that cookie, so the browser's new one cannot answer instead.
    const oldClient = await playwright.request.newContext({
      baseURL: BASE_URL,
      ignoreHTTPSErrors: true,
      extraHTTPHeaders: { Cookie: `htcondor_session=${before}` },
    });
    try {
      const stale = await oldClient.get('/api/v1/auth/me');
      expect(stale.status()).toBe(200);
      expect((await stale.json()).authenticated).toBe(false);
    } finally {
      await oldClient.dispose();
    }

    // Their request reads approved, and they cannot file another.
    const mine = await newbie.request.get('/api/v1/placement/me/request');
    expect((await mine.json()).request).toMatchObject({ status: 'approved', account: NEWBIE_ACCOUNT });
    expect((await postRequest(newbie, {})).status()).toBe(409);
  });

  await test.step('newbie gets a token in the browser', async () => {
    const main = newbie.getByRole('main');
    // Still refused would mean the approval did not reach the placementd.
    await expect(newbie.getByText('newbie is not authorized to use this access point.')).toHaveCount(0);
    await expect(main.getByLabel('Project')).toHaveValue(PROJECT);
    await expect(main.locator('option')).toHaveText([PROJECT]);
    await expect(newbie.getByRole('checkbox', { name: 'Read: View jobs' })).toBeChecked();
    await expect(newbie.getByRole('checkbox', { name: 'Write: Submit and manage jobs' })).toBeChecked();
    await newbie.getByRole('button', { name: 'Request token' }).click();
    await expect(newbie.getByRole('heading', { name: 'Token granted' })).toBeVisible();

    const details = main.locator('dl');
    await expect(details.locator('dt')).toHaveText([
      'Name', 'AP identifier', 'AP host', 'Issued', 'Expires', 'Project', 'Permissions',
    ]);
    const dd = details.locator('dd');
    await expect(dd.nth(1)).toHaveText('newbie');
    await expect(dd.nth(2)).toHaveText(env('E2E_UID_DOMAIN'));
    await expect(dd.nth(5)).toHaveText(PROJECT);
    await expect(dd.nth(6)).toHaveText('READ, WRITE');

    const shown = await newbie.getByLabel('Token').inputValue();
    const download = newbie.waitForEvent('download');
    await newbie.getByRole('button', { name: 'Download token' }).click();
    const file = await download;
    expect(file.suggestedFilename()).toBe('Placement.token');
    await file.saveAs(browserToken);
    expect(readFileSync(browserToken, 'utf8')).toBe(shown + '\n');

    expectPlacementToken(await tokenRecord(browserToken), NEWBIE_ACCOUNT);
  });

  await test.step('a placement client gets postdoc a token through the device flow', async () => {
    const client = startDeviceClient(deviceToken);
    try {
      const url = await client.verificationURL;
      await postdoc.goto(url);
      await expect(postdoc.getByRole('heading', { name: 'Placement token request' })).toBeVisible();
      await expect(postdoc.locator('p').first()).toHaveText(
        'Placement Client is asking for a placement token for postdoc.',
      );
      await postdoc.getByRole('button', { name: 'Approve' }).click();
      await expect(postdoc.getByRole('heading', { name: '✓ Request approved' })).toBeVisible();

      const lines = await client.finished();
      expect(lines.get('GRANTED_SCOPE')).toBe('placement');
      expect(lines.get('REFUSED_PROJECT')).toMatch(/^403 /);
      expect(JSON.parse(lines.get('REFUSED_PROJECT')!.slice(4)).message).toBe('User not authorized for project');
      expect(lines.get('ACCOUNT')).toBe(POSTDOC_ACCOUNT);
    } finally {
      client.kill();
    }
    expectPlacementToken(await tokenRecord(deviceToken), POSTDOC_ACCOUNT);
  });

  await test.step('each token submits a job that runs as its account', async () => {
    const runJob = (token: string, name: string, account: string) =>
      run(path.join(SCRIPTS, 'run-job.sh'), [token, path.join(RUNDIR, 'out', name), account, PROJECT]);
    const [fromBrowser, fromDevice] = await Promise.all([
      runJob(browserToken, 'browser-job', NEWBIE_ACCOUNT),
      runJob(deviceToken, 'device-job', POSTDOC_ACCOUNT),
    ]);
    console.log(fromBrowser + fromDevice);
    expect(fromBrowser).toContain('run-job: OK');
    expect(fromDevice).toContain('run-job: OK');
  });
});
