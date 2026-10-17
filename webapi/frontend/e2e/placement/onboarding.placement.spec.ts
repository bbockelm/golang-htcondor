import { execFile, spawn } from 'node:child_process';
import { readFileSync } from 'node:fs';
import path from 'node:path';

import { expect, test, type Page } from '@playwright/test';

import { adminPassword, loginAs } from '../fixtures/login';
import { serverLog } from '../fixtures/serverlog';

// Placement onboarding, end to end, against a real pool
// (scripts/placement-e2e/harness.sh): someone the placementd does not know
// signs in and is refused a token; an admin onboards them in the Directory;
// they then get a token in the browser and another through the standard
// device flow, and each token submits a job with the HTCondor CLI that runs
// as the account the admin created.

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
const ACCOUNT = `physnewbie@${env('E2E_UID_DOMAIN')}`;
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

function expectPlacementToken(t: TokenRecord) {
  // A capability token: no subject or scope in the JWT itself.
  expect(t.payload.cap).toBe(true);
  expect(t.payload.sub).toBeUndefined();
  expect(t.payload.scope).toBeUndefined();
  expect(t.payload.iss).toBe(env('E2E_UID_DOMAIN'));
  expect(t.record, 'the token is recorded in TOKENS_DATABASE').not.toBeNull();
  expect(t.record!.sub).toBe(ACCOUNT);
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

test('an unknown identity is onboarded, and both of its tokens run jobs as its account', async ({ browser }) => {
  const newbieContext = await browser.newContext();
  const newbie = await newbieContext.newPage();
  const adminContext = await browser.newContext();
  const admin = await adminContext.newPage();
  const browserToken = path.join(RUNDIR, 'out', 'browser.token');
  const deviceToken = path.join(RUNDIR, 'out', 'device.token');

  await test.step('an identity the placementd does not map is refused a token', async () => {
    await loginAs(newbie, 'newbie', NEWBIE_PASSWORD);
    await expect(newbie).toHaveURL(/\/placement\/?$/);
    await expect(newbie.getByRole('heading', { name: 'Placement token' })).toBeVisible();
    await expect(newbie.getByText('newbie is not authorized to use this access point.')).toBeVisible();
    // The reduced shell: none of the access point's own pages.
    await expect(newbie.getByRole('link', { name: 'Jobs' })).toHaveCount(0);

    const resp = await postToken(newbie, { project: PROJECT, authorizations: ['READ'] });
    expect(resp.status()).toBe(403);
    expect((await resp.json()).message).toBe(
      'Your identity is not authorized to receive a token on this access point.',
    );
  });

  await test.step('an admin onboards the identity from the Directory', async () => {
    await loginAs(admin, 'admin', adminPassword(serverLog()));
    await admin.goto('/admin/placement');
    await admin.getByRole('button', { name: 'Directory' }).click();
    await expect(admin.getByRole('tab', { name: 'Identities' })).toHaveAttribute('aria-selected', 'true');

    await admin.getByRole('button', { name: 'Onboard user' }).click();
    const dialog = admin.getByRole('dialog', { name: 'Onboard user' });
    await dialog.getByLabel('Identity', { exact: true }).fill('newbie');
    await dialog.getByLabel(/^Account/).fill(ACCOUNT);
    await expect(dialog.getByText('New account.')).toBeVisible();
    // Every requestable authorization starts checked.
    await expect(dialog.getByRole('checkbox', { name: 'Read' })).toBeChecked();
    await expect(dialog.getByRole('checkbox', { name: 'Write' })).toBeChecked();
    await dialog.getByRole('checkbox', { name: PROJECT, exact: true }).check();
    await expect(dialog.getByRole('checkbox', { name: OTHER_PROJECT, exact: true })).not.toBeChecked();
    await expect(dialog.getByLabel('Default project')).toHaveValue(PROJECT);
    await expect(dialog.getByRole('list', { name: 'Changes' }).getByRole('listitem')).toHaveText([
      `Create account ${ACCOUNT}`,
      'Create identity newbie',
    ]);
    await dialog.getByLabel('Change comment (optional)').fill('placement e2e');
    await dialog.getByRole('button', { name: 'Onboard' }).click();
    await expect(dialog).toHaveCount(0);
    await expect(admin.getByText('User onboarded.')).toBeVisible();

    const rows = admin.getByTestId(/^dir-row-/);
    const created = rows.filter({ hasText: ACCOUNT });
    await expect(created).toHaveCount(1);
    await expect(created.getByRole('cell').first()).toHaveText('newbie');
    await expect(created.getByText('internal', { exact: true })).toBeVisible();
    // The admin's own identity comes from the map file, and says so.
    const mapped = rows.filter({ hasText: 'apadmin@' });
    await expect(mapped.getByText('mapfile', { exact: true })).toBeVisible();
  });

  await test.step('the onboarded identity gets a token in the browser', async () => {
    await newbie.reload();
    // Still refused would mean the onboarding did not reach the placementd.
    await expect(newbie.getByText('newbie is not authorized to use this access point.')).toHaveCount(0);
    await expect(newbie.getByLabel('Project')).toHaveValue(PROJECT);
    await expect(newbie.locator('option')).toHaveText([PROJECT]);
    await expect(newbie.getByRole('checkbox', { name: 'Read: View jobs' })).toBeChecked();
    await expect(newbie.getByRole('checkbox', { name: 'Write: Submit and manage jobs' })).toBeChecked();
    await newbie.getByRole('button', { name: 'Request token' }).click();
    await expect(newbie.getByRole('heading', { name: 'Token granted' })).toBeVisible();

    const details = newbie.locator('dl');
    await expect(details.locator('dt')).toHaveText([
      'Name', 'AP identifier', 'AP host', 'Issued', 'Expires', 'Project', 'Permissions',
    ]);
    const dd = details.locator('dd');
    await expect(dd.nth(1)).toHaveText('physnewbie');
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

    expectPlacementToken(await tokenRecord(browserToken));
  });

  await test.step('a placement client gets a token through the device flow', async () => {
    const client = startDeviceClient(deviceToken);
    try {
      const url = await client.verificationURL;
      await newbie.goto(url);
      await expect(newbie.getByRole('heading', { name: 'Placement token request' })).toBeVisible();
      await expect(newbie.locator('p').first()).toHaveText(
        'Placement Client is asking for a placement token for newbie.',
      );
      await newbie.getByRole('button', { name: 'Approve' }).click();
      await expect(newbie.getByRole('heading', { name: '✓ Request approved' })).toBeVisible();

      const lines = await client.finished();
      expect(lines.get('GRANTED_SCOPE')).toBe('placement');
      expect(lines.get('REFUSED_PROJECT')).toMatch(/^403 /);
      expect(JSON.parse(lines.get('REFUSED_PROJECT')!.slice(4)).message).toBe('User not authorized for project');
      expect(lines.get('ACCOUNT')).toBe(ACCOUNT);
    } finally {
      client.kill();
    }
    expectPlacementToken(await tokenRecord(deviceToken));
  });

  await test.step('each token submits a job that runs as the account', async () => {
    const runJob = (token: string, name: string) =>
      run(path.join(SCRIPTS, 'run-job.sh'), [token, path.join(RUNDIR, 'out', name), ACCOUNT, PROJECT]);
    const [fromBrowser, fromDevice] = await Promise.all([
      runJob(browserToken, 'browser-job'),
      runJob(deviceToken, 'device-job'),
    ]);
    console.log(fromBrowser + fromDevice);
    expect(fromBrowser).toContain('run-job: OK');
    expect(fromDevice).toContain('run-job: OK');
  });
});
