import type { Page } from '@playwright/test';
import type {
  AdminReservation,
  AdminReservationHealth,
  AdminReservationWindow,
} from '../../src/lib/api';
import { SMOKE_NOW } from './clock';

// The admin reservations API, as a server with an application database
// answers it. Install after installApiFixtures so these routes win.
//
// The store is stateful on purpose: the page's whole flow is save, then
// read back the windows the save implies, and a frozen list would let a
// POST that sent the wrong body still look right.

// Scheduled starts, as absolute instants. SMOKE_NOW is Wed 14 Oct 2026,
// 12:00 in America/Chicago; both windows are after it, and both are
// inside the default 14-day horizon.
const THU_1400 = '2026-10-15T14:00:00-05:00';
const THU_1500 = '2026-10-15T15:00:00-05:00';
const MON_0900 = '2026-10-19T09:00:00-05:00';
const MON_1200 = '2026-10-19T12:00:00-05:00';

export const cs301Fixture: AdminReservation = {
  id: 'cs301',
  owner: 'jsmith',
  project: 'cs301-f26',
  submit: 'executable = /usr/bin/jupyter\nrequest_cpus = 4\nrequest_gpus = 1\nrequest_memory = 16384\nqueue\n',
  seats: 48,
  standing: 4,
  duration_seconds: 3600,
  lead_seconds: 6 * 3600,
  hold_seconds: 15 * 60,
  // Mondays and Wednesdays from the start of term to the end of it:
  // the shape the picker exists to draw.
  schedule_kind: 'recurrence',
  schedule: '',
  recurrence: {
    freq: 'weekly',
    interval: 1,
    by_weekday: [1, 3],
    time_of_day: '14:00',
  },
  timezone: 'America/Chicago',
  enabled: true,
  starts_at: '2026-09-02T14:00:00-05:00',
  ends_at: '2026-12-11T23:59:59-06:00',
  occurrences: 0,
};


export const alwaysFixture: AdminReservation = {
  id: 'openlab',
  owner: 'rsingh',
  project: 'openlab',
  submit: 'executable = /usr/bin/python3\nrequest_cpus = 2\nrequest_memory = 8192\nqueue\n',
  seats: 8,
  standing: 2,
  // No window, so none of the three durations describe anything.
  duration_seconds: 0,
  lead_seconds: 0,
  hold_seconds: 0,
  schedule_kind: 'always',
  schedule: '',
  recurrence: null,
  timezone: 'America/Chicago',
  enabled: true,
  starts_at: '',
  ends_at: '',
  occurrences: 0,
};

export const astroFixture: AdminReservation = {
  id: 'astro-lab',
  owner: 'kpatel',
  project: 'astro-lab',
  submit: 'executable = /usr/bin/python3\nrequest_cpus = 8\nrequest_memory = 32768\nqueue\n',
  seats: 16,
  standing: 0,
  duration_seconds: 2 * 3600 + 30 * 60,
  lead_seconds: 90 * 60,
  hold_seconds: 0,
  schedule_kind: 'cron',
  schedule: '30 9 * * 5',
  recurrence: null,
  timezone: 'America/Chicago',
  enabled: false,
  starts_at: '',
  ends_at: '',
  occurrences: 0,
};

// The two windows every reservation previews, with the drain derived
// from the reservation's own lead so a test can assert the lead it just
// typed came back.
function windowsFor(res: AdminReservation): AdminReservationWindow[] {
  // An always-on reservation has no windows at all: it never stops
  // holding, so there is nothing upcoming to list.
  if (res.schedule_kind === 'always') return [];
  const back = (iso: string) =>
    new Date(Date.parse(iso) - res.lead_seconds * 1000).toISOString();
  return [
    {
      start: new Date(THU_1400).toISOString(),
      end: new Date(THU_1500).toISOString(),
      plan_from: back(THU_1400),
      occurrences: 1,
    },
    {
      start: new Date(MON_0900).toISOString(),
      end: new Date(MON_1200).toISOString(),
      plan_from: back(MON_0900),
      occurrences: 2,
    },
  ];
}

export interface ReservationFixtures {
  // Every write the page sent, in order. Window previews are not
  // writes and are not in here: the form asks for one on every change,
  // and a test looking for the reservation it just saved would find a
  // preview instead.
  writes: { method: string; path: string; body: unknown }[];
  // Every draft the form asked for a preview of, in order.
  previews: AdminReservation[];
  // The server's view, for a test that wants to assert what was stored.
  stored: () => AdminReservation[];
}

// A pool where everything is as it should be. A test that wants a
// warning passes its own.
export const healthyFixture: AdminReservationHealth = {
  running: true,
  healthy: true,
  outcome: 'ok',
  machine: 'wn01.example.edu',
  checked_at: '2026-10-14T11:58:00-05:00',
  stanza: 'START = $(START) && ( ReservationStart ?: True )',
};

export async function installReservationFixtures(
  page: Page,
  initial: AdminReservation[] = [cs301Fixture, astroFixture, alwaysFixture],
  health: AdminReservationHealth = healthyFixture,
): Promise<ReservationFixtures> {
  const writes: { method: string; path: string; body: unknown }[] = [];
  const previews: AdminReservation[] = [];
  let store = initial.map((r) => ({ ...r }));

  await page.route('**/api/v1/admin/reservations**', async (route) => {
    const req = route.request();
    const url = new URL(req.url());
    const path = url.pathname;
    const rest = path.replace(/^\/api\/v1\/admin\/reservations\/?/, '');
    const [id, tail] = rest.split('/');

    // Before the collection branch: the glob matches this path too, and
    // answering it with a reservation list leaves the page unable to
    // warn about anything.
    if (req.method() === 'GET' && id === 'health') {
      await route.fulfill({ json: health });
      return;
    }
    // The draft preview, which takes a whole reservation in the body
    // and writes nothing.
    if (req.method() === 'POST' && id === 'windows') {
      const draft = (req.postDataJSON?.() ?? {}) as AdminReservation;
      previews.push(draft);
      await route.fulfill({
        json: { windows: windowsFor(draft), schedule_kind: draft.schedule_kind || 'cron' },
      });
      return;
    }
    if (req.method() === 'GET' && tail === 'windows') {
      const res = store.find((r) => r.id === id);
      if (!res) {
        await route.fulfill({ status: 404, json: { error: 'Not Found', message: 'No such reservation' } });
        return;
      }
      await route.fulfill({
        json: { windows: windowsFor(res), schedule_kind: res.schedule_kind || 'cron' },
      });
      return;
    }
    if (req.method() === 'GET') {
      await route.fulfill({ json: { reservations: store } });
      return;
    }
    if (req.method() === 'DELETE') {
      writes.push({ method: 'DELETE', path, body: null });
      store = store.filter((r) => r.id !== id);
      await route.fulfill({ status: 204, body: '' });
      return;
    }
    // POST: create or replace, with the server's eager validation. Only
    // the schedule is checked here -- enough to prove the page shows the
    // server's own wording rather than inventing its own.
    const body = (req.postDataJSON?.() ?? {}) as AdminReservation;
    writes.push({ method: 'POST', path, body });
    if (
      (body.schedule_kind === 'cron' || body.schedule_kind === '') &&
      body.schedule.split(/\s+/).filter(Boolean).length !== 5
    ) {
      await route.fulfill({
        status: 400,
        json: {
          error: 'Bad Request',
          message: `parsing schedule ${JSON.stringify(body.schedule)}: expected 5 fields, got ${
            body.schedule.split(/\s+/).filter(Boolean).length
          }`,
        },
      });
      return;
    }
    store = [...store.filter((r) => r.id !== body.id), body].sort((a, b) =>
      a.id.localeCompare(b.id),
    );
    await route.fulfill({ json: body });
  });

  return { writes, previews, stored: () => store };
}

// Exported so a test can state when "now" is without importing the clock
// module as well.
export { SMOKE_NOW };
