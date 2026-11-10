// A reservation's submit file, as fields where that is safe and as text
// where it is not.
//
// The wire carries the file as one string and the server is the
// authority on what a submit file may be. Nothing here validates one;
// this parses a file so the form can offer the same resource-request
// fields the submit page offers, over the same component.
//
// One rule runs through the file, and it is the rule the schedule's cron
// box already follows (src/lib/recurrence.ts): the fields are only ever
// shown over a file they can reproduce exactly. `parseReservationSubmit`
// splits a file into resource requests, the lines it did not recognise
// and the queue statement, regenerates the file from those three, and
// refuses the whole thing unless the result is the original string byte
// for byte. So `request_memory=4096` written without the spaces, or
// `request_cpus` stated twice, or a request inside an `if` block, all
// stay text -- not because the fields could not hold those numbers, but
// because opening a reservation and pressing Save is not an invitation
// to reformat its submit file.
//
// Where a file does fit the fields, its own layout survives: the
// recognised commands are written back in the order that file stated
// them, and a command the file does not state is not added until
// somebody changes its value.

import { DEFAULT_RESOURCE_REQUEST, type ResourceRequest } from '@/components/ResourceRequest';

/** The resource-request fields that map onto a submit command. The rest
 *  of a file is kept verbatim. */
export type ResourceKey = keyof ResourceRequest;

interface Command {
  key: ResourceKey;
  command: string;
  // `count` values are written as bare integers, so a file that states
  // them any other way (`16G`, `0x10`, an expression) cannot come back
  // from the fields unchanged and keeps the file as text.
  kind: 'count' | 'text';
}

const COMMANDS: Command[] = [
  { key: 'cpus', command: 'request_cpus', kind: 'count' },
  { key: 'memoryMB', command: 'request_memory', kind: 'count' },
  { key: 'diskMB', command: 'request_disk', kind: 'count' },
  { key: 'gpus', command: 'request_gpus', kind: 'count' },
  { key: 'gpuMinCapability', command: 'gpus_minimum_capability', kind: 'text' },
  { key: 'gpuMinMemoryMB', command: 'gpus_minimum_memory', kind: 'count' },
  { key: 'gpuMinRuntime', command: 'gpus_minimum_runtime', kind: 'text' },
  { key: 'cudaVersion', command: 'cuda_version', kind: 'text' },
  { key: 'requireGpus', command: 'require_gpus', kind: 'text' },
];

const BY_KEY = new Map(COMMANDS.map((c) => [c.key, c]));

// HTCondor's submit commands are case-insensitive, and so is this, but
// the command is written back in its canonical spelling -- which is why
// a file that spells it `Request_Cpus` stays text.
function commandRE(command: string): RegExp {
  return new RegExp(`^${command}\\s*=\\s*(.*?)\\s*$`, 'i');
}

const QUEUE_RE = /^\s*queue(\s|$)/i;

export interface ReservationSubmit {
  /** The structured request, with the shared defaults standing in for
   *  commands the file does not state. */
  request: ResourceRequest;
  /** Which commands the file states, in the order it states them. A key
   *  outside this list is a field showing a default, not a line in the
   *  file. */
  stated: ResourceKey[];
  /** Every other line, verbatim and in order -- the executable, any
   *  `+Attr`, anything this module has no opinion about. */
  extraLines: string;
  /** The queue statement, verbatim, or null when the file has none. */
  queueLine: string | null;
  trailingNewline: boolean;
}

/** parseReservationSubmit reads a stored submit file into the form's
 *  fields, or returns null when the fields cannot reproduce it exactly
 *  and the file has to stay text.
 *
 *  The regeneration check at the end is the whole point; see the note at
 *  the top of this file. */
export function parseReservationSubmit(text: string): ReservationSubmit | null {
  if (text.trim() === '') return null;

  const trailingNewline = text.endsWith('\n');
  const body = trailingNewline ? text.slice(0, -1) : text;

  const request = { ...DEFAULT_RESOURCE_REQUEST };
  const stated: ResourceKey[] = [];
  const extra: string[] = [];
  let queueLine: string | null = null;

  for (const line of body.split('\n')) {
    if (queueLine === null && QUEUE_RE.test(line)) {
      queueLine = line;
      continue;
    }
    const recognised = COMMANDS.find(
      (c) => !stated.includes(c.key) && commandRE(c.command).test(line.trim()),
    );
    if (!recognised) {
      extra.push(line);
      continue;
    }
    const raw = commandRE(recognised.command).exec(line.trim())![1];
    if (recognised.kind === 'count' && !/^\d+$/.test(raw)) return null;
    // Every field of a ResourceRequest is a number or a string, and
    // which one each command wants is the table's business, not the
    // caller's.
    (request as Record<ResourceKey, number | string>)[recognised.key] =
      recognised.kind === 'count' ? Number(raw) : raw;
    stated.push(recognised.key);
  }

  const parsed: ReservationSubmit = {
    request,
    stated,
    extraLines: extra.join('\n'),
    queueLine,
    trailingNewline,
  };
  return renderReservationSubmit(parsed) === text ? parsed : null;
}

/** renderReservationSubmit writes the fields back out as a submit file:
 *  the lines it did not recognise, then the commands it did, then the
 *  queue statement. */
export function renderReservationSubmit(s: ReservationSubmit): string {
  const lines: string[] = [];
  if (s.extraLines !== '') lines.push(...s.extraLines.split('\n'));
  for (const key of s.stated) {
    const c = BY_KEY.get(key);
    if (c) lines.push(`${c.command} = ${s.request[key]}`);
  }
  if (s.queueLine !== null) lines.push(s.queueLine);
  return lines.join('\n') + (s.trailingNewline ? '\n' : '');
}

/** withResourceRequest takes a changed request from the resource panel
 *  and works out which commands the file should now state.
 *
 *  A command is added when its value changes, not when the panel shows
 *  it: every panel field has a value, and writing all of them back would
 *  add lines to a file over an edit to one unrelated number. Clearing a
 *  free-text command removes its line, since `cuda_version = ` states
 *  nothing. */
export function withResourceRequest(
  s: ReservationSubmit,
  next: ResourceRequest,
): ReservationSubmit {
  let stated = [...s.stated];
  for (const { key, kind } of COMMANDS) {
    if (kind === 'text' && next[key] === '') {
      stated = stated.filter((k) => k !== key);
      continue;
    }
    if (!stated.includes(key) && next[key] !== s.request[key]) stated.push(key);
  }
  return { ...s, request: next, stated };
}
