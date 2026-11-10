import { describe, expect, it } from 'vitest';

import {
  parseReservationSubmit,
  renderReservationSubmit,
  withResourceRequest,
} from '@/lib/reservationSubmit';

// The files the form actually opens on: the one a new reservation starts
// from, and the two the e2e fixtures store.
const DEFAULT_FILE =
  'executable = /usr/bin/python3\nrequest_cpus = 1\nrequest_memory = 4096\nqueue\n';
const JUPYTER_FILE =
  'executable = /usr/bin/jupyter\nrequest_cpus = 4\nrequest_gpus = 1\nrequest_memory = 16384\nqueue\n';

describe('parseReservationSubmit', () => {
  it('reads the commands a file states and keeps the rest verbatim', () => {
    const s = parseReservationSubmit(DEFAULT_FILE)!;
    expect(s).not.toBeNull();
    expect(s.request.cpus).toBe(1);
    expect(s.request.memoryMB).toBe(4096);
    expect(s.stated).toEqual(['cpus', 'memoryMB']);
    expect(s.extraLines).toBe('executable = /usr/bin/python3');
    expect(s.queueLine).toBe('queue');
  });

  it('keeps the order the file states its commands in', () => {
    // request_gpus before request_memory, which is not the order the
    // fields are laid out in. Writing them back in field order would
    // reorder somebody's file.
    const s = parseReservationSubmit(JUPYTER_FILE)!;
    expect(s.stated).toEqual(['cpus', 'gpus', 'memoryMB']);
    expect(renderReservationSubmit(s)).toBe(JUPYTER_FILE);
  });

  it('reads the GPU subfields', () => {
    const file =
      'executable = /usr/bin/train\nrequest_gpus = 2\ngpus_minimum_memory = 16384\ncuda_version = 12.1\nrequire_gpus = Capability >= 7.0\nqueue\n';
    const s = parseReservationSubmit(file)!;
    expect(s.request.gpus).toBe(2);
    expect(s.request.gpuMinMemoryMB).toBe(16384);
    expect(s.request.cudaVersion).toBe('12.1');
    expect(s.request.requireGpus).toBe('Capability >= 7.0');
    expect(renderReservationSubmit(s)).toBe(file);
  });

  it('keeps a file with no recognised command at all', () => {
    const file = 'executable = /bin/sleep\narguments = 3600\nqueue\n';
    const s = parseReservationSubmit(file)!;
    expect(s.stated).toEqual([]);
    expect(renderReservationSubmit(s)).toBe(file);
  });

  it('round-trips a file with no queue statement, and one with no trailing newline', () => {
    for (const file of [
      'executable = /bin/sleep\nrequest_cpus = 2\n',
      'executable = /bin/sleep\nrequest_cpus = 2\nqueue',
    ]) {
      const s = parseReservationSubmit(file)!;
      expect(s, file).not.toBeNull();
      expect(renderReservationSubmit(s)).toBe(file);
    }
  });

  // The refusals. Every one of these is a file the fields could hold the
  // values of, and would hand back in a different shape.
  it.each([
    ['no spaces around the equals', 'executable = /bin/sleep\nrequest_memory=4096\nqueue\n'],
    ['a unit suffix', 'executable = /bin/sleep\nrequest_memory = 16G\nqueue\n'],
    // This one would survive the regeneration check -- 1.5 is written
    // back as 1.5 -- so the count fields refuse it on their own.
    ['a fractional count', 'executable = /bin/sleep\nrequest_cpus = 1.5\nqueue\n'],
    ['an expression for a count', 'executable = /bin/sleep\nrequest_cpus = $(Cpus)\nqueue\n'],
    [
      'the same command twice',
      'executable = /bin/sleep\nrequest_cpus = 1\nrequest_cpus = 2\nqueue\n',
    ],
    [
      'a request inside a conditional',
      'executable = /bin/sleep\nif defined GPU\n  request_gpus = 1\nendif\nqueue\n',
    ],
    [
      'a request stated after the queue statement',
      'executable = /bin/sleep\nqueue\nrequest_cpus = 2\n',
    ],
    [
      'a command between two requests it does not recognise',
      'request_cpus = 1\narguments = 3600\nrequest_memory = 4096\nqueue\n',
    ],
    ['a non-canonical spelling', 'executable = /bin/sleep\nRequest_Cpus = 2\nqueue\n'],
    ['nothing at all', ''],
    ['only whitespace', '\n\n'],
  ])('refuses %s', (_why, file) => {
    expect(parseReservationSubmit(file)).toBeNull();
  });

  it('refuses a file it would reformat even when every value parses', () => {
    // The invariant itself, stated once over a file that fails for no
    // reason a value check would catch: the blank line moves.
    const file = 'request_cpus = 1\n\nqueue\n';
    const s = parseReservationSubmit(file);
    expect(s).toBeNull();
  });
});

describe('withResourceRequest', () => {
  it('writes nothing back when nothing changed', () => {
    // Opening a reservation and pressing Save must hand the server the
    // bytes it stored.
    for (const file of [DEFAULT_FILE, JUPYTER_FILE]) {
      const s = parseReservationSubmit(file)!;
      expect(renderReservationSubmit(withResourceRequest(s, s.request))).toBe(file);
    }
  });

  it('rewrites a stated command in place', () => {
    const s = parseReservationSubmit(JUPYTER_FILE)!;
    const next = withResourceRequest(s, { ...s.request, cpus: 8 });
    expect(renderReservationSubmit(next)).toBe(
      'executable = /usr/bin/jupyter\nrequest_cpus = 8\nrequest_gpus = 1\nrequest_memory = 16384\nqueue\n',
    );
  });

  it('adds a command the file did not state, and only that one', () => {
    const s = parseReservationSubmit(DEFAULT_FILE)!;
    const next = withResourceRequest(s, { ...s.request, diskMB: 20480 });
    expect(next.stated).toEqual(['cpus', 'memoryMB', 'diskMB']);
    expect(renderReservationSubmit(next)).toBe(
      'executable = /usr/bin/python3\nrequest_cpus = 1\nrequest_memory = 4096\nrequest_disk = 20480\nqueue\n',
    );
  });

  it('drops a free-text command when it is cleared', () => {
    const file = 'executable = /bin/train\nrequest_gpus = 1\ncuda_version = 12.1\nqueue\n';
    const s = parseReservationSubmit(file)!;
    const next = withResourceRequest(s, { ...s.request, cudaVersion: '' });
    expect(next.stated).toEqual(['gpus']);
    expect(renderReservationSubmit(next)).toBe(
      'executable = /bin/train\nrequest_gpus = 1\nqueue\n',
    );
  });

  it('leaves a hidden GPU subfield alone while the count is zero', () => {
    // The panel hides the subfields at zero GPUs but keeps their values,
    // so a line the file already states survives an edit elsewhere.
    const file = 'request_gpus = 0\ngpus_minimum_memory = 8192\nqueue\n';
    const s = parseReservationSubmit(file)!;
    const next = withResourceRequest(s, { ...s.request, cpus: 4 });
    expect(renderReservationSubmit(next)).toBe(
      'request_gpus = 0\ngpus_minimum_memory = 8192\nrequest_cpus = 4\nqueue\n',
    );
  });

  it('keeps everything it does not recognise through an edit', () => {
    const file =
      'executable = /usr/bin/python3\narguments = train.py --epochs 10\n+WantWholeMachine = true\nrequest_cpus = 1\nqueue\n';
    const s = parseReservationSubmit(file)!;
    const next = withResourceRequest(s, { ...s.request, cpus: 16 });
    expect(renderReservationSubmit(next)).toBe(
      'executable = /usr/bin/python3\narguments = train.py --epochs 10\n+WantWholeMachine = true\nrequest_cpus = 16\nqueue\n',
    );
  });
});

describe('the editor and the text box agree', () => {
  it('re-parses whatever it renders', () => {
    // Anything the fields can produce has to be readable back by the
    // fields, or a save would flip the form into text mode on the next
    // open.
    const s = parseReservationSubmit(DEFAULT_FILE)!;
    const edited = withResourceRequest(s, {
      ...s.request,
      cpus: 2,
      diskMB: 4096,
      gpus: 1,
      cudaVersion: '12.4',
    });
    const text = renderReservationSubmit(edited);
    const again = parseReservationSubmit(text);
    expect(again).not.toBeNull();
    expect(again!.request.cpus).toBe(2);
    expect(again!.request.cudaVersion).toBe('12.4');
    expect(renderReservationSubmit(again!)).toBe(text);
  });
});
