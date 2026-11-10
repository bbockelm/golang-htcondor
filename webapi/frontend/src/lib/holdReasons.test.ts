import { describe, expect, it } from 'vitest';
import { displayHoldReason, maskHoldReason, NO_REASON, summarizeHoldReasons } from './holdReasons';

describe('maskHoldReason', () => {
  it('gives occurrences of one problem on different nodes one template', () => {
    const a = maskHoldReason(
      'Error from slot1_40@glidein_181693_77062752@a529.anvil.rcac.purdue.edu: memory usage exceeded request_memory',
    );
    const b = maskHoldReason(
      'Error from slot1_13@IU-Jetstream2-Backfill.green-7b499568d4-pbfjk: memory usage exceeded request_memory',
    );
    expect(a).toBe(b);
    expect(a).toContain('memory usage exceeded request_memory');
  });

  it('masks paths, numbers, hex, addresses and quoted names', () => {
    const a = maskHoldReason(
      'Transfer input files failure at access point submit1 while sending files to the execute node 10.0.3.17:9618: reading from file /home/alice/run_17/input.dat: (errno 2) No such file or directory',
    );
    const b = maskHoldReason(
      'Transfer input files failure at access point submit1 while sending files to the execute node 10.0.9.4:9618: reading from file /home/alice/run_388/input.dat: (errno 2) No such file or directory',
    );
    expect(a).toBe(b);
    expect(maskHoldReason('Cannot open "out_17.txt" in dir_3fa8c2e9d1')).toBe(
      maskHoldReason('Cannot open "out_9.txt" in dir_77aa01bc42'),
    );
  });

  it('keeps different problems apart', () => {
    expect(maskHoldReason('memory usage exceeded request_memory')).not.toBe(
      maskHoldReason('disk usage exceeded request_disk'),
    );
  });
});

describe('summarizeHoldReasons', () => {
  it('shows a real message from the biggest group, with its count', () => {
    const s = summarizeHoldReasons([
      'Job exceeded 2048 MB of memory on node-17',
      'Job exceeded 4096 MB of memory on node-3',
      'Job exceeded 2048 MB of memory on node-99',
      'Policy hold: ran too long',
    ])!;
    // The first message of the group, not its masked template.
    expect(s.top.example).toBe('Job exceeded 2048 MB of memory on node-17');
    expect(s.top.count).toBe(3);
    expect(s.otherReasons).toBe(1);
    expect(s.held).toBe(4);
  });

  it('groups held jobs with no message together', () => {
    const s = summarizeHoldReasons([undefined, '', 'x'])!;
    expect(s.top.example).toBe(NO_REASON);
    expect(s.top.count).toBe(2);
    expect(s.otherReasons).toBe(1);
  });

  it('has nothing to say about no held jobs', () => {
    expect(summarizeHoldReasons([])).toBeUndefined();
  });
});

describe('displayHoldReason', () => {
  it('starts with the problem, not the machine it happened on', () => {
    expect(
      displayHoldReason(
        'Error from slot1_27@glidein_18169@node9.anvil.rcac.purdue.edu: memory usage exceeded request_memory',
      ),
    ).toBe('memory usage exceeded request_memory');
  });

  it('leaves other messages alone', () => {
    expect(displayHoldReason('Job policy: exceeded maximum runtime')).toBe('Job policy: exceeded maximum runtime');
    // Only a leading prefix, and only one without spaces before the colon.
    expect(displayHoldReason('Transfer failed. Error from server: 404')).toBe('Transfer failed. Error from server: 404');
    expect(displayHoldReason('Error from the starter: died')).toBe('Error from the starter: died');
  });

  it('keeps a message that is nothing but the prefix', () => {
    expect(displayHoldReason('Error from slot1@host: ')).toBe('Error from slot1@host: ');
  });
});
