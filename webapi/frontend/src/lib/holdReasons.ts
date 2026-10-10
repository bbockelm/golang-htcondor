// Grouping a batch's hold messages so the row can say what is wrong.
//
// A batch of five hundred jobs held for one reason has five hundred
// different HoldReason strings: each names its own execute node, sandbox
// directory, byte count or URL. Grouping by the exact text would report
// five hundred reasons; grouping by HoldReasonCode would lump every
// transfer failure together whatever file it was. So messages are grouped
// by a masked template -- the variable parts replaced by placeholders --
// and the row shows a real message from the biggest group, because a
// template with the detail masked out is not something a person can act
// on.
//
// The rules are a small subset of the server's issue clustering
// (webapi/issues/mask.go), in the same most-specific-first order: a URL
// must go before the path rule, and a version before the number rule,
// or an earlier placeholder gets re-matched by a later one.

const MASK_RULES: [RegExp, string][] = [
  [/\b[a-zA-Z][a-zA-Z0-9+.-]*:\/\/[^\s,)"'|]+/g, '<url>'],
  [/\b\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(\.\d+)?Z?\b/g, '<time>'],
  [/\bslot\d+(_\d+)?@\S+/g, '<slot>'],
  [/\b[\w.-]+@[\w.-]+\b/g, '<host>'],
  [/\b\d{1,3}(\.\d{1,3}){3}(:\d+)?\b/g, '<ip>'],
  [/\bv?\d+\.\d+(\.\d+)+\b/g, '<ver>'],
  [/(\/[\w.+-]+){2,}\/?/g, '<path>'],
  [/\b[a-zA-Z][\w-]*(\.[\w-]+){2,}\b/g, '<host>'],
  // Quoted strings: a file name, an attribute value, a command line.
  [/"[^"]*"|'[^']*'/g, '<quoted>'],
  [/\b[0-9a-fA-F]{8,}\b/g, '<hex>'],
  [/\b\d+(\.\d+)?\b/g, '<num>'],
  // A run with a digit in it -- glide_AGd9bW, dir_260525 -- is a
  // per-occurrence name.
  [/\b(?:[a-zA-Z]+[_-]?)*\d[\w-]*\b/g, '<id>'],
];

// maskHoldReason reduces a hold message to the template its occurrences
// share.
export function maskHoldReason(message: string): string {
  let s = message;
  for (const [re, with_] of MASK_RULES) s = s.replace(re, with_);
  // Whitespace and trailing punctuation are not part of what makes two
  // messages the same.
  return s.replace(/\s+/g, ' ').replace(/[.:;\s]+$/, '').trim();
}

export const NO_REASON = 'No reason recorded';

// The "Error from <slot>@<host>: " that starts most execute-side holds.
// It names the machine, which is the one thing a narrow cell has room for
// and the one thing the reader does not need first.
const ERROR_FROM = /^Error from \S+:\s+/;

// displayHoldReason is a hold message as a cell shows it: the problem
// first, without the leading "Error from <where>: ". The full message
// stays available for the tooltip.
export function displayHoldReason(message: string): string {
  const stripped = message.replace(ERROR_FROM, '');
  return stripped === '' ? message : stripped;
}

export interface HoldReasonGroup {
  // A real message from the group, to show.
  example: string;
  count: number;
}

export interface HoldSummary {
  // The most common reason. Ties go to the one met first.
  top: HoldReasonGroup;
  // How many other distinct reasons there are besides it.
  otherReasons: number;
  // Held jobs considered, with or without a recorded reason.
  held: number;
}

// summarizeHoldReasons groups the messages of a batch's held jobs. Jobs
// with no recorded reason are counted under one "no reason recorded"
// group, so the ×N always adds up to the jobs it describes. Undefined when
// there is nothing to summarize.
export function summarizeHoldReasons(
  reasons: (string | undefined)[],
): HoldSummary | undefined {
  if (reasons.length === 0) return undefined;
  const groups = new Map<string, HoldReasonGroup>();
  for (const r of reasons) {
    const message = r?.trim() || NO_REASON;
    const key = message === NO_REASON ? NO_REASON : maskHoldReason(message);
    const g = groups.get(key);
    if (g) g.count++;
    else groups.set(key, { example: message, count: 1 });
  }
  let top: HoldReasonGroup | undefined;
  for (const g of groups.values()) {
    if (!top || g.count > top.count) top = g;
  }
  return { top: top!, otherReasons: groups.size - 1, held: reasons.length };
}
