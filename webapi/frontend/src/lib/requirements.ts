// Decompose an HTCondor job Requirements expression into something a
// human can skim. condor_submit builds Requirements as a deep AND-tree
// where the interesting clause (a machine or pool pin) is buried among
// boilerplate presence/resource checks:
//
//   ((TARGET.PoolName == "CHTC") && (((((((Machine is "dgx-spark1...")
//     && (TARGET.Arch isnt undefined)) && (TARGET.OpSys isnt undefined))
//     && (TARGET.Disk >= RequestDisk)) && (TARGET.Memory >= RequestMemory))
//     && (TARGET.Cpus >= RequestCpus)) && TARGET.HasFileTransfer))
//
// summarizeRequirements flattens that to the notable clauses (PoolName,
// Machine) plus a single "standard resource requirements" summary, so the
// UI can render a line per real requirement.

// splitTopLevel splits s on the given operator ("&&" / "||") only where it
// sits at parenthesis depth 0 and outside a string literal. Returns the
// parts (length 1 when the operator does not appear at the top level).
function splitTopLevel(s: string, op: string): string[] {
  const parts: string[] = [];
  let depth = 0;
  let inStr = false;
  let start = 0;
  for (let i = 0; i < s.length; i++) {
    const c = s[i];
    if (inStr) {
      if (c === '\\') i++; // skip escaped char
      else if (c === '"') inStr = false;
      continue;
    }
    if (c === '"') inStr = true;
    else if (c === '(') depth++;
    else if (c === ')') depth--;
    else if (depth === 0 && s.startsWith(op, i)) {
      parts.push(s.slice(start, i));
      i += op.length - 1;
      start = i + 1;
    }
  }
  parts.push(s.slice(start));
  return parts;
}

// stripOuterParens removes fully-enclosing parentheses (and surrounding
// whitespace), repeatedly: "((x))" -> "x". It only strips a paren pair
// that spans the whole string, so "(a) && (b)" is left intact.
export function stripOuterParens(expr: string): string {
  let s = expr.trim();
  while (s.startsWith('(') && s.endsWith(')')) {
    let depth = 0;
    let inStr = false;
    let spans = true;
    for (let i = 0; i < s.length; i++) {
      const c = s[i];
      if (inStr) {
        if (c === '\\') i++;
        else if (c === '"') inStr = false;
        continue;
      }
      if (c === '"') inStr = true;
      else if (c === '(') depth++;
      else if (c === ')') {
        depth--;
        if (depth === 0 && i !== s.length - 1) {
          // The opening paren closed before the end, so the outer pair
          // does not enclose the whole expression (e.g. "(a) && (b)").
          spans = false;
          break;
        }
      }
    }
    if (!spans) break;
    s = s.slice(1, -1).trim();
  }
  return s;
}

// splitConjuncts flattens a boolean expression into its top-level AND
// clauses. A clause containing a top-level OR is returned whole (it is one
// compound requirement, not several), and never split further.
export function splitConjuncts(expr: string): string[] {
  const s = stripOuterParens(expr);
  if (s === '') return [];
  // A top-level OR means the whole thing is one disjunctive requirement.
  if (splitTopLevel(s, '||').length > 1) return [s];
  const parts = splitTopLevel(s, '&&');
  if (parts.length === 1) return [s]; // leaf
  const out: string[] = [];
  for (const p of parts) out.push(...splitConjuncts(p));
  return out;
}

// normalizeClause cleans a clause for matching/display: strips enclosing
// parens, drops the noise-only "TARGET." scope prefix, and collapses
// whitespace. MY. is kept (it names a job attribute, which is meaningful).
export function normalizeClause(clause: string): string {
  return stripOuterParens(clause)
    .replace(/\bTARGET\./g, '')
    .replace(/\s+/g, ' ')
    .trim();
}

export interface StandardReqs {
  cpus: boolean;
  memory: boolean;
  disk: boolean;
  arch: boolean;
  opsys: boolean;
  gpus: boolean;
  fileTransfer: boolean;
}

// standardMatch tests a normalized clause against the boilerplate
// condor_submit always emits. Returns which standard requirement it is, or
// null if the clause is notable. Matching is case-insensitive and tolerant
// of spacing; both `isnt undefined` and `=!= undefined` presence forms are
// accepted, and a bare `HasFileTransfer` or `== true` form.
function standardMatch(normalized: string): keyof StandardReqs | null {
  const n = normalized.toLowerCase().replace(/\s+/g, ' ').trim();
  const presence = (attr: string) =>
    n === `${attr} isnt undefined` || n === `${attr} =!= undefined`;
  const geRequest = (attr: string, req: string) => n === `${attr} >= ${req}`;
  const truthy = (attr: string) =>
    n === attr || n === `${attr} == true` || n === `${attr} =?= true` || n === `${attr} is true`;

  if (geRequest('cpus', 'requestcpus')) return 'cpus';
  if (geRequest('memory', 'requestmemory')) return 'memory';
  if (geRequest('disk', 'requestdisk')) return 'disk';
  if (geRequest('gpus', 'requestgpus')) return 'gpus';
  if (presence('arch')) return 'arch';
  if (presence('opsys')) return 'opsys';
  if (truthy('hasfiletransfer')) return 'fileTransfer';
  return null;
}

export interface RequirementsSummary {
  notable: string[]; // cleaned, human-readable notable clauses
  standard: StandardReqs;
  hasStandard: boolean;
  raw: string; // the original expression, trimmed
  empty: boolean; // no requirements at all
}

export function summarizeRequirements(
  expr: string | undefined | null,
): RequirementsSummary {
  const raw = (expr ?? '').trim();
  const standard: StandardReqs = {
    cpus: false,
    memory: false,
    disk: false,
    arch: false,
    opsys: false,
    gpus: false,
    fileTransfer: false,
  };
  if (raw === '') {
    return { notable: [], standard, hasStandard: false, raw, empty: true };
  }

  const notable: string[] = [];
  for (const clause of splitConjuncts(raw)) {
    const norm = normalizeClause(clause);
    if (norm === '' || norm.toLowerCase() === 'true') continue;
    const kind = standardMatch(norm);
    if (kind) standard[kind] = true;
    else notable.push(norm);
  }
  const hasStandard = Object.values(standard).some(Boolean);
  return { notable, standard, hasStandard, raw, empty: false };
}

// standardLabels renders the set flags as human words, in a stable order,
// for the "standard resource requirements" summary line.
export function standardLabels(s: StandardReqs): string[] {
  const out: string[] = [];
  if (s.cpus) out.push('CPUs');
  if (s.memory) out.push('memory');
  if (s.disk) out.push('disk');
  if (s.gpus) out.push('GPUs');
  if (s.arch) out.push('architecture');
  if (s.opsys) out.push('OS');
  if (s.fileTransfer) out.push('file transfer');
  return out;
}
