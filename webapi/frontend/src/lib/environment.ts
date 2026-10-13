// HTCondor's two environment syntaxes, as a job ad carries them.
//
//   Environment (V2): entries separated by whitespace. A single-quoted
//     section keeps its whitespace, and inside one '' is a literal
//     single quote: FOO=1 GREETING='hello world' Q='it''s'.
//   Env (V1): entries separated by semicolons, with no quoting:
//     FOO=1;BAR=2.
//
// The submit file wraps the V2 form in double quotes and doubles any
// embedded double quote; that layer is submitFile.decodeEnvironment's.
// The job ad holds the string after condor_submit removed it.

export interface EnvVar {
  name: string;
  value: string;
}

// splitEnvironmentV2 returns the entries of a V2 environment string with
// the single quoting resolved, so GREETING='hello world' comes back as
// "GREETING=hello world".
export function splitEnvironmentV2(s: string): string[] {
  const tokens: string[] = [];
  let buf = '';
  // A token can be all quotes ('' is an empty quoted section), so
  // whether there is one is tracked apart from whether buf has text.
  let started = false;
  let inSingle = false;
  for (let i = 0; i < s.length; i++) {
    const ch = s[i];
    if (ch === "'") {
      started = true;
      if (inSingle && s[i + 1] === "'") {
        buf += "'";
        i++;
        continue;
      }
      inSingle = !inSingle;
      continue;
    }
    if (!inSingle && /\s/.test(ch)) {
      if (started) tokens.push(buf);
      buf = '';
      started = false;
      continue;
    }
    buf += ch;
    started = true;
  }
  if (started) tokens.push(buf);
  return tokens;
}

// splitEnvironmentV1 returns the entries of a V1 environment string.
export function splitEnvironmentV1(s: string): string[] {
  return s
    .split(';')
    .map((t) => t.trim())
    .filter((t) => t !== '');
}

// toEnvVars keeps the entries that have a name: NAME=value. An entry
// without "=" is not a variable, and HTCondor rejects one.
export function toEnvVars(entries: string[]): EnvVar[] {
  const out: EnvVar[] = [];
  for (const t of entries) {
    const eq = t.indexOf('=');
    if (eq <= 0) continue;
    out.push({ name: t.slice(0, eq), value: t.slice(eq + 1) });
  }
  return out;
}

// environmentEntries returns one NAME=value line per variable when attr
// is a job's environment (ClassAd names are case-insensitive), and null
// for any other attribute.
export function environmentEntries(attr: string, value: string): string[] | null {
  switch (attr.toLowerCase()) {
    case 'environment':
      return splitEnvironmentV2(value);
    case 'env':
      return splitEnvironmentV1(value);
    default:
      return null;
  }
}
