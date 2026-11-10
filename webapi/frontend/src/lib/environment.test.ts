import { describe, expect, it } from 'vitest';

import { environmentEntries, splitEnvironmentV1, splitEnvironmentV2, toEnvVars } from './environment';
import { decodeEnvironment, encodeEnvironment } from './submitFile';

describe('splitEnvironmentV2', () => {
  it('splits on any whitespace', () => {
    expect(splitEnvironmentV2('A=1  B=2\tC=3\n')).toEqual(['A=1', 'B=2', 'C=3']);
  });

  it('keeps whitespace inside single quotes and drops the quotes', () => {
    expect(splitEnvironmentV2("GREETING='hello world' X=1")).toEqual(['GREETING=hello world', 'X=1']);
  });

  it("reads '' inside quotes as a literal single quote", () => {
    expect(splitEnvironmentV2("Q='it''s'")).toEqual(["Q=it's"]);
  });

  it('quotes may cover part of an entry', () => {
    expect(splitEnvironmentV2("PATH=/bin:'/my dir'/bin")).toEqual(['PATH=/bin:/my dir/bin']);
  });

  it("keeps a variable set to the empty string ('')", () => {
    expect(splitEnvironmentV2("EMPTY='' B=2")).toEqual(['EMPTY=', 'B=2']);
  });

  it('returns nothing for an empty or blank value', () => {
    expect(splitEnvironmentV2('')).toEqual([]);
    expect(splitEnvironmentV2('   ')).toEqual([]);
  });
});

describe('splitEnvironmentV1', () => {
  it('splits on semicolons and keeps spaces in values', () => {
    expect(splitEnvironmentV1('A=1;GREETING=hello world;B=2')).toEqual(['A=1', 'GREETING=hello world', 'B=2']);
  });

  it('skips empty entries', () => {
    expect(splitEnvironmentV1(';A=1;;')).toEqual(['A=1']);
    expect(splitEnvironmentV1('')).toEqual([]);
  });
});

describe('environmentEntries', () => {
  it('reads Environment as V2 and Env as V1, in any case', () => {
    expect(environmentEntries('Environment', "A=1 B='x y'")).toEqual(['A=1', 'B=x y']);
    expect(environmentEntries('environment', 'A=1')).toEqual(['A=1']);
    expect(environmentEntries('Env', 'A=1;B=x y')).toEqual(['A=1', 'B=x y']);
  });

  it('is null for any other attribute', () => {
    expect(environmentEntries('Args', 'A=1 B=2')).toBeNull();
  });
});

describe('toEnvVars', () => {
  it('splits at the first = and drops entries without a name', () => {
    expect(toEnvVars(['A=b=c', 'NOEQ', '=x'])).toEqual([{ name: 'A', value: 'b=c' }]);
  });
});

// decodeEnvironment now reads through splitEnvironmentV2; the submit
// form's round trip has to survive that.
describe('decodeEnvironment', () => {
  it('round-trips what encodeEnvironment writes', () => {
    const vars = [
      { name: 'A', value: '1' },
      { name: 'GREETING', value: 'hello world' },
      { name: 'Q', value: "it's \"quoted\"" },
    ];
    expect(decodeEnvironment(encodeEnvironment(vars)!)).toEqual(vars);
  });

  it('is null without the enclosing double quotes', () => {
    expect(decodeEnvironment('A=1')).toBeNull();
  });
});
