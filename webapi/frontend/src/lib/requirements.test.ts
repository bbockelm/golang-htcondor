import { describe, expect, it } from 'vitest';
import {
  normalizeClause,
  splitConjuncts,
  standardLabels,
  summarizeRequirements,
  unwrapExpr,
} from './requirements';
import { CONTAINER_GPU_NOTABLE, CONTAINER_GPU_REQUIREMENTS } from './requirements.fixture';

// The real-world expression from a CHTC job pinned to one machine.
const CHTC_EXAMPLE =
  '((TARGET.PoolName == "CHTC") && (((((((Machine is "dgx-spark1.chtc.wisc.edu") && (TARGET.Arch isnt undefined)) && (TARGET.OpSys isnt undefined)) && (TARGET.Disk >= RequestDisk)) && (TARGET.Memory >= RequestMemory)) && (TARGET.Cpus >= RequestCpus)) && TARGET.HasFileTransfer))';

describe('summarizeRequirements', () => {
  it('reduces the CHTC example to PoolName + Machine plus standard reqs', () => {
    const s = summarizeRequirements(CHTC_EXAMPLE);
    expect(s.empty).toBe(false);
    expect(s.notable).toEqual([
      'PoolName == "CHTC"',
      'Machine is "dgx-spark1.chtc.wisc.edu"',
    ]);
    expect(s.standard).toEqual({
      cpus: true,
      memory: true,
      disk: true,
      arch: true,
      opsys: true,
      gpus: false,
      fileTransfer: true,
    });
    expect(s.hasStandard).toBe(true);
    expect(standardLabels(s.standard)).toEqual([
      'CPUs',
      'memory',
      'disk',
      'architecture',
      'OS',
      'file transfer',
    ]);
  });

  it('treats a bare "true" as no requirements of note', () => {
    const s = summarizeRequirements('true');
    expect(s.notable).toEqual([]);
    expect(s.hasStandard).toBe(false);
  });

  it('reports empty for a missing expression', () => {
    expect(summarizeRequirements(undefined).empty).toBe(true);
    expect(summarizeRequirements('').empty).toBe(true);
  });

  it('keeps a top-level OR clause whole rather than splitting it', () => {
    const s = summarizeRequirements(
      '(TARGET.Cpus >= RequestCpus) && ((OpSysAndVer == "AlmaLinux9") || (OpSysAndVer == "CentOS7"))',
    );
    expect(s.standard.cpus).toBe(true);
    expect(s.notable).toEqual([
      '(OpSysAndVer == "AlmaLinux9") || (OpSysAndVer == "CentOS7")',
    ]);
  });

  it('accepts the =!= presence form and == true file-transfer form', () => {
    const s = summarizeRequirements(
      '(TARGET.Arch =!= undefined) && (TARGET.HasFileTransfer == true) && (TARGET.GPUs >= RequestGPUs)',
    );
    expect(s.standard.arch).toBe(true);
    expect(s.standard.fileTransfer).toBe(true);
    expect(s.standard.gpus).toBe(true);
    expect(s.notable).toEqual([]);
  });
});

describe('splitConjuncts / normalizeClause', () => {
  it('flattens a left-nested AND tree', () => {
    expect(splitConjuncts('(((a) && (b)) && (c))')).toEqual(['a', 'b', 'c']);
  });
  it('strips TARGET. and enclosing parens but keeps MY.', () => {
    expect(normalizeClause('(TARGET.PoolName == "CHTC")')).toBe(
      'PoolName == "CHTC"',
    );
    expect(normalizeClause('(MY.WantGpuLab == true)')).toBe(
      'MY.WantGpuLab == true',
    );
  });
});

describe('a Requirements expression as the API sends it', () => {
  // Verbatim from a CHTC job page: the API wraps an unevaluated expression
  // as "/Expr(...)/", the tree is left-nested ten deep, and it carries
  // function calls with commas and string literals.
  const fromApi =
    '/Expr(((((((((((PoolName == "CHTC") || (substr(Machine, 0, 3) == "gzk")) && ((Machine != "txie-dsigpu4000.chtc.wisc.edu") && (Machine != "gpu4002.chtc.wisc.edu"))) && (Arch == "X86_64")) && HasContainer) && HasDockerURL) && (Memory >= RequestMemory)) && (Cpus >= RequestCpus)) && (countMatches(MY.RequireGPUs, AvailableGPUs) >= RequestGPUs)) && ((FileSystemDomain == MY.FileSystemDomain) || (HasFileTransfer && stringListIMember("osdf", HasFileTransferPluginMethods)))))/';

  it('lists one line per real requirement', () => {
    const s = summarizeRequirements(fromApi);
    expect(s.notable).toEqual([
      '(PoolName == "CHTC") || (substr(Machine, 0, 3) == "gzk")',
      'Machine != "txie-dsigpu4000.chtc.wisc.edu"',
      'Machine != "gpu4002.chtc.wisc.edu"',
      'Arch == "X86_64"',
      'HasContainer',
      'HasDockerURL',
      '(FileSystemDomain == MY.FileSystemDomain) || (HasFileTransfer && stringListIMember("osdf", HasFileTransferPluginMethods))',
    ]);
    expect(s.standard).toMatchObject({ memory: true, cpus: true, gpus: true });
    expect(standardLabels(s.standard)).toEqual(['CPUs', 'memory', 'GPUs']);
  });

  it('shows the raw expression without the wrapper', () => {
    expect(summarizeRequirements(fromApi).raw.startsWith('((((((((((PoolName')).toBe(true);
    expect(unwrapExpr(fromApi).endsWith('HasFileTransferPluginMethods))))')).toBe(true);
    expect(unwrapExpr('  Arch == "X86_64" ')).toBe('Arch == "X86_64"');
  });

  it('does not split on operators or parens inside a string literal', () => {
    const s = summarizeRequirements('/Expr((Name == "a && (b") && (OpSys == "LINUX"))/');
    expect(s.notable).toEqual(['Name == "a && (b"', 'OpSys == "LINUX"']);
  });
});

describe('a container job that asks for a GPU', () => {
  // The archive page showed no breakdown for a job with this Requirements.
  // The parser was not the cause -- the page never rendered the section --
  // but each form here is one a parser could plausibly trip on.
  it('lists each notable clause and folds the resource checks into one line', () => {
    const s = summarizeRequirements(CONTAINER_GPU_REQUIREMENTS);
    expect(s.notable).toEqual(CONTAINER_GPU_NOTABLE);
    expect(standardLabels(s.standard)).toEqual(['CPUs', 'memory', 'GPUs']);
  });

  it('keeps a clause it cannot take apart as its own text', () => {
    // An unbalanced clause: listed as written, and the rest still broken down.
    const s = summarizeRequirements('/Expr((TARGET.Cpus >= RequestCpus) && TARGET.HasContainer && (Foo == "x")/');
    expect(s.standard.cpus).toBe(true);
    expect(s.notable).toEqual(['HasContainer', '(Foo == "x"']);
  });
});
