import { describe, expect, it } from 'vitest';
import {
  normalizeClause,
  splitConjuncts,
  standardLabels,
  summarizeRequirements,
} from './requirements';

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
