// A Requirements expression in the shape condor_submit writes for a
// container job that asks for a GPU and may use a shared filesystem, as the
// API sends it: a machine exclusion in doubled parentheses, bare boolean
// attributes, a countMatches() call and an || clause.
export const CONTAINER_GPU_REQUIREMENTS =
  '/Expr(((Machine != "excluded-node.example.org")) && (TARGET.Arch == "X86_64") && TARGET.HasContainer && ' +
  'TARGET.HasSandboxImage && (TARGET.Memory >= RequestMemory) && (TARGET.Cpus >= RequestCpus) && ' +
  '(countMatches(MY.RequireGPUs,TARGET.AvailableGPUs) >= RequestGPUs) && ' +
  '((TARGET.FileSystemDomain == MY.FileSystemDomain) || (TARGET.HasFileTransfer)) && TARGET.HasSingularity)/';

// The clauses the breakdown lists for it, in order.
export const CONTAINER_GPU_NOTABLE = [
  'Machine != "excluded-node.example.org"',
  'Arch == "X86_64"',
  'HasContainer',
  'HasSandboxImage',
  '(FileSystemDomain == MY.FileSystemDomain) || (HasFileTransfer)',
  'HasSingularity',
];
