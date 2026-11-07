The generated `Requirements` expression differs in shape, not in one clause.
HTCONDOR-3932 deleted the versioned disk clause
(`versionGE(split(TARGET.CondorVersion)[1],"25.12.0") || TARGET.Disk >=
RequestDisk`) from the vanilla expression, and HTCONDOR-3926 separately
stopped emitting Arch, OpSys and the disk clause for the local and scheduler
universes and writes `Requirements = true` when nothing is left.

This entry is the most expensive one here: Requirements is what decides which
machines a job can run on, and excusing the attribute stops the nightly
checking any of it. It should be the first thing fixed, not the last.

The trait names HTCONDOR-3932 alone, because an entry is about one upstream
change. An oracle with HTCONDOR-3926 and not HTCONDOR-3932 would report this
as a fresh divergence rather than excuse it, which is the safe direction.

Oracle: has HTCONDOR-3932
