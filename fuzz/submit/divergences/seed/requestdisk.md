C++ puts a MAX(...) expression on the cluster ad; Go emits its own value on the proc.
Sweep cannot prove this: the difference is WHERE the attribute is written, cluster ad versus proc ad, and the sweep compares each proc's MERGED ad -- so both sides read the same value and it cannot see the placement at all. The oracle's ModePlacement mode can; nothing uses it yet.
