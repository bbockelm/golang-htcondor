same as streamout, for stdin.
Sweep cannot prove this: the generator does not write `transfer_input = true` without an `input` keyword, which is the only shape that triggers it; TestStdFileTransferMatchesOracle compares the whole std-file family directly, including this case.
