`restricttoannex` is written by the annex submit commands HTCONDOR-2015 added. The C++
side produces it from `annex_name`, which the generator now reaches because it
builds its vocabulary from the oracle's own keyword table; Go does not know
the keyword and writes nothing.

Oracle: has HTCONDOR-2015
