//go:build libcondor_utils

/* Differential-fuzz oracle bridge to HTCondor's C++ submit-file parser
 * (SubmitHash, src/condor_utils/submit_utils.cpp, in libcondor_utils).
 * Compiled by cgo only under the `libcondor_utils` build tag; see cgo.go. */

#ifndef HTCONDOR_SUBMIT_FUZZ_SHIM_H
#define HTCONDOR_SUBMIT_FUZZ_SHIM_H

#ifdef __cplusplus
extern "C" {
#endif

/* Mode selectors for submit_make_ads. */
#define SUBMIT_ORACLE_MODE_ADS       0 /* each proc's complete job ad */
#define SUBMIT_ORACLE_MODE_PLACEMENT 1 /* cluster ad + each proc's own attrs */

/*
 * Parse `text` as a submit file and drive SubmitHash exactly as condor_submit
 * does: parse_up_to_q_line, then SubmitStepFromQArgs over the queue statement,
 * calling make_job_ad for each proc.
 *
 * mode SUBMIT_ORACLE_MODE_ADS emits every proc's complete job ad, which is what
 * `condor_submit -dry-run` shows: the ad a proc resolves to, parent chain
 * included.
 *
 * mode SUBMIT_ORACLE_MODE_PLACEMENT additionally calls fold_job_into_base_ad
 * after proc 0 -- as condor_submit does before sending the cluster ad -- and
 * emits the cluster ad plus each later proc's OWN attributes only, skipping
 * everything it inherits through the chain. That is the attribute placement
 * the schedd ends up storing.
 *
 * `max_procs` caps how many procs are materialized (a fuzzer will write
 * `queue 100000000`). When the queue statement asks for more, the emitted
 * output ends with a "#truncated" line and the caller should compare only the
 * procs present.
 *
 * Return value:
 *    1  success; *out points to a malloc'd canonical encoding (see below).
 *    0  the submit file was rejected; *out holds the C++ error message.
 *   -1  a C++ exception escaped (itself a finding); *out may hold its what().
 *
 * Canonical encoding, with attributes sorted within each ad:
 *    "#ad <cluster>.<proc>\n"   (<proc> is -1 for the cluster ad)
 *    "<Name>\x1f<value>\n"  ...
 *    "#truncated\n"             (optional, last)
 * Caller must submit_oracle_free() the result.
 */
int submit_make_ads(const char *text, int mode, int max_procs, char **out);

/*
 * Report what condor_submit would send for a LATE-MATERIALIZATION (job factory)
 * submission of this file, instead of materialized job ads.
 *
 * No schedd is involved: whether a submission is a factory, its materialize
 * limit, the submit digest the schedd later expands per proc, and the itemdata
 * rows are all computed client-side by SubmitHash. Only the schedd's expansion
 * of the digest would need one, and that is the schedd's behavior, not the
 * parser's.
 *
 * Output:
 *    "#factory <0|1>\n"          want_factory_submit()
 *    "#max_materialize <n>\n"    only when factory
 *    "#vars <v1,v2,...>\n"       the queue statement's loop variables
 *    "#items <n>\n" then one "#item\x1f<row>\n" per itemdata row
 *    "#digest\n" then the digest text, then "#enddigest\n"
 *
 * Return value matches submit_make_ads.
 */
int submit_factory_info(const char *text, int max_items, char **out);

/*
 * Emit HTCondor's own submit-keyword table, so the fuzzer's vocabulary comes
 * from the parser being tested rather than a hand-maintained list that drifts.
 *
 * Lines are "<keyword>\x1f<attribute>\x1f<opts>\n", sorted, where <opts> is the
 * SimpleSubmitKeyword flag word (value type, file role, special parsing).
 * <attribute> is empty for keywords with no single target attribute.
 *
 * Returns 1 on success, -1 if the table looks wrong (see shim.cc). Caller must
 * submit_oracle_free() the result.
 */
int submit_keyword_table(char **out);

/* Free a string previously returned via submit_make_ads's out parameter. */
void submit_oracle_free(char *p);

#ifdef __cplusplus
}
#endif

#endif
