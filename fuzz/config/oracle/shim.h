//go:build libcondor_utils

/* Differential-fuzz oracle bridge to HTCondor's C++ config parser
 * (libcondor_utils). Compiled by cgo only under the `libcondor_utils` build
 * tag; see cgo.go. */

#ifndef HTCONDOR_CONFIG_FUZZ_SHIM_H
#define HTCONDOR_CONFIG_FUZZ_SHIM_H

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Parse `text` as a config source into a fresh MACRO_SET whose defaults table
 * is NULL (so no param_info.in defaults leak in — a pure parse), then expand
 * every resulting macro and emit a canonical table.
 *
 * Return value:
 *    1  parse succeeded; *out points to a malloc'd canonical encoding: the set
 *       of keys, sorted, one per line as "KEY\x1Fexpanded_value\n". Caller must
 *       config_free() it.
 *    0  Parse_config_string reported an error (bad line); *out is left NULL.
 *   -1  a C++ exception escaped (itself a finding); *out is left NULL.
 *
 * The reference environment (time constants, FULL_HOSTNAME, DETECTED_*, ...) is
 * NOT injected here — the caller prepends it to `text` so both engines parse
 * exactly the same source. None of those names are special-cased in
 * expand_macro, so they behave as ordinary macros on both sides.
 */
int config_parse_expand(const char *text, char **out);

/* Free a string previously returned via config_parse_expand's out parameter. */
void config_free(char *p);

#ifdef __cplusplus
}
#endif

#endif
