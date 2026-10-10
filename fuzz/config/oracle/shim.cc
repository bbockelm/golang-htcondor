//go:build libcondor_utils

// Differential-fuzz oracle: parse + expand a config source with HTCondor's
// reference C++ parser (libcondor_utils) and emit a canonical table. Built by
// cgo only under the `libcondor_utils` tag.

#include "condor_common.h"
#include "condor_config.h"
#include "CondorError.h"
#include "condor_classad.h"

#include "shim.h"

#include <algorithm>
#include <cstdlib>
#include <cstring>
#include <string>
#include <utility>
#include <vector>

extern "C" int config_parse_expand(const char *text, char **out) {
	*out = nullptr;
	// Production config() runs ClassAdReconfig, which turns on old ClassAd
	// semantics unless STRICT_CLASSAD_EVALUATION is set. $INT/$REAL/$STRING/
	// $EVAL parse their argument as a ClassAd expression, so do the same:
	// under new semantics "0x10" lexes as 0, under old it is an error.
	static const bool old_semantics = (classad::SetOldClassAdSemantics(true), true);
	(void)old_semantics;
	try {
		// A fresh, empty macro set with NO defaults table: a pure parse of the
		// input, matching config.ConfigOptions{SkipDefaults: true} on the Go
		// side. All members are C++ default-initialized (0/nullptr).
		MACRO_SET set;
		// Match the option flags production real_config() applies to the config
		// macro set (condor_config.cpp): colon assignment is accepted with a
		// warning, smart comment/line-continuation handling, and keep values
		// even when they equal a built-in default (otherwise insert elides e.g.
		// MINUTE=60 via the global param_info table, and later references
		// resolve empty).
		// We deliberately do NOT set CONFIG_OPT_DEFAULTS_ARE_PARAM_INFO, and we
		// leave defaults NULL, so no param_info.in defaults leak in (mode #1).
		set.options = CONFIG_OPT_COLON_IS_META_ONLY | CONFIG_OPT_SMART_COM_IN_CONT |
		              CONFIG_OPT_KEEP_DEFAULTS;
		set.defaults = nullptr;

		MACRO_EVAL_CONTEXT ctx;
		ctx.init(nullptr, MACRO_EVAL_CONTEXT::um_COUNT_REFS); // no subsystem, as Go

		// Errors go to this stack instead of stderr (the set owns and frees it).
		set.errors = new CondorError();

		MACRO_SOURCE src = {false, false, 0, 0, 0, 0};
		insert_source("fuzz", set, src);

		// Read the text the way HTCondor reads a config FILE: Parse_macros fed
		// by a MacroStreamMemoryFile, which shares getline_implementation with
		// the FILE* stream production uses (process_config_source), so
		// whitespace trimming and backslash continuation are HTCondor's own.
		// Parse_config_string is NOT that path: it is the lenient parser for
		// metaknob bodies, and accepts lines (e.g. "foo bar") that a config
		// file rejects.
		//
		// Production passes options = 0. We add CONFIG_OPT_NO_INCLUDE_FILE so a
		// fuzz input can never read a host file or run a command through
		// `include [command] : ...`; every include form is then a parse error,
		// matching the Go side's ConfigOptions{NoLocalAccess: true}.
		MacroStreamMemoryFile ms(text, (ssize_t)strlen(text), src);
		std::string errmsg;
		int rc = Parse_macros(ms, 0, set, CONFIG_OPT_NO_INCLUDE_FILE, &ctx, errmsg, nullptr, nullptr);
		if (rc < 0) {
			// Parse error. Production (process_config_source) treats only a
			// negative return as fatal; a positive `error N :` code stops the
			// read without failing it, so it falls through as a success. The
			// table may be partial; we do not compare it — the caller only needs
			// to see that the C++ parser rejected this input.
			return 0;
		}

		std::vector<std::pair<std::string, std::string>> items;
		for (HASHITER it = hash_iter_begin(set, HASHITER_NO_DEFAULTS);
		     !hash_iter_done(it); hash_iter_next(it)) {
			const char *k = hash_iter_key(it);
			if (!k) {
				continue;
			}
			// Expand the way param() does (expand_param -> the char* overload
			// of expand_macro), not with the std::string overload: the two
			// differ ($DIRNAME/$BASENAME, re-scanning an expansion's result).
			const char *raw = hash_iter_value(it);
			char *expanded = expand_macro(raw ? raw : "", set, ctx);
			std::string v = expanded ? expanded : "";
			free(expanded);
			items.emplace_back(k, std::move(v));
		}
		std::sort(items.begin(), items.end());

		std::string result;
		for (const auto &kv : items) {
			result += kv.first;
			result += '\x1f'; // unit separator between key and value
			result += kv.second;
			result += '\n';
		}
		*out = strdup(result.c_str());
		return *out ? 1 : -1;
	} catch (...) {
		if (*out) {
			free(*out);
			*out = nullptr;
		}
		return -1;
	}
}

extern "C" void config_free(char *p) { free(p); }
