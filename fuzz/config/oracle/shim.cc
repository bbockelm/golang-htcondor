//go:build libcondor_utils

// Differential-fuzz oracle: parse + expand a config source with HTCondor's
// reference C++ parser (libcondor_utils) and emit a canonical table. Built by
// cgo only under the `libcondor_utils` tag.

#include "condor_common.h"
#include "condor_config.h"

#include "shim.h"

#include <algorithm>
#include <cstdlib>
#include <cstring>
#include <string>
#include <utility>
#include <vector>

extern "C" int config_parse_expand(const char *text, char **out) {
	*out = nullptr;
	try {
		// A fresh, empty macro set with NO defaults table: a pure parse of the
		// input, matching config.ConfigOptions{SkipDefaults: true} on the Go
		// side. All members are C++ default-initialized (0/nullptr).
		MACRO_SET set;
		// Match the option flags production real_config() applies to the config
		// macro set (condor_config.cpp): colon is not an assignment operator,
		// smart comment/line-continuation handling, and keep values even when
		// they equal a built-in default (otherwise insert elides e.g. MINUTE=60
		// via the global param_info table, and later references resolve empty).
		// We deliberately do NOT set CONFIG_OPT_DEFAULTS_ARE_PARAM_INFO, and we
		// leave defaults NULL, so no param_info.in defaults leak in (mode #1).
		set.options = CONFIG_OPT_COLON_IS_META_ONLY | CONFIG_OPT_SMART_COM_IN_CONT |
		              CONFIG_OPT_KEEP_DEFAULTS;
		set.defaults = nullptr;

		MACRO_EVAL_CONTEXT ctx;
		ctx.init(nullptr, 2); // no subsystem; matches Go's empty Subsystem

		MACRO_SOURCE src = {false, false, 0, 0, 0, 0};
		insert_source("fuzz", set, src);

		int rc = Parse_config_string(src, 0, text, set, ctx);
		if (rc != 0) {
			// Parse error (rc is the offending line, or negative). The table may
			// be partial; we do not compare it — the caller only needs to see
			// that the C++ parser rejected this input.
			return 0;
		}

		std::vector<std::pair<std::string, std::string>> items;
		for (HASHITER it = hash_iter_begin(set, HASHITER_NO_DEFAULTS);
		     !hash_iter_done(it); hash_iter_next(it)) {
			const char *k = hash_iter_key(it);
			if (!k) {
				continue;
			}
			const char *raw = hash_iter_value(it);
			std::string v = raw ? raw : "";
			expand_macro(v, 0, set, ctx);
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
