//go:build libcondor_utils

// Differential-fuzz oracle: drive HTCondor's reference C++ SubmitHash over a
// submit file and emit the resulting job ads canonically. Built by cgo only
// under the `libcondor_utils` tag.

#include "condor_common.h"
#include "condor_config.h"
#include "condor_attributes.h"
#include "submit_utils.h"
#include "submit_protocol.h"
#include "condor_version.h"

#include "shim.h"

#include <algorithm>
#include <map>
#include <memory>
#include <cstdlib>
#include <cstring>
#include <string>
#include <utility>
#include <vector>

// SimpleSubmitKeyword lives in submit_utils.cpp rather than the header, while
// get_submit_keywords() is declared in the header. condor_submit's own
// submit_help.cpp resolves that by redeclaring the struct; this does the same.
struct SimpleSubmitKeyword {
	char const *key;
	char const *attr;
	int opts;
};


namespace {


// A fixed submit time and user, so two runs of the same input agree and the Go
// side can be handed the same values. Any attribute derived from the clock or
// the invoking account would otherwise differ run to run.
const time_t kSubmitTime = 1700000000;
const char *const kSubmitUser = "fuzzuser";

// emit_ad appends one ad to the canonical output.
//
// make_job_ad returns an ad CHAINED to the submit hash's base ad, and iterating
// a ClassAd yields only the attributes stored on the ad itself -- the printer is
// what walks the chain. The two modes want opposite things, so this takes the
// choice explicitly rather than relying on that asymmetry:
//
//   include_chain  the complete job ad, parent attributes merged in, with the
//                  proc's own values winning. This is the ad condor_submit
//                  -dry-run shows and what the schedd serves for the job.
//   !include_chain only the attributes stored on this ad, which is the
//                  placement the schedd records for it.
void emit_ad(std::string &out, int cluster, int proc, ClassAd *ad, bool include_chain) {
	char hdr[64];
	snprintf(hdr, sizeof(hdr), "#ad %d.%d\n", cluster, proc);
	out += hdr;

	// Walk parents first so a child's value overwrites the one it inherits.
	std::map<std::string, std::string> items;
	std::vector<ClassAd *> chain;
	for (ClassAd *p = ad; p; p = p->GetChainedParentAd()) {
		chain.push_back(p);
		if (!include_chain) {
			break;
		}
	}
	for (auto it = chain.rbegin(); it != chain.rend(); ++it) {
		for (auto &kv : **it) {
			classad::ClassAdUnParser unp;
			std::string v;
			unp.Unparse(v, kv.second);
			items[kv.first] = v;
		}
	}

	for (const auto &kv : items) {  // std::map iterates sorted
		out += kv.first;
		out += '\x1f';
		out += kv.second;
		out += '\n';
	}
}

// prepare does the setup condor_submit does before it materializes anything:
// a hash with the filesystem checks disabled, a fixed submit time and user, the
// parse up to the queue line, and the queue statement's item list.
//
// ms is built here because it must outlive the parse but can only be
// constructed once buf holds the text.
//
// Returns 1 on success, 0 if the submit file was rejected (err is set).
// ensure_config initializes HTCondor's global config exactly once.
//
// condor_submit calls config() before it ever builds a SubmitHash, and parts of
// the submit code reach param() as a result. Without this step those lookups
// run against an uninitialized config, which both suppresses attributes the
// tool would set and leaves make_job_ad dereferencing what param() returned --
// a submit file as short as
//
//     container_image = docker://busybox
//     queue
//
// was enough. Real condor_submit parses that file fine; the oracle was simply
// missing a step the tool performs.
//
// CONDOR_CONFIG is forced to an empty file so param() answers from built-in
// defaults only. The oracle must give the same answer on a developer laptop
// with a populated /etc/condor and on a CI runner with none, and reading the
// host's real configuration would break that.
void ensure_config() {
	static bool done = false;
	if (done) {
		return;
	}
	done = true;
	setenv("CONDOR_CONFIG", "/dev/null", 1);
	config();
}

int prepare(const char *text, SubmitHash &hash, std::string &buf, MACRO_SOURCE &src,
            std::unique_ptr<MacroStreamMemoryFile> &ms, SubmitStepFromQArgs &ssqa,
            std::string &err) {
	ensure_config();
	hash.init(JSM_CONDOR_SUBMIT);
	hash.setDisableFileChecks(true);
	hash.setFakeFileCreationChecks(true);
	hash.setScheddVersion(CondorVersion());
	if (hash.init_base_ad(kSubmitTime, kSubmitUser) != 0) {
		err = "init_base_ad failed";
		return 0;
	}

	insert_source("fuzz", hash.macros(), src);
	buf = text ? text : "";
	ms = std::make_unique<MacroStreamMemoryFile>(buf.c_str(), (ssize_t)buf.size(), src);

	char *qline = nullptr;
	int rval = hash.parse_up_to_q_line(*ms, err, &qline);
	if (rval != 0) {
		if (err.empty()) err = "parse error";
		return 0;
	}
	hash.optimize();

	const char *queue_args = qline ? SubmitHash::is_queue_statement(qline) : nullptr;
	if ((rval = ssqa.init(queue_args, err)) != 0) {
		if (err.empty()) err = "queue statement error";
		return 0;
	}
	if ((rval = ssqa.load_items(*ms, true, err)) != 0) {
		if (err.empty()) err = "queue item error";
		return 0;
	}
	return 1;
}

} // namespace

extern "C" int submit_make_ads(const char *text, int mode, int max_procs, char **out) {
	*out = nullptr;
	try {
		if (max_procs <= 0) {
			max_procs = 1;
		}

		SubmitHash hash;
		std::string buf, err;
		MACRO_SOURCE src = {false, false, 0, 0, 0, 0};
		std::unique_ptr<MacroStreamMemoryFile> ms;
		SubmitStepFromQArgs ssqa(hash);
		if (!prepare(text, hash, buf, src, ms, ssqa, err)) {
			*out = strdup(err.c_str());
			return 0;
		}

		const int cluster = 1;
		ssqa.begin(JOB_ID_KEY(cluster, 0), false);

		const bool placement = (mode == SUBMIT_ORACLE_MODE_PLACEMENT);
		std::string result;
		JOB_ID_KEY jid;
		int rval = 0;
		int item_index = 0, step = 0, n = 0;
		bool truncated = false;

		while ((rval = ssqa.next_selected(jid, item_index, step, true)) > 0) {
			if (n >= max_procs) {
				truncated = true;
				break;
			}
			ClassAd *ad = hash.make_job_ad(jid, item_index, step, false, false, nullptr, nullptr);
			if (!ad) {
				*out = strdup("make_job_ad returned null");
				return 0;
			}
			if (placement && jid.proc == 0) {
				// condor_submit folds proc 0 into the cluster ad and sends that
				// ad first; later procs are only what differs from it.
				hash.fold_job_into_base_ad(cluster, ad);
				if (ClassAd *base = hash.get_cluster_ad()) {
					emit_ad(result, cluster, -1, base, false);
				}
			}
			emit_ad(result, jid.cluster, jid.proc, ad, !placement);
			++n;
		}
		if (rval < 0) {
			*out = strdup("queue iteration failed");
			return 0;
		}
		if (truncated) {
			result += "#truncated\n";
		}

		*out = strdup(result.c_str());
		return *out ? 1 : -1;
	} catch (const std::exception &e) {
		if (*out) {
			free(*out);
		}
		*out = strdup(e.what());
		return -1;
	} catch (...) {
		if (*out) {
			free(*out);
			*out = nullptr;
		}
		return -1;
	}
}

extern "C" int submit_factory_info(const char *text, int max_items, const char *items_filename, char **out) {
	*out = nullptr;
	try {
		if (max_items <= 0) {
			max_items = 16;
		}

		SubmitHash hash;
		std::string buf, err;
		MACRO_SOURCE src = {false, false, 0, 0, 0, 0};
		std::unique_ptr<MacroStreamMemoryFile> ms;
		SubmitStepFromQArgs ssqa(hash);
		if (!prepare(text, hash, buf, src, ms, ssqa, err)) {
			*out = strdup(err.c_str());
			return 0;
		}

		const int cluster = 1;
		std::string result;

		// The order below is condor_submit's (submit.cpp, the want_factory
		// branch) and it is load-bearing:
		//
		//   begin(set_live=false) then next_raw(set_live=false) loads the
		//   first row WITHOUT pushing the loop variables into the submit
		//   hash. A digest built once they are live has that row's values
		//   baked into it -- `arguments=a 0` instead of
		//   `arguments=$(item) $(Process)` -- and every proc the schedd
		//   materializes would then be the first one.
		ssqa.begin(JOB_ID_KEY(cluster, 0), false);
		JOB_ID_KEY jid;
		int item_index = 0, step = 0;
		if (ssqa.next_raw(jid, item_index, step, false) < 0) {
			*out = strdup("queue iteration failed");
			return 0;
		}

		// want_factory_submit reads max_materialize, else max_idle (or its
		// alternate spelling), and is the whole of the client-side decision.
		long long max_materialize = 0;
		const bool factory = hash.want_factory_submit(max_materialize);
		result += factory ? "#factory 1\n" : "#factory 0\n";
		if (factory) {
			// condor_submit's clamp: an unspecified limit becomes INT_MAX,
			// then the total job count, then at least one.
			int total_procs = ssqa.selected_job_count();
			if (max_materialize <= 0) max_materialize = INT_MAX;
			max_materialize = MIN(max_materialize, total_procs);
			max_materialize = MAX(max_materialize, 1);
			result += "#max_materialize " + std::to_string(max_materialize) + "\n";
			result += "#total_procs " + std::to_string(total_procs) + "\n";
		}

		const auto &vars = ssqa.vars();
		result += "#vars ";
		for (size_t i = 0; i < vars.size(); ++i) {
			if (i) result += ",";
			result += vars[i];
		}
		result += "\n";

		// The itemdata rows, encoded by the same function that feeds
		// SendMaterializeData: multi-field rows are split and rejoined with
		// the ASCII unit separator, and every row ends in a newline. The
		// newline is stripped here only because the report is line-oriented.
		//
		// This consumes m_fea.items_idx, so it runs before anything that
		// iterates the rows again.
		std::vector<std::string> rows;
		ssqa.m_fea.items_idx = 0;
		std::string row;
		int rrv = 0, n = 0;
		while (n < max_items && (rrv = AbstractScheddQ::next_rowdata(&ssqa.m_fea, row)) == 1) {
			while (!row.empty() && row.back() == '\n') { row.pop_back(); }
			rows.push_back(row);
			++n;
		}
		if (rrv < 0) {
			*out = strdup("itemdata row encoding failed");
			return 0;
		}
		result += "#items " + std::to_string(rows.size()) + "\n";
		for (const auto &r : rows) {
			result += "#item\x1f";
			result += r;
			result += "\n";
		}

		// The digest: the submit file reduced to what the schedd needs to
		// expand each proc itself. This is the payload a factory submission
		// sends in place of per-proc ads.
		std::string digest;
		hash.make_digest(digest, cluster, vars, 0);

		// send_Itemdata spools the rows at the schedd and rewrites the queue
		// statement to read them back from the file the schedd named, so the
		// queue statement appended below says `from <that file>` rather than
		// carrying an inline item list the digest never contains. There is no
		// schedd here, so the caller supplies the name.
		if (!ssqa.m_fea.items.empty()) {
			ssqa.m_fea.foreach_mode = foreach_from;
			ssqa.m_fea.items_filename = items_filename ? items_filename : "";
		}

		// Without this the digest has no queue statement and the schedd would
		// not know how to iterate. condor_submit appends it after
		// send_Itemdata and before set_Factory.
		if (append_queue_statement(digest, ssqa.m_fea) < 0) {
			*out = strdup("append_queue_statement failed");
			return 0;
		}

		result += "#digest\n";
		result += digest;
		if (!digest.empty() && digest.back() != '\n') {
			result += "\n";
		}
		result += "#enddigest\n";

		*out = strdup(result.c_str());
		return *out ? 1 : -1;
	} catch (const std::exception &e) {
		*out = strdup(e.what());
		return -1;
	} catch (...) {
		return -1;
	}
}

extern "C" int submit_keyword_table(char **out) {
	*out = nullptr;
	try {
		ensure_config();
		const SimpleSubmitKeyword *table = get_submit_keywords();
		if (!table) {
			return -1;
		}

		std::vector<std::string> lines;
		for (const SimpleSubmitKeyword *k = table; k->key || k->attr; ++k) {
			std::string line;
			line += k->key ? k->key : "";
			line += '\x1f';
			line += k->attr ? k->attr : "";
			line += '\x1f';
			line += std::to_string(k->opts);
			lines.push_back(std::move(line));
		}
		// SimpleSubmitKeyword is defined in submit_utils.cpp, not the header,
		// so this file redeclares it -- which is what condor_submit's own
		// submit_help.cpp does to call get_submit_keywords(). A layout change
		// upstream would show up as garbage rather than a compile error, so
		// sanity-check that the table looks like keywords before trusting it.
		if (lines.size() < 50) {
			return -1;
		}
		std::sort(lines.begin(), lines.end());

		std::string result;
		for (const auto &l : lines) {
			result += l;
			result += '\n';
		}
		*out = strdup(result.c_str());
		return *out ? 1 : -1;
	} catch (...) {
		return -1;
	}
}

extern "C" void submit_oracle_free(char *p) { free(p); }
