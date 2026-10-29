//go:build libcondor_utils

// Differential-fuzz oracle: drive HTCondor's reference C++ SubmitHash over a
// submit file and emit the resulting job ads canonically. Built by cgo only
// under the `libcondor_utils` tag.

#include "condor_common.h"
#include "condor_config.h"
#include "condor_attributes.h"
#include "submit_utils.h"
#include "condor_version.h"

#include "shim.h"

#include <algorithm>
#include <map>
#include <cstdlib>
#include <cstring>
#include <string>
#include <utility>
#include <vector>

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

} // namespace

extern "C" int submit_make_ads(const char *text, int mode, int max_procs, char **out) {
	*out = nullptr;
	try {
		if (max_procs <= 0) {
			max_procs = 1;
		}

		SubmitHash hash;
		hash.init(JSM_CONDOR_SUBMIT);
		// Never touch the filesystem: a fuzzer-authored executable or input file
		// must not make the oracle's answer depend on what happens to exist.
		hash.setDisableFileChecks(true);
		hash.setFakeFileCreationChecks(true);
		hash.setScheddVersion(CondorVersion());
		if (hash.init_base_ad(kSubmitTime, kSubmitUser) != 0) {
			*out = strdup("init_base_ad failed");
			return 0;
		}

		MACRO_SOURCE src = {false, false, 0, 0, 0, 0};
		insert_source("fuzz", hash.macros(), src);

		std::string buf(text ? text : "");
		MacroStreamMemoryFile ms(buf.c_str(), (ssize_t)buf.size(), src);

		std::string errmsg;
		char *qline = nullptr;
		int rval = hash.parse_up_to_q_line(ms, errmsg, &qline);
		if (rval != 0) {
			*out = strdup(errmsg.empty() ? "parse error" : errmsg.c_str());
			return 0;
		}
		hash.optimize();

		SubmitStepFromQArgs ssqa(hash);
		const char *queue_args = qline ? SubmitHash::is_queue_statement(qline) : nullptr;
		if ((rval = ssqa.init(queue_args, errmsg)) != 0) {
			*out = strdup(errmsg.empty() ? "queue statement error" : errmsg.c_str());
			return 0;
		}
		if ((rval = ssqa.load_items(ms, true, errmsg)) != 0) {
			*out = strdup(errmsg.empty() ? "queue item error" : errmsg.c_str());
			return 0;
		}

		const int cluster = 1;
		ssqa.begin(JOB_ID_KEY(cluster, 0), false);

		const bool placement = (mode == SUBMIT_ORACLE_MODE_PLACEMENT);
		std::string result;
		JOB_ID_KEY jid;
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

extern "C" void submit_oracle_free(char *p) { free(p); }
