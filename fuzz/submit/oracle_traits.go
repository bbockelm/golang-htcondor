package fuzzsubmit

import (
	"fmt"
	"sort"
	"strings"

	htcondor "github.com/bbockelm/golang-htcondor"
	"github.com/bbockelm/golang-htcondor/fuzz/submit/oracle"
)

// Oracle traits: which upstream changes the linked HTCondor carries.
//
// The same tree is compared against two different C++ parsers. Pull-request CI
// pins a release, and the nightly builds the oracle from HTCondor's main
// branch, which moves. A change to condor_submit therefore shows up as a
// divergence in the nightly long before the pinned oracle has it, and once the
// Go side is fixed ahead of the release the divergence shows up against the
// PIN instead. Both are expected, and neither should fail.
//
// A recorded divergence can say which side of one upstream change it belongs
// to, by naming a trait; see divergences/README.md. An entry whose trait does
// not match the linked oracle is dropped at startup, so it neither excuses a
// divergence that oracle should not produce nor is swept as stale.
//
// Traits are decided by PROBING the oracle, never by reading its version
// string. Upstream backports across release branches, so one change can reach
// a 25.x patch release and a 26.x release with no version number between them
// that separates the two, and a numeric threshold would be wrong the moment
// the pin moves.

// oracleFacts is what the probes get to look at: one run of the oracle per
// shape, taken once, so a probe is a cheap predicate over facts rather than
// its own call into C++.
type oracleFacts struct {
	// vanilla is proc 0 of the simplest possible submit file.
	vanilla map[string]string
	// local is proc 0 of that same file in the local universe, where the
	// resource defaults and the Requirements expression differ.
	local map[string]string
	// keyword is the oracle's own submit-keyword table, keyed by the
	// lower-cased keyword.
	keyword map[string]oracle.Keyword
}

// has reports whether an ad carries an attribute, folding case.
func (f oracleFacts) has(ad map[string]string, attr string) bool {
	_, ok := lookupFold(ad, attr)
	return ok
}

// oracleTrait is one upstream change the linked HTCondor either has or does
// not. The ticket is the identity -- it is what the entry files name, and what
// a reader greps for in HTCondor's history.
type oracleTrait struct {
	ticket string
	// what the change does, in one line, for the report.
	what string
	// probe reports whether the oracle HAS the change.
	probe func(oracleFacts) bool
}

// oracleTraits are the upstream changes recorded divergences currently need to
// distinguish. A trait earns its place by being named in an entry file; an
// unnamed one is checked by TestEveryTraitIsNamed and removed.
var oracleTraits = []oracleTrait{
	{
		ticket: "HTCONDOR-4020",
		what:   "the base job ad no longer carries ExitStatus",
		probe:  func(f oracleFacts) bool { return !f.has(f.vanilla, "ExitStatus") },
	},
	{
		ticket: "HTCONDOR-3998",
		what:   "the base job ad no longer carries the zeroed run-time counters",
		probe:  func(f oracleFacts) bool { return !f.has(f.vanilla, "RemoteUserCpu") },
	},
	{
		ticket: "HTCONDOR-3998-remoteio",
		what:   "standard-universe RemoteIO is gone, with its buffer_* keywords",
		probe:  func(f oracleFacts) bool { _, ok := f.keyword["buffer_size"]; return !ok },
	},
	{
		ticket: "HTCONDOR-3932",
		what:   "the vanilla Requirements no longer carries the versioned disk clause",
		probe: func(f oracleFacts) bool {
			req, _ := lookupFold(f.vanilla, "Requirements")
			return !strings.Contains(req, "RequestDisk")
		},
	},
	{
		ticket: "HTCONDOR-3926",
		what:   "the local and scheduler universes get no default resource requests",
		probe:  func(f oracleFacts) bool { return !f.has(f.local, "RequestCpus") },
	},
	{
		ticket: "HTCONDOR-2015",
		what:   "the annex submit commands exist",
		probe:  func(f oracleFacts) bool { _, ok := f.keyword["annex_name"]; return ok },
	},
	{
		ticket: "HTCONDOR-3065",
		what:   "min_condor_version and max_condor_version exist",
		probe:  func(f oracleFacts) bool { _, ok := f.keyword["min_condor_version"]; return ok },
	},
	{
		ticket: "HTCONDOR-3955",
		what:   "common_input_files is spelled require_common_files",
		probe:  func(f oracleFacts) bool { _, ok := f.keyword["require_common_files"]; return ok },
	},
	{
		ticket: "HTCONDOR-4053",
		what:   "the batch cpu/node submit commands exist",
		probe:  func(f oracleFacts) bool { _, ok := f.keyword["batch_whole_nodes"]; return ok },
	},
	{
		ticket: "HTCONDOR-3932-container",
		what:   "container_is_common is parsed specially and targets no attribute",
		probe: func(f oracleFacts) bool {
			k, ok := f.keyword["container_is_common"]
			return ok && k.Attr == ""
		},
	},
}

// probeMinimal is the submit file the facts are taken from: the least that
// parses, so what the oracle writes into the ad is its own doing and not an
// echo of the file.
const probeMinimal = "executable = /bin/true\nqueue\n"

// gatherOracleFacts runs the oracle the few times the probes need.
func gatherOracleFacts() (oracleFacts, error) {
	var f oracleFacts

	adOf := func(src string) (map[string]string, error) {
		res := oracle.MakeAds(src, oracle.ModeAds, 1)
		if !res.OK {
			return nil, fmt.Errorf("the oracle rejected the probe file %q: %s", src, res.Err)
		}
		ads, err := ParseCanon(res.Ads)
		if err != nil {
			return nil, fmt.Errorf("probe file %q: %w", src, err)
		}
		for _, k := range ads.Keys() {
			if k.Proc == 0 {
				return ads.ByKey[k], nil
			}
		}
		return nil, fmt.Errorf("probe file %q produced no proc ad", src)
	}

	var err error
	if f.vanilla, err = adOf(probeMinimal); err != nil {
		return f, err
	}
	if f.local, err = adOf("universe = local\n" + probeMinimal); err != nil {
		return f, err
	}

	kws := oracle.Keywords()
	if len(kws) == 0 {
		return f, fmt.Errorf("the oracle reported no submit keywords, so no trait can be probed")
	}
	f.keyword = make(map[string]oracle.Keyword, len(kws))
	for _, k := range kws {
		f.keyword[strings.ToLower(k.Key)] = k
	}
	return f, nil
}

// oracleHas is the probe result, settled by TestMain: per ticket, whether the
// linked oracle carries that upstream change. It is read by the tests that
// have to know which HTCondor they are comparing against, and is empty when
// no oracle is linked.
//
//nolint:unused // set by TestMain and read by the tagged tests
var oracleHas map[string]bool

// keywordsAheadOfOracle are the submit keywords the Go parser knows and an
// older HTCondor does not, each with the ticket that added it upstream.
//
// Parsing one of these is not gated. A submit file naming `annex_name` means
// the same thing wherever it is submitted, and a library that refuses it
// against an older access point would be wrong about the FILE rather than
// faithful to the access point -- the ad it builds is what the schedd is
// asked to store, and an attribute an older schedd ignores costs nothing.
//
// So the Go table is legitimately ahead of a pinned oracle, and
// TestSimpleKeywordTableMatchesOracle has to be told which rows that applies
// to. Each one is allowed only while the oracle LACKS the named change: once
// the pin moves, the allowance stops applying and the row is compared like
// every other.
//
//nolint:unused // read by TestSimpleKeywordTableMatchesOracle
var keywordsAheadOfOracle = map[string]string{
	"annex_name":         "HTCONDOR-2015",
	"restrict_to_annex":  "HTCONDOR-2015",
	"min_condor_version": "HTCONDOR-3065",
	"max_condor_version": "HTCONDOR-3065",
}

// digestKeywordsBehindOracle are names a newer HTCondor prunes from a submit
// digest and this library does not prune yet, each with the change that added
// the keyword upstream.
//
// Leaving a key in the digest is the SAFE direction. A pruned key is one the
// schedd takes from the cluster ad instead of the digest, so keeping it only
// makes the digest larger than it needs to be -- every proc still gets the
// right value. The opposite, pruning a key HTCondor keeps, could drop a
// per-proc value, and that direction is still an error here.
//
// An entry is honored only while the oracle HAS the named change, so it
// lapses by itself if the pin moves to an HTCondor without it. Pruning these
// for real is a separate change: it means deciding, per keyword, that this
// library puts the attribute in the cluster ad in every case the schedd would
// have read it from the digest.
//
//nolint:unused // read by TestDigestKeywordsMatchOracle
var digestKeywordsBehindOracle = map[string]string{
	"annex_name":           "HTCONDOR-2015",
	"restrict_to_annex":    "HTCONDOR-2015",
	"targetannexname":      "HTCONDOR-2015",
	"restricttoannex":      "HTCONDOR-2015",
	"min_condor_version":   "HTCONDOR-3065",
	"max_condor_version":   "HTCONDOR-3065",
	"mincondorversion":     "HTCONDOR-3065",
	"maxcondorversion":     "HTCONDOR-3065",
	"batch_cpu_count":      "HTCONDOR-4053",
	"batch_cpus_per_node":  "HTCONDOR-4053",
	"batch_node_count":     "HTCONDOR-4053",
	"batch_whole_nodes":    "HTCONDOR-4053",
	"batchcpucount":        "HTCONDOR-4053",
	"batchcpuspernode":     "HTCONDOR-4053",
	"batchnodecount":       "HTCONDOR-4053",
	"batchwholenodes":      "HTCONDOR-4053",
	"require_common_files": "HTCONDOR-3955",
	"common_input_files":   "HTCONDOR-3955",
}

// digestKeywordsAheadOfOracle are names in this library's prunable-keyword
// table that a newer HTCondor does not have at all, because the change named
// here removed the submit keyword. It is the mirror of
// digestKeywordsBehindOracle: there the oracle knows a keyword we do not
// prune, here we prune a keyword the oracle no longer knows.
//
// Neither parser can put one of these in a digest. condor_submit does not
// recognize the keyword, and this library stops accepting it under the same
// trait, so the entry in the prunable table is inert rather than wrong. It is
// left in place because the table is generated for every HTCondor this
// library talks to, and an older schedd still writes digests with these keys.
//
// As with the other direction, an entry is honored only while the oracle HAS
// the named change.
//
//nolint:unused // read by TestDigestKeywordsMatchOracle
var digestKeywordsAheadOfOracle = map[string]string{
	"append_files":      "HTCONDOR-3998-remoteio",
	"appendfiles":       "HTCONDOR-3998-remoteio",
	"buffer_block_size": "HTCONDOR-3998-remoteio",
	"bufferblocksize":   "HTCONDOR-3998-remoteio",
	"buffer_files":      "HTCONDOR-3998-remoteio",
	"bufferfiles":       "HTCONDOR-3998-remoteio",
	"buffer_size":       "HTCONDOR-3998-remoteio",
	"buffersize":        "HTCONDOR-3998-remoteio",
	"compress_files":    "HTCONDOR-3998-remoteio",
	"compressfiles":     "HTCONDOR-3998-remoteio",
	"fetch_files":       "HTCONDOR-3998-remoteio",
	"fetchfiles":        "HTCONDOR-3998-remoteio",
	"file_remaps":       "HTCONDOR-3998-remoteio",
	"fileremaps":        "HTCONDOR-3998-remoteio",
	"local_files":       "HTCONDOR-3998-remoteio",
	"localfiles":        "HTCONDOR-3998-remoteio",
	"containeriscommon": "HTCONDOR-3932-container",
}

// digestKeywordDiff is one comparison of the two prunable-keyword tables, in
// four buckets: the two differences that are errors and the two an upstream
// change accounts for.
type digestKeywordDiff struct {
	missing []string // the oracle has it, we do not prune it, nothing excuses that
	extra   []string // we prune it, the oracle has no such keyword, nothing excuses that
	behind  []string // ditto missing, but a trait this oracle has accounts for it
	ahead   []string // ditto extra, but a trait this oracle has accounts for it
}

// classifyDigestKeywords splits the two tables into those buckets. It takes
// the oracle's keyword set, this library's prunable names and the probed
// traits as arguments rather than reading them, because the two allowances
// only ever fire against an HTCondor newer than the pinned one: no run with
// an oracle attached exercises them, and without this seam nothing local
// could. See TestDigestKeywordClassification.
func classifyDigestKeywords(want map[string]bool, prunable []string, have map[string]bool) digestKeywordDiff {
	var d digestKeywordDiff
	for name := range want {
		if htcondor.DigestKeywordIsPrunable(name) {
			continue
		}
		// A keyword this HTCondor has and we do not prune yet is the safe
		// direction; see digestKeywordsBehindOracle.
		if ticket, known := digestKeywordsBehindOracle[name]; known && have[ticket] {
			d.behind = append(d.behind, name)
			continue
		}
		d.missing = append(d.missing, name)
	}
	for _, name := range prunable {
		if want[name] {
			continue
		}
		// A keyword this HTCondor has dropped entirely: neither side can
		// put it in a digest, so the table naming it is inert. See
		// digestKeywordsAheadOfOracle.
		if ticket, known := digestKeywordsAheadOfOracle[name]; known && have[ticket] {
			d.ahead = append(d.ahead, name)
			continue
		}
		d.extra = append(d.extra, name)
	}
	sort.Strings(d.missing)
	sort.Strings(d.extra)
	sort.Strings(d.behind)
	sort.Strings(d.ahead)
	return d
}

// probeOracleTraits reports, per ticket, whether the linked oracle has that
// change.
func probeOracleTraits(f oracleFacts) map[string]bool {
	have := make(map[string]bool, len(oracleTraits))
	for _, tr := range oracleTraits {
		have[tr.ticket] = tr.probe(f)
	}
	return have
}

// goBehaviorFor is the other half of a trait: having probed what the oracle
// does, the Go side is asked to do the same thing.
//
// This is what makes a version-gated fix land without a red window. Once a
// behavior is gated and wired here, the two parsers agree against BOTH
// oracles -- the pinned release and HTCondor main -- and the entries that
// recorded the difference are deleted rather than flipped. An entry stays
// only for a difference the Go side cannot yet produce either way.
//
// A trait with no field here is not yet implemented on the Go side; its
// entries carry the difference instead.
func goBehaviorFor(have map[string]bool) htcondor.SubmitBehavior {
	return htcondor.SubmitBehavior{
		OmitExitStatus:             have["HTCONDOR-4020"],
		OmitZeroedRunTimeCounters:  have["HTCONDOR-3998"],
		OmitLeaveJobInQueueDefault: have["HTCONDOR-3998"],

		OmitVanillaDiskClause:    have["HTCONDOR-3932"],
		OmitTransferVersionCheck: have["HTCONDOR-3932"],

		OmitLocalAndSchedulerMachineChecks:    have["HTCONDOR-3926"],
		OmitLocalAndSchedulerResourceDefaults: have["HTCONDOR-3926"],

		OmitRemoteIOKeywords:      have["HTCONDOR-3998-remoteio"],
		OmitContainerIsCommonAttr: have["HTCONDOR-3932-container"],
	}
}

// describeTraits renders the probe result for the test log, so a run says
// which HTCondor it was comparing against in terms of behavior and not only
// the version banner.
func describeTraits(have map[string]bool) string {
	var b strings.Builder
	tickets := make([]string, 0, len(have))
	for t := range have {
		tickets = append(tickets, t)
	}
	sort.Strings(tickets)
	for _, t := range tickets {
		state := "lacks"
		if have[t] {
			state = "has"
		}
		fmt.Fprintf(&b, "\n  %-5s %s", state, t)
	}
	return b.String()
}
