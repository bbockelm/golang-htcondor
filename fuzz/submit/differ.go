package fuzzsubmit

import (
	"fmt"
	"sort"
	"strconv"
	"strings"
)

// hostDerived are attributes whose value comes from the clock, the machine or
// the account running the parse rather than from the submit file. The two sides
// cannot agree on them by construction -- the C++ oracle is pinned to a fixed
// submit time and user, and the Go parser reads the real clock -- so they are
// never compared. This list must stay SHORT and justified: every name here is a
// hole in the oracle.
var hostDerived = map[string]string{
	"qdate":                "submit time; the oracle is pinned to a fixed clock",
	"enteredcurrentstatus": "submit time",
	"condorversion":        "version of the binary that parsed the file",
	"condorplatform":       "platform of the binary that parsed the file",
	"submitversion":        "version of the binary that parsed the file",
	"filesystemdomain":     "the parsing host's FILESYSTEM_DOMAIN",
	"owner":                "the account running the parse",
	"user":                 "the account running the parse",
	"globaljobid":          "embeds the schedd name and submit time",
	// These four are computed by stat()ing the executable, which the oracle
	// deliberately does not do (setDisableFileChecks), so neither side has a
	// meaningful value to compare.
	"diskusage":           "stat of the executable",
	"executablesize":      "stat of the executable",
	"imagesize":           "stat of the executable",
	"transferinputsizemb": "stat of the input files",
}

// knownDivergent are attributes the two parsers genuinely disagree about today.
// Each entry is a finding, not an excuse: the reason says what the difference
// is, so the list reads as the inventory of Go/C++ submit drift. Removing an
// entry is how a fix gets locked in -- see TestKnownDivergencesStillDiverge,
// which fails when one of these starts agreeing.
var knownDivergent = map[string]string{
	"shouldtransferfiles": `C++ defaults to "IF_NEEDED", Go to "YES". Changes whether the job transfers files when it lands on a machine sharing a filesystem.`,
	"requirements":        `different expressions entirely: C++ pins TARGET.Arch/OpSys to the submitting machine's values and adds Disk and FileSystemDomain||HasFileTransfer clauses; Go emits "isnt undefined" for Arch/OpSys and adds a TARGET.Cpus clause.`,
	"rank":                `C++ emits the real 0.0, Go the integer 0. Same value, different ClassAd type.`,

	// Attributes only the C++ side produces. Most are per-job bookkeeping
	// counters the schedd would otherwise fill in, but several change behavior.
	"environment":              "C++ always sets it (empty when unspecified); Go omits it when the submit file says nothing.",
	"jobleaseduration":         "C++ sets JobLeaseDuration (2400 by default, from JOB_DEFAULT_LEASE_DURATION); Go omits it. A job ad with no lease tells the schedd not to hold the claim across a disconnect.",
	"jobprio":                  "C++ defaults JobPrio to 0; Go omits it.",
	"jobnotification":          "C++ defaults it; Go omits it.",
	"leavejobinqueue":          "C++ defaults it to false; Go omits it.",
	"mytype":                   `C++ sets MyType = "Job"; Go omits it.`,
	"targettype":               `C++ sets TargetType = "Machine"; Go omits it.`,
	"exitstatus":               "C++ defaults it to 0; Go omits it.",
	"exitbysignal":             "C++ defaults it to false; Go omits it.",
	"currenthosts":             "C++ defaults it to 0; Go omits it.",
	"jobsubmitmethod":          "C++ records how the job was submitted; Go omits it.",
	"numckpts":                 "C++ zeroes the checkpoint counters; Go omits them.",
	"numjobcompletions":        "C++ zeroes the completion counter; Go omits it.",
	"lastsuspensiontime":       "C++ zeroes the suspension counters; Go omits them.",
	"totalsuspensions":         "C++ zeroes the suspension counters; Go omits them.",
	"committedtime":            "C++ zeroes the accounting counters; Go omits them.",
	"committedslottime":        "C++ zeroes the accounting counters; Go omits them.",
	"committedsuspensiontime":  "C++ zeroes the accounting counters; Go omits them.",
	"cumulativeslottime":       "C++ zeroes the accounting counters; Go omits them.",
	"cumulativesuspensiontime": "C++ zeroes the accounting counters; Go omits them.",
	"cumulativeremotesyscpu":   "C++ zeroes the accounting counters; Go omits them.",
	"cumulativeremoteusercpu":  "C++ zeroes the accounting counters; Go omits them.",
	"remotesyscpu":             "C++ zeroes the accounting counters; Go omits them.",
	"remoteusercpu":            "C++ zeroes the accounting counters; Go omits them.",
	"remotewallclocktime":      "C++ zeroes the accounting counters; Go omits them.",

	"args":          `empty arguments: C++ emits Arguments (V2 syntax), Go emits Args (V1). The attribute NAME differs, which changes how the starter splits them.`,
	"arguments":     `the other half of the Args/Arguments naming split above.`,
	"requestcpus":   "when the submit file does not say, Go synthesizes RequestCpus=1; C++ sets nothing and lets the negotiator apply the pool default.",
	"requestmemory": "when the submit file does not say, Go synthesizes RequestMemory=128; C++ sets nothing.",

	// Attributes only the Go side produces.
	"transferexecutable": "Go always sets it; C++ only when the submit file asks.",
	"jobruncount":        "Go sets it; C++ does not.",
	"requestdisk":        "C++ puts a MAX(...) expression on the cluster ad; Go emits its own value on the proc.",
	"requestgpumemory":   "Go turns request_gpu_memory into RequestGpuMemory; C++ lists request_gpu_memory as a disallowed keyword (f_error in prunable_keywords), warns that gpus_minimum_memory was probably meant, and sets no attribute.",
}

// knownDivergentGenerated is the inventory the keyword-table generator added
// (see gen.go). The hand-written seed corpus reached 17 of HTCondor's 258
// submit keywords; generating files from the keyword table reached most of the
// rest, and these are what the comparison found there. They are divided three
// ways by what the difference IS:
//
//   - the Go parser has no code for the keyword, so the setting is silently
//     dropped from the job;
//   - the Go parser writes the SUBMIT KEYWORD's name as the attribute name
//     where HTCondor writes the job attribute (VM_Memory vs JobVMMemory,
//     CronWindow vs DeferralWindow). The ad looks populated and nothing reads
//     it. Both halves of such a pair are listed, under each name;
//   - both sides write the attribute and the VALUES differ.
//
// Kept separate from knownDivergent above so the provenance of a finding stays
// visible; record() consults both.
//
// gosec flags this map for "hardcoded credentials": the keys are ClassAd
// attribute names, several of which are named after cloud credentials.
//
//nolint:gosec // G101: attribute names, not secrets
var knownDivergentGenerated = map[string]string{
	"commoninputfiles":                  "the Go parser does not implement `transfer_common_input`: C++ sets this attribute, Go sets nothing.",
	"delegatejobgsicredentialslifetime": "the Go parser does not implement `DelegateJobGSICredentialsLifetime`: C++ sets this attribute, Go sets nothing.",
	"env":                               "empty-ish or V1 environments: Go emits Env (V1), C++ emits Environment (V2). The attribute NAME differs, which changes how the starter splits it -- the same split as Args/Arguments.",
	"gpusmaxcapability":                 "the Go parser does not implement `gpus_maximum_capability`: C++ sets this attribute, Go sets nothing.",
	"gpusmincapability":                 "the Go parser does not implement `gpus_minimum_capability`: C++ sets this attribute, Go sets nothing.",
	"jobleaseduration":                  "C++ raises a short `job_lease_duration` to its 20-second floor; Go stores whatever was written.",
	"jobstarterdebug":                   "`starter_log` without a `starter_debug` makes SetAutoAttributes default JobStarterDebug to true; Go writes the keyword but not the derived default, so the starter log it was asked for is never written.",
	"jobrequiressandbox":                "C++ derives it from the transfer settings; Go does not.",
	"maxjobretirementtime":              "the Go parser does not implement `max_job_retirement_time`: C++ sets this attribute, Go sets nothing.",
	"niceuser":                          "Go writes NiceUser even when `nice_user` is false; C++ omits it.",
	"projectname":                       "the Go parser does not implement `project_name`: C++ sets this attribute, Go sets nothing.",
	"scheddinterval":                    "a cron_* schedule makes C++ write ScheddInterval so the deferral clause of its generated Requirements can read it; Go generates neither that clause nor the attribute. Tied to the Requirements divergence above, not to the cron attributes, which now agree.",
	"scitokensfile":                     "the Go parser does not implement `scitokens_file`: C++ sets this attribute, Go sets nothing.",
	"transferinput":                     "a container job's image now reaches TransferInput; the keywords that feed it from a java job -- the entry class and jar_files -- are still added by C++ and by nothing in Go, and a filename containing a space is split away rather than kept as one entry.",
	"transferoutputremaps":              "C++ keeps the remap string verbatim; Go rewrites it, dropping the spaces around = and ;.",
	"transformonevict":                  "the Go parser does not implement `on_evict_checks`, the other writer of this attribute, so it cannot be compared file by file. What the memory retry family writes to it IS checked against the oracle, in TestOnEvictMemoryTransformMatchesOracle.",
	"wantioproxy":                       "the Go parser does not implement `want_io_proxy`: C++ sets this attribute, Go sets nothing.",
	"wantparallelscheduling":            "the Go parser does not implement `WantParallelScheduling`: C++ sets this attribute, Go sets nothing.",
}

// knownDivergentPrefix covers families of attributes whose names are not fixed,
// so they cannot be listed by name. Checked after knownDivergent.
//
// Empty: the one family that was here, Request<Tag> from a generic
// request_<tag> command, now agrees. Keeping the entry would have gone on
// excusing every Request* attribute the Go side failed to produce, which is
// the whole class of bug the fix was for.
var knownDivergentPrefix = []struct {
	prefix string
	reason string
}{}

// Divergence is one attribute the two sides disagree about.
type Divergence struct {
	Ad   AdKey
	Attr string
	Cpp  string // "" when absent
	Go   string // "" when absent
	Kind string // "only-cpp", "only-go" or "value"
}

func (d Divergence) String() string {
	switch d.Kind {
	case "only-cpp":
		return fmt.Sprintf("%s %s: only C++ has it (=%s)", d.Ad, d.Attr, d.Cpp)
	case "only-go":
		return fmt.Sprintf("%s %s: only Go has it (=%s)", d.Ad, d.Attr, d.Go)
	default:
		return fmt.Sprintf("%s %s: cpp=%s go=%s", d.Ad, d.Attr, d.Cpp, d.Go)
	}
}

// Compare returns the divergences between the two sides that are neither
// host-derived nor already known, plus the subset of known ones that showed up
// (so a test can tell when a known divergence has been FIXED).
//
// Only ads both sides produced are compared attribute by attribute; a missing
// ad is reported on its own, since comparing its attributes would bury the
// bigger fact that one side made a different number of jobs.
func Compare(cpp, goAds Ads) (fresh []Divergence, seenKnown map[string]bool) {
	seenKnown = make(map[string]bool)

	cppKeys, goKeys := cpp.Keys(), goAds.Keys()
	if len(cppKeys) != len(goKeys) {
		return []Divergence{{
			Attr: "#procs",
			Kind: "value",
			Cpp:  fmt.Sprint(adKeyList(cppKeys)),
			Go:   fmt.Sprint(adKeyList(goKeys)),
		}}, seenKnown
	}

	for _, key := range cppKeys {
		c := cpp.ByKey[key]
		g, ok := goAds.ByKey[key]
		if !ok {
			fresh = append(fresh, Divergence{Ad: key, Attr: "#ad", Kind: "only-cpp"})
			continue
		}
		// The universe comes from the C++ ad: it is the side that decides
		// what the universe means, and a Go bug that drops JobUniverse must
		// not also hand itself an excuse.
		universe, _ := universeOf(c)

		for _, n := range namesFold(c) {
			cv, _ := lookupFold(c, n)
			gv, present := lookupFold(g, n)
			switch {
			case !present:
				record(&fresh, seenKnown, universe, Divergence{Ad: key, Attr: n, Cpp: cv, Kind: "only-cpp"})
			case !sameValue(cv, gv):
				record(&fresh, seenKnown, universe, Divergence{Ad: key, Attr: n, Cpp: cv, Go: gv, Kind: "value"})
			}
		}
		for _, n := range namesFold(g) {
			if _, present := lookupFold(c, n); !present {
				gv, _ := lookupFold(g, n)
				record(&fresh, seenKnown, universe, Divergence{Ad: key, Attr: n, Go: gv, Kind: "only-go"})
			}
		}
	}
	sort.Slice(fresh, func(i, j int) bool { return fresh[i].String() < fresh[j].String() })
	return fresh, seenKnown
}

// knownDivergentInUniverse excuses an attribute only inside one job universe.
//
// It exists so a quirk of a single universe cannot excuse that attribute
// everywhere. Putting "cmd" in knownDivergent would have undone the Cmd/UserLog
// path comparison, which is the whole point of having it compared.
var knownDivergentInUniverse = map[int]map[string]string{
	universeJava: {
		"cmd": "for universe = java C++ replaces Cmd with the JVM from param(\"JAVA\") and passes the submitted class through Args; Go leaves the resolved executable in Cmd, so the job would run the class file instead of a JVM.",
	},
}

// universeJava is CONDOR_UNIVERSE_JAVA (condor_includes/condor_universe.h).
const universeJava = 10

// universeOf reports the JobUniverse an ad resolves to. The attribute is an
// integer literal in both parsers' output, so no evaluation is needed.
func universeOf(attrs map[string]string) (int, bool) {
	v, ok := lookupFold(attrs, "JobUniverse")
	if !ok {
		return 0, false
	}
	n, err := strconv.Atoi(strings.TrimSpace(v))
	if err != nil {
		return 0, false
	}
	return n, true
}

func record(fresh *[]Divergence, seenKnown map[string]bool, universe int, d Divergence) {
	attr := strings.ToLower(d.Attr)
	if byAttr, ok := knownDivergentInUniverse[universe]; ok {
		if _, known := byAttr[attr]; known {
			seenKnown[attr] = true
			return
		}
	}
	if _, skip := hostDerived[attr]; skip {
		return
	}
	if _, known := knownDivergent[attr]; known {
		seenKnown[attr] = true
		return
	}
	if _, known := knownDivergentGenerated[attr]; known {
		seenKnown[attr] = true
		return
	}
	// Prefix families only excuse an attribute the Go side never produced. If
	// both sides produce one and the VALUES differ, that is a fresh finding
	// about an attribute Go does understand, and it must not be swallowed here.
	if d.Kind == "only-cpp" {
		for _, kp := range knownDivergentPrefix {
			if strings.HasPrefix(attr, kp.prefix) {
				seenKnown[kp.prefix+"*"] = true
				return
			}
		}
	}
	*fresh = append(*fresh, d)
}

func adKeyList(keys []AdKey) []string {
	out := make([]string, 0, len(keys))
	for _, k := range keys {
		out = append(out, k.String())
	}
	return out
}
