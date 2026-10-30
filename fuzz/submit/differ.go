package fuzzsubmit

import (
	"fmt"
	"sort"
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
	"iwd":                  "the process's working directory",
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
	"jobprio":                  "C++ defaults JobPrio to 0; Go omits it.",
	"jobnotification":          "C++ defaults it; Go omits it.",
	"leavejobinqueue":          "C++ defaults it to false; Go omits it.",
	"maxhosts":                 "C++ defaults it to 1; Go omits it.",
	"minhosts":                 "C++ defaults it to 1; Go omits it.",
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
	"cmd":           "C++ resolves the executable against Iwd into an absolute path; Go stores the relative name as written. Found by the fuzzer, not by a seed.",
	"userlog":       "C++ resolves the log path against Iwd into an absolute path; Go stores the relative name as written.",

	// Attributes only the Go side produces.
	"transferexecutable": "Go always sets it; C++ only when the submit file asks.",
	"emailattributes":    "Go sets it; C++ has no such attribute here.",
	"jobruncount":        "Go sets it; C++ does not.",
	"requestdisk":        "C++ puts a MAX(...) expression on the cluster ad; Go emits its own value on the proc.",
	"requestgpumemory":   "Go turns request_gpu_memory into RequestGpuMemory; C++ lists request_gpu_memory as a disallowed keyword (f_error in prunable_keywords), warns that gpus_minimum_memory was probably meant, and sets no attribute.",
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
		for _, n := range namesFold(c) {
			cv, _ := lookupFold(c, n)
			gv, present := lookupFold(g, n)
			switch {
			case !present:
				record(&fresh, seenKnown, Divergence{Ad: key, Attr: n, Cpp: cv, Kind: "only-cpp"})
			case !sameValue(cv, gv):
				record(&fresh, seenKnown, Divergence{Ad: key, Attr: n, Cpp: cv, Go: gv, Kind: "value"})
			}
		}
		for _, n := range namesFold(g) {
			if _, present := lookupFold(c, n); !present {
				gv, _ := lookupFold(g, n)
				record(&fresh, seenKnown, Divergence{Ad: key, Attr: n, Go: gv, Kind: "only-go"})
			}
		}
	}
	sort.Slice(fresh, func(i, j int) bool { return fresh[i].String() < fresh[j].String() })
	return fresh, seenKnown
}

func record(fresh *[]Divergence, seenKnown map[string]bool, d Divergence) {
	attr := strings.ToLower(d.Attr)
	if _, skip := hostDerived[attr]; skip {
		return
	}
	if _, known := knownDivergent[attr]; known {
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
