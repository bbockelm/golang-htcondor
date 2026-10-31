package fuzzsubmit

import (
	"fmt"
	"sort"
	"strconv"
	"strings"
)

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
