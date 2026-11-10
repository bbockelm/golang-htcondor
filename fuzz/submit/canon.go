// Package fuzzsubmit holds the differential fuzz target comparing the native Go
// submit-file parser against HTCondor's reference C++ SubmitHash
// (src/condor_utils/submit_utils.cpp). See README.md for design and usage.
package fuzzsubmit

import (
	"fmt"
	"sort"
	"strconv"
	"strings"

	"github.com/PelicanPlatform/classad/classad"
)

// AdKey identifies one ad in a submission. Proc is -1 for the cluster ad.
type AdKey struct {
	Cluster int
	Proc    int
}

func (k AdKey) String() string { return strconv.Itoa(k.Cluster) + "." + strconv.Itoa(k.Proc) }

// Ads is one side's view of a submission: the attributes of each ad it
// produced, keyed by ad.
type Ads struct {
	// ByKey maps an ad to its attributes. Attribute names are kept as the
	// producing side spelled them; lookups must fold case, since ClassAd
	// attribute names are case-insensitive.
	ByKey map[AdKey]map[string]string
	// Truncated is set when the queue statement asked for more procs than the
	// cap, so the two sides must only be compared over the procs present.
	Truncated bool
}

// Keys returns the ad keys in a stable order: the cluster ad first, then procs
// in numeric order.
func (a Ads) Keys() []AdKey {
	keys := make([]AdKey, 0, len(a.ByKey))
	for k := range a.ByKey {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool {
		if keys[i].Cluster != keys[j].Cluster {
			return keys[i].Cluster < keys[j].Cluster
		}
		return keys[i].Proc < keys[j].Proc
	})
	return keys
}

// ParseCanon decodes the oracle's canonical encoding (see oracle/shim.h):
// "#ad <cluster>.<proc>" header lines, then "<Name>\x1f<value>" attribute
// lines, optionally ending with "#truncated".
func ParseCanon(s string) (Ads, error) {
	ads := Ads{ByKey: make(map[AdKey]map[string]string)}
	var cur map[string]string
	for _, line := range strings.Split(s, "\n") {
		if line == "" {
			continue
		}
		if line == "#truncated" {
			ads.Truncated = true
			continue
		}
		if rest, ok := strings.CutPrefix(line, "#ad "); ok {
			key, err := parseAdKey(rest)
			if err != nil {
				return ads, err
			}
			cur = make(map[string]string)
			ads.ByKey[key] = cur
			continue
		}
		name, value, ok := strings.Cut(line, "\x1f")
		if !ok {
			return ads, fmt.Errorf("malformed attribute line %q", line)
		}
		if cur == nil {
			return ads, fmt.Errorf("attribute line %q before any #ad header", line)
		}
		cur[name] = value
	}
	return ads, nil
}

func parseAdKey(s string) (AdKey, error) {
	c, p, ok := strings.Cut(s, ".")
	if !ok {
		return AdKey{}, fmt.Errorf("malformed ad header %q", s)
	}
	cluster, err := strconv.Atoi(c)
	if err != nil {
		return AdKey{}, fmt.Errorf("malformed cluster in ad header %q: %w", s, err)
	}
	proc, err := strconv.Atoi(p)
	if err != nil {
		return AdKey{}, fmt.Errorf("malformed proc in ad header %q: %w", s, err)
	}
	return AdKey{Cluster: cluster, Proc: proc}, nil
}

// lookupFold finds an attribute however either side spelled it. ClassAd
// attribute names are case-insensitive, so a case difference is not a
// divergence.
func lookupFold(attrs map[string]string, name string) (string, bool) {
	if v, ok := attrs[name]; ok {
		return v, true
	}
	for k, v := range attrs {
		if strings.EqualFold(k, name) {
			return v, true
		}
	}
	return "", false
}

// namesFold returns the attribute names of an ad, lowercased and sorted, so the
// two sides' name sets can be compared without case noise.
func namesFold(attrs map[string]string) []string {
	out := make([]string, 0, len(attrs))
	for k := range attrs {
		out = append(out, strings.ToLower(k))
	}
	sort.Strings(out)
	return out
}

// sameValue reports whether two rendered attribute values mean the same thing.
//
// The two sides print ClassAd values with different unparsers, so comparing the
// text directly reports differences that are pure formatting (0.0 vs 0.000000,
// spacing inside an expression). Both are parsed as ClassAd expressions and
// compared structurally; text comparison is the fallback for anything that does
// not parse.
func sameValue(a, b string) bool {
	if a == b {
		return true
	}
	ea, erra := classad.ParseExpr(a)
	eb, errb := classad.ParseExpr(b)
	if erra != nil || errb != nil || ea == nil || eb == nil {
		return false
	}
	return ea.Equal(eb)
}
