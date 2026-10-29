package fuzzsubmit

import (
	"strings"

	htcondor "github.com/bbockelm/golang-htcondor"
)

// ClusterID is the cluster both sides submit into. The C++ shim hard-codes it,
// so the Go side must use the same value: $(Cluster) is expandable in a submit
// file and lands in the ads.
const ClusterID = 1

// MaxProcs caps how many procs either side materializes. A fuzzer writes
// `queue 100000000` sooner rather than later, and nothing is learned from the
// millionth proc that the third did not already show.
const MaxProcs = 8

// GoResult is the Go parser's view of a submit file, shaped like oracle.Result
// so the two can be compared without special-casing either.
type GoResult struct {
	OK  bool
	Ads Ads
	Err string
	// Panic is set when the Go parser panicked, which is a finding on its own.
	Panic bool
}

// GoMakeAds parses text with the Go submit parser and returns the resulting
// job ads.
//
// AllowLocalAccess stays OFF: `include command` runs a shell command and
// $ENV()/`queue from <file>` read the host, so a fuzzer-authored submit file
// must not reach the machine. The C++ oracle is given no such switch, which
// makes those constructs a known, documented divergence rather than something
// to compare.
func GoMakeAds(text string) (res GoResult) {
	defer func() {
		if r := recover(); r != nil {
			res = GoResult{Panic: true, Err: "panic in Go submit parser"}
		}
	}()

	sf, err := htcondor.ParseSubmitFile(strings.NewReader(text))
	if err != nil {
		return GoResult{Err: err.Error()}
	}
	sub, err := sf.Submit(ClusterID)
	if err != nil {
		return GoResult{Err: err.Error()}
	}

	ads := Ads{ByKey: make(map[AdKey]map[string]string)}
	for proc, ad := range sub.ProcAds {
		if proc >= MaxProcs {
			ads.Truncated = true
			break
		}
		attrs := make(map[string]string)
		for _, name := range ad.GetAttributes() {
			expr, ok := ad.Lookup(name)
			if !ok || expr == nil {
				continue
			}
			attrs[name] = expr.String()
		}
		ads.ByKey[AdKey{Cluster: ClusterID, Proc: proc}] = attrs
	}
	return GoResult{OK: true, Ads: ads}
}
