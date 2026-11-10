package utilization

import (
	"fmt"
	"math"
	"strings"

	"github.com/PelicanPlatform/classad/classad"
)

// GPUs a job held, and GPU usage that could have come from them.
//
// GPUsAverageUsage (and the running job's GPUsUsage) is GPU-seconds busy
// per second, summed over the job's GPUs: a job holding two GPUs can
// report at most 2.0. Execute points sometimes report far more -- 53.67,
// 12973.47, 110688.3 from jobs holding two or four GPUs -- and a value
// like that is not a measurement of anything. It is treated as missing,
// not clamped: clamped to the GPUs held it would read as a job keeping
// every GPU fully busy, which is a claim nobody measured.
//
// The bound is the GPUs the job HAD, not the GPUs it asked for: a job
// asking for one GPU can be matched to a slot with two, hold both, and
// keep both busy.

// GPUUsageTolerance is how far above the GPUs held a usage figure may go
// and still count: sampling jitter puts a fully busy GPU at 1.004.
const GPUUsageTolerance = 0.01

// GPUsHeld is how many GPUs a job had: GPUsProvisioned, else the number
// of distinct ids in AssignedGPUs, else RequestGPUs. ok is false when
// none of them is known.
func GPUsHeld(provisioned Num, assigned string, request Num) (held float64, ok bool) {
	if provisioned.OK() && provisioned.V() > 0 {
		return provisioned.V(), true
	}
	if n := distinctGPUIDs(assigned); n > 0 {
		return float64(n), true
	}
	if request.OK() && request.V() >= 0 {
		return request.V(), true
	}
	return 0, false
}

// GPUsHeldFromAd is GPUsHeld read from a job ad.
func GPUsHeldFromAd(ad *classad.ClassAd) (float64, bool) {
	assigned, _ := ad.EvaluateAttrString("AssignedGPUs")
	return GPUsHeld(numAttr(ad, "GPUsProvisioned"), assigned, numAttr(ad, "RequestGPUs"))
}

// distinctGPUIDs counts the distinct device ids in an AssignedGPUs list.
func distinctGPUIDs(assigned string) int {
	seen := map[string]bool{}
	for _, id := range strings.FieldsFunc(assigned, func(r rune) bool { return r == ',' || r == ' ' || r == '\t' }) {
		seen[id] = true
	}
	return len(seen)
}

// PlausibleGPUUsage reports whether usage -- GPUs kept busy, summed over
// the job's GPUs -- could have come from held GPUs.
func PlausibleGPUUsage(usage, held float64) bool {
	return !math.IsNaN(usage) && !math.IsInf(usage, 0) && usage >= 0 && usage <= held*(1+GPUUsageTolerance)
}

// GPUUsageAttrs are the job attributes that carry GPU usage in GPUs kept
// busy: the run's average, and the running job's recent figure.
var GPUUsageAttrs = []string{"GPUsAverageUsage", "GPUsUsage"}

// ImplausibleGPUUsage names the GPU usage attributes of a job ad that
// exceed the GPUs the job held. A job whose GPUs are not known at all
// has nothing to compare with, and none are named.
func ImplausibleGPUUsage(ad *classad.ClassAd) []string {
	held, ok := GPUsHeldFromAd(ad)
	if !ok {
		return nil
	}
	var out []string
	for _, name := range GPUUsageAttrs {
		if u := numAttr(ad, name); u.OK() && !PlausibleGPUUsage(u.V(), held) {
			out = append(out, name)
		}
	}
	return out
}

// GPUUsageSampleFilter is a ClassAd expression true for a resource sample
// whose attr -- a GPU usage in GPUs kept busy -- is plausible. A sample
// records the job's RequestGpus; it is the bound unless the sample also
// carries a larger GPUsProvisioned.
func GPUUsageSampleFilter(attr string) string {
	return fmt.Sprintf("%[1]s >= 0 && %[1]s <= %[2]g * ifThenElse(GPUsProvisioned isnt undefined && GPUsProvisioned > RequestGpus, GPUsProvisioned, RequestGpus)",
		attr, 1+GPUUsageTolerance)
}
