package httpserver

import (
	"github.com/PelicanPlatform/classad/classad"
)

// usageAttrsToEvaluate are job attributes that HTCondor stores as expressions
// but that every consumer wants as a number.
//
// The motivating case is MemoryUsage, which the schedd writes as
//
//	MemoryUsage = ((ResidentSetSize + 1023) / 1024)
//
// A ClassAd carrying an expression serialises to JSON as the literal string
// "/Expr(((ResidentSetSize + 1023) / 1024))/" -- see ClassAd.marshalValue --
// so the API was handing clients an expression where they expected a number,
// and the Web UI rendered a dash for a job that had plainly used memory.
//
// Deliberately a short allowlist rather than "evaluate everything". A job ad
// is full of expressions that are meant to stay expressions: Requirements,
// periodic policy, JobLeaseDuration formulas. Those describe rules, and
// collapsing them to whatever they happen to evaluate to right now would
// destroy information an operator reads the raw ad to see. These few are
// different: they are measurements that merely happen to be recorded as
// arithmetic over other measurements.
var usageAttrsToEvaluate = []string{
	// Resource usage, in the units HTCondor reports them.
	"MemoryUsage",
	"DiskUsage",
	"CpusUsage",
	"GpusUsage",
	// Image/size accounting, occasionally expressed in terms of the above.
	"ImageSize",
	"ResidentSetSize",
	"ExecutableSize",
}

// evaluateUsageAttrs replaces expression-valued usage attributes with their
// evaluated numbers, in place.
//
// Evaluating and writing back is a no-op for an attribute the schedd already
// wrote as a literal -- the value evaluates to itself -- so there is no need
// to first ask whether the value is an expression, and no risk of the answer
// drifting from the marshaller's own idea of what counts as one.
//
// An attribute that does NOT evaluate to a number is left exactly as it was.
// That covers the case worth being careful about: a projection that omitted
// ResidentSetSize leaves MemoryUsage referring to something absent, and the
// honest result is the visible "/Expr(...)/", not a silently invented number.
// The integer/real distinction is preserved so a byte count does not acquire
// a decimal point on its way through.
func evaluateUsageAttrs(ad *classad.ClassAd) {
	if ad == nil {
		return
	}
	for _, name := range usageAttrsToEvaluate {
		if _, ok := ad.Lookup(name); !ok {
			continue
		}
		v := ad.EvaluateAttr(name)
		switch {
		case v.IsInteger():
			if n, err := v.IntValue(); err == nil {
				_ = ad.Set(name, n)
			}
		case v.IsReal():
			if f, err := v.RealValue(); err == nil {
				_ = ad.Set(name, f)
			}
		}
	}
}
