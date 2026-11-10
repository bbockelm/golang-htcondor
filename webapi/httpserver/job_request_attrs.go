package httpserver

import (
	"strings"

	"github.com/PelicanPlatform/classad/classad"
)

// requestAttrsToEvaluate are the resource requests a job page compares
// usage against.
//
// Unlike the usage attributes (see evaluateUsageAttrs), a request is often
// written as a rule rather than a number, e.g.
//
//	RequestMemory = ifthenelse(MemoryUsage =!= undefined, max({ 2048, 3 * MemoryUsage / 2 }), 2048)
//
// and the rule is what the user wrote, so it stays on the ad untouched. What
// a client cannot do without a ClassAd evaluator of its own is turn it into
// the number the job is asking for, so that number goes alongside it.
var requestAttrsToEvaluate = []string{
	"RequestCpus",
	"RequestMemory",
	"RequestDisk",
	"RequestGPUs",
}

// evaluatedRequestsKey is the member holding the evaluated requests. Lower
// case, like the other members the server adds to a job object (schedd,
// job_id, source, ...), so it does not read as a schedd attribute.
const evaluatedRequestsKey = "evaluated"

// annotateEvaluatedRequests adds an "evaluated" member to the ad holding the
// value each Request* attribute evaluates to in the job's own context
// (MY.MemoryUsage, MY.ResidentSetSize and so on), so a client reads one
// number whether the request was written as a literal or an expression.
//
// Only call this on a whole ad. An expression evaluated against a projection
// that left out an attribute it refers to evaluates as if that attribute
// were undefined -- the ifthenelse above would quietly answer 2048 -- and a
// wrong number is worse than none.
//
// A request that does not evaluate to a number (one that refers to the
// machine, say) is left out; the raw attribute is still on the ad. Nothing
// is added when no request evaluates.
func annotateEvaluatedRequests(ad *classad.ClassAd) {
	if ad == nil {
		return
	}
	out := classad.New()
	n := 0
	for _, name := range requestAttrsToEvaluate {
		if _, ok := ad.Lookup(name); !ok {
			continue
		}
		v := ad.EvaluateAttr(name)
		switch {
		case v.IsInteger():
			if i, err := v.IntValue(); err == nil {
				out.InsertAttr(name, i)
				n++
			}
		case v.IsReal():
			if f, err := v.RealValue(); err == nil {
				out.InsertAttrFloat(name, f)
				n++
			}
		}
	}
	if n == 0 {
		return
	}
	// An attribute of the same name (any case) would give the object two
	// spellings of one member; the server's member wins, as in RowJSON.
	for _, name := range ad.GetAttributes() {
		if strings.EqualFold(name, evaluatedRequestsKey) {
			ad.Delete(name)
		}
	}
	ad.InsertAttrClassAd(evaluatedRequestsKey, out)
}

// isWholeAdProjection reports whether a projection asks for every attribute,
// the case where annotateEvaluatedRequests can trust what it evaluates.
func isWholeAdProjection(projection []string) bool {
	for _, a := range projection {
		if a == "*" {
			return true
		}
	}
	return false
}
