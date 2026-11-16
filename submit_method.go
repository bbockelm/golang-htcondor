package htcondor

import "context"

// JobSubmitMethod values. HTCondor records on every job how it was
// submitted, as an integer in ATTR_JOB_SUBMIT_METHOD, and condor_q turns
// the number back into a name. The attribute left undefined reads as
// "Unknown", which is what every job this library submits has said until
// now -- it is not condor_submit and declines to claim to be.
//
// 0 through 5 are HTCondor's own tools, named here so a caller stamping
// one does not have to hard-code a bare number. Anything from 100 up is
// the band HTCondor reserves for portals and other submitting services;
// condor_q displays the whole band as "Portal/User-set", so the
// individual values are for constraints rather than for display.
//
// 101 and 102 are this project's claim inside that band. They are split
// REST from MCP rather than naming one "htcondor-api", because the
// distinction a site needs is whether a person drove the submission or an
// agent did: `JobSubmitMethod == 102` is then a constraint a schedd's
// SUBMIT_REQUIREMENT can be written against, with no configuration here
// at all. Nothing outside this repository should stamp 101 or 102; a
// service that wants its own identity picks another number in the band,
// which collides with nobody who is not in the same pool.
const (
	// SubmitMethodUnset leaves ATTR_JOB_SUBMIT_METHOD off the job, which
	// reads as "Unknown". The zero value of an int is a real method
	// (condor_submit), so the absence of one is spelled negative, as
	// HTCondor spells it internally.
	SubmitMethodUnset = -1

	SubmitMethodCondorSubmit    = 0 // condor_submit
	SubmitMethodDAGMan          = 1 // DAGMan, submitting a node directly
	SubmitMethodPythonBindings  = 2 // the Python bindings
	SubmitMethodHTCJobSubmit    = 3 // htcondor job submit
	SubmitMethodHTCDAGSubmit    = 4 // htcondor dag submit
	SubmitMethodHTCJobsetSubmit = 5 // htcondor jobset submit

	// SubmitMethodPortal is the generic "a portal submitted this" value,
	// the bottom of the reserved band.
	SubmitMethodPortal = 100
	// SubmitMethodRESTAPI is a submission a person drove through this
	// project's HTTP API -- the REST endpoints and the web submission
	// page.
	SubmitMethodRESTAPI = 101
	// SubmitMethodMCP is a submission an agent drove through this
	// project's MCP server, including the jobs that carry a workflow, an
	// interactive session or a container build.
	SubmitMethodMCP = 102
)

type submitMethodKey struct{}

// WithSubmitMethod returns a context under which Schedd.Submit and
// Schedd.SubmitRemote stamp ATTR_JOB_SUBMIT_METHOD on every job of the
// submission, so that a job carries which service submitted it.
//
// A context rather than another parameter, for the reason given on
// [WithSubmitParams]: the submit methods are reached through interfaces
// that several callers and their test doubles implement, and the
// submitting service is a property of the submission in the same way the
// caller's credentials on the context are. It also means a surface sets
// it once, at its own door, and everything it reaches -- a workflow's
// manager job, an interactive session, a container build -- is stamped
// with it without those paths knowing the attribute exists.
//
// SubmitMethodUnset, or no call at all, stamps nothing.
func WithSubmitMethod(ctx context.Context, method int) context.Context {
	if method < 0 {
		return ctx
	}
	return context.WithValue(ctx, submitMethodKey{}, method)
}

// SubmitMethodFromContext reports the submitting service ctx names, or
// SubmitMethodUnset if it names none.
func SubmitMethodFromContext(ctx context.Context) int {
	if ctx == nil {
		return SubmitMethodUnset
	}
	if method, ok := ctx.Value(submitMethodKey{}).(int); ok {
		return method
	}
	return SubmitMethodUnset
}

// stampSubmitMethod records on every ad of a submission how it was
// submitted, if the context says.
//
// Called on the finished ads rather than during MakeJobAd, which is what
// makes the value the submitting service's rather than the submit file's.
// A submit file's `+JobSubmitMethod` is a custom attribute, and custom
// attributes are applied last inside MakeJobAd (see finishJobAd, which
// follows condor_submit's "SetForcedAttributes should be last so that it
// trumps values"). Stamping any earlier would let a submit file claim to
// be condor_submit, which is exactly the claim a site writing a
// SUBMIT_REQUIREMENT against this attribute needs to be unable to make.
//
// Both the cluster ad and the proc ads are stamped. For an ordinary
// submission ClusterAd is ProcAds[0] and is simply set twice; for a job
// factory ProcAds is empty and the cluster ad is the only one there is,
// the schedd materializing the procs from it.
func stampSubmitMethod(ctx context.Context, result *SubmitResult) {
	method := SubmitMethodFromContext(ctx)
	if method < 0 || result == nil {
		return
	}
	if result.ClusterAd != nil {
		result.ClusterAd.InsertAttr(attrJobSubmitMethod, int64(method))
	}
	for _, ad := range result.ProcAds {
		if ad != nil {
			ad.InsertAttr(attrJobSubmitMethod, int64(method))
		}
	}
}

// attrJobSubmitMethod is HTCondor's ATTR_JOB_SUBMIT_METHOD.
const attrJobSubmitMethod = "JobSubmitMethod"
