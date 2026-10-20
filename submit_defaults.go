package htcondor

import (
	"context"
	"fmt"
	"strings"

	"github.com/PelicanPlatform/classad/classad"
)

// SubmitParams is where the submit engine reads the configuration knobs
// condor_submit reads with param() rather than from the submit file --
// today the JOB_DEFAULT_REQUEST* defaults a job gets when it omits a
// request_* command. *config.Config satisfies it.
//
// Get reports a knob's value and whether this source has an answer for
// it at all. An answer that is empty means "no value": the knob is
// unset, and condor_submit applies no default for it. No answer at all
// sends the engine to HTCondor's built-in default instead. The
// difference matters to a caller layering sources: an access point that
// says JOB_DEFAULT_REQUESTGPUS is unset has answered, and that answer
// must not be overridden by some other configuration that sets it.
type SubmitParams interface {
	Get(name string) (string, bool)
}

// SubmitParamMap is a SubmitParams over a fixed set of values, keyed by
// knob name in any case. A name absent from the map has no answer here.
type SubmitParamMap map[string]string

// Get implements SubmitParams.
func (m SubmitParamMap) Get(name string) (string, bool) {
	if v, ok := m[name]; ok {
		return v, true
	}
	for k, v := range m {
		if strings.EqualFold(k, name) {
			return v, true
		}
	}
	return "", false
}

type submitParamsKey struct{}

// WithSubmitParams returns a context under which Schedd.Submit and
// Schedd.SubmitRemote read the configuration knobs condor_submit takes
// from its own configuration (JOB_DEFAULT_REQUEST*) from params.
//
// condor_submit reads them from the configuration of the host it runs
// on, which for a user at an access point is the access point's. A
// program submitting on someone's behalf from elsewhere has to say whose
// configuration applies; without this the built-in defaults do.
//
// A context rather than another parameter, because the submit methods
// are reached through interfaces that several callers and their test
// doubles implement, and the defaults are a property of the submission
// in the same way the caller's credentials on the context are.
func WithSubmitParams(ctx context.Context, params SubmitParams) context.Context {
	if params == nil {
		return ctx
	}
	return context.WithValue(ctx, submitParamsKey{}, params)
}

// SubmitParamsFromContext returns the params WithSubmitParams attached,
// or nil.
func SubmitParamsFromContext(ctx context.Context) SubmitParams {
	if ctx == nil {
		return nil
	}
	p, _ := ctx.Value(submitParamsKey{}).(SubmitParams)
	return p
}

// requestDefaultKnobs maps each request_* command that has a configured
// default to the knob holding it, as SubmitHash::SetRequestCpus, SetRequestMem,
// SetRequestDisk and SetRequestGpus read them (condor_utils/submit_utils.cpp).
var requestDefaultKnobs = map[string]string{
	"request_cpus":   "JOB_DEFAULT_REQUESTCPUS",
	"request_memory": "JOB_DEFAULT_REQUESTMEMORY",
	"request_disk":   "JOB_DEFAULT_REQUESTDISK",
	"request_gpus":   "JOB_DEFAULT_REQUESTGPUS",
}

// param reads a configuration knob the way condor_submit's param() does
// for the submit engine: from the injected params when they answer, and
// otherwise from HTCondor's built-in default.
//
// It deliberately does not read the submit file's own assignments. In
// condor_submit a submit file is a separate macro set from the
// configuration, so a submit file that writes JOB_DEFAULT_REQUESTMEMORY
// sets a macro nothing reads; sf.cfg holds both, so only its built-in
// defaults are consulted here.
func (sf *SubmitFile) param(name string) (string, bool) {
	if sf.params != nil {
		if v, ok := sf.params.Get(name); ok {
			return v, true
		}
	}
	return sf.cfg.DefaultValue(name)
}

// usesDefaultResourceParams reports whether the JOB_DEFAULT_REQUEST*
// defaults apply to this job at all. condor_submit turns them off for
// grid jobs bound for a batch system through the blahp (grid_resource
// "batch ..."): that job's resources are the remote batch system's
// business, not this pool's.
func (sf *SubmitFile) usesDefaultResourceParams() bool {
	if sf.universe != UniverseGrid {
		return true
	}
	gr, _ := sf.submitCommand("grid_resource")
	fields := strings.Fields(gr)
	return len(fields) == 0 || !strings.EqualFold(fields[0], "batch")
}

// requestDefault is the configured default for a request_* command the
// submit file did not give, or false when none applies: no knob, an
// unset or empty one, or a job that takes no defaults.
func (sf *SubmitFile) requestDefault(command string) (string, bool) {
	knob, ok := requestDefaultKnobs[command]
	if !ok || !sf.usesDefaultResourceParams() {
		return "", false
	}
	v, ok := sf.param(knob)
	v = strings.TrimSpace(v)
	if !ok || v == "" {
		return "", false
	}
	return v, true
}

// requestValue is what a request_* command effectively says: the submit
// file's value if it gave one, otherwise the configured default. False
// means the job will carry no such request -- including the value
// "undefined", which condor_submit takes as "leave the attribute unset"
// whether the user wrote it or the default did.
func (sf *SubmitFile) requestValue(command string) (string, bool) {
	v, ok := sf.submitCommand(command)
	if !ok {
		v, ok = sf.requestDefault(command)
	}
	if !ok || isUndefinedRequest(v) {
		return "", false
	}
	return v, true
}

func isUndefinedRequest(v string) bool {
	return strings.EqualFold(strings.TrimSpace(v), "undefined")
}

// defaultDiskEvaluates keeps a RequestDisk that came from
// JOB_DEFAULT_REQUESTDISK from leaving the job unable to match.
//
// HTCondor's own default is MAX({1024, (TransferInputSizeMB+1) * 1.25}) *
// 1024. condor_submit computes TransferInputSizeMB from the input files it
// can stat on the submit host. This engine never sees the input files --
// they reach the schedd in a separate spool step, after the ad is built
// -- so it does not stamp TransferInputSizeMB at all: a zero there would
// be a false statement the schedd's MAX_TRANSFER_INPUT_MB check and every
// other reader would believe.
//
// For the built-in expression that is harmless. MAX over a list skips
// undefined elements, in HTCondor's ClassAd library (minMax in
// classad/fnCall.cpp) and in this module's alike, so it evaluates to
// 1024 * 1024 KiB -- the 1 GiB floor condor_submit itself gets for any
// job whose inputs total less than about 800 MB. That is why the
// expression is stored as written, exactly as condor_submit stores it.
//
// A site's own JOB_DEFAULT_REQUESTDISK may not be so forgiving: one
// written against condor_submit's ads can use TransferInputSizeMB or
// DiskUsage in plain arithmetic, which is undefined here, and a job whose
// RequestDisk is undefined matches no slot and sits idle forever with
// nothing to say why. So when the default does not evaluate to a number
// against the finished ad, HTCondor's built-in expression replaces it --
// a request sized for an unknown input, rather than none that can ever be
// satisfied. A request_disk the user wrote is never second-guessed: that
// is their expression, and condor_submit stores it unchecked too.
func (sf *SubmitFile) defaultDiskEvaluates(ad *classad.ClassAd) error {
	if sf.defaultDisk == "" {
		return nil
	}
	expr, ok := ad.Lookup("RequestDisk")
	if !ok || expr.String() != sf.defaultDisk {
		// A custom attribute (+RequestDisk) replaced the default after
		// it was set; that is the submit file's value now.
		return nil
	}
	if ad.EvaluateAttr("RequestDisk").IsNumber() {
		return nil
	}
	builtin, ok := sf.cfg.DefaultValue("JOB_DEFAULT_REQUESTDISK")
	if !ok {
		return fmt.Errorf("RequestDisk: the configured default %q does not evaluate to a number "+
			"for this job, and there is no built-in default to use instead", sf.defaultDisk)
	}
	return setSizeAttr(ad, "RequestDisk", builtin, unitKiB)
}
