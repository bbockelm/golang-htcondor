package appolicy

import (
	"strconv"
	"strings"

	"github.com/bbockelm/golang-htcondor/config"
)

// The allowlist. Every knob read is named here or formed from a name in
// one of the *_NAMES lists below, and nothing else is ever asked for.
//
// Each name was checked against the HTCondor source for the daemon that
// reads it. Three that look natural are deliberately absent:
// ENABLE_SSH_TO_JOB is read by the starter on the execute node, so the
// access point's value says nothing (the schedd's own switch is
// SCHEDD_ENABLE_SSH_TO_JOB); CREDD_CHECK_CREDS is a command, not a knob
// (the knobs behind it are the *_CREDMON_PROVIDER* ones); and the file
// transfer plugin knobs describe execute nodes, not this one.

// Group names, in the order they are reported.
const (
	GroupSubmissionLimits   = "submission_limits"
	GroupSubmitRequirements = "submit_requirements"
	GroupJobTransforms      = "job_transforms"
	GroupRequestDefaults    = "request_defaults"
	GroupHoldPolicy         = "hold_remove_release"
	GroupFileTransfer       = "file_transfer"
	GroupDAGMan             = "dagman"
	GroupFeatures           = "features"
)

// staticGroups are the fixed knobs of each group.
var staticGroups = []struct {
	group string
	knobs []string
}{
	{GroupSubmissionLimits, []string{
		"MAX_JOBS_PER_SUBMISSION", "MAX_JOBS_PER_OWNER", "MAX_JOBS_SUBMITTED", "MAX_RUNNING_SCHEDULER_JOBS_PER_OWNER",
	}},
	{GroupSubmitRequirements, []string{"SUBMIT_REQUIREMENT_NAMES"}},
	{GroupJobTransforms, []string{"JOB_TRANSFORM_NAMES"}},
	{GroupRequestDefaults, []string{
		"JOB_DEFAULT_REQUESTCPUS", "JOB_DEFAULT_REQUESTMEMORY", "JOB_DEFAULT_REQUESTDISK", "JOB_DEFAULT_REQUESTGPUS",
	}},
	{GroupHoldPolicy, []string{
		"SYSTEM_PERIODIC_HOLD_NAMES", "SYSTEM_PERIODIC_HOLD", "SYSTEM_PERIODIC_HOLD_REASON", "SYSTEM_PERIODIC_HOLD_SUBCODE",
		"SYSTEM_PERIODIC_REMOVE_NAMES", "SYSTEM_PERIODIC_REMOVE", "SYSTEM_PERIODIC_REMOVE_REASON",
		"SYSTEM_PERIODIC_RELEASE_NAMES", "SYSTEM_PERIODIC_RELEASE", "SYSTEM_PERIODIC_RELEASE_REASON",
		"SYSTEM_MAX_RELEASES",
	}},
	{GroupFileTransfer, []string{
		"MAX_TRANSFER_INPUT_MB", "MAX_TRANSFER_OUTPUT_MB", "MAX_CONCURRENT_UPLOADS", "MAX_CONCURRENT_DOWNLOADS",
	}},
	{GroupDAGMan, []string{
		"DAGMAN_MAX_JOBS_IDLE", "DAGMAN_MAX_JOBS_SUBMITTED", "DAGMAN_MAX_PRE_SCRIPTS", "DAGMAN_MAX_POST_SCRIPTS",
	}},
	{GroupFeatures, []string{
		"SCHEDD_ALLOW_LATE_MATERIALIZE", "SCHEDD_ENABLE_SSH_TO_JOB", "START_SCHEDULER_UNIVERSE", "JOB_EPOCH_HISTORY",
		"LOCAL_CREDMON_PROVIDER_NAMES", "CLIENT_CREDMON_PROVIDER_NAMES",
		"SUBMIT_ADD_LOCAL_CREDMON_PROVIDERS", "SUBMIT_ADD_LOCAL_CREDMON_PROVIDER_NAMES",
		"SUBMIT_TEMPLATE_NAMES",
	}},
}

// RequestDefaultKnobs are the knobs the submit engine reads for a job
// that omits a request_* command.
var RequestDefaultKnobs = []string{
	"JOB_DEFAULT_REQUESTCPUS", "JOB_DEFAULT_REQUESTMEMORY", "JOB_DEFAULT_REQUESTDISK", "JOB_DEFAULT_REQUESTGPUS",
}

// staticKnobs is every fixed knob, in reading order. The first is the
// one fetch reads alone to see whether the schedd answers at all.
func staticKnobs() []string {
	var out []string
	for _, g := range staticGroups {
		out = append(out, g.knobs...)
	}
	return out
}

// namedList is a *_NAMES knob and the knobs each name in it forms. The
// suffixes are the ones the schedd reads for each name: SUBMIT_REQUIREMENT
// in Scheduler::reconfig (schedd.cpp), JOB_TRANSFORM in
// JobTransforms::initAndReconfig, and the SYSTEM_PERIODIC_* policies in
// load_policy_list and AnalyzeSinglePeriodicPolicy (user_job_policy.cpp),
// which read <knob>_<Name>_REASON and _SUBCODE for whichever one fired.
type namedList struct {
	names    string
	prefix   string
	suffixes []string
}

var namedLists = []namedList{
	{"SUBMIT_REQUIREMENT_NAMES", "SUBMIT_REQUIREMENT_", []string{"", "_REASON", "_IS_WARNING"}},
	{"JOB_TRANSFORM_NAMES", "JOB_TRANSFORM_", []string{""}},
	{"SYSTEM_PERIODIC_HOLD_NAMES", "SYSTEM_PERIODIC_HOLD_", []string{"", "_REASON", "_SUBCODE"}},
	{"SYSTEM_PERIODIC_REMOVE_NAMES", "SYSTEM_PERIODIC_REMOVE_", []string{"", "_REASON"}},
	{"SYSTEM_PERIODIC_RELEASE_NAMES", "SYSTEM_PERIODIC_RELEASE_", []string{"", "_REASON"}},
}

// codeDefaults are the values the daemons use for a knob param_info gives
// no default, where the reading code supplies one. Without these an unset
// SCHEDD_ENABLE_SSH_TO_JOB would read as "off".
var codeDefaults = map[string]string{
	"SCHEDD_ENABLE_SSH_TO_JOB":           "true", // schedd.cpp: param_boolean(..., true, ...)
	"SUBMIT_ADD_LOCAL_CREDMON_PROVIDERS": "true", // schedd.cpp: param_boolean(..., true)
}

// isNonDefault reports whether a value differs from HTCondor's default.
//
// A knob param_info gives a default is reported by the schedd with that
// default when the configuration leaves it alone, so "unset" there means
// someone cleared it. A knob whose default lives only in the reading code
// (codeDefaults) is reported unset when left alone. A knob with neither
// has "unset" as its default.
//
// A default that is built from other knobs ("$(SPOOL)/epoch_history")
// cannot be compared with the expanded value the schedd reports, so a
// knob with one counts as changed only when it was cleared.
func isNonDefault(name string, v Value) bool {
	if v.Err != nil {
		return false
	}
	def, ok := config.BuiltinDefault(name)
	if !ok || strings.TrimSpace(def) == "" {
		code, ok := codeDefaults[strings.ToUpper(name)]
		if !ok {
			return v.Set
		}
		return v.Set && !sameValue(v.Raw, code)
	}
	if !v.Set {
		return true
	}
	if strings.Contains(def, "$(") {
		return false
	}
	return !sameValue(v.Raw, def)
}

// sameValue compares two configuration values as the daemons would read
// them: booleans without case, numbers by value, anything else without
// regard to whitespace.
func sameValue(a, b string) bool {
	a, b = strings.TrimSpace(a), strings.TrimSpace(b)
	if ab, aok := parseBool(a); aok {
		if bb, bok := parseBool(b); bok {
			return ab == bb
		}
	}
	if an, err := strconv.ParseFloat(a, 64); err == nil {
		if bn, err := strconv.ParseFloat(b, 64); err == nil {
			return an == bn
		}
	}
	strip := func(s string) string { return strings.Join(strings.Fields(s), "") }
	return strings.EqualFold(strip(a), strip(b))
}

// parseBool reads HTCondor's boolean spellings.
func parseBool(v string) (bool, bool) {
	switch strings.ToUpper(strings.TrimSpace(v)) {
	case "TRUE", "T", "YES", "Y", "1":
		return true, true
	case "FALSE", "F", "NO", "N", "0":
		return false, true
	}
	return false, false
}
