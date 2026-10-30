package htcondor

import (
	"fmt"
	"strings"

	"github.com/PelicanPlatform/classad/classad"
)

// Flag bits of SimpleSubmitKeyword.Opts, the same values and meanings as the
// enum inside HTCondor's SimpleSubmitKeyword (src/condor_utils/submit_utils.cpp).
//
// The low five bits are the VALUE TYPE and are mutually exclusive except for
// kwAsList, which only ever appears together with kwAsString. Above them sit
// modifiers: whether to strip surrounding quotes, whether the keyword is an
// alternate spelling of the one before it, and which file role the value has.
//
// The numbers are part of the contract rather than an internal choice: the
// differential fuzzer reads the same flags out of the linked libcondor_utils
// and checks this table against them, so a keyword whose flags change upstream
// shows up as a test failure instead of as silently wrong job ads.
const (
	kwAsExpr      = 0x00 // no type bit set: store the value as a ClassAd expression
	kwAsBool      = 0x01
	kwAsInt       = 0x02
	kwAsUint      = 0x04 // as int, but a negative value is an error
	kwAsString    = 0x08
	kwAsList      = 0x10 // canonicalize the separators: "a, b  c" becomes "a,b,c"
	kwTypeMask    = 0x1f
	kwStripQuotes = 0x20 // drop one surrounding pair of double quotes
	kwError       = 0x40 // using this keyword is an error
	kwAltName     = 0x80 // alternate spelling: skip when the preceding keyword was present

	kwFileMask = 0x700 // the value names a file, so resolve it against Iwd
	kwExeFile  = 0x100
	kwLogFile  = 0x200
	kwInFile   = 0x300
	kwOutFile  = 0x400
	kwErrFile  = 0x500
	kwVMInFile = 0x600
	kwGenFile  = 0x700
)

// SimpleSubmitKeyword is one row of HTCondor's submit-keyword table: a submit
// command, the job attribute it writes, and the flags that say what shape the
// value takes in the ad.
type SimpleSubmitKeyword struct {
	Key  string
	Attr string
	Opts int
}

// SimpleSubmitKeywords returns the submit commands whose job attribute is
// written by the table-driven pass -- everything in HTCondor's
// prunable_keywords table that is not marked f_special -- in the order
// SubmitHash walks them. The order is load-bearing: kwAltName means "skip this
// row if the row before it matched", and several keywords share an attribute,
// where the last one present wins.
func SimpleSubmitKeywords() []SimpleSubmitKeyword {
	out := make([]SimpleSubmitKeyword, len(simpleSubmitKeywords))
	copy(out, simpleSubmitKeywords)
	return out
}

// simpleSubmitKeywords is the non-special part of HTCondor's prunable_keywords
// table. Each row is transcribed from submit_utils.cpp, and
// TestSimpleKeywordTableMatchesOracle in fuzz/submit checks every field of
// every row against the table the linked libcondor_utils actually carries.
var simpleSubmitKeywords = []SimpleSubmitKeyword{
	{"next_job_start_delay", "NextJobStartDelay", kwAsExpr},
	{"keep_claim_idle", "KeepClaimIdle", kwAsExpr},
	{"job_ad_information_attrs", "JobAdInformationAttrs", kwAsString},
	{"ulog_execute_attrs", "UserLogExecuteEventAttrs", kwAsString},
	{"max_idle", "JobMaterializeMaxIdle", kwAsExpr},
	{"materialize_max_idle", "JobMaterializeMaxIdle", kwAsExpr | kwAltName},
	{"docker_network_type", "DockerNetworkType", kwAsString},
	{"docker_pull_policy", "DockerPullPolicy", kwAsString},
	{"docker_override_entrypoint", "DockerOverrideEntrypoint", kwAsBool},
	{"docker_send_credentials", "DockerSendCredentials", kwAsBool},
	{"container_target_dir", "ContainerTargetDir", kwAsString | kwStripQuotes},
	{"mount_under_scratch", "MountUnderScratch", kwAsString | kwStripQuotes},
	{"transfer_container", "TransferContainer", kwAsBool},
	{"transfer_plugins", "TransferPlugins", kwAsString},
	{"want_io_proxy", "WantIOProxy", kwAsBool},
	{"want_job_networking", "WantJobNetworking", kwAsBool},
	{"starter_debug", "JobStarterDebug", kwAsString | kwStripQuotes},
	{"starter_log", "JobStarterLog", kwAsString | kwStripQuotes | kwLogFile},
	{"container_is_common", "ContainerIsCommon", kwAsBool},
	{"job_machine_attrs", "JobMachineAttrs", kwAsString},
	{"job_machine_attrs_history_length", "JobMachineAttrsHistoryLength", kwAsInt},
	{"notify_user", "NotifyUser", kwAsString},
	{"email_attributes", "EmailAttributes", kwAsString | kwAsList},
	{"remote_initialdir", "RemoteIwd", kwAsString},
	{"Remote_grid_resource", "Remote_GridResource", kwAsString},
	{"Remote_Remote_grid_resource", "Remote_Remote_GridResource", kwAsString},
	{"output_destination", "OutputDestination", kwAsString},
	{"output_directory", "OutputDirectory", kwAsString | kwGenFile},
	{"want_graceful_removal", "WantGracefulRemoval", kwAsExpr},
	{"job_max_vacate_time", "JobMaxVacateTime", kwAsExpr},
	{"encrypt_execute_directory", "EncryptExecuteDirectory", kwAsBool},
	{"encrypt_input_files", "EncryptInputFiles", kwAsString},
	{"encrypt_output_files", "EncryptOutputFiles", kwAsString},
	{"dont_encrypt_input_files", "DontEncryptInputFiles", kwAsString},
	{"dont_encrypt_output_files", "DontEncryptOutputFiles", kwAsString},
	{"load_profile", "LoadProfile", kwAsBool},
	{"primary_unix_group", "PrimaryUnixGroup", kwAsString},
	{"file_remaps", "FileRemaps", kwAsExpr},
	{"buffer_files", "BufferFiles", kwAsExpr},
	{"buffer_size", "BufferSize", kwAsExpr},
	{"buffer_block_size", "BufferBlockSize", kwAsExpr},
	{"fetch_files", "FetchFiles", kwAsString},
	{"compress_files", "CompressFiles", kwAsString},
	{"append_files", "AppendFiles", kwAsString},
	{"local_files", "LocalFiles", kwAsString},
	{"log", "UserLog", kwAsString | kwLogFile},
	{"dagman_log", "DAGManNodesLog", kwAsString | kwLogFile},
	{"log_xml", "UserLogUseXML", kwAsBool},
	{"noop_job", "IsNoopJob", kwAsExpr},
	{"noop_job_exit_signal", "NoopJobExitSignal", kwAsExpr},
	{"noop_job_exit_code", "NoopJobExitCode", kwAsExpr},
	{"dag_node_name", "DAGNodeName", kwAsString},
	{"match_list_length", "LastMatchListLength", kwAsInt},
	{"dagman_job_id", "DAGManJobId", kwAsUint},
	{"submit_event_notes", "SubmitEventNotes", kwAsString},
	{"submit_event_user_notes", "SubmitEventUserNotes", kwAsString},
	{"submit_event_notes_attrs", "SubmitEventNotesAttrs", kwAsString},
	{"stack_size", "StackSize", kwAsExpr},
	{"jar_files", "JarFiles", kwAsString},
	{"parallel_script_shadow", "ParallelScriptShadow", kwAsString},
	{"parallel_script_starter", "ParallelScriptStarter", kwAsString},
	{"cron_minute", "CronMinute", kwAsString},
	{"cron_hour", "CronHour", kwAsString},
	{"cron_day_of_month", "CronDayOfMonth", kwAsString},
	{"cron_month", "CronMonth", kwAsString},
	{"cron_day_of_week", "CronDayOfWeek", kwAsString},
	{"description", "JobDescription", kwAsString},
	{"batch_name", "JobBatchName", kwAsString | kwStripQuotes},
	{"batch_id", "JobBatchId", kwAsString | kwStripQuotes},
	{"max_job_retirement_time", "MaxJobRetirementTime", kwAsExpr},
	{"job_lease_duration", "JobLeaseDuration", kwAsExpr},
	{"core_size", "CoreSize", kwAsInt},
	{"priority", "JobPrio", kwAsInt},
	{"prio", "JobPrio", kwAsInt | kwAltName},
	{"run_as_owner", "RunAsOwner", kwAsBool},
	{"max_transfer_input_mb", "MaxTransferInputMB", kwAsExpr},
	{"max_transfer_output_mb", "MaxTransferOutputMB", kwAsExpr},
	{"manifest", "ManifestDesired", kwAsBool},
	{"manifest_dir", "ManifestDir", kwAsString},
	{"checkpoint_exit_code", "SuccessCheckpointExitCode", kwAsInt},
	{"checkpoint_destination", "CheckpointDestination", kwAsString},
	{"aws_region", "AWSRegion", kwAsString},
	{"aws_access_key_id_file", "EC2AccessKeyId", kwAsString},
	{"aws_secret_access_key_file", "EC2SecretAccessKey", kwAsString},
	{"s3_access_key_id_file", "EC2AccessKeyId", kwAsString},
	{"s3_secret_access_key_file", "EC2SecretAccessKey", kwAsString},
	{"gs_access_key_id_file", "EC2AccessKeyId", kwAsString},
	{"gs_secret_access_key_file", "EC2SecretAccessKey", kwAsString},
	{"erase_output_and_error_on_restart", "EraseOutputAndErrorOnRestart", kwAsBool},
	{"transfer_checkpoint_files", "TransferCheckpoint", kwAsString},
	{"preserve_relative_paths", "PreserveRelativePaths", kwAsBool},
	{"cuda_version", "CUDAVersion", kwAsString},
	{"skip_if_dataflow", "SkipIfDataflow", kwAsBool},
	{"allowed_job_duration", "AllowedJobDuration", kwAsExpr},
	{"allowed_execute_duration", "AllowedExecuteDuration", kwAsExpr},
	{"jobset", "JobSetName", kwAsString | kwStripQuotes},
}

// setSimpleSubmitKeywords is SubmitHash::do_simple_commands over the
// non-special part of the keyword table: for every keyword the submit file
// sets, it writes the job attribute the table names, with the VALUE SHAPE the
// table's flags call for.
//
// The shape is the point. Before this, each of these keywords had its own
// hand-written block, and each block decided for itself whether the value was
// a string, a number, a boolean or an expression -- so the Go parser
// canonicalized separators HTCondor stores verbatim, stored verbatim what
// HTCondor canonicalizes, kept quotes HTCondor strips, and dropped anything
// its parseInt could not read. Deriving the shape from the same flags makes a
// keyword nobody has looked at behave correctly, and makes one added upstream
// behave correctly as soon as the table gains its row.
//
// Two rules are easy to miss and both come straight from SubmitHash:
//
//   - a keyword is looked up under its submit name OR under the attribute
//     name, because submit_param(key, attr) tries both; and
//   - a value that expands to the empty string counts as ABSENT. submit_param
//     returns NULL for it, so the attribute is not written at all, and the
//     alternate spelling of a keyword whose primary name is present but empty
//     is suppressed rather than used.
func (sf *SubmitFile) setSimpleSubmitKeywords(ad *classad.ClassAd) error {
	lastOneExisted := false
	for _, kw := range simpleSubmitKeywords {
		if kw.Opts&kwAltName != 0 && lastOneExisted {
			lastOneExisted = false
			continue
		}
		value, ok := sf.simpleKeywordParam(kw.Key, kw.Attr)
		lastOneExisted = ok
		if !ok {
			continue
		}
		if err := sf.assignSimpleKeyword(ad, kw, value); err != nil {
			return err
		}
	}
	return nil
}

// simpleKeywordParam is SubmitHash::submit_param(name, alt_name) for one table
// row: the submit command's own name first, the job attribute's name second,
// and a value that expands to nothing treated as if the file had not set it.
func (sf *SubmitFile) simpleKeywordParam(key, attr string) (string, bool) {
	value, ok := sf.submitCommand(key)
	if !ok {
		value, ok = sf.submitCommand(attr)
	}
	if !ok || value == "" {
		return "", false
	}
	return value, true
}

// assignSimpleKeyword writes one keyword's value onto the ad in the shape its
// flags call for, following the branches of do_simple_commands in order.
func (sf *SubmitFile) assignSimpleKeyword(ad *classad.ClassAd, kw SimpleSubmitKeyword, value string) error {
	switch {
	case kw.Opts&kwAsString != 0:
		str := value
		if kw.Opts&kwStripQuotes != 0 {
			str = trimAndStripSubmitQuotes(str)
		}
		if kw.Opts&kwAsList != 0 {
			str = canonicalizeSubmitList(str)
		}
		if kw.Opts&kwFileMask != 0 && str != "" {
			iwd, err := sf.jobIwd()
			if err != nil {
				return err
			}
			str = fullPath(str, iwd)
		}
		_ = ad.Set(kw.Attr, str)
	case kw.Opts&kwError != 0 && kw.Opts&kwAltName == 0:
		// f_error, as opposed to f_alt_err, which is f_error|f_alt_name
		// and means something else entirely.
		return fmt.Errorf("%s=%s has been disabled by the administrator", kw.Key, value)
	case kw.Opts&kwAsBool != 0:
		b, ok := evalBoolParam(value)
		if !ok {
			return fmt.Errorf("%s=%s is invalid, must eval to a boolean", kw.Key, value)
		}
		_ = ad.Set(kw.Attr, b)
	case kw.Opts&(kwAsInt|kwAsUint) != 0:
		n, ok := evalLongParam(value)
		if !ok {
			return fmt.Errorf("%s=%s is invalid, must eval to an integer", kw.Key, value)
		}
		if n < 0 && kw.Opts&kwAsUint != 0 {
			return fmt.Errorf("%s=%s is invalid, must eval to a non-negative integer", kw.Key, value)
		}
		_ = ad.Set(kw.Attr, n)
	default:
		return setExprAttr(ad, kw.Attr, kw.Key, value)
	}
	return nil
}

// trimAndStripSubmitQuotes is trim_and_strip_quotes_in_place: trim whitespace
// from both ends, then remove ONE surrounding pair of double quotes.
//
// A value that is a single `"` is both ends at once, which HTCondor reduces to
// the empty string; strings.Trim would do the same thing to `""""`, which it
// does not.
func trimAndStripSubmitQuotes(s string) string {
	t := strings.Trim(s, " \t\n\v\f\r")
	if len(t) >= 1 && t[0] == '"' && t[len(t)-1] == '"' {
		if len(t) == 1 {
			return ""
		}
		return t[1 : len(t)-1]
	}
	return t
}

// canonicalizeSubmitList is split(str) followed by join(list, ","): the value
// is cut on commas and whitespace, empty items are dropped, and the items are
// rejoined with a single comma. `a, b  c` and `a,b,c` become the same string.
//
// The separator set is HTCondor's default for split(), ", \t\r\n". A vertical
// tab or form feed is NOT a separator -- it survives inside an item, and is
// trimmed only at an item's edges, which is what STI_TRIM does.
func canonicalizeSubmitList(s string) string {
	items := strings.FieldsFunc(s, func(r rune) bool {
		switch r {
		case ',', ' ', '\t', '\r', '\n':
			return true
		}
		return false
	})
	out := items[:0]
	for _, item := range items {
		if item = strings.Trim(item, "\v\f"); item != "" {
			out = append(out, item)
		}
	}
	return strings.Join(out, ",")
}

// evalBoolParam is string_is_boolean_param (condor_config.cpp): "true"/"1" or
// "false"/"0" with nothing but whitespace after them, and failing that the
// value parsed as a ClassAd expression and evaluated for a boolean-equivalent
// result, which is how an integer or a real counts as a boolean here.
//
// The literal test matches a PREFIX, exactly as the C++ does, so `truest` is
// not "true" with junk ignored -- it fails the literal test and goes to the
// expression, which rejects it.
func evalBoolParam(value string) (bool, bool) {
	var (
		result  bool
		rest    string
		matched bool
	)
	switch {
	case len(value) >= 4 && strings.EqualFold(value[:4], "true"):
		result, rest, matched = true, value[4:], true
	case len(value) >= 1 && value[0] == '1':
		result, rest, matched = true, value[1:], true
	case len(value) >= 5 && strings.EqualFold(value[:5], "false"):
		result, rest, matched = false, value[5:], true
	case len(value) >= 1 && value[0] == '0':
		result, rest, matched = false, value[1:], true
	}
	if matched && strings.TrimLeft(rest, " \t\n\v\f\r") == "" {
		return result, true
	}

	expr, err := classad.ParseExpr(strings.TrimSpace(value))
	if err != nil {
		return false, false
	}
	v := expr.Eval(classad.New())
	switch {
	case v.IsBool():
		b, _ := v.BoolValue()
		return b, true
	case v.IsInteger():
		i, _ := v.IntValue()
		return i != 0, true
	case v.IsReal():
		f, _ := v.RealValue()
		return f != 0, true
	}
	return false, false
}
