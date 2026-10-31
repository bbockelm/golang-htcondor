//go:build libcondor_utils

package fuzzsubmit

import (
	"strings"
	"testing"

	"github.com/bbockelm/golang-htcondor/fuzz/submit/oracle"
)

// seedCase is a hand-written submit file. When reason is empty, the Go and C++
// parsers are expected to AGREE on the ads (parity). When reason is non-empty,
// the case is a KNOWN divergence this fuzzer already surfaced: the test asserts
// it still diverges, so a fix flips the case and we get told to promote it to
// parity. See FINDINGS.md.
type seedCase struct {
	input  string
	reason string
}

// seeds double as the fuzz seed corpus. They are submit files, not arbitrary
// bytes: the fuzzer mutates from here, and starting at plausible syntax is what
// gets it past the first parse error into the semantics worth comparing.
var seeds = []seedCase{
	// --- parity ---
	{input: "executable = /bin/sleep\nrequest_cpus = 2\nrequest_memory = 512\narguments = x\nqueue\n"},
	{input: "executable = /bin/sleep\nrequest_cpus = 1\nrequest_memory = 128\narguments = $(Process)\nqueue 3\n"},
	{input: "executable = /bin/sleep\nrequest_cpus = 1\nrequest_memory = 128\narguments = a\nuniverse = vanilla\nqueue 2\n"},

	// --- known divergences (findings) ---
	{input: "executable = /bin/sleep\nqueue\n"},
	{input: "executable = /bin/sleep\narguments = $(Process)\nqueue 3\n"},
	{input: "executable = /bin/sleep\noutput = out.$(Process)\nerror = err.$(Process)\nlog = j.log\nqueue 2\n"},
	{input: "executable = /bin/sleep\nrequest_cpus = 1\nrequest_memory = 128\nqueue\n"},

	// --- parity: line endings and parameter names ---
	// The first two were the known divergences the Cmd/UserLog comparison
	// exposed; they are parity assertions now. The rest pin the rules they
	// turned on, which libcondor_utils 26.2.0 answered for each case.
	//
	// A submit file written on Windows. getline_implementation trims the
	// line with isspace(), so the carriage return never reaches the value.
	{input: "executable = /bin/sleep\r\nrequest_cpus = 1\r\nrequest_memory = 128\r\narguments = a\r\nlog = j.log\r\nqueue\r\n"},
	{input: "executable = /bin/sleep\nrequest_cpus = 1\nrequest_memory = 128\narguments = a\n0 = x\nlog = j.log\nqueue\n"},
	{input: "\r\nexecutable = /bin/sleep\r\n\r\narguments = a\r\nqueue\r\n"},
	// A '\r' away from the end of the line is not trailing whitespace and
	// survives on both sides.
	{input: "executable = /bin/sl\reep\nqueue\n"},
	{input: "executable = /bin/sleep\narguments =\ra\nqueue\n"},
	// is_valid_param_name() accepts any run of [A-Za-z0-9_./], with no
	// restriction on the first character, so all of these name macros.
	{input: "executable = /bin/sleep\n0 = x\narguments = $(0)\nlog = j.log\nqueue\n"},
	{input: "executable = /bin/sleep\n0abc = x\narguments = $(0abc)\nqueue\n"},
	{input: "executable = /bin/sleep\n_x = 1\narguments = $(_x)\nqueue\n"},
	{input: "executable = /bin/sleep\na/b = 1\narguments = $(a/b)\nqueue\n"},
	{input: "executable = /bin/sleep\nfoo.bar = 1\narguments = $(foo.bar)\nqueue\n"},
	// A character outside that set makes the name illegal, and HTCondor
	// fails the whole file rather than skipping the line.
	{input: "executable = /bin/sleep\na-b = 1\nlog = j.log\nqueue\n"},
	// The same charset governs a job attribute name, which `+Attr` and
	// `MY.Attr` both reach. HTCondor builds "MY." + the name scanned after
	// the '+' without further validation.
	{input: "executable = /bin/sleep\n+0 = 7\nqueue\n"},
	{input: "executable = /bin/sleep\n+0abc = 7\n+0.5 = 7\nqueue\n"},
	{input: "executable = /bin/sleep\nMY.0 = 7\nMY.0abc = 7\nqueue\n"},
	{input: "executable = /bin/sleep\n+a.b = 7\n+a/b = 7\nqueue\n"},
	// A letter outside ASCII is not a parameter-name character, so a macro
	// named with one fails the file -- but the +Attr form never validates
	// the name, so the same letter is fine in a job attribute.
	{input: "executable = /bin/sleep\n\u00e9 = 7\nqueue\n"},
	{input: "executable = /bin/sleep\n+caf\u00e9 = 7\nqueue\n"},
	// `+Attr` skips name validation entirely, so the attribute name may
	// hold characters a macro name may not.
	{input: "executable = /bin/sleep\n+a-b = 7\nqueue\n"},
	// submit's `-Attr` form. It is not the inverse of `+Attr`: it stores an
	// empty value, which reaches the ad as `undefined`, and a later `-Attr`
	// overrides an earlier `+Attr`.
	{input: "executable = /bin/sleep\n-Foo = 7\nqueue\n"},
	{input: "executable = /bin/sleep\n-a-b = 7\n-1 = 7\nqueue\n"},
	{input: "executable = /bin/sleep\n+Foo = 7\n-Foo = 9\nqueue\n"},
	// An empty value is the same thing: `undefined`, not "leave it off".
	{input: "executable = /bin/sleep\n+A =\n+B = \nMY.C =\nqueue\n"},
	{input: "executable = /bin/sleep\n+A = $(nosuch)\nqueue\n"},

	// --- parity: line continuation ---
	// Each physical line is trimmed of trailing whitespace BEFORE the text
	// is tested for a trailing backslash, so whitespace before the
	// backslash is part of the value, the next line is joined on with
	// nothing between, and whitespace AFTER the backslash still continues
	// the line. One space before the backslash agrees under either rule,
	// which is how a space-inserting version of this hid.
	{input: "executable = /bin/sleep\n+Note = \"a   \\\n   b\"\nqueue\n"},
	{input: "executable = /bin/sleep\n+Note = \"a\\\nb\"\nqueue\n"},
	{input: "executable = /bin/sleep\n+Note = \"a\t\t\\\n\t\tb\"\nqueue\n"},
	{input: "executable = /bin/sleep\n+Note = \"a \\   \nb\"\nqueue\n"},
	{input: "executable = /bin/sleep\narguments = $(Item)\nqueue in a\\\n b\n"},
	// The join contributes nothing on either side: with an empty left half
	// the executable is the continuation line itself, not a path with a
	// leading space in it.
	{input: "eXeCutABle=\\\nqueue\n"},
	// The backslash test looks at the whole logical line so far, not just
	// the physical line that was read last, so an empty continuation line
	// leaves the character before it as the one tested.
	{input: "executable = /bin/sleep\nX = a\\\\\n\nb\n+Note = \"[$(X)]\"\nqueue\n"},
	// A continuation inside a multi-line item list is assembled before the
	// list is split, on both sides.
	{input: "executable = /bin/sleep\narguments = $(Item)\nqueue in (\na \\\nb\nc\n)\n"},

	// --- parity: path resolution ---
	// A relative executable or log is resolved to an absolute path, and
	// initialdir moves the log but NOT the executable. Both parsers run
	// in this process, so they see the same working directory and the
	// resolved values are compared exactly.
	{input: "executable = sleep\nrequest_cpus = 1\nrequest_memory = 128\narguments = a\nlog = j.log\nqueue\n"},
	{input: "executable = sleep\nrequest_cpus = 1\nrequest_memory = 128\narguments = a\nlog = j.log\ninitialdir = testdata\nqueue\n"},
	{input: "executable = /bin/sleep\nrequest_cpus = 1\nrequest_memory = 128\narguments = a\nlog = /var/tmp/j.log\ninitialdir = /tmp\nqueue\n"},
	{input: "executable = ./sleep\nrequest_cpus = 1\nrequest_memory = 128\narguments = a\nlog = ./d/../j.log\nqueue\n"},
	{input: "executable = sleep\nrequest_cpus = 1\nrequest_memory = 128\narguments = a\ntransfer_executable = false\nqueue\n"},
	{input: "executable = sleep\nrequest_cpus = 1\nrequest_memory = 128\narguments = a\nlog =\nqueue\n"},

	// --- parity, exercising specific commands ---
	{input: "executable = /bin/sleep\nrequest_cpus = 1\nrequest_memory = 128\narguments = a\nMY.Foo = 1\n+Bar = \"two\"\nqueue\n"},
	{input: "executable = /bin/sleep\nrequest_cpus = 1\nrequest_memory = 128\narguments = $(X)\nX = 7\nqueue\n"},
	{input: "executable = /bin/sleep\nrequest_cpus = 1\nrequest_memory = 128\narguments = a\nrequirements = (Memory > 1024)\nqueue\n"},
	{input: "executable = /bin/sleep\nrequest_cpus = 1\nrequest_memory = 128\narguments = a\nenvironment = \"A=1 B=2\"\nqueue\n"},
	{input: "executable = /bin/sleep\nrequest_cpus = 1\nrequest_memory = 128\narguments = a\ntransfer_input_files = a.txt, b.txt\nqueue\n"},
	{input: "executable = /bin/sleep\nrequest_cpus = 1\nrequest_memory = 128\narguments = a\nshould_transfer_files = YES\nwhen_to_transfer_output = ON_EXIT\nqueue\n"},
	{input: "executable = /bin/sleep\nrequest_cpus = 1\nrequest_memory = 128\narguments = a\npriority = 5\nqueue\n"},
	{input: "executable = /bin/sleep\nrequest_cpus = 1\nrequest_memory = 128\narguments = a\nperiodic_remove = (JobStatus == 5)\nqueue\n"},
	{input: "# just a comment\nexecutable = /bin/sleep\nrequest_cpus = 1\nrequest_memory = 128\narguments = a\nqueue\n"},
	// request_<tag> with no dedicated handling. request_A0 is the input
	// the fuzzer found the generic-request gap from.
	{input: "executable = /bin/sleep\nrequest_A0 = 3\nqueue\n"},
	{input: "executable = /bin/sleep\nrequest_licenses = 4\nrequest_my_thing = 5\nqueue\n"},
	{input: "executable = /bin/sleep\nrequest_slots = 2*2\nrequest_bandwidth = \"high\"\nqueue\n"},
	{input: "executable = /bin/sleep\nRequest_Foo = 5\nrequest_foo = 6\nqueue\n"},
	{input: "executable = /bin/sleep\nrequest_colors = undefined\nqueue\n"},
	{input: "executable = /bin/sleep\nrequest_f = 5\nrequest__foo = 6\nrequest_1 = 7\nqueue\n"},
	{input: "executable = /bin/sleep\nrequest_cpu = 2\nrequest_gpu = 2\nqueue\n"},
	{input: "executable = /bin/sleep\nrequest_gpus = 1\nrequest_gpus_memory = 100\nqueue\n"},
	{input: "executable = /bin/sleep\n+Requestfoo = 9\nrequest_foo = 3\nqueue\n"},
	{input: "executable = /bin/sleep\nrequest_shards = $(Process)+1\nqueue 2\n"},

	// --- parity: the attribute a submit command actually lands in ---
	// Each of these was a case where the Go parser wrote the submit
	// keyword's own name, or the right name with the wrong value.
	//
	// machine_count is MinHosts/MaxHosts, and only for a parallel job;
	// every other universe gets the default pair of 1.
	{input: "executable = /bin/sleep\nuniverse = parallel\nmachine_count = 4\nqueue\n"},
	{input: "executable = /bin/sleep\nuniverse = parallel\nnode_count = 3\nqueue\n"},
	{input: "executable = /bin/sleep\nmachine_count = 4\nqueue\n"},
	// The accounting group is completed with a user, and the oracle and
	// the Go parser are given the same one (oracle.SubmitUser).
	{input: "executable = /bin/sleep\naccounting_group = Proj-1\nqueue\n"},
	{input: "executable = /bin/sleep\naccounting_group = Proj-1\naccounting_group_user = alice\nqueue\n"},
	{input: "executable = /bin/sleep\naccounting_group_user = alice\nqueue\n"},
	// A group that already carries a user is appended to anyway.
	{input: "executable = /bin/sleep\naccounting_group = Proj.bob\nqueue\n"},
	// nice_user is shorthand for the NICE_USER_ACCOUNTING_GROUP_NAME
	// group, and is ignored when the file names a group of its own.
	{input: "executable = /bin/sleep\nnice_user = true\nqueue\n"},
	{input: "executable = /bin/sleep\nnice_user = true\naccounting_group = Grp\nqueue\n"},
	{input: "executable = /bin/sleep\nnice_user = true\nmax_job_retirement_time = 300\nqueue\n"},
	// remote_initialdir is RemoteIwd, stored as written; it names a
	// directory on a machine this one knows nothing about.
	{input: "executable = /bin/sleep\nremote_initialdir = /scratch/foo\nqueue\n"},
	{input: "executable = /bin/sleep\nremote_initialdir = rel/dir\nqueue\n"},
	// checkpoint_exit_code is SuccessCheckpointExitCode.
	{input: "executable = /bin/sleep\ncheckpoint_exit_code = 77\nqueue\n"},
	// Both concurrency_limits spellings land in ConcurrencyLimits; the
	// list form is lower-cased, sorted and comma-joined.
	{input: "executable = /bin/sleep\nconcurrency_limits_expr = strcat(\"lic\", \":2\")\nqueue\n"},
	{input: "executable = /bin/sleep\nconcurrency_limits = B, a , C\nqueue\n"},
	{input: "executable = /bin/sleep\nconcurrency_limits = lic:2, db:3\nqueue\n"},
	// WantDocker means the docker universe and nothing else; an image
	// keyword anywhere else is an implicit container job.
	{input: "executable = /bin/sleep\nuniverse = docker\ndocker_image = busybox\nqueue\n"},
	{input: "executable = /bin/sleep\nuniverse = container\ndocker_image = busybox\nqueue\n"},
	{input: "executable = /bin/sleep\ndocker_image = busybox\nqueue\n"},
	{input: "executable = /bin/sleep\nuniverse = local\ndocker_image = busybox\nqueue\n"},
	// The image-kind flag follows the image, and follows it only where
	// the container topping applies.
	{input: "executable = /bin/sleep\nuniverse = container\ncontainer_image = ./img.sif\nqueue\n"},
	{input: "executable = /bin/sleep\ncontainer_image = docker://alpine:3.19\nqueue\n"},
	{input: "executable = /bin/sleep\ncontainer_image = ./sandboxdir\nqueue\n"},
	{input: "executable = /bin/sleep\nuniverse = grid\ngrid_resource = batch slurm\ncontainer_image = ./img.sif\nqueue\n"},
	{input: "executable = /bin/sleep\nuniverse = scheduler\ncontainer_image = ./img.sif\nqueue\n"},
	{input: "executable = /bin/sleep\nqueue 0\n"},
	{input: ""},
	{input: "queue\n"},

	// --- parity: cron / deferral scheduling ---
	// cron_window and cron_prep_time are spellings of DeferralWindow and
	// DeferralPrepTime; a deferred job always carries both, defaulted when
	// the file is silent; and a timing value is an expression, not an int.
	{input: "executable = /bin/sleep\ncron_minute = 0\nqueue\n"},
	{input: "executable = /bin/sleep\ncron_minute = 0\ncron_hour = */2\ncron_day_of_month = *\ncron_month = *\ncron_day_of_week = *\ncron_window = 60\ncron_prep_time = 30\nqueue\n"},
	{input: "executable = /bin/sleep\ndeferral_time = 1700000000\nqueue\n"},
	{input: "executable = /bin/sleep\ndeferral_time = 1700000000\ndeferral_window = 120\ndeferral_prep_time = 45\nqueue\n"},
	{input: "executable = /bin/sleep\ndeferral_time = (time() + 3600)\nqueue\n"},
	// cron_ wins over deferral_ for the same attribute, and the alternate
	// spellings CronWindow / DeferralPrepTime reach it too.
	{input: "executable = /bin/sleep\ncron_minute = 0\ncron_window = 60\ndeferral_window = 999\ncron_prep_time = 30\ndeferral_prep_time = 999\nqueue\n"},
	{input: "executable = /bin/sleep\ncron_minute = 0\ndeferral_window = 7\nCronWindow = 9\nqueue\n"},
	{input: "executable = /bin/sleep\ncron_minute = 0\nDeferralPrepTime = 11\nqueue\n"},
	// Timing without a schedule sets nothing at all.
	{input: "executable = /bin/sleep\ncron_window = 60\ncron_prep_time = 30\nqueue\n"},
	{input: "executable = /bin/sleep\ndeferral_window = 120\ndeferral_prep_time = 45\nqueue\n"},
	// An empty value is not a value: the window falls back to its default
	// and an empty cron_minute leaves the job undeferred.
	{input: "executable = /bin/sleep\ncron_minute = 0\ncron_window =\nqueue\n"},
	{input: "executable = /bin/sleep\ncron_minute =\nqueue\n"},
	{input: "executable = /bin/sleep\ncron_minute = 0\ncron_window = 1+1\nqueue\n"},

	// --- parity: job retries ---
	// Each of max_retries, retry_until and success_exit_code turns retries
	// on by itself, and OnExitRemove becomes the generated expression.
	{input: "executable = /bin/sleep\nmax_retries = 3\nqueue\n"},
	{input: "executable = /bin/sleep\nretry_until = 42\nqueue\n"},
	{input: "executable = /bin/sleep\nsuccess_exit_code = 5\nqueue\n"},
	{input: "executable = /bin/sleep\nmax_retries = 0\nqueue\n"},
	{input: "executable = /bin/sleep\nmax_retries = -1\nqueue\n"},
	{input: "executable = /bin/sleep\nmax_retries = 2+3\nqueue\n"},
	// retry_until: a constant is a futility exit code, anything naming an
	// attribute is the expression it is, and a ternary keeps its parens.
	{input: "executable = /bin/sleep\nretry_until = 1+1\nqueue\n"},
	{input: "executable = /bin/sleep\nretry_until = true\nqueue\n"},
	{input: "executable = /bin/sleep\nretry_until = 1.9\nqueue\n"},
	{input: "executable = /bin/sleep\nretry_until = -1\nqueue\n"},
	{input: "executable = /bin/sleep\nretry_until = undefined\nqueue\n"},
	{input: "executable = /bin/sleep\nretry_until = JobStatus\nqueue\n"},
	{input: "executable = /bin/sleep\nretry_until = ExitCode == 7\nqueue\n"},
	{input: "executable = /bin/sleep\nmax_retries = 3\nretry_until = ExitCode == 7 || ExitCode == 8\nqueue\n"},
	{input: "executable = /bin/sleep\nretry_until = (ExitCode > 0) && (JobStatus < 5)\nqueue\n"},
	{input: "executable = /bin/sleep\nmax_retries = 1\nretry_until = ExitCode > 0 ? true : false\nqueue\n"},
	// The submitter's on_exit_remove is OR'd onto the generated expression,
	// never kept on its own. A top-level || in what the submitter wrote
	// must NOT gain parentheses -- C++ left-associates it onto the chain,
	// and wrapping it would regroup the tree -- while a ternary must.
	{input: "executable = /bin/sleep\nmax_retries = 3\non_exit_remove = ExitCode == 0 || ExitCode == 1\nqueue\n"},
	{input: "executable = /bin/sleep\nmax_retries = 3\non_exit_remove = ExitCode > 0 ? true : false\nqueue\n"},
	{input: "executable = /bin/sleep\nretry_until = ExitCode == 7\non_exit_remove = ExitCode == 0 || JobStatus == 4\nqueue\n"},
	{input: "executable = /bin/sleep\nretry_until = 42\non_exit_remove = ExitCode == 0\nqueue\n"},
	{input: "executable = /bin/sleep\nsuccess_exit_code = 7\non_exit_remove = ExitCode == 0\nqueue\n"},
	{input: "executable = /bin/sleep\non_exit_remove = ExitCode == 0\nqueue\n"},
	{input: "executable = /bin/sleep\nmax_retries = 3\non_exit_remove = ExitCode == 0\nqueue\n"},
	{input: "executable = /bin/sleep\nmax_retries = 3\non_exit_remove = ExitCode == 0 || ExitCode == 1\nretry_until = 42\nqueue\n"},
	{input: "executable = /bin/sleep\nsuccess_exit_code = 5\non_exit_remove = ExitCode == 0\nqueue\n"},
	{input: "executable = /bin/sleep\non_exit_remove =\nmax_retries = 2\nqueue\n"},
	{input: "executable = /bin/sleep\nmax_retries = 3\nsuccess_exit_code = 5\nretry_until = 42\non_exit_remove = (ExitCode == 1)\non_exit_hold = (ExitCode == 2)\nqueue\n"},
	// on_exit_hold is SetJobRetries' too: retries default it to false.
	{input: "executable = /bin/sleep\non_exit_hold = ExitCode == 3\nqueue\n"},
	{input: "executable = /bin/sleep\non_exit_hold = ExitCode == 3\nmax_retries = 2\nqueue\n"},
	{input: "executable = /bin/sleep\nOnExitHold = ExitCode == 3\nmax_retries = 2\nqueue\n"},
	// An OnExitRemove or JobMaxRetries the submitter set directly stands,
	// and the alternate submit spellings reach the same attributes.
	{input: "executable = /bin/sleep\nMY.OnExitRemove = ExitCode == 9\nmax_retries = 3\nqueue\n"},
	{input: "executable = /bin/sleep\nOnExitRemove = ExitCode == 9\nmax_retries = 3\nqueue\n"},
	{input: "executable = /bin/sleep\nJobMaxRetries = 4\nqueue\n"},
	{input: "executable = /bin/sleep\nMY.JobMaxRetries = 9\nretry_until = 7\nqueue\n"},
	// Both families in one file, over two procs.
	{input: "executable = /bin/sleep\ncron_minute = 0\ncron_window = 60\nmax_retries = 2\nretry_until = 9\non_exit_remove = ExitCode == 4\nqueue 2\n"},

	// --- parity: automatic memory retry ---
	// The three shapes of the on-evict transform: one value, a sequence,
	// and an increment capped by a ceiling. Only the last two leave
	// anything on the ad besides the transform body.
	{input: "executable = /bin/sleep\nrequest_memory = 100\nretry_request_memory = 2048\nqueue\n"},
	{input: "executable = /bin/sleep\nrequest_memory = 100\nretry_request_memory = 128, 256, 512\nqueue\n"},
	{input: "executable = /bin/sleep\nrequest_memory = 100\nretry_request_memory_max = 4096\nretry_request_memory_increase = 128\nqueue\n"},
	// An increment with no ceiling has nothing to grow, so the value is
	// evaluated once against the request the job starts with.
	{input: "executable = /bin/sleep\nrequest_memory = 100\nretry_request_memory_increase = 128\nqueue\n"},
	{input: "executable = /bin/sleep\nrequest_memory = 100\nretry_request_memory_increase = RequestMemory * 2\nqueue\n"},
	// A ceiling on its own is a single retry value, NOT a MaxRequestMemory.
	{input: "executable = /bin/sleep\nrequest_memory = 100\nretry_request_memory_max = 4096\nqueue\n"},
	// `request_memory = a, b` is the short spelling of the same thing, and
	// it supersedes the retry_ commands because condor_submit never reads
	// them in that case.
	{input: "executable = /bin/sleep\nrequest_memory = 100, 400\nqueue\n"},
	{input: "executable = /bin/sleep\nrequest_memory = 100, 200, 400\nqueue\n"},
	{input: "executable = /bin/sleep\nrequest_memory = 100, 400\nretry_request_memory = 8192\nqueue\n"},
	// The list form supersedes retry_request_memory_increase.
	{input: "executable = /bin/sleep\nrequest_memory = 100\nretry_request_memory = 128, 256, 512\nretry_request_memory_increase = 64\nqueue\n"},
	// Sizes carry units, and the result is rounded UP to whole MiB.
	{input: "executable = /bin/sleep\nrequest_memory = 100\nretry_request_memory = 512K, 2M, 1G\nqueue\n"},
	{input: "executable = /bin/sleep\nrequest_memory = 2.5G\nretry_request_memory = 3G\nqueue\n"},
	{input: "executable = /bin/sleep\nrequest_memory = 100\nretry_request_memory_increase = 1.5G\nretry_request_memory_max = 8G\nqueue\n"},
	// The last value of a sequence, and a ceiling, may be an expression
	// the schedd evaluates at retry time rather than a number. Its text
	// goes into the transform body, so its SPELLING has to be HTCondor's
	// own: `MAX({ a,b }) * 2`, not `MAX({a, b}) * 2`.
	{input: "executable = /bin/sleep\nrequest_memory = 100\nretry_request_memory = MAX({RequestMemory, MemoryUsage}) * 2\nqueue\n"},
	{input: "executable = /bin/sleep\nrequest_memory = 100\nretry_request_memory = 128, MAX({RequestMemory, MemoryUsage}) * 2\nqueue\n"},
	{input: "executable = /bin/sleep\nrequest_memory = 100\nretry_request_memory = 2 * 1024\nqueue\n"},
	{input: "executable = /bin/sleep\nrequest_memory = 100\nretry_request_memory = ifThenElse(0, \"str\", RequestMemory)\nqueue\n"},
	{input: "executable = /bin/sleep\nrequest_memory = 100\nretry_request_memory_max = MemoryUsage * 4\nretry_request_memory_increase = 128\nqueue\n"},
	// A request_memory that is not a size takes the whole family out of
	// play: there is no number for the transform to grow from.
	{input: "executable = /bin/sleep\nrequest_memory = ifThenElse(true, 100, 200)\nretry_request_memory_max = 4096\nretry_request_memory_increase = 128\nqueue\n"},
	// With no request_memory at all the configured default is the number
	// the retry grows from, so the family still applies.
	{input: "executable = /bin/sleep\nretry_request_memory = 128, 256\nqueue\n"},
	{input: "executable = /bin/sleep\nretry_request_memory_max = 4096\nretry_request_memory_increase = 128\nqueue\n"},
	// An empty value is not a value.
	{input: "executable = /bin/sleep\nrequest_memory = 100\nretry_request_memory =\nqueue\n"},
	{input: "executable = /bin/sleep\nrequest_memory = 100\nretry_request_memory_max =\nretry_request_memory_increase = 128\nqueue\n"},
	// A directly set TransformOnEvict stands: the +Attr pass runs last.
	{input: "executable = /bin/sleep\nrequest_memory = 100\nretry_request_memory = 256\n+TransformOnEvict = \"Foo\"\nqueue\n"},
	// Both the transform body and the growing expression reach every proc.
	{input: "executable = /bin/sleep\nrequest_memory = 100\nretry_request_memory_max = 4096\nretry_request_memory_increase = 128\nqueue 2\n"},

	// --- parity, exercising inline queue item lists ---
	// Whitespace separates items exactly as a comma does, so none of these
	// lists produces an item with two fields.
	{input: "executable = /bin/sleep\nrequest_cpus = 1\nrequest_memory = 128\narguments = a\nqueue 2 in (a b)\n"},
	{input: "executable = /bin/sleep\nqueue name in (alice bob)\n"},
	{input: "executable = /bin/sleep\narguments = $(Item)\nqueue in (a b, c d)\n"},
	{input: "executable = /bin/sleep\narguments = $(x) $(y)\nqueue x, y in (1 2, 3 4)\n"},
	// The list ends at the last ')' on the line, so the first one here is an
	// item rather than a syntax error.
	{input: "executable = /bin/sleep\narguments = $(Item)\nqueue in(A  ))\n"},
	// Inline `from ( ... )`: unlike `in`, it takes each line whole, so these
	// are the item lists that do fill a second loop variable.
	{input: "executable = /bin/sleep\nqueue name from (\n  x\n  y\n)\n"},
	{input: "executable = /bin/sleep\narguments = $(x) $(y)\nqueue x, y from (\n1 2\n3 4\n)\n"},
	{input: "executable = /bin/sleep\narguments = $(x) $(y)\nqueue x, y from (\n1 2 3\n4\n)\n"},

	// --- parity, exercising item lists written without parentheses ---
	// HTCondor anchors the parse on the `in` keyword and takes the rest of
	// the line as the list, so the parentheses are decoration.
	{input: "executable = /bin/sleep\narguments = $(Item)\nqueue in a b\n"},
	{input: "executable = /bin/sleep\narguments = $(Item)\nqueue in 0 00\n"},
	{input: "executable = /bin/sleep\narguments = $(Item)\nqueue in a, b , c\n"},
	{input: "executable = /bin/sleep\narguments = $(Item)\nqueue 2 in a b\n"},
	{input: "executable = /bin/sleep\narguments = $(Item)\nqueue x in a  b\n"},
	{input: "executable = /bin/sleep\narguments = $(x) $(y)\nqueue x,y in a b, c d\n"},
	{input: "executable = /bin/sleep\narguments = $(Item)\nqueue in\ta\tb\n"},
	// Without a list to delimit, ')' and '#' are ordinary item characters.
	{input: "executable = /bin/sleep\narguments = $(Item)\nqueue in a)\n"},
	{input: "executable = /bin/sleep\narguments = $(Item)\nqueue in a b # c\n"},
	// A qualifier is only a qualifier when something on the line terminates
	// it; at the end of the line it is an ordinary item.
	{input: "executable = /bin/sleep\narguments = $(Item)\nqueue in files\n"},
	{input: "executable = /bin/sleep\narguments = $(Item)\nqueue in table\n"},
	{input: "executable = /bin/sleep\narguments = $(Item)\nqueue in [1:2]\n"},
	// An item list that is empty queues the count with every loop variable
	// expanding to nothing, rather than queueing nothing.
	{input: "executable = /bin/sleep\narguments = A$(Item)B\nqueue in ()\n"},
	{input: "executable = /bin/sleep\narguments = A$(Item)B\nqueue 2 in ()\n"},
	{input: "executable = /bin/sleep\narguments = A$(Item)B\nqueue x in ()\n"},

	// --- parity: the tool daemon (TDP) ---
	// tool_daemon_cmd is the gate for the whole family, the paths are stored
	// as written, and the argument spelling decides the attribute.
	{input: "executable = /bin/sleep\ntool_daemon_cmd = /usr/bin/strace\ntool_daemon_args = -f -p 1\ntool_daemon_input = in.txt\ntool_daemon_output = out.txt\ntool_daemon_error = err.txt\nsuspend_job_at_exec = true\nqueue\n"},
	{input: "executable = /bin/sleep\ntool_daemon_cmd = tdp.sh\ntool_daemon_arguments = -f -p 1\nqueue\n"},
	{input: "executable = /bin/sleep\ntool_daemon_cmd = tdp.sh\ntool_daemon_arguments = \"-f 'a b' c\"\nqueue\n"},
	{input: "executable = /bin/sleep\ntool_daemon_cmd = tdp.sh\ntool_daemon_arguments2 = \"-f 'a b'\"\nqueue\n"},
	// Runs of whitespace between V1 arguments collapse on the way through
	// the ArgList, and an escaped quote survives as a literal one.
	{input: "executable = /bin/sleep\ntool_daemon_cmd = tdp.sh\ntool_daemon_args = -a    -b\t-c\nqueue\n"},
	{input: "executable = /bin/sleep\ntool_daemon_cmd = tdp.sh\ntool_daemon_args = -m \\\"a\\\"\nqueue\n"},
	// Without tool_daemon_cmd the rest of the family is not read at all --
	// not even far enough to notice the two argument spellings together,
	// which is an error when the daemon IS named.
	{input: "executable = /bin/sleep\ntool_daemon_args = -f\ntool_daemon_input = in.txt\ntool_daemon_output = out.txt\nsuspend_job_at_exec = true\nqueue\n"},
	{input: "executable = /bin/sleep\ntool_daemon_args = -f\ntool_daemon_arguments = -g\nqueue\n"},
	// The attribute names double as submit keywords.
	{input: "executable = /bin/sleep\nToolDaemonCmd = tdp.sh\nToolDaemonArgs = -f\nToolDaemonOutput = out.txt\nqueue\n"},

	// --- parity: the buffer settings ---
	// All three are expressions, so an arithmetic value reaches the ad whole.
	{input: "executable = /bin/sleep\nbuffer_files = \"a.txt = b.txt\"\nbuffer_size = 1024\nbuffer_block_size = 2 * 1024\nqueue\n"},
	{input: "executable = /bin/sleep\nbuffer_size = 524288\nqueue\n"},

	// --- parity: the noop job ---
	{input: "executable = /bin/sleep\nnoop_job = true\nnoop_job_exit_code = 42\nnoop_job_exit_signal = 9\nqueue\n"},
	{input: "executable = /bin/sleep\nnoop_job = (JobStatus == 1)\nqueue\n"},

	// --- parity: the java settings ---
	// Neither jar_files nor the java VM arguments are gated on the java
	// universe: condor_submit reads both from every job.
	{input: "executable = /bin/sleep\njar_files = a.jar, b.jar\njava_vm_arguments = -Xmx128m -server\nqueue\n"},
	{input: "executable = /bin/sleep\njava_vm_args = \"-Xmx128m -Dx='a b'\"\nqueue\n"},
	{input: "universe = java\nexecutable = Main\njar_files = app.jar\narguments = MyClass\njava_vm_arguments = -Xmx128m\nqueue\n"},
	{input: "universe = java\nexecutable = Main\njar_files = app.jar\narguments = MyClass\njava_vm_arguments2 = \"-server -Dx='a b'\"\nqueue\n"},

	// --- parity: vm universe ---
	// These pin the attribute names and the gating SetVMParams applies.
	// vm_type decides how much of the rest condor_submit reads at all, and
	// is stored lower-cased.
	{input: "universe = vm\nvm_type = kvm\nvm_memory = 512\nvm_disk = d.img:vda:w\nexecutable = /bin/sleep\nqueue\n"},
	{input: "universe = vm\nvm_type = KVM\nvm_memory = 2G\nvm_vcpus = 4\nvm_macaddr = 00:11:22:33:44:55\nvm_vnc = true\nvm_no_output_vm = true\nvm_disk = d.img:vda:w\nexecutable = /bin/sleep\nqueue\n"},
	// The networking type is read only when networking is on.
	{input: "universe = vm\nvm_type = kvm\nvm_memory = 512\nvm_disk = d.img:vda:w\nvm_networking_type = bridge\nexecutable = /bin/sleep\nqueue\n"},
	{input: "universe = vm\nvm_type = kvm\nvm_memory = 512\nvm_disk = d.img:vda:w\nvm_networking = true\nvm_networking_type = bridge\nexecutable = /bin/sleep\nqueue\n"},
	{input: "universe = vm\nvm_type = kvm\nvm_memory = 512\nvm_disk = d.img:vda:w\nvm_networking = true\nvm_checkpoint = true\nwhen_to_transfer_output = ON_EXIT_OR_EVICT\nexecutable = /bin/sleep\nqueue\n"},
	// SetUniverse forces a vm job's transfer settings and discards what
	// the file asked for, so these seeds pin the override rather than the
	// submitter's value. The generated sweep reaches them only by
	// accident -- it took a change to the GENERATOR, which shifted which
	// files the corpus draws, to produce the ON_EXIT_OR_EVICT one at all
	// -- which is the reason they are written down here instead.
	//
	// A VM job always transfers: ShouldTransferFiles = YES even when the
	// file says NO, and when_to_transfer_output is ON_EXIT unless
	// vm_checkpoint asks for ON_EXIT_OR_EVICT.
	{input: "universe = vm\nvm_type = kvm\nvm_memory = 512\nvm_disk = d.img:vda:w\nexecutable = /bin/sleep\nqueue\n"},
	{input: "universe = vm\nvm_type = kvm\nvm_memory = 512\nvm_disk = d.img:vda:w\nexecutable = /bin/sleep\nwhen_to_transfer_output = ON_EXIT_OR_EVICT\nqueue\n"},
	{input: "universe = vm\nvm_type = kvm\nvm_memory = 512\nvm_disk = d.img:vda:w\nexecutable = /bin/sleep\nshould_transfer_files = NO\nqueue\n"},
	{input: "universe = vm\nvm_type = kvm\nvm_memory = 512\nvm_disk = d.img:vda:w\nexecutable = /bin/sleep\nvm_checkpoint = true\nqueue\n"},
	{input: "universe = vm\nvm_type = kvm\nvm_memory = 512\nvm_disk = d.img:vda:w\nexecutable = /bin/sleep\nvm_checkpoint = true\nwhen_to_transfer_output = ON_EXIT\nqueue\n"},
	// The attribute spelling of vm_checkpoint counts as well.
	{input: "universe = vm\nvm_type = kvm\nvm_memory = 512\nvm_disk = d.img:vda:w\nexecutable = /bin/sleep\nJobVMCheckpoint = true\nqueue\n"},
	// The override runs before anything validates the two settings, so a
	// value that is a hard error in any other universe is accepted here.
	{input: "universe = vm\nvm_type = kvm\nvm_memory = 512\nvm_disk = d.img:vda:w\nexecutable = /bin/sleep\nshould_transfer_files = MAYBE\nqueue\n"},
	{input: "universe = vm\nvm_type = kvm\nvm_memory = 512\nvm_disk = d.img:vda:w\nexecutable = /bin/sleep\nwhen_to_transfer_output = SOMETIME\nqueue\n"},
	{input: "universe = vm\nvm_type = kvm\nvm_memory = 512\nvm_disk = d.img:vda:w\nexecutable = /bin/sleep\nshould_transfer_files = NO\ntransfer_input_files = a.txt\nqueue\n"},
	// vm_memory defaults to $(Request_Memory) and vm_vcpus to $(Request_CPUs),
	// and the default is the macro's text: 2*2 is two CPUs, not four.
	{input: "universe = vm\nvm_type = kvm\nvm_disk = d.img:vda:w\nrequest_memory = 1024\nrequest_cpus = 2*2\nexecutable = /bin/sleep\nqueue\n"},
	{input: "universe = vm\nvm_type = kvm\nvm_disk = d.img:vda:w\nRequestMemory = 777\nRequestCpus = 6\nexecutable = /bin/sleep\nqueue\n"},
	// The xen_* keywords belong to a Xen VM; under kvm they are dropped.
	{input: "universe = vm\nvm_type = kvm\nvm_memory = 512\nvm_disk = d.img:vda:w\nxen_kernel = /boot/vmlinuz\nxen_root = /dev/sda1\nxen_initrd = /boot/initrd\nxen_kernel_params = ro\nexecutable = /bin/sleep\nqueue\n"},
	{input: "universe = vm\nvm_type = xen\nvm_memory = 512\nvm_disk = d.img:vda:w\nxen_kernel = /boot/vmlinuz\nxen_root = /dev/sda1\nxen_initrd = /boot/initrd\nxen_kernel_params = \"ro quiet\"\nexecutable = /bin/sleep\nqueue\n"},
	// "included" boots from the disk image and "vmx" asks for hardware
	// virtualization; neither is a kernel file, so initrd and root do not
	// apply, and "vmx" turns on JobVMHardwareVT.
	{input: "universe = vm\nvm_type = xen\nvm_memory = 512\nvm_disk = d.img:vda:w\nxen_kernel = included\nexecutable = /bin/sleep\nqueue\n"},
	{input: "universe = vm\nvm_type = xen\nvm_memory = 512\nvm_disk = d.img:vda:w\nxen_kernel = vmx\nexecutable = /bin/sleep\nqueue\n"},
	// ... and a xen_root written anyway is read by neither.
	{input: "universe = vm\nvm_type = xen\nvm_memory = 512\nvm_disk = d.img:vda:w\nxen_kernel = included\nxen_root = /dev/sda1\nexecutable = /bin/sleep\nqueue\n"},
	{input: "universe = vm\nvm_type = xen\nvm_memory = 512\nvm_disk = d.img:vda:w\nxen_kernel = vmx\nxen_root = /dev/sda1\nexecutable = /bin/sleep\nqueue\n"},
	// vm_vcpus is (int)strtol() of the value with a floor of 1: the leading
	// digits, 0 for anything else, and a 32-bit truncation on the way.
	{input: "universe = vm\nvm_type = kvm\nvm_memory = 512\nvm_disk = d.img:vda:w\nvm_vcpus = 0\nexecutable = /bin/sleep\nqueue\n"},
	{input: "universe = vm\nvm_type = kvm\nvm_memory = 512\nvm_disk = d.img:vda:w\nvm_vcpus = -3\nexecutable = /bin/sleep\nqueue\n"},
	{input: "universe = vm\nvm_type = kvm\nvm_memory = 512\nvm_disk = d.img:vda:w\nvm_vcpus = abc\nexecutable = /bin/sleep\nqueue\n"},
	{input: "universe = vm\nvm_type = kvm\nvm_memory = 512\nvm_disk = d.img:vda:w\nvm_vcpus = 2 cpus\nexecutable = /bin/sleep\nqueue\n"},
	{input: "universe = vm\nvm_type = kvm\nvm_memory = 512\nvm_disk = d.img:vda:w\nvm_vcpus = 4294967296\nexecutable = /bin/sleep\nqueue\n"},
	// --- parity: grid universe ---
	// The grid TYPE is the first word of grid_resource, and it governs only
	// which settings are required and whether the job gets the implicit Name
	// tag. Every other keyword in the family is read whatever the type, so a
	// batch job that names an AMI carries EC2AmiID all the same.
	//
	// The generated sweep only ever writes `grid_resource = batch slurm`, so
	// everything here that depends on the ec2, gce or azure type -- the
	// implicit Name tag most of all -- is reachable from the seeds alone.
	{input: "universe = grid\ngrid_resource = batch slurm\nexecutable = /bin/sleep\nbatch_queue = q\nbatch_project = p\nbatch_runtime = 60\nbatch_extra_submit_args = --exclusive\nqueue\n"},
	{input: "universe = grid\ngrid_resource = batch slurm\nexecutable = /bin/sleep\nec2_ami_id = ami-dead\nec2_elastic_ip = 1.2.3.4\nec2_vpc_ip = 10.0.0.1\nec2_vpc_subnet = subnet-1\nec2_user_data_file = ud.txt\nqueue\n"},
	// An ec2 job must name an AMI and both halves of its credentials, or
	// condor_submit refuses the file.
	{input: "universe = grid\ngrid_resource = ec2 https://ec2.example.com/\nexecutable = myjob\nec2_access_key_id = akid.txt\nec2_secret_access_key = skey.txt\nec2_ami_id = ami-dead\nec2_instance_type = m1.small\nqueue\n"},
	// "FROM INSTANCE" under either half sets BOTH, and is kept verbatim
	// rather than resolved against Iwd the way a key file is.
	{input: "universe = grid\ngrid_resource = ec2 https://ec2.example.com/\nexecutable = myjob\nec2_access_key_id = FROM INSTANCE\nec2_ami_id = ami-dead\nqueue\n"},
	{input: "universe = grid\ngrid_resource = ec2 https://ec2.example.com/\nexecutable = myjob\nec2_secret_access_key = from instance\nec2_ami_id = ami-dead\nqueue\n"},
	// ec2_keypair names a pair already registered with EC2 and
	// ec2_keypair_file names where to write a generated one, so naming both
	// drops the file; and an instance profile NAME is kept only alongside
	// its ARN.
	{input: "universe = grid\ngrid_resource = ec2 https://ec2.example.com/\nexecutable = myjob\nec2_access_key_id = FROM INSTANCE\nec2_ami_id = ami-dead\nec2_keypair = kp\nec2_keypair_file = kp.out\nec2_iam_profile_name = prof\nqueue\n"},
	{input: "universe = grid\ngrid_resource = ec2 https://ec2.example.com/\nexecutable = myjob\nec2_access_key_id = FROM INSTANCE\nec2_ami_id = ami-dead\nec2_key_pair_file = kp.out\nec2_iam_profile_arn = arn:aws:iam::1:instance-profile/p\nec2_iam_profile_name = prof\nqueue\n"},
	// Tags and labels: a name list, pairs written under either the submit
	// or the attribute prefix, and the implicit Name tag an ec2 job gets
	// from its executable unless WantNameTag says otherwise.
	{input: "universe = grid\ngrid_resource = ec2 https://ec2.example.com/\nexecutable = myjob\nec2_access_key_id = FROM INSTANCE\nec2_ami_id = ami-dead\nec2_tag_names = t1 t2\nec2_tag_t1 = v1\nEC2Tagzed = v3\ncloud_label_x = lv\nqueue\n"},
	{input: "universe = grid\ngrid_resource = ec2 https://ec2.example.com/\nexecutable = myjob\nec2_access_key_id = FROM INSTANCE\nec2_ami_id = ami-dead\nWantNameTag = false\nec2_tag_names = a, b\nqueue\n"},
	{input: "universe = grid\ngrid_resource = ec2 https://ec2.example.com/\nexecutable = myjob\nec2_access_key_id = FROM INSTANCE\nec2_ami_id = ami-dead\nec2_tag_Name = mine\nqueue\n"},
	// Arbitrary RunInstances parameters. The names are joined with ", "
	// where tag names are joined with ",", and a name holding a dot never
	// matches itself in the de-duplication, so it is listed twice.
	{input: "universe = grid\ngrid_resource = ec2 https://ec2.example.com/\nexecutable = myjob\nec2_access_key_id = FROM INSTANCE\nec2_ami_id = ami-dead\nWantNameTag = false\nec2_parameter_names = Zed foo.bar\nec2_parameter_Alpha = 1\nec2_parameter_foo.bar = 2\nqueue\n"},
	// A gce job must name an image and a machine type. gce_metadata is
	// re-joined from its fields, which drops the spacing.
	{input: "universe = grid\ngrid_resource = gce https://gce.example.com/ proj zone\nexecutable = myjob\ngce_image = img\ngce_machine_type = n1-standard-1\ngce_account = acct\ngce_auth_file = auth.txt\ngce_json_file = j.json\ngce_metadata_file = md.txt\ngce_metadata = a=1, b=2\ngce_preemptible = true\nqueue\n"},
	// An azure job must name all five of image, location, size and the
	// admin credentials.
	{input: "universe = grid\ngrid_resource = azure sub-id\nexecutable = myjob\nazure_image = img\nazure_location = westus2\nazure_size = Standard_A1\nazure_admin_username = u\nazure_admin_key = k.pub\nazure_auth_file = auth.json\nqueue\n"},
	// The presigned-URL credential keywords are not part of the grid
	// family: they are read in any universe, share the EC2 attributes, and
	// are stored exactly as written. The last spelling in HTCondor's table
	// wins, which is the gs_ one.
	{input: "executable = /bin/sleep\naws_region = us-east-1\naws_access_key_id_file = akid.txt\naws_secret_access_key_file = skey.txt\nqueue\n"},
	{input: "executable = /bin/sleep\naws_access_key_id_file = akid.txt\ns3_access_key_id_file = s3kid.txt\ngs_access_key_id_file = gskid.txt\nqueue\n"},
	// ... and in a grid job the verbatim value overrides the absolute path
	// the grid pass resolved.
	{input: "universe = grid\ngrid_resource = ec2 https://ec2.example.com/\nexecutable = myjob\naws_access_key_id_file = akid.txt\naws_secret_access_key_file = skey.txt\nec2_ami_id = ami-dead\nWantNameTag = false\nqueue\n"},
	// Outside the grid universe none of the family is read at all.
	{input: "executable = /bin/sleep\nec2_elastic_ip = 1.2.3.4\nec2_keypair_file = kp.out\ngce_image = img\nazure_size = Standard_A1\nqueue\n"},

	// --- parity: the GPU request keywords ---
	// The generated sweep reaches these keywords but rarely in the one
	// combination that makes them do anything: SetRequestGpus reads them
	// only when the file ALSO asked for a GPU, and the derived RequireGPUs
	// needs two of them at once to show its shape. The seeds pin both.
	//
	// Without a request_gpus the keywords set nothing at all, however many
	// of them a file carries.
	{input: "executable = /bin/sleep\ngpus_minimum_capability = 7.5\ngpus_maximum_capability = 8.0\ngpus_minimum_memory = 4G\ngpus_minimum_runtime = 12.1\nrequire_gpus = Capability > 5\nqueue\n"},
	{input: "executable = /bin/sleep\nrequest_gpus = undefined\ngpus_minimum_capability = 7.5\nqueue\n"},
	// One at a time, so each clause of the derived expression is pinned on
	// its own.
	{input: "executable = /bin/sleep\nrequest_gpus = 1\ngpus_minimum_capability = 7.5\nqueue\n"},
	{input: "executable = /bin/sleep\nrequest_gpus = 1\ngpus_maximum_capability = 8.0\nqueue\n"},
	{input: "executable = /bin/sleep\nrequest_gpus = 1\ngpus_minimum_memory = 4G\nqueue\n"},
	{input: "executable = /bin/sleep\nrequest_gpus = 1\ngpus_minimum_runtime = 12.1\nqueue\n"},
	// All four, which is where the ORDER and the left-associative grouping
	// of the `&&` chain are visible.
	{input: "executable = /bin/sleep\nrequest_gpus = 1\ngpus_minimum_capability = 7.5\ngpus_maximum_capability = 8.0\ngpus_minimum_memory = 4G\ngpus_minimum_runtime = 12.1\nqueue\n"},
	// gpus_minimum_memory is a MB quantity with the usual unit suffixes,
	// rounded up, and falls back to an expression when it is not a size.
	{input: "executable = /bin/sleep\nrequest_gpus = 1\ngpus_minimum_memory = 4000\nqueue\n"},
	{input: "executable = /bin/sleep\nrequest_gpus = 1\ngpus_minimum_memory = 2.5G\nqueue\n"},
	{input: "executable = /bin/sleep\nrequest_gpus = 1\ngpus_minimum_memory = 1T\nqueue\n"},
	{input: "executable = /bin/sleep\nrequest_gpus = 1\ngpus_minimum_memory = SomeAttr + 1\nqueue\n"},
	// gpus_minimum_runtime is a CUDA version in "x" or "x.y" form,
	// canonicalized to x*1000 + y*10. A number already past 1000 with no
	// minor part is taken to be canonical; a minor part of 100 or more, or
	// anything that is not a version, stays an expression.
	{input: "executable = /bin/sleep\nrequest_gpus = 1\ngpus_minimum_runtime = 12\nqueue\n"},
	{input: "executable = /bin/sleep\nrequest_gpus = 1\ngpus_minimum_runtime = 12010\nqueue\n"},
	{input: "executable = /bin/sleep\nrequest_gpus = 1\ngpus_minimum_runtime = 1000\nqueue\n"},
	{input: "executable = /bin/sleep\nrequest_gpus = 1\ngpus_minimum_runtime = .5\nqueue\n"},
	{input: "executable = /bin/sleep\nrequest_gpus = 1\ngpus_minimum_runtime = 12.100\nqueue\n"},
	{input: "executable = /bin/sleep\nrequest_gpus = 1\ngpus_minimum_runtime = SomeAttr\nqueue\n"},
	// A require_gpus the submitter wrote is an EXPRESSION, and the derived
	// clauses are AND'd onto it -- except for a property it already
	// mentions, which it keeps to itself. TARGET.Capability names the
	// machine ad rather than the GPU and suppresses nothing; MY.Capability
	// and a bare lower-case capability both do suppress.
	{input: "executable = /bin/sleep\nrequest_gpus = 1\nrequire_gpus = DriverVersion > 11\nqueue\n"},
	{input: "executable = /bin/sleep\nrequest_gpus = 1\nrequire_gpus = DriverVersion > 11\ngpus_minimum_capability = 7.5\ngpus_minimum_memory = 4G\nqueue\n"},
	{input: "executable = /bin/sleep\nrequest_gpus = 1\nrequire_gpus = Capability > 5\ngpus_minimum_capability = 7.5\ngpus_minimum_memory = 4G\nqueue\n"},
	{input: "executable = /bin/sleep\nrequest_gpus = 1\nrequire_gpus = capability > 5\ngpus_minimum_capability = 7.5\nqueue\n"},
	{input: "executable = /bin/sleep\nrequest_gpus = 1\nrequire_gpus = MY.Capability > 5\ngpus_minimum_capability = 7.5\nqueue\n"},
	{input: "executable = /bin/sleep\nrequest_gpus = 1\nrequire_gpus = TARGET.Capability > 5\ngpus_minimum_capability = 7.5\nqueue\n"},
	{input: "executable = /bin/sleep\nrequest_gpus = 1\nrequire_gpus = foo(Capability)\ngpus_minimum_capability = 7.5\nqueue\n"},
	// The parenthesization of that join is load-bearing: only a `||` or a
	// ternary binds more loosely than the `&&` it is about to sit under,
	// and parenthesizing anything else would regroup the tree.
	{input: "executable = /bin/sleep\nrequest_gpus = 1\nrequire_gpus = GlobalMemoryMb > 100 || DriverVersion > 11\ngpus_minimum_runtime = 12.1\nqueue\n"},
	{input: "executable = /bin/sleep\nrequest_gpus = 1\nrequire_gpus = Capability ? 1 : 2\ngpus_minimum_memory = 4G\nqueue\n"},
	{input: "executable = /bin/sleep\nrequest_gpus = 1\nrequire_gpus = DriverVersion > 11 && SomeAttr > 1\ngpus_minimum_runtime = 12.1\nqueue\n"},
	{input: "executable = /bin/sleep\nrequest_gpus = 1\nrequire_gpus = (Capability > 5)\ngpus_minimum_memory = 4G\nqueue\n"},
	{input: "executable = /bin/sleep\nrequest_gpus = 1\nrequire_gpus = !DriverVersion\ngpus_minimum_memory = 4G\nqueue\n"},
	// Each keyword answers to its attribute name as a second spelling, and
	// the derivation reads the AD, so a `+GPUsMinCapability` reaches it
	// even though the KEYWORD would have needed a request_gpus first.
	{input: "executable = /bin/sleep\nrequest_gpus = 1\nGPUsMinCapability = 7.5\nRequireGPUs = DriverVersion > 11\nqueue\n"},
	{input: "executable = /bin/sleep\nrequest_gpus = 1\n+GPUsMinCapability = 7.5\n+GPUsMinMemory = 100\nqueue\n"},
	{input: "executable = /bin/sleep\nMY.RequestGPUs = 1\nMY.GPUsMinCapability = 7.5\nqueue\n"},
	{input: "executable = /bin/sleep\n+RequestGPUs = 1\ngpus_minimum_capability = 7.5\nqueue\n"},

	// --- parity: cuda_version ---
	// The keyword reaches the ad as a string and SetRequirements rewrites
	// it as an integer -- with a DIFFERENT encoding from
	// gpus_minimum_runtime's, however alike the two look: "12.1" is 12001
	// here and 12010 there.
	{input: "executable = /bin/sleep\ncuda_version = 12.1\nqueue\n"},
	{input: "executable = /bin/sleep\ncuda_version = 11.2\nqueue\n"},
	{input: "executable = /bin/sleep\ncuda_version = 12\nqueue\n"},
	{input: "executable = /bin/sleep\ncuda_version = 999\nqueue\n"},
	{input: "executable = /bin/sleep\ncuda_version = 1000\nqueue\n"},
	{input: "executable = /bin/sleep\ncuda_version = 12010\nqueue\n"},
	{input: "executable = /bin/sleep\ncuda_version = 0\nqueue\n"},
	// %u is unsigned, so a negative wraps rather than failing.
	{input: "executable = /bin/sleep\ncuda_version = -1\nqueue\n"},
	// The conversion lives inside SetRequirements, so it is skipped
	// wherever that function returns early with a Requirements expression
	// it was handed -- and a value it would otherwise reject survives.
	{input: "executable = /bin/sleep\ncuda_version = 12.1\nrequirements = true\nqueue\n"},
	{input: "executable = /bin/sleep\ncuda_version = 12.1\n+Requirements = true\nqueue\n"},
	{input: "executable = /bin/sleep\ncuda_version = 12.1\nMY.Requirements = true\nqueue\n"},
	{input: "executable = /bin/sleep\ncuda_version = junk\n+Requirements = true\nqueue\n"},
	{input: "executable = /bin/sleep\ncuda_version = 12.1\nFACTORY.Requirements = true\nqueue\n"},
	// A non-Condor-C grid job gets no generated requirements at all, and
	// so keeps the string; a Condor-C one does not.
	{input: "universe = grid\ngrid_resource = batch slurm\nexecutable = myjob\ncuda_version = 12.1\nqueue\n"},
	{input: "universe = grid\ngrid_resource = batch slurm\nexecutable = myjob\ncuda_version = junk\nqueue\n"},
	{input: "universe = grid\ngrid_resource = condor host host\nexecutable = myjob\ncuda_version = 12.1\nqueue\n"},
	{input: "executable = /bin/sleep\nuniverse = scheduler\ncuda_version = 12.1\nqueue\n"},
	{input: "executable = /bin/sleep\nuniverse = local\ncuda_version = 12.1\nqueue\n"},
	// --- parity: attributes condor_submit derives rather than reads ---
	// None of these comes from a keyword, so the keyword-table comparison
	// says nothing about them; the whole-ad comparison does.
	// TestDerivedAttributesMatchOracle takes each one apart.
	{input: "executable = /bin/sleep\nstarter_log = s.log\nqueue\n"},
	{input: "executable = /bin/sleep\nstarter_log = s.log\nstarter_debug = D_FULLDEBUG\nqueue\n"},
	{input: "universe = parallel\nexecutable = /bin/sleep\nmachine_count = 2\nqueue\n"},
	{input: "universe = parallel\nexecutable = /bin/sleep\nmachine_count = 2\nwant_io_proxy = false\nqueue\n"},
	{input: "executable = /bin/sleep\nnice_user = true\nqueue\n"},
	{input: "executable = /bin/sleep\nnice_user = false\nqueue\n"},
}

func requireOracle(t testing.TB) {
	if !oracle.Available {
		t.Skip("differential submit test needs the C++ oracle: `source hack/submit-fuzz-env.sh` then run with -tags libcondor_utils")
	}
}

// check runs one submit file through both parsers and returns the divergences
// that are neither host-derived nor already known, plus which known ones
// appeared. skip is true when the case is not comparable: the C++ side threw,
// or the two sides disagree about whether the file parses at all.
//
// Parse ACCEPTANCE is deliberately not asserted. The Go parser is stricter in
// places and more lenient in others, and a fuzzer finds those immediately and
// endlessly; what this target is for is the semantics of files both sides
// accept. Acceptance divergence is tracked separately by
// TestSeedParseAcceptance, which reports rather than fails.
func check(t testing.TB, src string) (fresh []Divergence, seenKnown map[string]bool, skip bool) {
	t.Helper()

	cpp := oracle.MakeAds(src, oracle.ModeAds, MaxProcs)
	if cpp.Panic {
		return nil, nil, true // a C++ exception is uncomparable, not a Go bug
	}
	goRes := GoMakeAds(src)
	if goRes.Panic {
		t.Fatalf("Go submit parser panicked on:\n%q", src)
	}
	if !cpp.OK || !goRes.OK {
		return nil, nil, true
	}

	cppAds, err := ParseCanon(cpp.Ads)
	if err != nil {
		t.Fatalf("malformed oracle output for %q: %v", src, err)
	}
	if cppAds.Truncated != goRes.Ads.Truncated {
		return nil, nil, true // one side capped the procs and the other did not
	}

	fresh, seenKnown = Compare(cppAds, goRes.Ads)
	return fresh, seenKnown, false
}

// TestSeedsHaveNoFreshDivergence is the parity assertion. A seed with no
// reason must produce no differences beyond hostDerived and knownDivergent; a
// seed WITH a reason must still differ somehow, so that fixing the Go side
// turns the case red and the finding gets promoted to parity.
func TestSeedsHaveNoFreshDivergence(t *testing.T) {
	requireOracle(t)
	for _, sc := range seeds {
		t.Run(strings.ReplaceAll(firstLine(sc.input), " ", "_"), func(t *testing.T) {
			fresh, _, skip := check(t, sc.input)
			if sc.reason != "" {
				if !skip && len(fresh) == 0 {
					t.Errorf("known divergence no longer reproduces -- promote it to parity and delete the reason:\n  %s", sc.reason)
				}
				for _, d := range fresh {
					t.Logf("known: %s", d)
				}
				return
			}
			if skip {
				t.Skip("not comparable (one side rejected the file)")
			}
			for _, d := range fresh {
				t.Errorf("fresh divergence: %s", d)
			}
		})
	}
}

// TestKnownDivergencesStillDiverge keeps the knownDivergent ATTRIBUTE table
// honest, the way the reason strings keep the seed table honest. Every entry
// listed here must still diverge; when one starts agreeing, the Go side was
// fixed and the entry should be deleted so the fix cannot silently regress.
func TestKnownDivergencesStillDiverge(t *testing.T) {
	requireOracle(t)

	seen := make(map[string]bool)
	for _, sc := range seeds {
		_, s, skip := check(t, sc.input)
		if skip {
			continue
		}
		for attr := range s {
			seen[attr] = true
		}
	}
	// Only attributes a basic submit file always produces are asserted; the
	// rest of the table depends on which commands a seed uses.
	for _, attr := range []string{"shouldtransferfiles", "requirements", "rank", "mytype", "targettype"} {
		if !seen[attr] {
			t.Errorf("%q no longer diverges from the C++ parser: delete it from knownDivergent so the fix is locked in", attr)
		}
	}
}

// TestSeedParseAcceptance reports, without failing, which seeds the two sides
// disagree about accepting. That disagreement is real and worth knowing, but it
// is a different question from whether the ads match, and failing on it would
// bury every semantic finding.
func TestSeedParseAcceptance(t *testing.T) {
	requireOracle(t)
	for _, sc := range seeds {
		cpp := oracle.MakeAds(sc.input, oracle.ModeAds, MaxProcs)
		goRes := GoMakeAds(sc.input)
		if cpp.Panic {
			t.Logf("C++ EXCEPTION on %q: %s", firstLine(sc.input), cpp.Err)
			continue
		}
		if cpp.OK != goRes.OK {
			t.Logf("acceptance differs on %q: cpp.ok=%v (%s) go.ok=%v (%s)",
				firstLine(sc.input), cpp.OK, cpp.Err, goRes.OK, goRes.Err)
		}
	}
}

// FuzzSubmitAds compares the job ads the two parsers build from the same submit
// file. Run it with hack/submit-fuzz.sh, which builds the test binary and runs
// it directly (go test's re-exec loses the oracle's library path on macOS).
func FuzzSubmitAds(f *testing.F) {
	requireOracle(f)
	for _, sc := range seeds {
		f.Add(sc.input)
	}
	f.Fuzz(func(t *testing.T, src string) {
		// The seeds that carry a reason are known divergences, kept in the
		// corpus so the fuzzer explores their syntax. The exact input is
		// skipped -- TestSeedsHaveNoFreshDivergence is what asserts those --
		// while every mutation of it is still compared.
		if knownDivergentSeed(src) {
			t.Skip("known divergent seed; see its reason in the seeds table")
		}

		// Bracket the whole iteration: a worker that dies anywhere in here --
		// in the oracle, in the Go parser, or in the comparison -- leaves this
		// behind naming the input, which is otherwise unrecoverable.
		oracle.JournalEnter("FuzzSubmitAds", src)
		defer oracle.JournalLeave()
		// A submit file is text. Feeding the oracle arbitrary bytes tests the
		// lexers' handling of garbage, which the ClassAd and config fuzzers
		// already cover, and crowds out the semantic comparison this is for.
		if !isPlausibleSubmit(src) {
			t.Skip("not plausible submit text")
		}
		fresh, _, skip := check(t, src)
		if skip {
			return
		}
		for _, d := range fresh {
			t.Errorf("fresh divergence on:\n%s\n  %s", src, d)
		}
	})
}

// isPlausibleSubmit keeps the fuzzer on inputs that can reach the semantics:
// printable, bounded, and with a queue statement.
func isPlausibleSubmit(src string) bool {
	if len(src) == 0 || len(src) > 4096 {
		return false
	}
	for _, r := range src {
		if r == 0 || (r < 0x20 && r != '\n' && r != '\t' && r != '\r') || r > 0x7e {
			return false
		}
	}
	return strings.Contains(strings.ToLower(src), "queue")
}

func firstLine(s string) string {
	line, _, _ := strings.Cut(s, "\n")
	if line == "" {
		line = "(empty)"
	}
	if len(line) > 40 {
		line = line[:40]
	}
	return line
}

// knownDivergentSeed reports whether src is exactly one of the seeds recorded
// as a known divergence.
func knownDivergentSeed(src string) bool {
	for _, sc := range seeds {
		if sc.reason != "" && sc.input == src {
			return true
		}
	}
	return false
}
