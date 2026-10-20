package appolicy

import (
	"fmt"
	"strconv"
	"strings"
	"time"
)

// Entry is one knob in a report.
type Entry struct {
	Name string
	// Value is what the schedd reported, "" when unset. JOB_EPOCH_HISTORY
	// is a path and reports only "enabled"; a transform reports its
	// summary, not its text.
	Value       string
	Set         bool
	NonDefault  bool
	Description string
	// Unknown is true when the schedd could not be asked for this knob.
	Unknown bool
	// Effective, when not "", is the value that actually applies because
	// this server overrides the access point's (the DAGMan throttles).
	Effective string
	// Extra carries per-kind detail: a requirement's reason, a policy's
	// subcode.
	Extra map[string]interface{}
}

// Group is one section of a report.
type Group struct {
	Name    string
	Title   string
	Entries []Entry
}

// Report is an access point's policy, rendered.
type Report struct {
	AccessPoint string
	FetchedAt   time.Time
	Groups      []Group
}

// RenderOptions is what this server adds to the access point's own
// configuration.
type RenderOptions struct {
	// DagmanEnv is the environment this server starts every DAGMan
	// with. A _CONDOR_<KNOB> there overrides the access point's value
	// for every workflow submitted through it.
	DagmanEnv map[string]string
	// TTL is how long a reading is served, for the report's header.
	TTL time.Duration
}

// maxExprText bounds an expression quoted in prose. The structured value
// always carries the whole of it.
const maxExprText = 400

// Render describes a reading.
func Render(s *Snapshot, opts RenderOptions) *Report {
	r := &Report{AccessPoint: s.AccessPoint, FetchedAt: s.FetchedAt}
	r.Groups = []Group{
		{GroupSubmissionLimits, "Submission limits", submissionLimits(s)},
		{GroupSubmitRequirements, "Submit requirements (checked when a job is submitted)", submitRequirements(s)},
		{GroupJobTransforms, "Job transforms (changes the schedd makes to submitted jobs)", jobTransforms(s)},
		{GroupRequestDefaults, "Resource requests of a job that omits request_*", requestDefaults(s)},
		{GroupHoldPolicy, "Hold, remove and release policy", holdPolicy(s)},
		{GroupFileTransfer, "File transfer limits", fileTransfer(s)},
		{GroupDAGMan, "DAGMan throttles (per workflow)", dagman(s, opts.DagmanEnv)},
		{GroupFeatures, "Features", features(s)},
	}
	return r
}

// entry builds the common part of an entry; describe writes the sentence
// for a value that was read.
func entry(s *Snapshot, name string, describe func(v Value) string) Entry {
	v := s.Get(name)
	e := Entry{Name: name, Value: v.Raw, Set: v.Set, NonDefault: isNonDefault(name, v)}
	if v.Err != nil {
		e.Unknown = true
		e.Description = "Could not be read from the schedd: " + v.Err.Error() + "."
		return e
	}
	e.Description = describe(v)
	return e
}

// --- submission limits ------------------------------------------------------

func submissionLimits(s *Snapshot) []Entry {
	return []Entry{
		entry(s, "MAX_JOBS_PER_SUBMISSION", func(v Value) string {
			return limitSentence(v, "One submission -- one submit_job call, or one submit file's queue statements -- "+
				"may create at most %s jobs; a larger one is refused whole, so split it.",
				"One submission may create any number of jobs.")
		}),
		entry(s, "MAX_JOBS_PER_OWNER", func(v Value) string {
			return limitSentence(v, "You may have at most %s jobs in this access point's queue at once, in any state; "+
				"a submission that would go past that is refused.",
				"There is no limit on how many jobs one user may have in the queue.")
		}),
		entry(s, "MAX_JOBS_SUBMITTED", func(v Value) string {
			return limitSentence(v, "The queue holds at most %s jobs from all users together; past that, every "+
				"submission is refused until jobs leave.",
				"There is no limit on the size of the queue as a whole.")
		}),
		entry(s, "MAX_RUNNING_SCHEDULER_JOBS_PER_OWNER", func(v Value) string {
			return limitSentence(v, "At most %s of your scheduler-universe jobs run at once. Every DAG workflow runs "+
				"as one (its DAGMan), so this is also how many of your workflows can run concurrently; "+
				"the rest wait idle.",
				"There is no limit on how many scheduler-universe jobs (each DAG's DAGMan is one) a user may run at once.")
		}),
	}
}

// limitSentence words a count limit. The schedd reads these with
// param_integer; a value at or past the largest int, or unset, is no
// limit at all.
func limitSentence(v Value, format, unlimited string) string {
	if !v.Set {
		return "Not set: " + strings.ToLower(unlimited[:1]) + unlimited[1:]
	}
	if n, err := strconv.ParseInt(v.Raw, 10, 64); err == nil && n >= 2147483647 {
		return unlimited
	}
	return fmt.Sprintf(format, v.Raw)
}

// --- submit requirements ----------------------------------------------------

func submitRequirements(s *Snapshot) []Entry {
	list := s.Get("SUBMIT_REQUIREMENT_NAMES")
	names, _ := splitNames(list.Raw)
	out := []Entry{entry(s, "SUBMIT_REQUIREMENT_NAMES", func(v Value) string {
		if !v.Set || len(names) == 0 {
			return "No submit requirements: the schedd accepts any job it can parse."
		}
		return fmt.Sprintf("Every submitted job is checked against %d requirement(s), in this order: %s. "+
			"The first one a job fails refuses it at submit, unless that one is only a warning.%s",
			len(names), strings.Join(names, ", "), truncatedNote(s, "SUBMIT_REQUIREMENT_NAMES"))
	})}
	for _, n := range names {
		name := "SUBMIT_REQUIREMENT_" + n
		reason := s.Get(name + "_REASON")
		warning := s.Get(name + "_IS_WARNING")
		isWarning, _ := parseBool(warning.Raw)
		e := entry(s, name, func(v Value) string {
			if !v.Set {
				return "Listed in SUBMIT_REQUIREMENT_NAMES but not defined; the schedd ignores it."
			}
			outcome := "A job is refused"
			if isWarning {
				outcome = "A job is accepted, with a warning,"
			}
			var b strings.Builder
			switch text, literal := stringLiteral(reason.Raw); {
			case reason.Set && literal:
				fmt.Fprintf(&b, "%s with the message %q unless %s.", outcome, text, quoteExpr(v.Raw))
			case reason.Set:
				fmt.Fprintf(&b, "%s unless %s. The message is computed from the job: %s.",
					outcome, quoteExpr(v.Raw), quoteExpr(reason.Raw))
			default:
				fmt.Fprintf(&b, "%s unless %s; the message names the requirement %q.", outcome, quoteExpr(v.Raw), n)
			}
			return b.String()
		})
		e.Extra = map[string]interface{}{"reason": reasonText(reason), "is_warning": isWarning}
		out = append(out, e)
	}
	return out
}

// --- job transforms ---------------------------------------------------------

func jobTransforms(s *Snapshot) []Entry {
	names, _ := splitNames(s.Get("JOB_TRANSFORM_NAMES").Raw)
	out := []Entry{entry(s, "JOB_TRANSFORM_NAMES", func(v Value) string {
		if !v.Set || len(names) == 0 {
			return "No transforms: jobs are queued as submitted."
		}
		return fmt.Sprintf("The schedd rewrites matching jobs as they are submitted, applying these transforms "+
			"in order: %s. A job's attributes after submit can differ from what its submit file said; "+
			"get_job shows the result.%s", strings.Join(names, ", "), truncatedNote(s, "JOB_TRANSFORM_NAMES"))
	})}
	for _, n := range names {
		name := "JOB_TRANSFORM_" + n
		var sum TransformSummary
		e := entry(s, name, func(v Value) string {
			if !v.Set {
				return "Listed in JOB_TRANSFORM_NAMES but not defined; the schedd ignores it."
			}
			sum = SummarizeTransform(v.Raw)
			return sum.Prose()
		})
		// The transform's text is never returned: only what it does.
		if e.Set && !e.Unknown {
			e.Value = sum.Compact()
		}
		out = append(out, e)
	}
	return out
}

// --- request defaults -------------------------------------------------------

func requestDefaults(s *Snapshot) []Entry {
	const via = " Submissions through this server get the same default."
	return []Entry{
		entry(s, "JOB_DEFAULT_REQUESTCPUS", func(v Value) string {
			return requestSentence(v, "request_cpus", "CPUs", "") + via
		}),
		entry(s, "JOB_DEFAULT_REQUESTMEMORY", func(v Value) string {
			return requestSentence(v, "request_memory", "memory", "MiB") + via
		}),
		entry(s, "JOB_DEFAULT_REQUESTDISK", func(v Value) string {
			text := requestSentence(v, "request_disk", "disk", "KiB")
			if strings.Contains(v.Raw, "TransferInputSizeMB") {
				text += " That expression scales with the job's input size, which is not known when a job is " +
					"submitted through this server, so such a job gets the expression's value for an unknown " +
					"input size (for HTCondor's own default, 1 GiB)."
			}
			return text + via
		}),
		entry(s, "JOB_DEFAULT_REQUESTGPUS", func(v Value) string {
			if !v.Set {
				return "Not set: a job with no request_gpus asks for no GPUs." + via
			}
			return requestSentence(v, "request_gpus", "GPUs", "") + via
		}),
	}
}

// requestSentence words a JOB_DEFAULT_REQUEST* value the way the submit
// engine reads it: a plain number in the attribute's base unit, a number
// with a unit suffix, "undefined", or an expression.
func requestSentence(v Value, command, what, unit string) string {
	switch {
	case !v.Set:
		return fmt.Sprintf("Not set: a job with no %s asks for no particular amount of %s.", command, what)
	case strings.EqualFold(v.Raw, "undefined"):
		return fmt.Sprintf("A job with no %s asks for no particular amount of %s.", command, what)
	}
	if _, err := strconv.ParseFloat(v.Raw, 64); err == nil {
		if unit != "" {
			return fmt.Sprintf("A job with no %s asks for %s %s of %s.", command, v.Raw, unit, what)
		}
		return fmt.Sprintf("A job with no %s asks for %s %s.", command, v.Raw, what)
	}
	if hasSizeSuffix(v.Raw) {
		return fmt.Sprintf("A job with no %s asks for %s of %s.", command, v.Raw, what)
	}
	return fmt.Sprintf("A job with no %s asks for %s computed as %s%s.", command, what, quoteExpr(v.Raw), unitNote(unit))
}

func unitNote(unit string) string {
	if unit == "" {
		return ""
	}
	return " (in " + unit + ")"
}

// hasSizeSuffix reports a number with a K/M/G/T unit, which the submit
// engine scales rather than storing as an expression.
func hasSizeSuffix(v string) bool {
	v = strings.TrimSpace(v)
	i := 0
	for i < len(v) && (v[i] >= '0' && v[i] <= '9' || v[i] == '.') {
		i++
	}
	if i == 0 {
		return false
	}
	rest := strings.ToUpper(strings.TrimSpace(v[i:]))
	switch rest {
	case "K", "KB", "M", "MB", "G", "GB", "T", "TB":
		return true
	}
	return false
}

// --- hold, remove, release --------------------------------------------------

// policyKind is one of the three SYSTEM_PERIODIC_* policies.
type policyKind struct {
	knob string
	// action is the sentence's subject and verb, e.g. "jobs are put on hold".
	action  string
	subcode bool
}

var policyKinds = []policyKind{
	{"SYSTEM_PERIODIC_HOLD", "A job is put on hold (HoldReasonCode 26)", true},
	{"SYSTEM_PERIODIC_REMOVE", "A job is removed from the queue", false},
	{"SYSTEM_PERIODIC_RELEASE", "A held job is released automatically", false},
}

func holdPolicy(s *Snapshot) []Entry {
	var out []Entry
	for _, k := range policyKinds {
		names, _ := splitNames(s.Get(k.knob + "_NAMES").Raw)
		out = append(out, entry(s, k.knob+"_NAMES", func(v Value) string {
			if !v.Set || len(names) == 0 {
				return "No named " + k.knob + " policies."
			}
			return fmt.Sprintf("Named %s policies, checked in this order before the unnamed one: %s.%s",
				k.knob, strings.Join(names, ", "), truncatedNote(s, k.knob+"_NAMES"))
		}))
		for _, n := range names {
			out = append(out, policyEntry(s, k, k.knob+"_"+n))
		}
		out = append(out, policyEntry(s, k, k.knob))
	}
	out = append(out, entry(s, "SYSTEM_MAX_RELEASES", func(v Value) string {
		n, err := strconv.Atoi(v.Raw)
		if !v.Set || err != nil || n < 0 {
			return "No limit on how many times a held job may be released."
		}
		return fmt.Sprintf("A job that has been held more than %d times is not released again -- not by "+
			"SYSTEM_PERIODIC_RELEASE, and not by you with release_job; only an administrator can.", n)
	}))
	return out
}

// policyEntry describes one SYSTEM_PERIODIC_* expression, leading with
// the reason a job will carry, which is written for people.
func policyEntry(s *Snapshot, k policyKind, name string) Entry {
	reason := s.Get(name + "_REASON")
	subcode := s.Get(name + "_SUBCODE")
	e := entry(s, name, func(v Value) string {
		if !v.Set {
			if name == k.knob {
				return "Not set."
			}
			return "Listed in " + k.knob + "_NAMES but not defined; the schedd ignores it."
		}
		if isTrivialPolicy(v.Raw) {
			return "Set to " + v.Raw + ", so it never applies."
		}
		var b strings.Builder
		b.WriteString(k.action)
		if text, literal := stringLiteral(reason.Raw); reason.Set && literal {
			fmt.Fprintf(&b, " with the reason %q", text)
		}
		fmt.Fprintf(&b, " when %s.", quoteExpr(v.Raw))
		if _, literal := stringLiteral(reason.Raw); reason.Set && !literal {
			fmt.Fprintf(&b, " The reason is computed from the job: %s.", quoteExpr(reason.Raw))
		}
		if k.subcode && subcode.Set {
			fmt.Fprintf(&b, " HoldReasonSubCode is %s.", quoteExpr(subcode.Raw))
		}
		return b.String()
	})
	e.Extra = map[string]interface{}{"reason": reasonText(reason)}
	if k.subcode {
		e.Extra["subcode"] = subcode.Raw
	}
	return e
}

// isTrivialPolicy matches what load_policy_list skips: a literal false.
func isTrivialPolicy(v string) bool {
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "false", "0":
		return true
	}
	return false
}

// --- file transfer ----------------------------------------------------------

func fileTransfer(s *Snapshot) []Entry {
	sizeLimit := func(files, when, command string) func(Value) string {
		return func(v Value) string {
			n, err := strconv.Atoi(v.Raw)
			switch {
			case !v.Set || err == nil && n < 0:
				return fmt.Sprintf("No limit on the size of a job's %s.", files)
			case err != nil:
				return fmt.Sprintf("A job is put on hold when its %s total more than %s MB, evaluated per job. "+
					"A job can set its own limit with %s.", files, quoteExpr(v.Raw), command)
			}
			return fmt.Sprintf("A job is put on hold when its %s total more than %d MB, %s. "+
				"A job can set its own limit with %s.", files, n, when, command)
		}
	}
	queueLimit := func(what string) func(Value) string {
		return func(v Value) string {
			n, err := strconv.Atoi(v.Raw)
			if !v.Set || err == nil && n == 0 {
				return fmt.Sprintf("No limit on how many %s run at once.", what)
			}
			return fmt.Sprintf("At most %s %s run at once, for all users together; the rest wait in the "+
				"transfer queue, so a job can sit in a transferring state for a while simply waiting its turn.",
				v.Raw, what)
		}
	}
	return []Entry{
		entry(s, "MAX_TRANSFER_INPUT_MB", sizeLimit("input files", "when they are sent to the execute node", "max_transfer_input_mb")),
		entry(s, "MAX_TRANSFER_OUTPUT_MB", sizeLimit("output files", "when they are brought back", "max_transfer_output_mb")),
		entry(s, "MAX_CONCURRENT_UPLOADS", queueLimit("input transfers (access point to execute node)")),
		entry(s, "MAX_CONCURRENT_DOWNLOADS", queueLimit("output transfers (execute node to access point)")),
	}
}

// --- DAGMan -----------------------------------------------------------------

func dagman(s *Snapshot, env map[string]string) []Entry {
	throttle := func(name, what, arg string) Entry {
		e := entry(s, name, func(v Value) string {
			return dagmanSentence(v.Raw, v.Set, what, arg)
		})
		if eff, ok := envOverride(env, name); ok {
			e.Effective = eff
			e.Description = fmt.Sprintf("This server starts DAGMan with _CONDOR_%s=%s, which overrides the "+
				"access point's value for every workflow submitted here: %s", name, eff,
				dagmanSentence(eff, eff != "", what, arg))
		}
		return e
	}
	return []Entry{
		throttle("DAGMAN_MAX_JOBS_IDLE", "idle node jobs, after which DAGMan submits no more until some start", "max_idle"),
		throttle("DAGMAN_MAX_JOBS_SUBMITTED", "node jobs in the queue at once", "max_jobs"),
		throttle("DAGMAN_MAX_PRE_SCRIPTS", "PRE scripts running at once", "max_pre"),
		throttle("DAGMAN_MAX_POST_SCRIPTS", "POST scripts running at once", "max_post"),
	}
}

func dagmanSentence(raw string, set bool, what, arg string) string {
	override := fmt.Sprintf(" submit_dag's %s argument overrides it for one workflow.", arg)
	n, err := strconv.Atoi(strings.TrimSpace(raw))
	if !set || err == nil && n <= 0 {
		return "No limit per workflow on " + what + "." + override
	}
	return fmt.Sprintf("Each workflow has at most %s %s.%s", raw, what, override)
}

// envOverride finds _CONDOR_<knob> in an environment. HTCondor matches
// the knob name without regard to case.
func envOverride(env map[string]string, knob string) (string, bool) {
	for k, v := range env {
		if strings.EqualFold(k, "_CONDOR_"+knob) {
			return strings.TrimSpace(v), true
		}
	}
	return "", false
}

// --- features ---------------------------------------------------------------

func features(s *Snapshot) []Entry {
	localNames := s.Get("LOCAL_CREDMON_PROVIDER_NAMES")
	clientNames := s.Get("CLIENT_CREDMON_PROVIDER_NAMES")
	addNames := s.Get("SUBMIT_ADD_LOCAL_CREDMON_PROVIDER_NAMES")

	epoch := entry(s, "JOB_EPOCH_HISTORY", func(v Value) string {
		if !v.Set {
			return "Not set: the access point keeps no record of a job's earlier run attempts, so " +
				"query_job_epochs finds nothing and analyze_issues sees only each job's latest attempt."
		}
		return "The access point records every run attempt of every job, so query_job_epochs and " +
			"analyze_issues can say why earlier attempts failed."
	})
	// A path on the access point: whether it is set is the policy, where
	// it points is not the caller's business.
	if epoch.Set {
		epoch.Value = "enabled"
	}

	return []Entry{
		entry(s, "SCHEDD_ALLOW_LATE_MATERIALIZE", func(v Value) string {
			lateNote := " Submissions through this server do not use it either way: every job is created when it " +
				"is submitted (max_materialize and max_idle in a submit file have no effect here), so each " +
				"counts in full against MAX_JOBS_PER_SUBMISSION and MAX_JOBS_PER_OWNER."
			if b, ok := parseBool(v.Raw); v.Set && ok && !b {
				return "The schedd refuses late materialization from condor_submit." + lateNote
			}
			return "The schedd accepts late materialization (max_materialize, max_idle) from condor_submit." + lateNote
		}),
		entry(s, "SCHEDD_ENABLE_SSH_TO_JOB", func(v Value) string {
			if b, ok := parseBool(v.Raw); v.Set && ok && !b {
				return "The access point refuses ssh into running jobs: exec_in_job and interactive sessions will not work."
			}
			text := "The access point allows ssh into a running job, which exec_in_job and interactive sessions use"
			if v.Set {
				if _, ok := parseBool(v.Raw); !ok {
					text += fmt.Sprintf(", for jobs where %s", quoteExpr(v.Raw))
				}
			}
			return text + ". It is necessary but not sufficient: each execute node can still refuse with its own " +
				"ENABLE_SSH_TO_JOB, and a job on such a node cannot be reached."
		}),
		entry(s, "START_SCHEDULER_UNIVERSE", func(v Value) string {
			if !v.Set {
				return "Not set: scheduler-universe jobs (each DAG's DAGMan is one) start whenever their own Requirements allow."
			}
			return fmt.Sprintf("Scheduler-universe jobs -- each DAG's DAGMan is one -- start only while %s; "+
				"otherwise they wait idle.", quoteExpr(v.Raw))
		}),
		epoch,
		entry(s, "LOCAL_CREDMON_PROVIDER_NAMES", func(v Value) string {
			if !v.Set {
				return "Not set: the access point issues no tokens of its own."
			}
			return fmt.Sprintf("Token services the access point issues itself: %s. use_oauth_services can name "+
				"them with nothing stored first.", listText(v.Raw))
		}),
		entry(s, "CLIENT_CREDMON_PROVIDER_NAMES", func(v Value) string {
			if !v.Set {
				return "Not set: no token services the access point obtains with its own client credentials."
			}
			return fmt.Sprintf("Token services the access point obtains with its own client credentials: %s. "+
				"use_oauth_services can name them with nothing stored first.", listText(v.Raw))
		}),
		entry(s, "SUBMIT_ADD_LOCAL_CREDMON_PROVIDERS", func(v Value) string {
			if b, ok := parseBool(v.Raw); v.Set && ok && !b {
				return "Jobs get only the tokens they name in use_oauth_services."
			}
			added := addNames.Raw
			if !addNames.Set {
				added = strings.TrimSpace(localNames.Raw + " " + clientNames.Raw)
			}
			if strings.TrimSpace(added) == "" {
				return "The access point would add its own token services to every job, but it has none."
			}
			return fmt.Sprintf("Every job gets tokens for %s, whether or not it names them in use_oauth_services.",
				listText(added))
		}),
		entry(s, "SUBMIT_ADD_LOCAL_CREDMON_PROVIDER_NAMES", func(v Value) string {
			if !v.Set {
				return "Not set: the services added to every job are the access point's own " +
					"(LOCAL_CREDMON_PROVIDER_NAMES and CLIENT_CREDMON_PROVIDER_NAMES)."
			}
			return fmt.Sprintf("The token services added to every job: %s.", listText(v.Raw))
		}),
		entry(s, "SUBMIT_TEMPLATE_NAMES", func(v Value) string {
			if !v.Set {
				return "No site submit templates."
			}
			return fmt.Sprintf("condor_submit on this access point offers the submit templates %s "+
				"(`use template : <name>`). Submissions through this server do not expand them -- such a line "+
				"has no effect here -- so write the submit commands out instead.", listText(v.Raw))
		}),
	}
}

// --- text helpers -----------------------------------------------------------

// stringLiteral unquotes a ClassAd string literal. False for anything
// else: a reason built with strcat() is an expression, quoted as one.
func stringLiteral(v string) (string, bool) {
	v = strings.TrimSpace(v)
	if len(v) < 2 || v[0] != '"' || v[len(v)-1] != '"' {
		return "", false
	}
	inner := v[1 : len(v)-1]
	var b strings.Builder
	for i := 0; i < len(inner); i++ {
		c := inner[i]
		if c == '\\' && i+1 < len(inner) {
			i++
			b.WriteByte(inner[i])
			continue
		}
		if c == '"' {
			return "", false
		}
		b.WriteByte(c)
	}
	return b.String(), true
}

// reasonText is a reason for the structured output: the message when it
// is a literal, the expression otherwise.
func reasonText(v Value) string {
	if text, ok := stringLiteral(v.Raw); ok {
		return text
	}
	return v.Raw
}

// quoteExpr renders an expression inline, bounded.
func quoteExpr(e string) string {
	return "`" + truncate(strings.Join(strings.Fields(e), " "), maxExprText) + "`"
}

func truncate(s string, n int) string {
	r := []rune(s)
	if len(r) <= n {
		return s
	}
	return string(r[:n]) + "…"
}

// listText renders a comma/space separated list as "a, b, c".
func listText(raw string) string {
	names, _ := splitNames(raw)
	return strings.Join(names, ", ")
}

func truncatedNote(s *Snapshot, list string) string {
	if n := s.truncated[list]; n > 0 {
		return fmt.Sprintf(" (%d more are listed but not reported here.)", n)
	}
	return ""
}

// Text renders the report as the tool's text answer.
func (r *Report) Text(ttl time.Duration) string {
	var b strings.Builder
	fmt.Fprintf(&b, "Policy of access point %s, as its schedd reports it (read %s", r.AccessPoint,
		r.FetchedAt.UTC().Format("2006-01-02 15:04 UTC"))
	if ttl > 0 {
		fmt.Fprintf(&b, "; re-read at most every %s", humanDuration(ttl))
	}
	b.WriteString("). [site] marks a value this access point changed from HTCondor's default.\n")
	for _, g := range r.Groups {
		fmt.Fprintf(&b, "\n## %s\n", g.Title)
		for _, e := range g.Entries {
			b.WriteString("- " + e.Name)
			if inline := inlineValue(e); inline != "" {
				b.WriteString(" = " + inline)
			}
			if e.NonDefault {
				b.WriteString(" [site]")
			}
			b.WriteString(": " + e.Description + "\n")
		}
	}
	return b.String()
}

// inlineValue is the value shown after a name in the text: short scalar
// values only. An expression is quoted in the sentence instead, and an
// unset knob shows nothing.
func inlineValue(e Entry) string {
	if !e.Set || e.Unknown || strings.ContainsAny(e.Value, "\n") || len(e.Value) > 40 {
		return ""
	}
	if strings.HasPrefix(e.Name, "JOB_TRANSFORM_") && e.Name != "JOB_TRANSFORM_NAMES" {
		return ""
	}
	return e.Value
}

func humanDuration(d time.Duration) string {
	if d%time.Minute == 0 {
		m := int(d / time.Minute)
		if m == 1 {
			return "minute"
		}
		return fmt.Sprintf("%d minutes", m)
	}
	return d.String()
}

// Structured renders the report as the tool's structuredContent.
func (r *Report) Structured() map[string]interface{} {
	groups := make([]map[string]interface{}, 0, len(r.Groups))
	for _, g := range r.Groups {
		entries := make([]map[string]interface{}, 0, len(g.Entries))
		for _, e := range g.Entries {
			m := map[string]interface{}{
				"name":        e.Name,
				"value":       e.Value,
				"set":         e.Set,
				"non_default": e.NonDefault,
				"description": e.Description,
			}
			if e.Unknown {
				m["unknown"] = true
			}
			if e.Effective != "" {
				m["effective"] = e.Effective
			}
			for k, v := range e.Extra {
				m[k] = v
			}
			entries = append(entries, m)
		}
		groups = append(groups, map[string]interface{}{"name": g.Name, "title": g.Title, "entries": entries})
	}
	return map[string]interface{}{
		"access_point": r.AccessPoint,
		"fetched_at":   r.FetchedAt.UTC().Format(time.RFC3339),
		"groups":       groups,
	}
}
