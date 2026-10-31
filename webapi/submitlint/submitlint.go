// Package submitlint reads a submit file before it is handed to the schedd
// and reports what the caller needs to know but cannot see: whether the job
// will sit held until its input is uploaded, and the constructs that parse
// cleanly while guaranteeing the job does not do what was meant.
//
// It lives apart from any one surface because every surface that accepts a
// submit file needs it. The MCP server has used it since the macro-expansion
// and transfer_executable footguns were found; the web submission page,
// which an LLM also writes submit descriptions for, submitted straight to
// the schedd with no check at all until these diagnostics were shared.
package submitlint

import (
	"fmt"
	"path"
	"regexp"
	"strings"

	"github.com/PelicanPlatform/classad/classad"

	htcondor "github.com/bbockelm/golang-htcondor"
	"github.com/bbockelm/golang-htcondor/config"
)

// Inspection is what a pre-submit read of a submit file tells us: whether
// the job will need an input upload to leave the HELD state, plus any
// constructs that parse cleanly but almost certainly do not do what the
// caller meant.
//
// Both diagnostic classes exist because HTCondor's submit language has
// footguns that a caller cannot discover from a successful submit:
// `$(...)` is macro-expanded by the submit parser before the shell ever
// sees it, a system-path executable is spool-copied unless
// transfer_executable is turned off, and an unset output, error or log
// discards that stream rather than defaulting to anything. The first
// produces a job that runs with silently corrupted arguments, the second a
// hold whose reason reads like a generic file-transfer failure, and the
// third a job that appears to have printed nothing. See
// https://github.com/bbockelm/golang-htcondor/issues/183.
type Inspection struct {
	// NeedsSpooling reports whether the caller must call
	// upload_job_input before the job can run.
	NeedsSpooling bool
	// Fatal is a submit-file mistake that cannot produce a working
	// job, so submit_job rejects the request instead of submitting.
	Fatal error
	// Warnings are non-fatal diagnostics surfaced in the submit_job
	// response.
	Warnings []string
}

// Advisory is every diagnostic as plain advice: the warnings, with the
// fatal one, if any, in front.
//
// It exists because "fatal" is a property of the caller, not of the submit
// file. submit_job refuses an executable under /bin with the default
// transfer_executable because the agent it serves has no way to put that
// file in the job's spool -- it is not on the submitting host and cannot
// get there. A REST caller may be sitting on that host, and the REST
// endpoint has accepted exactly these submit files since it existed, so
// there the same finding is something to mention rather than grounds to
// refuse a request that used to work.
//
// A surface that wants to refuse reads Fatal directly; this is for the
// ones that want to tell the caller and carry on.
func (i Inspection) Advisory() []string {
	if i.Fatal == nil {
		return i.Warnings
	}
	return append([]string{i.Fatal.Error()}, i.Warnings...)
}

// Inspect parses the submit file the way condor_submit would
// and reports what submit_job needs to know before and after handing it
// to the schedd. A submit file this package cannot parse yields a
// conservative inspection (spooling assumed, no diagnostics) rather than
// an error: the schedd is the authority on what it accepts, and refusing
// to submit over a local parse failure would be worse than letting the
// schedd answer.
func Inspect(raw string) Inspection {
	insp := Inspection{NeedsSpooling: true}

	sf, err := htcondor.ParseSubmitFile(strings.NewReader(raw))
	if err != nil {
		return insp
	}
	// Proc 0 of an arbitrary cluster: most attributes read below do not
	// depend on the job ID, and the real cluster is not known until
	// after the submit.
	ad, err := sf.MakeJobAd(htcondor.JobID{Cluster: 1, Proc: 0}, nil)
	if err != nil {
		return insp
	}
	// A second pair of ads, resolved for two different processes, used only
	// to ask whether a file name varies per process. Comparing two resolved
	// ads answers that for any macro the submit parser understands, where
	// matching $(ProcId) in the raw text would answer it only for the
	// spellings thought of here -- $(Process), $(Step), $(Row), $(ItemIndex)
	// and a queue variable all vary too.
	//
	// Their queue variables are bound to per-process sentinels rather than
	// left nil, because nil expands every one of them to the same empty
	// string: `output = $(name).out` would resolve to ".out" for both
	// processes and be reported as a collision, which is the opposite of the
	// truth. These two ads feed only that comparison -- the checks below
	// keep reading `ad`, so a sentinel can never be mistaken for a real
	// executable or input file.
	rowA, errA := sf.MakeJobAd(htcondor.JobID{Cluster: 1, Proc: 0}, queueVarSentinels(sf, "a"))
	rowB, errB := sf.MakeJobAd(htcondor.JobID{Cluster: 1, Proc: 1}, queueVarSentinels(sf, "b"))
	if errA != nil || errB != nil {
		rowA, rowB = nil, nil
	}

	// TransferExecutable defaults to true.
	transferExec := true
	if val, ok := ad.EvaluateAttrBool("TransferExecutable"); ok {
		transferExec = val
	}
	transferInput, _ := ad.EvaluateAttrString("TransferInput")
	// Input is stdin redirection; the file has to be spooled too.
	stdinFile, _ := ad.EvaluateAttrString("Input")
	insp.NeedsSpooling = transferExec || transferInput != "" || stdinFile != ""

	// The executable AS WRITTEN, not the ad's Cmd. The submit parser
	// resolves a relative executable against the submitting directory,
	// exactly as condor_submit does, so Cmd is absolute whatever the
	// caller typed and cannot answer what these two checks ask: whether
	// the caller named a path on a machine or a file they will upload.
	cmd, _ := sf.Command("executable")
	// The RAW transfer_executable value, for the diagnostics: a caller who
	// wrote one that does not turn the transfer off has a different problem
	// from one who wrote nothing, and needs to be told which.
	rawTransferExec, _ := sf.Command("transfer_executable")
	if err := checkExecutableTransfer(cmd, transferExec, rawTransferExec); err != nil {
		insp.Fatal = err
		return insp
	}
	insp.Warnings = append(insp.Warnings, warnExecutableTransfer(cmd, transferExec, rawTransferExec)...)
	insp.Warnings = append(insp.Warnings, warnUndefinedMacros(raw)...)
	insp.Warnings = append(insp.Warnings, warnDiscardedOutput(ad, rowA, rowB, sf.QueueCount())...)
	return insp
}

// discardedStream describes one of the three submit commands whose
// absence throws data away rather than defaulting to something useful.
type discardedStream struct {
	// command is the submit-file keyword, as a caller would write it.
	command string
	// attr is the job-ad attribute the keyword becomes, which is what is
	// read back here: by then the submit parser has resolved defaults and
	// expanded macros, so this is the value the job will really run with.
	attr string
	// loss is what the job no longer has, phrased as a consequence.
	loss string
}

var discardedStreams = []discardedStream{
	{"output", "Out", "the job's stdout is discarded"},
	{"error", "Err", "the job's stderr is discarded"},
	{"log", "UserLog", "nothing records when the job started, how often it was evicted, " +
		"or why it stopped"},
}

// warnDiscardedOutput reports streams this submit file throws away.
//
// This is the mistake with no second chance. A held job can be released and
// a corrupted command line can be resubmitted, but output that was never
// written is not recoverable at any price: the only remedy is to run the
// work again, which for a job that ran for hours is the expensive kind of
// again. It is invisible from the outcome, too -- a job whose stdout went
// nowhere looks exactly like a job that printed nothing -- so if this check
// does not raise it, nothing will.
//
// Leaving the command out and writing /dev/null are reported as the same
// thing because HTCondor makes them the same thing: an unset output or
// error resolves to /dev/null in the job ad, which is why this reads the
// resolved value rather than looking for the assignment.
func warnDiscardedOutput(ad, rowA, rowB *classad.ClassAd, procs int) []string {
	var lost []string
	for _, st := range discardedStreams {
		val := strings.TrimSpace(mustString(ad, st.attr))
		if val != "" && !isNullDevice(val) {
			continue
		}
		if val == "" {
			lost = append(lost, fmt.Sprintf("%s is not set, so %s", st.command, st.loss))
			continue
		}
		lost = append(lost, fmt.Sprintf("%s is %s, so %s", st.command, val, st.loss))
	}
	if len(lost) == 0 {
		return collidingOutputNames(rowA, rowB, procs)
	}
	return append([]string{fmt.Sprintf(
		"this submit file throws away output that cannot be recovered afterwards: %s. "+
			"None of output, error and log defaults to a file -- an unset output or error "+
			"resolves to /dev/null, and an unset log means no log at all. Set all three to "+
			"real file names (output = run-$(ProcId).out, error = run-$(ProcId).err, "+
			"log = run.log); the only way to get this job's output now is to run it again.",
		strings.Join(lost, "; "))}, collidingOutputNames(rowA, rowB, procs)...)
}

// mustString reads a string-valued attribute, treating an attribute that is
// absent or not a string as absent. Every attribute read here is one the
// submit parser writes as a path or does not write at all.
func mustString(ad *classad.ClassAd, attr string) string {
	val, _ := ad.EvaluateAttrString(attr)
	return val
}

// isNullDevice recognises the ways a submit file spells "throw it away".
// Only the device itself: a file genuinely named dev-null.txt is not this.
func isNullDevice(path string) bool {
	switch strings.TrimSpace(path) {
	case "/dev/null", "NUL", "nul":
		return true
	}
	return false
}

// collidingOutputNames reports a multi-process submission whose output and
// error names come out the same for every process.
//
// The last writer wins and the rest of the run is lost, which reads to the
// person who submitted it as "most of my jobs produced nothing" rather than
// as a submit-file mistake. It is checked separately from the discard
// warnings because a submit file can have this one while setting all three
// commands to perfectly good names.
//
// Whether a name varies is decided by resolving it for two different
// processes and comparing, so it is the submit parser's own answer rather
// than a guess from the macro text.
func collidingOutputNames(rowA, rowB *classad.ClassAd, procs int) []string {
	if procs < 2 || rowA == nil || rowB == nil {
		return nil
	}
	var fixed []string
	for _, st := range discardedStreams[:2] { // output and error; one shared log is correct
		val := strings.TrimSpace(mustString(rowA, st.attr))
		if val == "" || isNullDevice(val) {
			continue // already covered by warnDiscardedOutput
		}
		if strings.TrimSpace(mustString(rowB, st.attr)) != val {
			continue // varies per process, which is the point
		}
		fixed = append(fixed, st.command+" = "+val)
	}
	if len(fixed) == 0 {
		return nil
	}
	return []string{fmt.Sprintf("this submit file queues %d processes but %s does not vary per process, "+
		"so every process writes the same file and only the last one to finish survives. "+
		"Put $(ProcId) in the name (output = run-$(ProcId).out).",
		procs, strings.Join(fixed, " and "))}
}

// queueVarSentinels binds every variable the queue statement supplies to a
// value unique to one process, so that resolving the same submit file twice
// shows which file names actually depend on the row and which do not.
//
// The values are deliberately meaningless. Nothing reads them; only whether
// the two resolutions differ is read, and a real row's values are not
// knowable here anyway -- `queue from <file>` reads a file on the
// submitting host, which this server cannot see.
func queueVarSentinels(sf *htcondor.SubmitFile, suffix string) map[string]string {
	names := sf.QueueVars()
	if len(names) == 0 {
		return nil
	}
	vars := make(map[string]string, len(names))
	for _, name := range names {
		vars[name] = "row-" + suffix
	}
	return vars
}

// checkExecutableTransfer rejects the one executable/transfer_executable
// combination that has no working outcome: a machine-owned path that
// HTCondor will rewrite to a spool location the caller cannot populate.
func checkExecutableTransfer(cmd string, transferExec bool, rawTransferExec string) error {
	if !transferExec || !htcondor.IsSystemExecutablePath(cmd) {
		return nil
	}
	return fmt.Errorf("submit file rejected: executable = %s is a system path, but %s "+
		"so HTCondor spool-copies the executable from the submit directory. "+
		"That copy does not exist, and the job would go on hold with "+
		"\"Transfer input files failure ... (errno 2) No such file or directory\" "+
		"(HoldReasonCode 13, HoldReasonSubCode 2) instead of running.\n"+
		"Fix: add \"transfer_executable = False\" to run the %s already installed on the execute node. "+
		"To ship your own program instead, set executable to a bare filename (e.g. \"executable = %s\") "+
		"and upload it with upload_job_input", cmd, transferExecPhrase(rawTransferExec), path.Base(cmd), path.Base(cmd))
}

// warnExecutableTransfer flags an absolute-path executable that will be
// spooled. Unlike the system-path case this can work, but only if the
// upload names the basename, so say so.
func warnExecutableTransfer(cmd string, transferExec bool, rawTransferExec string) []string {
	if !transferExec || !strings.HasPrefix(cmd, "/") || htcondor.IsSystemExecutablePath(cmd) {
		return nil
	}
	return []string{fmt.Sprintf("executable = %s is an absolute path and %s "+
		"so HTCondor expects the executable to be spooled: upload_job_input must include "+
		"a file named %q (with is_executable set). If the file already exists on the execute node, "+
		"set transfer_executable = False instead.", cmd, transferExecPhrase(rawTransferExec), path.Base(cmd))}
}

// macroReference matches a `$(NAME)` or `$(NAME:default)` submit-file
// macro reference. `$$(...)` (deferred until matchmaking) is excluded by
// the check on the preceding byte in findMacroReferences, not here.
var macroReference = regexp.MustCompile(`\$\(([^()$]+)\)`)

// liveSubmitMacros are the per-job macros the submit parser defines
// itself, so a reference to one is never an undefined-macro mistake.
var liveSubmitMacros = map[string]bool{
	"cluster":   true,
	"clusterid": true,
	"process":   true,
	"procid":    true,
	"node":      true,
	"item":      true,
	"itemindex": true,
	"step":      true,
	"row":       true,
	"dollar":    true,
}

// warnUndefinedMacros reports `$(NAME)` references that no macro
// defines, which HTCondor silently expands to the empty string. The
// common way to hit this is writing shell command substitution —
// `arguments = -c "echo $(hostname)"` — which the submit parser eats
// before bash sees it, leaving a corrupted command line and, when the
// substitution sat inside quotes, unbalanced quoting.
//
// All such references collapse into a single warning: an agent that
// wrote one $(...) by mistake usually wrote several, and the
// explanation only needs saying once.
func warnUndefinedMacros(raw string) []string {
	// Read the submit file with the config grammar that parses it for
	// real, so line continuations, comments and `queue VARS from`
	// variable lists need no second implementation here. An
	// unparseable file yields no statements and no diagnostics; the
	// schedd is the authority on what it accepts.
	stmts, err := config.Parse(config.NewLexer(strings.NewReader(raw)))
	if err != nil {
		return nil
	}
	assignments, defined := collectSubmitAssignments(stmts)

	// Group the undefined references by the submit command that
	// referenced them, in the order they appear.
	var keys []string
	byKey := map[string][]string{}
	seen := map[string]bool{}
	for _, a := range assignments {
		key := strings.ToLower(a.Name)
		for _, ref := range findMacroReferences(a.Value) {
			// A `$(NAME:default)` reference expands to the default
			// rather than to nothing, so it is not this mistake.
			if strings.Contains(ref, ":") {
				continue
			}
			lowered := strings.ToLower(strings.TrimSpace(ref))
			if defined[lowered] || liveSubmitMacros[lowered] || seen[lowered] {
				continue
			}
			seen[lowered] = true
			if _, ok := byKey[key]; !ok {
				keys = append(keys, key)
			}
			byKey[key] = append(byKey[key], "$("+ref+")")
		}
	}
	if len(keys) == 0 {
		return nil
	}

	refs := make([]string, 0, len(keys))
	for _, key := range keys {
		refs = append(refs, key+" references "+strings.Join(byKey[key], ", "))
	}
	return []string{fmt.Sprintf("%s. No submit variable defines %s, so HTCondor's submit parser expanded each "+
		"to an empty string before the job was created. HTCondor expands every $(...) in a submit file itself, "+
		"so $(...) cannot be used for shell command substitution — the shell never sees it. Put the commands in "+
		"a script file, upload it with upload_job_input, and name it as the executable; or define the "+
		"variables in the submit file.", strings.Join(refs, "; "), pluralizeRefs(len(seen)))}
}

// pluralizeRefs keeps the one-reference case from reading as a plural.
func pluralizeRefs(n int) string {
	if n == 1 {
		return "it"
	}
	return "them"
}

// collectSubmitAssignments walks the parsed submit file and returns its
// assignments in order plus the set of names something defines: an
// assignment (`+Attr` included), or a `queue VARS in|from` variable
// list, whose names the queue iterator supplies per row. Conditional
// branches are walked because the submit parser executes one of them.
func collectSubmitAssignments(stmts []config.Statement) ([]*config.Assignment, map[string]bool) {
	var assignments []*config.Assignment
	defined := map[string]bool{}

	var walk func([]config.Statement)
	walk = func(in []config.Statement) {
		for _, stmt := range in {
			switch v := stmt.(type) {
			case *config.Assignment:
				assignments = append(assignments, v)
				// AssignedName, not v.Name: `+Foo = 1` defines
				// $(MY.Foo), not $(Foo). Recording the bare name would
				// keep this quiet about a $(Foo) that expands to
				// nothing — the exact mistake this check exists for.
				defined[strings.ToLower(config.AssignedName(v))] = true
			case *config.QueueStatement:
				for _, name := range v.VarNames {
					defined[strings.ToLower(name)] = true
				}
			case *config.Conditional:
				walk(v.ThenBlock)
				for _, elif := range v.ElseIfBlock {
					walk(elif.Block)
				}
				walk(v.ElseBlock)
			}
		}
	}
	walk(stmts)
	return assignments, defined
}

// findMacroReferences returns the macro names referenced by a submit
// value, skipping `$$(...)` and `$$([...])` (resolved at match time
// against the machine ad, not by the submit parser).
func findMacroReferences(value string) []string {
	var names []string
	for _, loc := range macroReference.FindAllStringSubmatchIndex(value, -1) {
		if loc[0] > 0 && value[loc[0]-1] == '$' {
			continue
		}
		names = append(names, value[loc[2]:loc[3]])
	}
	return names
}

// transferExecPhrase says WHY the executable is being transferred, which is
// not the same sentence in the two cases that reach it.
//
// condor_submit turns the transfer off only for a transfer_executable whose
// FIRST CHARACTER is 'f' or 'F' (SetExecutable tests exactly that), so
// "transfer_executable = NO" -- or "no", or "0" -- reads as a value it does
// not recognise and leaves the transfer ON. Telling such a caller that the
// setting "is not set" sends them looking for a line they already wrote;
// this names the value back to them instead.
func transferExecPhrase(raw string) string {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return "transfer_executable is not set (it defaults to true),"
	}
	if trimmed[0] == 'f' || trimmed[0] == 'F' {
		// Not reachable while transferExec is true, but keep the sentence
		// honest if it ever is.
		return "transfer_executable is off,"
	}
	return fmt.Sprintf("transfer_executable = %s does NOT turn the transfer off "+
		"(condor_submit tests only the first character of the value, so false/False/F work "+
		"and NO/no/0 do not),", trimmed)
}
