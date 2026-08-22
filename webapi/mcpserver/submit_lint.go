package mcpserver

import (
	"fmt"
	"path"
	"regexp"
	"strings"

	htcondor "github.com/bbockelm/golang-htcondor"
)

// submitInspection is what a pre-submit read of a submit file tells us:
// whether the job will need an upload_job_input round to leave the HELD
// state, plus any constructs that parse cleanly but almost certainly do
// not do what the caller meant.
//
// Both diagnostic classes exist because HTCondor's submit language has
// two footguns that an agent cannot discover from a successful submit:
// `$(...)` is macro-expanded by the submit parser before the shell ever
// sees it, and a system-path executable is spool-copied unless
// transfer_executable is turned off. The first produces a job that runs
// with silently corrupted arguments; the second produces a hold whose
// reason reads like a generic file-transfer failure. See
// https://github.com/bbockelm/golang-htcondor/issues/183.
type submitInspection struct {
	// needsSpooling reports whether the caller must call
	// upload_job_input before the job can run.
	needsSpooling bool
	// fatal is a submit-file mistake that cannot produce a working
	// job, so submit_job rejects the request instead of submitting.
	fatal error
	// warnings are non-fatal diagnostics surfaced in the submit_job
	// response.
	warnings []string
}

// formatSubmitWarnings renders the non-fatal diagnostics for the
// submit_job response. It leads the response text rather than trailing
// it: the job is already submitted by the time these are known, so the
// caller has to decide whether to remove and resubmit it.
func formatSubmitWarnings(warnings []string) string {
	if len(warnings) == 0 {
		return ""
	}
	var b strings.Builder
	b.WriteString("WARNINGS about this submit file:\n")
	for _, w := range warnings {
		fmt.Fprintf(&b, "- %s\n", w)
	}
	b.WriteString("The job was submitted anyway; remove it with remove_job and resubmit if a warning " +
		"describes a mistake.\n\n")
	return b.String()
}

// systemExecutablePrefixes are directories whose contents belong to the
// machine, not to the submitter: an executable under one of these can
// never be supplied through upload_job_input, so naming one while
// leaving transfer_executable at its default of true is always a
// mistake. Deliberately narrower than "any absolute path" — an absolute
// path into a home or project directory *can* be satisfied by uploading
// a file with the same basename, so that case only warns.
var systemExecutablePrefixes = []string{
	"/bin/",
	"/sbin/",
	"/lib/",
	"/lib64/",
	"/usr/",
	"/opt/",
	"/cvmfs/",
}

// inspectSubmitFile parses the submit file the way condor_submit would
// and reports what submit_job needs to know before and after handing it
// to the schedd. A submit file this package cannot parse yields a
// conservative inspection (spooling assumed, no diagnostics) rather than
// an error: the schedd is the authority on what it accepts, and refusing
// to submit over a local parse failure would be worse than letting the
// schedd answer.
func inspectSubmitFile(raw string) submitInspection {
	insp := submitInspection{needsSpooling: true}

	sf, err := htcondor.ParseSubmitFile(strings.NewReader(raw))
	if err != nil {
		return insp
	}
	// Proc 0 of an arbitrary cluster: the attributes read below do not
	// depend on the job ID, and the real cluster is not known until
	// after the submit.
	ad, err := sf.MakeJobAd(htcondor.JobID{Cluster: 1, Proc: 0}, nil)
	if err != nil {
		return insp
	}

	// TransferExecutable defaults to true.
	transferExec := true
	if val, ok := ad.EvaluateAttrBool("TransferExecutable"); ok {
		transferExec = val
	}
	transferInput, _ := ad.EvaluateAttrString("TransferInput")
	// Input is stdin redirection; the file has to be spooled too.
	stdinFile, _ := ad.EvaluateAttrString("Input")
	insp.needsSpooling = transferExec || transferInput != "" || stdinFile != ""

	cmd, _ := ad.EvaluateAttrString("Cmd")
	if err := checkExecutableTransfer(cmd, transferExec); err != nil {
		insp.fatal = err
		return insp
	}
	insp.warnings = append(insp.warnings, warnExecutableTransfer(cmd, transferExec)...)
	insp.warnings = append(insp.warnings, warnUndefinedMacros(raw)...)
	return insp
}

// checkExecutableTransfer rejects the one executable/transfer_executable
// combination that has no working outcome: a machine-owned path that
// HTCondor will rewrite to a spool location the caller cannot populate.
func checkExecutableTransfer(cmd string, transferExec bool) error {
	if !transferExec || !isSystemExecutablePath(cmd) {
		return nil
	}
	return fmt.Errorf("submit file rejected: executable = %s is a system path, but transfer_executable is not set "+
		"(it defaults to true), so HTCondor spool-copies the executable from the submit directory. "+
		"That copy does not exist, and the job would go on hold with "+
		"\"Transfer input files failure ... (errno 2) No such file or directory\" "+
		"(HoldReasonCode 13, HoldReasonSubCode 2) instead of running.\n"+
		"Fix: add \"transfer_executable = False\" to run the %s already installed on the execute node. "+
		"To ship your own program instead, set executable to a bare filename (e.g. \"executable = %s\") "+
		"and upload it with upload_job_input", cmd, path.Base(cmd), path.Base(cmd))
}

// warnExecutableTransfer flags an absolute-path executable that will be
// spooled. Unlike the system-path case this can work, but only if the
// upload names the basename, so say so.
func warnExecutableTransfer(cmd string, transferExec bool) []string {
	if !transferExec || !strings.HasPrefix(cmd, "/") || isSystemExecutablePath(cmd) {
		return nil
	}
	return []string{fmt.Sprintf("executable = %s is an absolute path and transfer_executable is not set "+
		"(it defaults to true), so HTCondor expects the executable to be spooled: upload_job_input must include "+
		"a file named %q (with is_executable set). If the file already exists on the execute node, "+
		"set transfer_executable = False instead.", cmd, path.Base(cmd))}
}

func isSystemExecutablePath(cmd string) bool {
	for _, prefix := range systemExecutablePrefixes {
		if strings.HasPrefix(cmd, prefix) {
			return true
		}
	}
	return false
}

// submitAssignment matches a submit-file assignment line: `key = value`,
// including the `+Attr = value` and `MY.Attr = value` spellings.
var submitAssignment = regexp.MustCompile(`^\s*([+A-Za-z_][A-Za-z0-9_.]*)\s*=\s*(.*)$`)

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

// queueVarNames matches the variable list of a `queue VARS in|from ...`
// statement; those names are defined per-row by the queue iterator.
var queueVarNames = regexp.MustCompile(`(?i)^\s*queue\s+(?:\d+\s+)?([A-Za-z_][A-Za-z0-9_,\s]*?)\s+(?:in|from)\b`)

// warnUndefinedMacros reports `$(NAME)` references that no macro
// defines, which HTCondor silently expands to the empty string. The
// common way to hit this is writing shell command substitution —
// `arguments = -c "echo $(hostname)"` — which the submit parser eats
// before bash sees it, leaving a corrupted command line and, when the
// substitution sat inside quotes, unbalanced quoting.
func warnUndefinedMacros(raw string) []string {
	lines := logicalLines(raw)

	defined := map[string]bool{}
	for _, line := range lines {
		if m := submitAssignment.FindStringSubmatch(line); m != nil {
			defined[strings.ToLower(strings.TrimPrefix(m[1], "+"))] = true
		}
		if m := queueVarNames.FindStringSubmatch(line); m != nil {
			for _, name := range strings.Split(m[1], ",") {
				if name = strings.TrimSpace(name); name != "" {
					defined[strings.ToLower(name)] = true
				}
			}
		}
	}

	var warnings []string
	seen := map[string]bool{}
	for _, line := range lines {
		m := submitAssignment.FindStringSubmatch(line)
		if m == nil {
			continue
		}
		key, value := m[1], m[2]
		for _, ref := range findMacroReferences(value) {
			// A `$(NAME:default)` reference expands to the default
			// rather than to nothing, so it is not this mistake.
			if strings.Contains(ref, ":") {
				continue
			}
			lowered := strings.ToLower(strings.TrimSpace(ref))
			if defined[lowered] || liveSubmitMacros[lowered] {
				continue
			}
			if seen[lowered] {
				continue
			}
			seen[lowered] = true
			warnings = append(warnings, fmt.Sprintf("%s references $(%s), which is not a submit variable: "+
				"HTCondor's submit parser expanded it to an empty string before the job was created. "+
				"HTCondor expands every $(...) in a submit file itself, so $(...) cannot be used for shell "+
				"command substitution — the shell never sees it. Put the commands in a script file, upload it "+
				"with upload_job_input, and name it as the executable; or define %s in the submit file.",
				strings.ToLower(key), ref, ref))
		}
	}
	return warnings
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

// logicalLines splits a submit file into logical lines: comments and
// blanks dropped, backslash continuations joined, so an assignment
// spread over several physical lines is linted as one value.
func logicalLines(raw string) []string {
	var out []string
	var pending strings.Builder
	for _, line := range strings.Split(raw, "\n") {
		line = strings.TrimRight(line, "\r")
		if pending.Len() == 0 {
			if trimmed := strings.TrimSpace(line); trimmed == "" || strings.HasPrefix(trimmed, "#") {
				continue
			}
		}
		if strings.HasSuffix(line, `\`) {
			pending.WriteString(strings.TrimSuffix(line, `\`))
			continue
		}
		if pending.Len() > 0 {
			pending.WriteString(line)
			out = append(out, pending.String())
			pending.Reset()
			continue
		}
		out = append(out, line)
	}
	if pending.Len() > 0 {
		out = append(out, pending.String())
	}
	return out
}
