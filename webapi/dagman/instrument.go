package dagman

import (
	"fmt"
	"path"
	"path/filepath"
	"strconv"
	"strings"
)

// Instrumenting a workflow is what makes it readable while it runs.
//
// A DAG submitted through this server is SPOOLED, and the only way to
// read anything back out of a spooled sandbox is TRANSFER_DATA -- which
// for a spooled job is a CHANGED-FILE transfer: the schedd stamps a
// catalog of the sandbox at stage-in and sends back only what is newer
// (FileTransfer::FindChangedFiles, file_transfer.cpp ~1300). The .dag
// itself was staged as input and DAGMan only ever reads it, so it is
// never newer and never comes back. Forcing it back by naming it in
// TransferOutputFiles would REPLACE the changed-file set, and with it the
// node jobs' own outputs -- which land in the DAG's spool because a node
// job inherits the DAG's Iwd, and whose names are arbitrary and often
// macro-expanded, so they cannot be enumerated in advance.
//
// What DAGMan CREATES during the run does come back, for free. So the
// graph is published by asking DAGMan to write it:
//
//   - DOT <base>.dot writes the structure once at startup
//     (dagman_main.cpp:1135 calls Dag::DumpDotFile unconditionally after
//     parsing). Without UPDATE it is never rewritten, which is what makes
//     it cheap: one small file, the full node and edge set.
//   - NODE_STATUS_FILE <base>.status 30 writes per-node state at most
//     every 30 seconds, and once more when the DAG ends. It is the only
//     source that distinguishes NOT_READY, PRERUN and POSTRUN -- states
//     that are not jobs and so appear in no queue.
//
// Only the portable spelling of each command is used. The DAG this
// produces is handed to whatever condor_dagman the access point happens
// to run, and a token that version does not know is not ignored -- it is
// a PARSE ERROR that kills the workflow before a single node is
// submitted. `NODE_STATUS_FILE <file> <seconds>` has been accepted for
// twenty years; the `CLASSAD | JSON` and `COMPACT` arguments were added
// on 2026-09-11 (HTCONDOR-3928, src/condor_utils/dag_parser.cpp
// ParseNodeStatus) and an access point one release older answers them
// with "Failed to parse NODE_STATUS_FILE command: Unexpected token
// 'JSON'" and exits. The reader accepts either format, so asking for the
// newer one would buy nothing and cost every workflow on an older
// access point.

// instrumentStatusSeconds is the NODE_STATUS_FILE minimum update
// interval. DAGMan's own default is 60; 30 is chosen so a page that polls
// sees a node change state within a reasonable time, and it is a floor
// rather than a schedule -- DAGMan rewrites the file at most this often,
// not at least this often.
const instrumentStatusSeconds = 30

// Instrumentation names the files an instrumented workflow will write,
// and says which commands this package added.
//
// The names matter to the READER: a caller that wants the graph looks for
// exactly these files in the workflow's spool. When the author had
// already declared DOT or NODE_STATUS_FILE, theirs is what is named here
// -- their file is just as good, and adding a second command would be
// ignored by DAGMan anyway (Dag::SetNodeStatusFileName warns and keeps
// the first) or, for DOT, would silently override it.
type Instrumentation struct {
	DotFile    string
	StatusFile string
	// AddedDot and AddedStatus are false when the DAG's author had
	// already declared that command.
	AddedDot    bool
	AddedStatus bool
}

// Added reports whether Instrument changed the DAG text at all.
func (i Instrumentation) Added() bool { return i.AddedDot || i.AddedStatus }

// InstrumentBase is the stem the instrumented file names are built on:
// the DAG's file name with a trailing ".dag" removed. It is exported
// because the reader derives the same names from the manager job's -Dag
// argument, and the two must agree.
func InstrumentBase(dagName string) string {
	b := path.Base(filepath.ToSlash(strings.TrimSpace(dagName)))
	if strings.EqualFold(path.Ext(b), ".dag") {
		b = b[:len(b)-len(".dag")]
	}
	// DAGMan's own parser splits these commands on whitespace
	// (parse.cpp uses strtok with " \t" and honours no quoting), so a
	// generated name may not contain any.
	b = strings.Map(func(r rune) rune {
		if r == ' ' || r == '\t' {
			return '_'
		}
		return r
	}, b)
	if b == "" || b == "." || b == "/" {
		b = "workflow"
	}
	return b
}

// DotFileName is the name Instrument picks for the DOT file when nothing
// collides with it. A reader tries this first.
func DotFileName(dagName string) string { return InstrumentBase(dagName) + ".dot" }

// StatusFileName is the name Instrument picks for the node status file
// when nothing collides with it. A reader tries this first.
func StatusFileName(dagName string) string { return InstrumentBase(dagName) + ".status" }

// Instrument appends the two commands that make a workflow readable
// while it runs, and reports what the instrumented workflow will write.
//
// dagName is the name the DAG text will be staged under; staged is the
// other files going into the same sandbox (only the keys are used), so a
// generated name can never land on one of them. A spooled sandbox is one
// flat directory, so a collision would silently overwrite a caller's
// file.
//
// The author's own declarations win. A DAG that already says DOT or
// NODE_STATUS_FILE is returned unchanged for that half, with their file
// name reported instead.
func Instrument(dagText, dagName string, staged map[string]string) (string, Instrumentation) {
	var instr Instrumentation

	// Parse the top-level text only. A DOT or NODE_STATUS_FILE inside a
	// splice is not the top-level DAG's, and resolving splices here would
	// need files this function is not given.
	parsed := Parse(dagText)
	for _, ref := range parsed.Outputs {
		switch {
		case strings.EqualFold(ref.Command, "DOT") && instr.DotFile == "":
			instr.DotFile = ref.Path
		case strings.EqualFold(ref.Command, "NODE_STATUS_FILE") && instr.StatusFile == "":
			instr.StatusFile = ref.Path
		}
	}

	taken := map[string]bool{path.Base(filepath.ToSlash(dagName)): true}
	for name := range staged {
		taken[path.Base(filepath.ToSlash(name))] = true
	}
	if instr.DotFile != "" {
		taken[path.Base(filepath.ToSlash(instr.DotFile))] = true
	}
	if instr.StatusFile != "" {
		taken[path.Base(filepath.ToSlash(instr.StatusFile))] = true
	}

	base := InstrumentBase(dagName)
	var added []string
	if instr.DotFile == "" {
		instr.DotFile = freeName(base, ".dot", taken)
		instr.AddedDot = true
		taken[instr.DotFile] = true
		// No UPDATE: the structure does not change while the DAG runs, so
		// one write at startup is the whole file. With UPDATE, DAGMan
		// rewrites it on every status change, which on a 100,000-node
		// workflow is a large file written thousands of times.
		//
		// OVERWRITE is what pins the NAME. Without it DAGMan appends a
		// number and writes <file>.0, <file>.1 ... and the two parsers
		// disagree about the default: the legacy one overwrites
		// (dag.h `_overwrite_dot_file{true}`), the current one does not
		// (dag_commands.h DotCommand `overwrite{false}`), which was
		// observed as a "fanout.dot.0" against a 25.8 access point. The
		// reader still copes with either, but a deterministic name is
		// worth one word.
		added = append(added, "DOT "+instr.DotFile+" OVERWRITE")
	}
	if instr.StatusFile == "" {
		instr.StatusFile = freeName(base, ".status", taken)
		instr.AddedStatus = true
		taken[instr.StatusFile] = true
		// No format argument: see the file comment. DAGMan's default is
		// a stream of New ClassAds, which the reader handles, and naming
		// a format at all is what breaks an older DAGMan.
		added = append(added, fmt.Sprintf("NODE_STATUS_FILE %s %d",
			instr.StatusFile, instrumentStatusSeconds))
	}
	if len(added) == 0 {
		return dagText, instr
	}

	var b strings.Builder
	b.WriteString(strings.TrimRight(dagText, " \t\r\n"))
	// Two newlines: the first ends the author's last line, the second
	// ends any line-continuation backslash on it, which would otherwise
	// swallow the first command appended.
	b.WriteString("\n\n")
	b.WriteString("# Added on submission so this workflow can be read while it runs.\n")
	for _, cmd := range added {
		b.WriteString(cmd)
		b.WriteByte('\n')
	}
	return b.String(), instr
}

// freeName picks base+ext, or base-1+ext, base-2+ext ... when the sandbox
// already holds that name.
func freeName(base, ext string, taken map[string]bool) string {
	if name := base + ext; !taken[name] {
		return name
	}
	for i := 1; i < 1000; i++ {
		if name := base + "-" + strconv.Itoa(i) + ext; !taken[name] {
			return name
		}
	}
	// A thousand collisions is not a sandbox anyone built on purpose.
	// Returning the plain name loses the file rather than the workflow.
	return base + ext
}
