package dagman

import (
	"bufio"
	"strings"
)

// This is a deliberately shallow reader of submit descriptions. It exists
// to answer one question -- which files does this node need staged with
// the DAG -- and it is wrong to grow it into a second condor_submit.
//
// It reads literal values only -- but "literal" is decided AFTER the
// node's own macros are substituted. VARS give each node a different
// value, which is what the expander supplies; a value that still depends
// on a macro once that is done ($(RETRY), $(DAGManJobId)) is dropped
// rather than guessed at, because a wrong guess here would either demand
// a file that is never used or, worse, quietly approve a workflow that is
// missing one.

// macroExpander substitutes the macros a node supplies into a submit
// value. A nil expander substitutes nothing, which is what a caller with
// no node in hand passes.
type macroExpander func(string) string

func (e macroExpander) apply(v string) string {
	if e == nil {
		return v
	}
	return e(v)
}

// submitValues returns the values assigned to key, split as a submit file
// splits a file list. A value that still depends on a macro after
// expansion is dropped.
func submitValues(body, key string, expand macroExpander) []string {
	var out []string
	sc := bufio.NewScanner(strings.NewReader(body))
	sc.Buffer(make([]byte, 0, 8*1024), 1024*1024)
	for sc.Scan() {
		k, v, ok := submitAssignment(sc.Text())
		if !ok || !strings.EqualFold(k, key) {
			continue
		}
		for _, f := range splitFileList(expand.apply(v)) {
			f = strings.TrimSpace(f)
			f = strings.Trim(f, `"`)
			if f == "" || strings.Contains(f, "$(") {
				continue
			}
			out = append(out, f)
		}
	}
	return out
}

// submitString returns the last value assigned to key, expanded, or "".
// Last wins, because a submit file is a sequence of macro assignments and
// the one in force at `queue` is the last one written.
func submitString(body, key string, expand macroExpander) string {
	out := ""
	sc := bufio.NewScanner(strings.NewReader(body))
	sc.Buffer(make([]byte, 0, 8*1024), 1024*1024)
	for sc.Scan() {
		k, v, ok := submitAssignment(sc.Text())
		if !ok || !strings.EqualFold(k, key) {
			continue
		}
		out = strings.Trim(strings.TrimSpace(expand.apply(v)), `"`)
	}
	return out
}

// submitBool reads a submit-file boolean, returning def when the key is
// absent or not a recognizable boolean.
func submitBool(body, key string, def bool) bool {
	v := submitString(body, key, nil)
	switch strings.ToLower(v) {
	case "true", "yes", "t", "1":
		return true
	case "false", "no", "f", "0":
		return false
	}
	return def
}

// submitInputFiles is every file a node needs staged alongside the DAG:
// its declared inputs, its stdin, and its executable when that is a
// relative path being transferred.
//
// Node jobs run with Iwd set to the DAG's own spool directory, so these
// have to be in the DAG's spool -- not the node's, which does not exist
// as a separate thing. Missing this is the classic way a DAG that submits
// cleanly fails on its first node.
func submitInputFiles(body string, expand macroExpander) []string {
	if strings.TrimSpace(body) == "" {
		return nil
	}
	seen := map[string]bool{}
	var out []string
	add := func(f string) {
		if f == "" || seen[f] {
			return
		}
		seen[f] = true
		out = append(out, f)
	}
	// should_transfer_files = NO means nothing is transferred at all, so
	// the node's declared inputs are not ours to stage: they are expected
	// to be on the execute machine already (a shared filesystem).
	if !transfersFiles(body) {
		return nil
	}
	for _, f := range submitValues(body, "transfer_input_files", expand) {
		// A trailing slash asks for a directory's CONTENTS. That cannot
		// survive the flat spool rewrite, and the name is not a file to
		// look for; analyzeJobNode reports it separately.
		if strings.HasSuffix(f, "/") {
			continue
		}
		add(f)
	}
	if in := submitString(body, "input", expand); in != "" && !strings.Contains(in, "$(") {
		add(in)
	}
	// The executable is transferred by default, but only a relative path
	// is ours to stage: an absolute one names a binary on the machine that
	// runs the job.
	if exe := submitString(body, "executable", expand); exe != "" &&
		!strings.Contains(exe, "$(") &&
		!strings.HasPrefix(exe, "/") &&
		submitBool(body, "transfer_executable", true) {
		add(exe)
	}
	return out
}

// submitAssignment splits one submit-file line into key and value.
// Returns ok=false for comments, blanks, and anything that is not an
// assignment (a bare `queue`, most obviously).
func submitAssignment(line string) (key, value string, ok bool) {
	line = strings.TrimSpace(line)
	if line == "" || strings.HasPrefix(line, "#") {
		return "", "", false
	}
	i := strings.IndexAny(line, "=")
	if i <= 0 {
		return "", "", false
	}
	key = strings.TrimSpace(line[:i])
	value = strings.TrimSpace(line[i+1:])
	// Submit files allow `key = value` and `key=value`; they do not allow
	// whitespace inside a key, so a "key" with a space in it means this
	// line was something else (an expression, a queue statement).
	if key == "" || strings.ContainsAny(key, " \t") {
		return "", "", false
	}
	return key, value, true
}

// splitFileList splits a submit-file list on commas, except inside a URL
// query string: `?a=1,2` is one URL, not two files.
//
// The discriminator is the missing space. A list an author wrote reads
// "a.txt, b.txt"; a comma inside a query string has nothing after it, so
// a fragment with no leading whitespace that follows a URL bearing a `?`
// is a continuation of that URL rather than the next entry.
func splitFileList(v string) []string {
	parts := strings.Split(v, ",")
	if !strings.Contains(v, "://") {
		return parts
	}
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		if n := len(out); n > 0 {
			prev := out[n-1]
			q := strings.Index(prev, "?")
			noLeadingSpace := p == strings.TrimLeft(p, " \t")
			if strings.Contains(prev, "://") && q > strings.Index(prev, "://") &&
				!strings.Contains(p, "://") && noLeadingSpace {
				out[n-1] = prev + "," + p
				continue
			}
		}
		out = append(out, p)
	}
	return out
}

// transfersFiles reports whether the node transfers files at all.
func transfersFiles(body string) bool {
	switch strings.ToLower(submitString(body, "should_transfer_files", nil)) {
	case "no", "never", "false":
		return false
	}
	return true
}

// submitDirTransfers returns the transfer_input_files entries that name a
// directory's contents with a trailing slash.
func submitDirTransfers(body string, expand macroExpander) []string {
	var out []string
	for _, f := range submitValues(body, "transfer_input_files", expand) {
		if strings.HasSuffix(f, "/") {
			out = append(out, f)
		}
	}
	return out
}

// submitHasMacroInput reports whether any file-naming key in the body has
// a value this reader deliberately drops because it STILL depends on a
// macro once the node's own VARS have been substituted. Those files exist
// but cannot be checked, which is what stops the analysis calling a
// supplied file unreferenced. A value the expander resolved is not a
// blind spot any more, so it does not count here.
func submitHasMacroInput(body string, expand macroExpander) bool {
	sc := bufio.NewScanner(strings.NewReader(body))
	sc.Buffer(make([]byte, 0, 8*1024), 1024*1024)
	for sc.Scan() {
		k, v, ok := submitAssignment(sc.Text())
		if !ok || !strings.Contains(expand.apply(v), "$(") {
			continue
		}
		switch strings.ToLower(k) {
		case "transfer_input_files", "input", "executable":
			return true
		}
	}
	return false
}
